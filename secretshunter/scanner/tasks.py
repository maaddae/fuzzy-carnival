"""Celery tasks for scanner app."""

import logging
from datetime import UTC
from datetime import datetime
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import transaction

from .detectors.github_client import GitHubClient
from .detectors.github_client import GitHubClientError
from .detectors.scanner import SecretScanner
from .models import RepositoryScan
from .models import RepositoryWatchlist
from .models import SecretFinding
from .services import IssueCreationError
from .services import create_github_issue_for_scan

logger = logging.getLogger(__name__)


def _update_scan_status(scan: RepositoryScan, status: str) -> None:
    """Update scan status."""
    scan.scan_status = status
    scan.save(update_fields=["scan_status"])


def _store_scan_findings(scan: RepositoryScan, matches: list) -> None:
    """Store findings in database using bulk create."""
    findings_to_create = [
        SecretFinding(
            scan=scan,
            file_path=match.file_path,
            line_number=match.line_number,
            secret_type=match.secret_type,
            matched_pattern=match.matched_pattern,
            context_snippet=match.context_snippet,
            severity=match.severity,
        )
        for match in matches
    ]

    SecretFinding.objects.bulk_create(findings_to_create, batch_size=100)


def _complete_scan(scan: RepositoryScan, matches: list, files_scanned: int) -> None:
    """Mark scan as completed and update statistics."""
    scan.scan_status = RepositoryScan.ScanStatus.COMPLETED
    scan.total_files_scanned = files_scanned
    scan.secrets_found_count = len(matches)
    scan.completed_at = datetime.now(tz=UTC)
    scan.save(
        update_fields=[
            "scan_status",
            "total_files_scanned",
            "secrets_found_count",
            "completed_at",
        ],
    )


def _mark_scan_failed(scan: RepositoryScan, error_msg: str, prefix: str = "") -> None:
    """Mark scan as failed with error message."""
    scan.scan_status = RepositoryScan.ScanStatus.FAILED
    scan.error_message = f"{prefix}{error_msg}" if prefix else error_msg
    scan.completed_at = datetime.now(tz=UTC)
    scan.save(update_fields=["scan_status", "error_message", "completed_at"])


def _should_auto_create_issue(matches: list) -> bool:
    """Check if auto-issue creation should be triggered."""
    return (
        settings.AUTO_CREATE_GITHUB_ISSUES
        and len(matches) >= settings.AUTO_CREATE_ISSUE_THRESHOLD
    )


def _schedule_issue_creation(scan_id: int, matches_count: int) -> None:
    """Schedule GitHub issue creation with configured delay."""
    logger.info(
        "Scheduling auto-create issue for scan %s (found %s secrets, threshold: %s)",
        scan_id,
        matches_count,
        settings.AUTO_CREATE_ISSUE_THRESHOLD,
    )
    create_github_issue_task.apply_async(
        args=[scan_id],
        countdown=settings.AUTO_CREATE_ISSUE_DELAY,
    )


def _update_watchlist_after_scan(scan: RepositoryScan) -> None:
    """Update watchlist entry statistics after scan completion."""
    watchlist_entries = RepositoryWatchlist.objects.filter(
        repository_url=scan.repository_url,
        last_scan=scan,
    )

    for entry in watchlist_entries:
        entry.last_secrets_found = scan.secrets_found_count
        entry.save(update_fields=["last_secrets_found"])
        logger.info(
            "Updated watchlist entry %s: %s secrets found",
            entry.id,
            scan.secrets_found_count,
        )


def _perform_repository_scan(scan: RepositoryScan) -> tuple[list, int]:
    """Execute the actual repository scan and return results."""
    github_client = GitHubClient()
    scanner = SecretScanner(github_client=github_client)
    return scanner.scan_repository(repo_url=scan.repository_url, branch="main")


@shared_task(
    bind=True,
    name="scanner.scan_repository",
    max_retries=3,
    default_retry_delay=60,
    time_limit=600,  # 10 minute timeout
    soft_time_limit=540,  # 9 minute soft timeout
)
def scan_repository_task(self, scan_id: int) -> dict:
    """Asynchronous task to scan a GitHub repository for secrets.

    Args:
        self: Celery task instance.
        scan_id: ID of the RepositoryScan to process.

    Returns:
        Dictionary with scan results summary.

    """
    try:
        scan = RepositoryScan.objects.get(id=scan_id)
    except RepositoryScan.DoesNotExist:
        logger.exception("RepositoryScan with id %s does not exist", scan_id)
        return {"error": "Scan not found"}

    try:
        # Update status to in_progress
        _update_scan_status(scan, RepositoryScan.ScanStatus.IN_PROGRESS)
        logger.info("Starting scan for %s", scan.repository_full_name)

        # Perform the scan
        matches, files_scanned = _perform_repository_scan(scan)

        # Store findings and update scan status atomically
        with transaction.atomic():
            _store_scan_findings(scan, matches)
            _complete_scan(scan, matches, files_scanned)

        logger.info(
            "Scan completed for %s. Found %s secrets in %s files.",
            scan.repository_full_name,
            len(matches),
            files_scanned,
        )

        # Update watchlist statistics if this scan is linked to a watchlist
        _update_watchlist_after_scan(scan)

        # Auto-create GitHub issue if configured
        if _should_auto_create_issue(matches):
            _schedule_issue_creation(scan_id, len(matches))

        return {
            "scan_id": scan_id,
            "status": "completed",
            "files_scanned": files_scanned,
            "secrets_found": len(matches),
        }

    except GitHubClientError as exc:
        error_msg = str(exc)
        logger.exception("GitHub error during scan %s: %s", scan_id, error_msg)
        _mark_scan_failed(scan, error_msg, "GitHub API Error: ")
        return {"scan_id": scan_id, "status": "failed", "error": error_msg}

    except Exception as exc:
        error_msg = str(exc)
        logger.exception("Unexpected error during scan %s: %s", scan_id, error_msg)
        _mark_scan_failed(scan, error_msg, "Internal Error: ")

        # Retry on unexpected errors
        if self.request.retries < self.max_retries:
            logger.info(
                "Retrying scan %s (attempt %s)",
                scan_id,
                self.request.retries + 1,
            )
            raise self.retry(exc=exc) from exc

        return {"scan_id": scan_id, "status": "failed", "error": error_msg}


def _check_issue_already_exists(scan: RepositoryScan, scan_id: int) -> dict | None:
    """Check if issue already exists, return skip result if so."""
    if scan.github_issue_number:
        logger.info(
            "Issue already exists for scan %s: #%s",
            scan_id,
            scan.github_issue_number,
        )
        return {
            "scan_id": scan_id,
            "status": "skipped",
            "reason": "Issue already exists",
            "issue_number": scan.github_issue_number,
        }
    return None


def _check_scan_completed(scan: RepositoryScan, scan_id: int) -> dict | None:
    """Check if scan is completed, return skip result if not."""
    if scan.scan_status != RepositoryScan.ScanStatus.COMPLETED:
        logger.warning(
            "Cannot create issue for scan %s: status is %s",
            scan_id,
            scan.scan_status,
        )
        return {
            "scan_id": scan_id,
            "status": "skipped",
            "reason": f"Scan status is {scan.scan_status}",
        }
    return None


def _check_has_findings(scan: RepositoryScan, scan_id: int) -> dict | None:
    """Check if scan has findings, return skip result if not."""
    findings_count = scan.findings.filter(is_false_positive=False).count()
    if findings_count == 0:
        logger.info(
            "No findings to report for scan %s (excluding false positives)",
            scan_id,
        )
        return {
            "scan_id": scan_id,
            "status": "skipped",
            "reason": "No findings to report",
        }
    return None


def _validate_github_token(scan_id: int) -> str | dict:
    """Validate GitHub token is configured, return error dict if not."""
    github_token = getattr(settings, "GITHUB_TOKEN", None)
    if not github_token:
        msg = "GitHub token not configured"
        logger.error(msg)
        return {"scan_id": scan_id, "status": "failed", "error": msg}
    return github_token


def _run_preflight_checks(scan: RepositoryScan, scan_id: int) -> dict | None:
    """Run all pre-flight checks. Returns error/skip dict or None if all pass."""
    # Check if issue already exists
    if result := _check_issue_already_exists(scan, scan_id):
        return result

    # Check if scan is completed
    if result := _check_scan_completed(scan, scan_id):
        return result

    # Check if scan has findings
    if result := _check_has_findings(scan, scan_id):
        return result

    # Validate token
    github_token = _validate_github_token(scan_id)
    if isinstance(github_token, dict):
        return github_token

    return None  # All checks passed


def _create_issue_for_scan(scan: RepositoryScan, github_token: str) -> dict:
    """Create GitHub issue and return result dictionary."""
    result = create_github_issue_for_scan(scan, github_token)
    return {
        "scan_id": scan.id,
        "status": "success",
        "issue_number": result["issue_number"],
        "issue_url": result["issue_url"],
        "findings_count": result["findings_count"],
    }


@shared_task(
    bind=True,
    name="scanner.create_github_issue",
    max_retries=3,
    default_retry_delay=120,  # 2 minute delay between retries
    time_limit=60,  # 1 minute timeout
)
def create_github_issue_task(self, scan_id: int) -> dict:
    """Asynchronous task to create a GitHub issue for scan findings.

    Args:
        self: Celery task instance.
        scan_id: ID of the RepositoryScan to create issue for.

    Returns:
        Dictionary with issue creation results.

    """
    try:
        scan = RepositoryScan.objects.get(id=scan_id)
    except RepositoryScan.DoesNotExist:
        logger.exception("RepositoryScan with id %s does not exist", scan_id)
        return {"error": "Scan not found", "scan_id": scan_id}

    # Run all pre-flight checks
    if preflight_result := _run_preflight_checks(scan, scan_id):
        return preflight_result

    # Get validated token
    github_token = _validate_github_token(scan_id)

    try:
        logger.info("Creating GitHub issue for scan %s", scan_id)
        result = _create_issue_for_scan(scan, github_token)
        logger.info(
            "Successfully created issue #%s for scan %s",
            result["issue_number"],
            scan_id,
        )
    except IssueCreationError as exc:
        error_msg = str(exc)
        logger.warning("Failed to create issue for scan %s: %s", scan_id, error_msg)
        # Don't retry on known errors
        return {"scan_id": scan_id, "status": "failed", "error": error_msg}
    except Exception as exc:
        error_msg = str(exc)
        logger.exception(
            "Unexpected error creating issue for scan %s: %s",
            scan_id,
            error_msg,
        )

        # Retry on unexpected errors
        if self.request.retries < self.max_retries:
            logger.info(
                "Retrying issue creation for scan %s (attempt %s)",
                scan_id,
                self.request.retries + 1,
            )
            raise self.retry(exc=exc) from exc

        return {"scan_id": scan_id, "status": "failed", "error": error_msg}
    else:
        return result


@shared_task(name="scanner.scan_watchlist_repositories")
def scan_watchlist_repositories_task() -> dict:
    """Periodic task to scan repositories from the watchlist.

    This task runs at configured intervals and scans repositories
    that are due for scanning based on their next_scan_at timestamp.

    Returns:
        Dictionary with scan statistics.

    """
    now = datetime.now(tz=UTC)

    # Find active watchlist entries that need scanning
    due_entries = RepositoryWatchlist.objects.filter(
        is_active=True,
        next_scan_at__lte=now,
    ).select_related("last_scan")

    scans_triggered = 0
    errors = []

    for entry in due_entries:
        try:
            logger.info(
                "Triggering scheduled scan for watchlist entry %s: %s",
                entry.id,
                entry.repository_full_name,
            )

            # Create a new scan
            scan = RepositoryScan.objects.create(
                repository_url=entry.repository_url,
                repository_owner=entry.repository_owner,
                repository_name=entry.repository_name,
                created_by=entry.added_by,
            )

            # Trigger scan task
            transaction.on_commit(lambda sid=scan.id: scan_repository_task.delay(sid))

            # Update watchlist entry
            entry.last_scanned_at = now
            entry.next_scan_at = now + timedelta(seconds=entry.scan_interval)
            entry.last_scan = scan
            entry.total_scans += 1
            entry.save(
                update_fields=[
                    "last_scanned_at",
                    "next_scan_at",
                    "last_scan",
                    "total_scans",
                ],
            )

            scans_triggered += 1
            logger.info(
                "Scan %s triggered for %s. Next scan at %s",
                scan.id,
                entry.repository_full_name,
                entry.next_scan_at,
            )

        except Exception as exc:
            error_msg = f"Error scanning {entry.repository_full_name}: {exc}"
            logger.exception(error_msg)
            errors.append(error_msg)

    logger.info(
        "Watchlist scan task completed. Triggered: %s, Errors: %s",
        scans_triggered,
        len(errors),
    )

    return {
        "scans_triggered": scans_triggered,
        "errors": errors,
        "timestamp": now.isoformat(),
    }
