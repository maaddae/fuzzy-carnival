"""Celery tasks for scanner app."""

import logging
from datetime import UTC
from datetime import datetime

from celery import shared_task
from django.db import transaction

from .detectors.github_client import GitHubClient
from .detectors.github_client import GitHubClientError
from .detectors.scanner import SecretScanner
from .models import RepositoryScan
from .models import SecretFinding

logger = logging.getLogger(__name__)


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
        scan.scan_status = RepositoryScan.ScanStatus.IN_PROGRESS
        scan.save(update_fields=["scan_status"])

        logger.info("Starting scan for %s", scan.repository_full_name)

        # Initialize GitHub client and scanner
        github_client = GitHubClient()
        scanner = SecretScanner(github_client=github_client)

        # Perform the scan
        matches, files_scanned = scanner.scan_repository(
            repo_url=scan.repository_url,
            branch="main",
        )

        # Store findings in database
        findings_to_create = []

        for match in matches:
            finding = SecretFinding(
                scan=scan,
                file_path=match.file_path,
                line_number=match.line_number,
                secret_type=match.secret_type,
                matched_pattern=match.matched_pattern,
                context_snippet=match.context_snippet,
                severity=match.severity,
            )
            findings_to_create.append(finding)

        # Bulk create findings for better performance
        with transaction.atomic():
            SecretFinding.objects.bulk_create(findings_to_create, batch_size=100)

            # Update scan with results
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

        logger.info(
            "Scan completed for %s. Found %s secrets in %s files.",
            scan.repository_full_name,
            len(matches),
            files_scanned,
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "files_scanned": files_scanned,
            "secrets_found": len(matches),
        }

    except GitHubClientError as exc:
        # Handle GitHub-specific errors
        error_msg = str(exc)
        logger.exception("GitHub error during scan %s: %s", scan_id, error_msg)

        scan.scan_status = RepositoryScan.ScanStatus.FAILED
        scan.error_message = f"GitHub API Error: {error_msg}"
        scan.completed_at = datetime.now(tz=UTC)
        scan.save(
            update_fields=["scan_status", "error_message", "completed_at"],
        )

        return {
            "scan_id": scan_id,
            "status": "failed",
            "error": error_msg,
        }

    except Exception as exc:
        # Handle unexpected errors
        error_msg = str(exc)
        logger.exception("Unexpected error during scan %s: %s", scan_id, error_msg)

        scan.scan_status = RepositoryScan.ScanStatus.FAILED
        scan.error_message = f"Internal Error: {error_msg}"
        scan.completed_at = datetime.now(tz=UTC)
        scan.save(
            update_fields=["scan_status", "error_message", "completed_at"],
        )

        # Retry on unexpected errors
        if self.request.retries < self.max_retries:
            logger.info(
                "Retrying scan %s (attempt %s)",
                scan_id,
                self.request.retries + 1,
            )
            raise self.retry(exc=exc) from exc

        return {
            "scan_id": scan_id,
            "status": "failed",
            "error": error_msg,
        }
