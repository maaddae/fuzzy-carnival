"""Services for scanner operations."""

import logging
from collections import defaultdict
from datetime import UTC
from datetime import datetime

from secretshunter.scanner.detectors.github_client import GitHubClient
from secretshunter.scanner.detectors.github_client import GitHubClientError
from secretshunter.scanner.detectors.github_client import RateLimitError
from secretshunter.scanner.models import RepositoryScan
from secretshunter.scanner.models import SecretFinding

logger = logging.getLogger(__name__)


class IssueCreationError(Exception):
    """Exception raised when issue creation fails."""


def generate_issue_body(scan: RepositoryScan, findings: list[SecretFinding]) -> str:
    """Generate formatted GitHub issue body from scan findings.

    Args:
        scan: RepositoryScan instance.
        findings: List of SecretFinding instances.

    Returns:
        Formatted markdown string for issue body.

    """
    # Group findings by severity and type
    findings_by_severity = defaultdict(list)
    for finding in findings:
        findings_by_severity[finding.severity].append(finding)

    # Build issue body
    body_parts = [
        "# 🔒 Security Scan Results",
        "",
        f"**Repository:** {scan.repository_full_name}",
        f"**Scan Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Commit SHA:** {scan.commit_sha[:8] if scan.commit_sha else 'N/A'}",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Summary",
        "",
        "This automated scan detected potential secrets and sensitive information "
        "in your repository. Please review each finding carefully and take "
        "appropriate action.",
        "",
    ]

    # Statistics by severity
    high_count = len(findings_by_severity.get("high", []))
    medium_count = len(findings_by_severity.get("medium", []))
    low_count = len(findings_by_severity.get("low", []))

    if high_count > 0:
        body_parts.append(f"- 🔴 **High Severity:** {high_count}")
    if medium_count > 0:
        body_parts.append(f"- 🟡 **Medium Severity:** {medium_count}")
    if low_count > 0:
        body_parts.append(f"- 🟢 **Low Severity:** {low_count}")

    body_parts.extend(["", "---", ""])

    # Detail findings by severity
    severity_order = ["high", "medium", "low"]
    severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}

    for severity in severity_order:
        severity_findings = findings_by_severity.get(severity, [])
        if not severity_findings:
            continue

        body_parts.append(
            f"## {severity_emoji[severity]} {severity.title()} Severity Findings",
        )
        body_parts.append("")

        # Group by file for better organization
        findings_by_file = defaultdict(list)
        for finding in severity_findings:
            findings_by_file[finding.file_path].append(finding)

        for file_path, file_findings in sorted(findings_by_file.items()):
            body_parts.append(f"### 📄 `{file_path}`")
            body_parts.append("")

            for finding in file_findings:
                body_parts.append(f"**Type:** {finding.get_secret_type_display()}")
                body_parts.append(f"**Line:** {finding.line_number}")
                body_parts.append(f"**Pattern:** {finding.matched_pattern}")
                body_parts.append("")
                body_parts.append("```")
                body_parts.append(finding.context_snippet.strip())
                body_parts.append("```")
                body_parts.append("")

        body_parts.append("---")
        body_parts.append("")

    # Add remediation advice
    body_parts.extend(
        [
            "## 🛠️ Remediation Advice",
            "",
            "### Immediate Actions",
            "",
            "1. **Rotate Compromised Credentials:** "
            "If any of these secrets are real and currently in use, "
            "rotate them immediately.",
            "2. **Remove from History:** "
            "Use tools like `git-filter-repo` or BFG Repo-Cleaner "
            "to remove secrets from Git history.",
            "3. **Update Code:** "
            "Replace hardcoded secrets with environment variables or "
            "secret management solutions.",
            "",
            "### Best Practices",
            "",
            "- **Use Environment Variables:** "
            "Store sensitive data in environment variables, not in code.",
            "- **Secret Management:** "
            "Consider using services like AWS Secrets Manager, "
            "HashiCorp Vault, or GitHub Secrets.",
            "- **Pre-commit Hooks:** "
            "Install tools like `detect-secrets` or `git-secrets` "
            "to prevent future leaks.",
            "- **`.gitignore`:** "
            "Ensure configuration files with secrets are in `.gitignore`.",
            "- **Code Review:** "
            "Always review code changes for sensitive information before committing.",
            "",
            "### Additional Resources",
            "",
            "- [GitHub: Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)",
            "- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)",
            "",
            "---",
            "",
            "*This issue was automatically generated by SecretsHunter on "
            f"{datetime.now(UTC).strftime('%Y-%m-%d')}.*",
        ],
    )

    return "\n".join(body_parts)


def create_github_issue_for_scan(
    scan: RepositoryScan,
    github_token: str | None = None,
) -> dict[str, str | int]:
    """Create a GitHub issue summarizing scan findings.

    Args:
        scan: RepositoryScan instance with findings.
        github_token: GitHub token (uses scan's default if not provided).

    Returns:
        Dictionary with issue details (number, url).

    Raises:
        IssueCreationError: If issue creation fails.

    """
    # Validate scan has findings
    findings = list(
        scan.findings.filter(is_false_positive=False).order_by(
            "-severity",
            "file_path",
        ),
    )

    if not findings:
        msg = "No findings to report (excluding false positives)"
        raise IssueCreationError(msg)

    # Check if issue already created
    if scan.github_issue_number:
        msg = f"Issue already exists: #{scan.github_issue_number}"
        raise IssueCreationError(msg)

    # Initialize GitHub client
    try:
        client = GitHubClient(token=github_token)
    except Exception as exc:
        logger.exception("Failed to initialize GitHub client")
        msg = f"Failed to initialize GitHub client: {exc}"
        raise IssueCreationError(msg) from exc

    # Check if issues are enabled
    try:
        if not client.check_issues_enabled(
            scan.repository_owner,
            scan.repository_name,
        ):
            msg = "Issues are disabled for this repository"
            raise IssueCreationError(msg)
    except GitHubClientError as exc:
        logger.warning("Could not check issues status: %s", exc)
        # Continue anyway, let the create_issue call handle it

    # Generate issue content
    try:
        high_count = findings.count(
            lambda f: f.severity == SecretFinding.Severity.HIGH,
        )
    except TypeError:
        # count() doesn't work on lists, use len with filter
        high_count = len(
            [f for f in findings if f.severity == SecretFinding.Severity.HIGH],
        )

    severity_label = "🔴 HIGH" if high_count > 0 else "⚠️ MEDIUM"
    issue_title = (
        f"[Security] {len(findings)} Potential Secret(s) Detected - {severity_label}"
    )

    issue_body = generate_issue_body(scan, findings)

    # Create the issue
    try:
        issue_data = client.create_issue(
            owner=scan.repository_owner,
            repo=scan.repository_name,
            title=issue_title,
            body=issue_body,
            labels=["security", "secrets"],
        )

        # Update scan with issue details
        scan.github_issue_number = issue_data["number"]
        scan.github_issue_url = issue_data["url"]
        scan.issue_created_at = datetime.now(UTC)
        scan.save(
            update_fields=[
                "github_issue_number",
                "github_issue_url",
                "issue_created_at",
            ],
        )

        logger.info(
            "Created issue #%s for scan %s",
            issue_data["number"],
            scan.id,
        )

        return {
            "issue_number": issue_data["number"],
            "issue_url": issue_data["url"],
            "findings_count": len(findings),
        }

    except RateLimitError as exc:
        logger.warning("Rate limit exceeded while creating issue: %s", exc)
        msg = "GitHub API rate limit exceeded. Please try again later."
        raise IssueCreationError(msg) from exc

    except GitHubClientError as exc:
        logger.exception("Failed to create GitHub issue")
        msg = f"Failed to create issue: {exc}"
        raise IssueCreationError(msg) from exc
