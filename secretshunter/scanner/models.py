from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class RepositoryScan(models.Model):
    """Model to track GitHub repository scans."""

    class ScanStatus(models.TextChoices):
        PENDING = "pending", _("Pending")
        IN_PROGRESS = "in_progress", _("In Progress")
        COMPLETED = "completed", _("Completed")
        FAILED = "failed", _("Failed")

    # Repository information
    repository_url = models.URLField(_("Repository URL"), max_length=500)
    repository_owner = models.CharField(_("Repository Owner"), max_length=255)
    repository_name = models.CharField(_("Repository Name"), max_length=255)

    # Scan metadata
    scan_status = models.CharField(
        _("Scan Status"),
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        db_index=True,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
        verbose_name=_("Created By"),
    )
    created_at = models.DateTimeField(_("Created At"), auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(_("Completed At"), null=True, blank=True)

    # Scan results summary
    total_files_scanned = models.IntegerField(_("Total Files Scanned"), default=0)
    secrets_found_count = models.IntegerField(_("Secrets Found"), default=0)
    error_message = models.TextField(_("Error Message"), blank=True)

    # Commit tracking for idempotency
    commit_sha = models.CharField(
        _("Commit SHA"),
        max_length=40,
        blank=True,
        db_index=True,
        help_text=_("Git commit SHA that was scanned"),
    )
    commit_date = models.DateTimeField(
        _("Commit Date"),
        null=True,
        blank=True,
        help_text=_("Date of the commit that was scanned"),
    )

    # GitHub issue tracking
    github_issue_number = models.IntegerField(
        _("GitHub Issue Number"),
        null=True,
        blank=True,
        help_text=_("GitHub issue number if findings were reported"),
    )
    github_issue_url = models.URLField(
        _("GitHub Issue URL"),
        max_length=500,
        blank=True,
        help_text=_("URL to the GitHub issue created for this scan"),
    )
    issue_created_at = models.DateTimeField(
        _("Issue Created At"),
        null=True,
        blank=True,
    )

    class Meta:
        verbose_name = _("Repository Scan")
        verbose_name_plural = _("Repository Scans")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at", "scan_status"]),
            models.Index(
                fields=["repository_owner", "repository_name", "commit_sha"],
            ),
        ]

    def __str__(self):
        return f"{self.repository_owner}/{self.repository_name} - {self.scan_status}"

    @property
    def repository_full_name(self):
        """Return the full repository name (owner/repo)."""
        return f"{self.repository_owner}/{self.repository_name}"

    @classmethod
    def get_existing_scan(
        cls,
        repository_owner: str,
        repository_name: str,
        commit_sha: str | None = None,
    ):
        """Find existing scan for idempotency.

        Checks in priority order:
        1. Exact commit SHA match (if provided)
        2. In-progress scans (PENDING or IN_PROGRESS)

        Args:
            repository_owner: Repository owner name.
            repository_name: Repository name.
            commit_sha: Git commit SHA (optional).

        Returns:
            Existing RepositoryScan instance or None.

        """
        # Priority 1: Exact commit SHA match (true idempotency)
        if commit_sha:
            sha_match = (
                cls.objects.filter(
                    repository_owner=repository_owner,
                    repository_name=repository_name,
                    commit_sha=commit_sha,
                    scan_status=cls.ScanStatus.COMPLETED,
                )
                .order_by("-completed_at")
                .first()
            )
            if sha_match:
                return sha_match

        # Priority 2: In-progress scans (prevent duplicates)
        return cls.objects.filter(
            repository_owner=repository_owner,
            repository_name=repository_name,
            scan_status__in=[cls.ScanStatus.PENDING, cls.ScanStatus.IN_PROGRESS],
        ).first()


class SecretFinding(models.Model):
    """Model to store individual secret findings from a scan."""

    class SecretType(models.TextChoices):
        AWS_ACCESS_KEY = "aws_access_key", _("AWS Access Key")
        AWS_SECRET_KEY = "aws_secret_key", _("AWS Secret Key")
        GITHUB_TOKEN = "github_token", _("GitHub Token")
        GENERIC_API_KEY = "generic_api_key", _("Generic API Key")
        PRIVATE_KEY = "private_key", _("Private Key")
        PASSWORD = "password", _("Password")
        SLACK_TOKEN = "slack_token", _("Slack Token")
        STRIPE_KEY = "stripe_key", _("Stripe Key")
        GOOGLE_API_KEY = "google_api_key", _("Google API Key")
        JWT_TOKEN = "jwt_token", _("JWT Token")
        GENERIC_SECRET = "generic_secret", _("Generic Secret")
        DATABASE_URL = "database_url", _("Database URL")
        OAUTH_TOKEN = "oauth_token", _("OAuth Token")

    class Severity(models.TextChoices):
        HIGH = "high", _("High")
        MEDIUM = "medium", _("Medium")
        LOW = "low", _("Low")

    # Relationship to scan
    scan = models.ForeignKey(
        RepositoryScan,
        on_delete=models.CASCADE,
        related_name="findings",
        verbose_name=_("Scan"),
    )

    # Finding location
    file_path = models.CharField(_("File Path"), max_length=1000)
    line_number = models.IntegerField(_("Line Number"))

    # Finding details
    secret_type = models.CharField(
        _("Secret Type"),
        max_length=50,
        choices=SecretType.choices,
        db_index=True,
    )
    matched_pattern = models.CharField(_("Matched Pattern"), max_length=200)
    context_snippet = models.TextField(_("Context Snippet"))
    severity = models.CharField(
        _("Severity"),
        max_length=10,
        choices=Severity.choices,
        default=Severity.MEDIUM,
        db_index=True,
    )

    # False positive tracking
    is_false_positive = models.BooleanField(_("Is False Positive"), default=False)
    false_positive_reason = models.TextField(_("False Positive Reason"), blank=True)

    # Timestamps
    created_at = models.DateTimeField(_("Created At"), auto_now_add=True)

    class Meta:
        verbose_name = _("Secret Finding")
        verbose_name_plural = _("Secret Findings")
        ordering = ["-severity", "file_path", "line_number"]
        indexes = [
            models.Index(fields=["scan", "secret_type"]),
            models.Index(fields=["scan", "severity"]),
        ]

    def __str__(self):
        return f"{self.secret_type} in {self.file_path}:{self.line_number}"
