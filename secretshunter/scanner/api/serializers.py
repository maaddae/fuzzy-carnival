"""API serializers for scanner app."""

import logging

from rest_framework import serializers

from secretshunter.scanner.detectors.github_client import GitHubClient
from secretshunter.scanner.detectors.github_client import GitHubClientError
from secretshunter.scanner.models import RepositoryScan
from secretshunter.scanner.models import RepositoryWatchlist
from secretshunter.scanner.models import SecretFinding

logger = logging.getLogger(__name__)


class SecretFindingSerializer(serializers.ModelSerializer):
    """Serializer for SecretFinding model."""

    secret_type_display = serializers.CharField(
        source="get_secret_type_display",
        read_only=True,
    )
    severity_display = serializers.CharField(
        source="get_severity_display",
        read_only=True,
    )

    class Meta:
        model = SecretFinding
        fields = [
            "id",
            "file_path",
            "line_number",
            "secret_type",
            "secret_type_display",
            "matched_pattern",
            "context_snippet",
            "severity",
            "severity_display",
            "is_false_positive",
            "false_positive_reason",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "file_path",
            "line_number",
            "secret_type",
            "matched_pattern",
            "context_snippet",
            "severity",
            "created_at",
        ]


class RepositoryScanSerializer(serializers.ModelSerializer):
    """Serializer for RepositoryScan model."""

    scan_status_display = serializers.CharField(
        source="get_scan_status_display",
        read_only=True,
    )
    findings = SecretFindingSerializer(many=True, read_only=True)
    created_by_email = serializers.EmailField(
        source="created_by.email",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = RepositoryScan
        fields = [
            "id",
            "repository_url",
            "repository_owner",
            "repository_name",
            "repository_full_name",
            "scan_status",
            "scan_status_display",
            "created_by",
            "created_by_email",
            "created_at",
            "completed_at",
            "total_files_scanned",
            "secrets_found_count",
            "error_message",
            "commit_sha",
            "commit_date",
            "github_issue_number",
            "github_issue_url",
            "issue_created_at",
            "findings",
        ]
        read_only_fields = [
            "id",
            "repository_owner",
            "repository_name",
            "repository_full_name",
            "scan_status",
            "created_at",
            "completed_at",
            "total_files_scanned",
            "secrets_found_count",
            "error_message",
            "commit_sha",
            "commit_date",
            "github_issue_number",
            "github_issue_url",
            "issue_created_at",
            "findings",
        ]

    def validate_repository_url(self, value: str) -> str:
        """Validate that the repository URL is a valid GitHub URL.

        Args:
            value: Repository URL to validate.

        Returns:
            Validated URL.

        Raises:
            serializers.ValidationError: If URL is invalid.

        """
        try:
            client = GitHubClient()
            owner, repo = client.parse_repo_url(value)

            # Ensure it's a reasonable URL
            if not owner or not repo:
                msg = "Invalid GitHub repository URL format"
                raise serializers.ValidationError(msg)

        except GitHubClientError as exc:
            raise serializers.ValidationError(str(exc)) from exc
        else:
            return value

    def create(self, validated_data: dict) -> RepositoryScan:
        """Create a new RepositoryScan and extract owner/repo from URL.

        Args:
            validated_data: Validated data from request.

        Returns:
            Created RepositoryScan instance.

        """
        # Parse the repository URL to extract owner and repo
        client = GitHubClient()
        owner, repo = client.parse_repo_url(validated_data["repository_url"])

        validated_data["repository_owner"] = owner
        validated_data["repository_name"] = repo

        # Set created_by if user is authenticated
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            validated_data["created_by"] = request.user

        return super().create(validated_data)


class IdempotentRepositoryScanSerializer(RepositoryScanSerializer):
    """Serializer for idempotent repository scans.

    Extends RepositoryScanSerializer with idempotency logic:
    1. Fetches latest commit SHA from GitHub
    2. Checks for existing scan with same SHA (true idempotency)
    3. Checks for in-progress scans (prevents duplicates)
    4. Only creates new scan if none of the above exist

    Query Parameters:
        force_rescan (bool): If true, bypass idempotency checks and create new scan.

    """

    # Additional fields to display reuse information
    reused = serializers.SerializerMethodField()
    reused_reason = serializers.SerializerMethodField()
    commit_sha = serializers.CharField(read_only=True)
    commit_date = serializers.DateTimeField(read_only=True)

    class Meta(RepositoryScanSerializer.Meta):
        fields = [
            *RepositoryScanSerializer.Meta.fields,
            "commit_sha",
            "commit_date",
            "reused",
            "reused_reason",
        ]
        read_only_fields = [
            *RepositoryScanSerializer.Meta.read_only_fields,
            "commit_sha",
            "commit_date",
            "reused",
            "reused_reason",
        ]

    def get_reused(self, obj):
        """Check if this scan was reused."""
        return getattr(obj, "_reused", False)

    def get_reused_reason(self, obj):
        """Get the reason why scan was reused."""
        return getattr(obj, "_reused_reason", None)

    def create(self, validated_data: dict) -> RepositoryScan:
        """Create or reuse a RepositoryScan with idempotency checks.

        Args:
            validated_data: Validated data from request.

        Returns:
            RepositoryScan instance (new or existing).

        """
        # Parse the repository URL to extract owner and repo
        client = GitHubClient()
        owner, repo = client.parse_repo_url(validated_data["repository_url"])

        logger.info(
            "Idempotent scan request for %s/%s",
            owner,
            repo,
        )

        # Check for force_rescan parameter
        request = self.context.get("request")
        force_rescan = False

        if request:
            force_rescan = (
                request.query_params.get("force_rescan", "false").lower() == "true"
            )

        if force_rescan:
            logger.info("Force rescan requested, bypassing idempotency checks")

        # Fetch latest commit SHA
        commit_sha = None
        commit_date = None
        try:
            result = client.get_latest_commit_sha(owner, repo)
            if result:
                commit_sha, commit_date = result
                logger.info(
                    "Fetched commit SHA: %s (date: %s)",
                    commit_sha[:7] if commit_sha else None,
                    commit_date,
                )
            else:
                logger.warning("get_latest_commit_sha returned None")
        except GitHubClientError as exc:
            # Continue without commit SHA if fetch fails
            logger.warning(
                "Failed to fetch commit SHA for %s/%s: %s",
                owner,
                repo,
                exc,
            )
        except Exception as exc:
            # Catch any other exceptions
            logger.exception(
                "Unexpected error fetching commit SHA for %s/%s: %s",
                owner,
                repo,
                type(exc).__name__,
            )

        # Check for existing scan (unless force_rescan)
        if not force_rescan:
            existing_scan = RepositoryScan.get_existing_scan(
                repository_owner=owner,
                repository_name=repo,
                commit_sha=commit_sha,
            )

            if existing_scan:
                # Mark as reused for response
                existing_scan._reused = True  # noqa: SLF001

                # Determine reason
                if commit_sha and existing_scan.commit_sha == commit_sha:
                    existing_scan._reused_reason = (  # noqa: SLF001
                        "Exact commit SHA match - repository unchanged"
                    )
                    logger.info(
                        "Reusing scan #%s: exact commit SHA match",
                        existing_scan.id,
                    )
                elif existing_scan.scan_status in [
                    RepositoryScan.ScanStatus.PENDING,
                    RepositoryScan.ScanStatus.IN_PROGRESS,
                ]:
                    existing_scan._reused_reason = "Scan already in progress"  # noqa: SLF001
                    logger.info(
                        "Reusing scan #%s: scan in progress",
                        existing_scan.id,
                    )
                else:
                    existing_scan._reused_reason = (  # noqa: SLF001
                        f"Recent scan found (completed {existing_scan.completed_at})"
                    )
                    logger.info(
                        "Reusing scan #%s: recent scan found",
                        existing_scan.id,
                    )

                return existing_scan
            logger.info(
                "No existing scan found for %s/%s with commit SHA %s",
                owner,
                repo,
                commit_sha[:7] if commit_sha else None,
            )

        # Add commit tracking data
        validated_data["commit_sha"] = commit_sha or ""
        validated_data["commit_date"] = commit_date

        logger.info(
            "Creating new scan for %s/%s with commit SHA: %s",
            owner,
            repo,
            commit_sha[:7] if commit_sha else "None",
        )

        # Call parent's create method (handles owner/repo/created_by)
        scan = super().create(validated_data)

        # Mark as new scan (not reused)
        scan._reused = False  # noqa: SLF001
        scan._reused_reason = None  # noqa: SLF001

        return scan


class RepositoryScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing scans (without findings)."""

    scan_status_display = serializers.CharField(
        source="get_scan_status_display",
        read_only=True,
    )
    created_by_email = serializers.EmailField(
        source="created_by.email",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = RepositoryScan
        fields = [
            "id",
            "repository_url",
            "repository_owner",
            "repository_name",
            "repository_full_name",
            "scan_status",
            "scan_status_display",
            "created_by_email",
            "created_at",
            "completed_at",
            "total_files_scanned",
            "secrets_found_count",
        ]
        read_only_fields = fields


class SecretFindingUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating SecretFinding (mark as false positive)."""

    class Meta:
        model = SecretFinding
        fields = [
            "is_false_positive",
            "false_positive_reason",
        ]


class RepositoryWatchlistSerializer(serializers.ModelSerializer):
    """Serializer for RepositoryWatchlist model."""

    scan_interval_display = serializers.CharField(
        source="get_scan_interval_display",
        read_only=True,
    )
    added_by_email = serializers.EmailField(
        source="added_by.email",
        read_only=True,
        allow_null=True,
    )
    last_scan_status = serializers.CharField(
        source="last_scan.scan_status",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = RepositoryWatchlist
        fields = [
            "id",
            "repository_url",
            "repository_owner",
            "repository_name",
            "repository_full_name",
            "scan_interval",
            "scan_interval_display",
            "is_active",
            "added_by_email",
            "created_at",
            "last_scanned_at",
            "next_scan_at",
            "last_scan",
            "last_scan_status",
            "total_scans",
            "last_secrets_found",
        ]
        read_only_fields = [
            "id",
            "repository_owner",
            "repository_name",
            "repository_full_name",
            "added_by_email",
            "created_at",
            "last_scanned_at",
            "next_scan_at",
            "last_scan",
            "last_scan_status",
            "total_scans",
            "last_secrets_found",
        ]

    def validate_repository_url(self, value):
        """Validate and parse GitHub repository URL."""
        github_client = GitHubClient()
        try:
            owner, repo = github_client.parse_repo_url(value)
            if not owner or not repo:
                msg = "Invalid GitHub repository URL"
                raise serializers.ValidationError(msg)
        except (ValueError, GitHubClientError) as e:
            raise serializers.ValidationError(str(e)) from e
        else:
            return value

    def create(self, validated_data):
        """Create watchlist entry and parse repository info."""
        github_client = GitHubClient()
        owner, repo = github_client.parse_repo_url(validated_data["repository_url"])

        validated_data["repository_owner"] = owner
        validated_data["repository_name"] = repo

        # Set added_by from request context
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            validated_data["added_by"] = request.user

        return super().create(validated_data)
