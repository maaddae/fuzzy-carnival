"""API serializers for scanner app."""

from rest_framework import serializers

from secretshunter.scanner.detectors.github_client import GitHubClient
from secretshunter.scanner.detectors.github_client import GitHubClientError
from secretshunter.scanner.models import RepositoryScan
from secretshunter.scanner.models import SecretFinding


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
