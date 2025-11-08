"""Integration tests for GitHub issue creation API endpoint."""

from unittest.mock import patch

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from secretshunter.scanner.models import RepositoryScan
from secretshunter.scanner.models import SecretFinding


@pytest.fixture
def api_client():
    """Create API client."""
    return APIClient()


@pytest.fixture
def completed_scan_with_findings():
    """Create a completed scan with findings."""
    scan = RepositoryScan.objects.create(
        repository_url="https://github.com/test/repo",
        repository_owner="test",
        repository_name="repo",
        scan_status=RepositoryScan.ScanStatus.COMPLETED,
        commit_sha="abc123",
        total_files_scanned=5,
        secrets_found_count=2,
    )

    SecretFinding.objects.create(
        scan=scan,
        file_path="config.py",
        line_number=10,
        secret_type=SecretFinding.SecretType.AWS_ACCESS_KEY,
        matched_pattern="AWS Key",
        context_snippet="key = 'AKIATEST'",
        severity=SecretFinding.Severity.HIGH,
    )

    SecretFinding.objects.create(
        scan=scan,
        file_path="utils.py",
        line_number=20,
        secret_type=SecretFinding.SecretType.PASSWORD,
        matched_pattern="Password",
        context_snippet="pwd = 'secret123'",
        severity=SecretFinding.Severity.MEDIUM,
    )

    return scan


@pytest.mark.django_db
class TestCreateIssueEndpoint:
    """Test the create-issue API endpoint."""

    def test_requires_completed_scan(self, api_client):
        """Test that endpoint requires scan to be completed."""
        scan = RepositoryScan.objects.create(
            repository_url="https://github.com/test/repo",
            repository_owner="test",
            repository_name="repo",
            scan_status=RepositoryScan.ScanStatus.PENDING,
        )

        url = reverse("api:scan-create-issue", kwargs={"pk": scan.id})
        response = api_client.post(url)

        assert response.status_code == 400  # noqa: PLR2004
        assert response.json()["success"] is False
        assert "must be completed" in response.json()["error"]

    def test_requires_findings(self, api_client):
        """Test that endpoint requires scan to have findings."""
        scan = RepositoryScan.objects.create(
            repository_url="https://github.com/test/repo",
            repository_owner="test",
            repository_name="repo",
            scan_status=RepositoryScan.ScanStatus.COMPLETED,
        )

        url = reverse("api:scan-create-issue", kwargs={"pk": scan.id})
        response = api_client.post(url)

        assert response.status_code == 400  # noqa: PLR2004
        assert response.json()["success"] is False
        assert "No findings" in response.json()["error"]

    @patch("secretshunter.scanner.api.views.create_github_issue_for_scan")
    @patch("secretshunter.scanner.api.views.settings")
    def test_creates_issue_successfully(
        self,
        mock_settings,
        mock_create_issue,
        api_client,
        completed_scan_with_findings,
    ):
        """Test successful issue creation."""
        mock_settings.GITHUB_TOKEN = "fake-token"  # noqa: S105
        mock_create_issue.return_value = {
            "issue_number": 42,
            "issue_url": "https://github.com/test/repo/issues/42",
            "findings_count": 2,
        }

        url = reverse(
            "api:scan-create-issue",
            kwargs={"pk": completed_scan_with_findings.id},
        )
        response = api_client.post(url)

        assert response.status_code == 201  # noqa: PLR2004
        assert response.json()["success"] is True
        assert response.json()["issue_number"] == 42  # noqa: PLR2004
        assert response.json()["findings_count"] == 2  # noqa: PLR2004
        assert "Successfully created issue" in response.json()["message"]

    @patch("secretshunter.scanner.api.views.settings")
    def test_requires_github_token(
        self,
        mock_settings,
        api_client,
        completed_scan_with_findings,
    ):
        """Test that endpoint requires GitHub token to be configured."""
        mock_settings.GITHUB_TOKEN = None

        url = reverse(
            "api:scan-create-issue",
            kwargs={"pk": completed_scan_with_findings.id},
        )
        response = api_client.post(url)

        assert response.status_code == 500  # noqa: PLR2004
        assert response.json()["success"] is False
        assert "token not configured" in response.json()["error"]

    def test_scan_not_found(self, api_client):
        """Test response when scan doesn't exist."""
        url = reverse("api:scan-create-issue", kwargs={"pk": 99999})
        response = api_client.post(url)

        assert response.status_code == 404  # noqa: PLR2004
