"""Tests for GitHub issue creation functionality."""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from secretshunter.scanner.models import RepositoryScan
from secretshunter.scanner.models import SecretFinding
from secretshunter.scanner.services import IssueCreationError
from secretshunter.scanner.services import create_github_issue_for_scan
from secretshunter.scanner.services import generate_issue_body


@pytest.fixture
def completed_scan():
    """Create a completed scan with findings."""
    return RepositoryScan.objects.create(
        repository_url="https://github.com/test/repo",
        repository_owner="test",
        repository_name="repo",
        scan_status=RepositoryScan.ScanStatus.COMPLETED,
        commit_sha="abc123def456",
        total_files_scanned=10,
        secrets_found_count=3,
    )


@pytest.fixture
def high_severity_finding(completed_scan):
    """Create a high severity finding."""
    return SecretFinding.objects.create(
        scan=completed_scan,
        file_path="config/settings.py",
        line_number=42,
        secret_type=SecretFinding.SecretType.AWS_ACCESS_KEY,
        matched_pattern="AWS Access Key ID",
        context_snippet='AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        severity=SecretFinding.Severity.HIGH,
    )


@pytest.fixture
def medium_severity_finding(completed_scan):
    """Create a medium severity finding."""
    return SecretFinding.objects.create(
        scan=completed_scan,
        file_path="app/utils.py",
        line_number=15,
        secret_type=SecretFinding.SecretType.PASSWORD,
        matched_pattern="Hardcoded Password",
        context_snippet='password = "MySecretPassword123"',
        severity=SecretFinding.Severity.MEDIUM,
    )


@pytest.mark.django_db
class TestGenerateIssueBody:
    """Test issue body generation."""

    def test_generates_markdown_body(self, completed_scan, high_severity_finding):
        """Test that issue body is generated in markdown format."""
        findings = [high_severity_finding]
        body = generate_issue_body(completed_scan, findings)

        assert "# 🔒 Security Scan Results" in body
        assert "**Repository:** test/repo" in body
        assert "**Total Findings:** 1" in body
        assert "config/settings.py" in body
        assert "AWS Access Key ID" in body

    def test_groups_by_severity(
        self,
        completed_scan,
        high_severity_finding,
        medium_severity_finding,
    ):
        """Test that findings are grouped by severity."""
        findings = [high_severity_finding, medium_severity_finding]
        body = generate_issue_body(completed_scan, findings)

        assert "🔴 High Severity" in body
        assert "🟡 Medium Severity" in body
        assert body.index("🔴 High") < body.index("🟡 Medium")

    def test_includes_remediation_advice(self, completed_scan, high_severity_finding):
        """Test that remediation advice is included."""
        findings = [high_severity_finding]
        body = generate_issue_body(completed_scan, findings)

        assert "## 🛠️ Remediation Advice" in body
        assert "Rotate Compromised Credentials" in body
        assert "Environment Variables" in body

    def test_includes_context_snippet(self, completed_scan, high_severity_finding):
        """Test that code context is included."""
        findings = [high_severity_finding]
        body = generate_issue_body(completed_scan, findings)

        assert 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"' in body


@pytest.mark.django_db
class TestCreateGitHubIssue:
    """Test GitHub issue creation."""

    def test_raises_error_when_no_findings(self, completed_scan):
        """Test that error is raised when scan has no findings."""
        with pytest.raises(IssueCreationError, match="No findings to report"):
            create_github_issue_for_scan(completed_scan, "fake-token")

    def test_raises_error_when_issue_already_exists(
        self,
        completed_scan,
        high_severity_finding,
    ):
        """Test that error is raised when issue already created."""
        completed_scan.github_issue_number = 42
        completed_scan.save()

        with pytest.raises(IssueCreationError, match="Issue already exists"):
            create_github_issue_for_scan(completed_scan, "fake-token")

    @patch("secretshunter.scanner.services.GitHubClient")
    def test_creates_issue_successfully(
        self,
        mock_client_class,
        completed_scan,
        high_severity_finding,
    ):
        """Test successful issue creation."""
        # Setup mock
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.check_issues_enabled.return_value = True
        mock_client.create_issue.return_value = {
            "number": 42,
            "url": "https://github.com/test/repo/issues/42",
            "api_url": "https://api.github.com/repos/test/repo/issues/42",
            "state": "open",
            "title": "Test Issue",
        }

        # Call function
        result = create_github_issue_for_scan(completed_scan, "fake-token")

        # Verify
        assert result["issue_number"] == 42  # noqa: PLR2004
        assert result["issue_url"] == "https://github.com/test/repo/issues/42"
        assert result["findings_count"] == 1

        # Verify scan was updated
        completed_scan.refresh_from_db()
        assert completed_scan.github_issue_number == 42  # noqa: PLR2004
        assert (
            completed_scan.github_issue_url == "https://github.com/test/repo/issues/42"
        )
        assert completed_scan.issue_created_at is not None

    @patch("secretshunter.scanner.services.GitHubClient")
    def test_excludes_false_positives(
        self,
        mock_client_class,
        completed_scan,
        high_severity_finding,
    ):
        """Test that false positives are excluded from issue."""
        # Mark finding as false positive
        high_severity_finding.is_false_positive = True
        high_severity_finding.save()

        # Should raise error since no real findings
        with pytest.raises(IssueCreationError, match="No findings to report"):
            create_github_issue_for_scan(completed_scan, "fake-token")

    @patch("secretshunter.scanner.services.GitHubClient")
    def test_checks_issues_enabled(
        self,
        mock_client_class,
        completed_scan,
        high_severity_finding,
    ):
        """Test that issues enabled check is performed."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.check_issues_enabled.return_value = False

        with pytest.raises(IssueCreationError, match="Issues are disabled"):
            create_github_issue_for_scan(completed_scan, "fake-token")

    @patch("secretshunter.scanner.services.GitHubClient")
    def test_includes_security_labels(
        self,
        mock_client_class,
        completed_scan,
        high_severity_finding,
    ):
        """Test that security labels are applied."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.check_issues_enabled.return_value = True
        mock_client.create_issue.return_value = {
            "number": 42,
            "url": "https://github.com/test/repo/issues/42",
            "api_url": "https://api.github.com/repos/test/repo/issues/42",
            "state": "open",
            "title": "Test Issue",
        }

        create_github_issue_for_scan(completed_scan, "fake-token")

        # Verify labels were passed
        mock_client.create_issue.assert_called_once()
        call_kwargs = mock_client.create_issue.call_args[1]
        assert "security" in call_kwargs["labels"]
        assert "secrets" in call_kwargs["labels"]
