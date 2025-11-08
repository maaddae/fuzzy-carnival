"""Tests for SecretScanner class."""

from unittest.mock import Mock
from unittest.mock import patch

import pytest

from secretshunter.scanner.detectors.github_client import GitHubClient
from secretshunter.scanner.detectors.github_client import GitHubFile
from secretshunter.scanner.detectors.scanner import SecretScanner


class TestSecretScanner:
    """Test SecretScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance."""
        return SecretScanner()

    @pytest.fixture
    def mock_github_client(self):
        """Create a mock GitHub client."""
        client = Mock(spec=GitHubClient)
        client.parse_repo_url.return_value = ("owner", "repo")
        return client

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = SecretScanner()
        assert scanner.github_client is not None
        assert len(scanner.patterns) > 0

    def test_scanner_with_custom_client(self, mock_github_client):
        """Test scanner with custom GitHub client."""
        scanner = SecretScanner(github_client=mock_github_client)
        assert scanner.github_client == mock_github_client

    def test_should_skip_file_by_extension(self, scanner):
        """Test file skipping by extension."""
        # Should skip
        assert scanner.should_skip_file("image.png")
        assert scanner.should_skip_file("video.mp4")
        assert scanner.should_skip_file("archive.zip")
        assert scanner.should_skip_file("data.pyc")

        # Should not skip
        assert not scanner.should_skip_file("code.py")
        assert not scanner.should_skip_file("config.json")
        assert not scanner.should_skip_file("script.js")

    def test_should_skip_file_by_name(self, scanner):
        """Test file skipping by filename."""
        # Should skip
        assert scanner.should_skip_file("package-lock.json")
        assert scanner.should_skip_file("yarn.lock")
        assert scanner.should_skip_file("poetry.lock")

        # Should not skip
        assert not scanner.should_skip_file("config.json")
        assert not scanner.should_skip_file("README.md")

    def test_should_skip_file_by_directory(self, scanner):
        """Test file skipping by directory."""
        # Should skip
        assert scanner.should_skip_file("node_modules/package/index.js")
        assert scanner.should_skip_file(".git/config")
        assert scanner.should_skip_file("dist/bundle.js")
        assert scanner.should_skip_file("vendor/library/file.py")

        # Should not skip
        assert not scanner.should_skip_file("src/main.py")
        assert not scanner.should_skip_file("lib/utils.js")

    def test_should_skip_file_by_size(self, scanner):
        """Test file skipping by size."""
        # Should skip large files (> 1MB)
        assert scanner.should_skip_file("large_file.js", file_size=2_000_000)

        # Should not skip normal files
        assert not scanner.should_skip_file("normal.py", file_size=50_000)

    def test_scan_content_with_aws_key(self, scanner):
        """Test scanning content with AWS key."""
        content = """
import boto3

# AWS Configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

client = boto3.client('s3')
"""
        matches = scanner.scan_content(content, "config.py")

        assert len(matches) >= 1
        assert any(
            m.secret_type == "aws_access_key"  # noqa: S105
            for m in matches
        )

        # Check match details
        aws_match = next(
            m
            for m in matches
            if m.secret_type == "aws_access_key"  # noqa: S105
        )
        assert aws_match.file_path == "config.py"
        assert aws_match.line_number > 0
        assert "AKIAIOSFODNN7EXAMPLE" in aws_match.line_content

    def test_scan_content_with_github_token(self, scanner):
        """Test scanning content with GitHub token."""
        content = """
# GitHub API Configuration
GITHUB_TOKEN = "ghp_1234567890123456789012345678901234AB"

headers = {
    'Authorization': f'token {GITHUB_TOKEN}'
}
"""
        matches = scanner.scan_content(content, "github_config.py")

        assert len(matches) >= 1
        assert any(m.secret_type == "github_token" for m in matches)  # noqa: S105

    def test_scan_content_with_private_key(self, scanner):
        """Test scanning content with private key."""
        # Using dummy key format to test pattern matching
        key_header = "-----BEGIN RSA PRIVATE KEY-----"
        content = f"""
private_key = '''
{key_header}
MIIEpAIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----
'''
"""
        matches = scanner.scan_content(content, "keys.py")

        assert len(matches) >= 1
        assert any(m.secret_type == "private_key" for m in matches)  # noqa: S105

    def test_scan_content_with_password(self, scanner):
        """Test scanning content with hardcoded password."""
        content = """
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': "supersecretpassword123",
    'database': 'myapp'
}
"""
        matches = scanner.scan_content(content, "db_config.py")

        assert len(matches) >= 1
        assert any(m.secret_type == "password" for m in matches)  # noqa: S105

    def test_scan_content_no_secrets(self, scanner):
        """Test scanning content with no secrets."""
        content = """
def hello_world():
    print("Hello, World!")
    return True
"""
        matches = scanner.scan_content(content, "hello.py")

        assert len(matches) == 0

    def test_scan_content_multiple_secrets(self, scanner):
        """Test scanning content with multiple secrets."""
        content = """
# Multiple secrets in one file
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_1234567890123456789012345678901234AB"
PASSWORD = "mysecretpassword123"
"""
        matches = scanner.scan_content(content, "secrets.py")

        expected_secret_count = 3
        assert len(matches) >= expected_secret_count
        secret_types = {m.secret_type for m in matches}
        assert "aws_access_key" in secret_types
        assert "github_token" in secret_types

    def test_scan_content_skips_empty_lines(self, scanner):
        """Test that empty lines are skipped."""
        content = "\n\n\n\nprint('test')\n\n\n"
        matches = scanner.scan_content(content, "test.py")

        assert len(matches) == 0

    def test_scan_content_skips_long_lines(self, scanner):
        """Test that very long lines (minified) are skipped."""
        # Create a line longer than 5000 characters
        long_line = "x" * 6000
        content = f"var data = '{long_line}';"

        matches = scanner.scan_content(content, "minified.js")

        # Should not crash, and should skip the long line
        assert isinstance(matches, list)

    def test_scan_content_provides_context(self, scanner):
        """Test that matches include context."""
        content = """
# Line before
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
# Line after
"""
        matches = scanner.scan_content(content, "test.py")

        assert len(matches) >= 1
        match = matches[0]
        assert (
            "Line before" in match.context_snippet
            or "Line after" in match.context_snippet
        )
        assert "AKIAIOSFODNN7EXAMPLE" in match.context_snippet

    def test_scan_content_one_match_per_line(self, scanner):
        """Test that only one match is reported per line."""
        # Line with multiple potential matches
        content = 'KEY = "AKIAIOSFODNN7EXAMPLE" # API_KEY = "test"'
        matches = scanner.scan_content(content, "test.py")

        # Should only report one match per line
        line_numbers = [m.line_number for m in matches]
        assert len(line_numbers) == len(set(line_numbers))

    def test_scan_file_wrapper(self, scanner):
        """Test scan_file method."""
        content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        matches = scanner.scan_file("config.py", content)

        assert len(matches) >= 1
        assert matches[0].file_path == "config.py"

    @patch.object(GitHubClient, "parse_repo_url")
    @patch.object(GitHubClient, "get_repository_tree")
    @patch.object(GitHubClient, "get_file_content")
    def test_scan_repository(
        self,
        mock_get_content,
        mock_get_tree,
        mock_parse_url,
        scanner,
    ):
        """Test scanning an entire repository."""
        # Mock repository data
        mock_parse_url.return_value = ("owner", "repo")
        mock_get_tree.return_value = [
            {"type": "blob", "path": "config.py", "size": 1000},
            {"type": "blob", "path": "test.js", "size": 500},
            {"type": "tree", "path": "src"},  # Directory, should be skipped
        ]

        # Mock file content with a secret
        mock_get_content.return_value = GitHubFile(
            path="config.py",
            content='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
            size=1000,
            sha="abc123",
        )

        matches, files_scanned = scanner.scan_repository(
            "https://github.com/owner/repo",
        )

        assert files_scanned >= 1
        assert len(matches) >= 1
        assert any(
            m.secret_type == "aws_access_key"  # noqa: S105
            for m in matches
        )

    @patch.object(GitHubClient, "parse_repo_url")
    @patch.object(GitHubClient, "get_repository_tree")
    @patch.object(GitHubClient, "get_file_content")
    def test_scan_repository_respects_file_filters(
        self,
        mock_get_content,
        mock_get_tree,
        mock_parse_url,
        scanner,
    ):
        """Test that repository scan respects file filters."""
        mock_parse_url.return_value = ("owner", "repo")
        mock_get_tree.return_value = [
            {"type": "blob", "path": "config.py", "size": 1000},
            {"type": "blob", "path": "image.png", "size": 500},  # Should skip
            {
                "type": "blob",
                "path": "node_modules/lib.js",
                "size": 500,
            },  # Should skip
        ]

        mock_get_content.return_value = GitHubFile(
            path="config.py",
            content="print('test')",
            size=1000,
            sha="abc123",
        )

        _matches, _files_scanned = scanner.scan_repository(
            "https://github.com/owner/repo",
        )

        # Should only scan config.py, not image.png or node_modules
        assert mock_get_content.call_count == 1

    @patch.object(GitHubClient, "parse_repo_url")
    @patch.object(GitHubClient, "get_repository_tree")
    @patch.object(GitHubClient, "get_file_content")
    def test_scan_repository_max_files(
        self,
        mock_get_content,
        mock_get_tree,
        mock_parse_url,
        scanner,
    ):
        """Test that repository scan respects max_files limit."""
        mock_parse_url.return_value = ("owner", "repo")

        # Create 10 files
        mock_get_tree.return_value = [
            {"type": "blob", "path": f"file{i}.py", "size": 1000} for i in range(10)
        ]

        mock_get_content.return_value = GitHubFile(
            path="file.py",
            content="print('test')",
            size=1000,
            sha="abc123",
        )

        # Scan with max_files=3
        max_files_limit = 3
        _matches, files_scanned = scanner.scan_repository(
            "https://github.com/owner/repo",
            max_files=max_files_limit,
        )

        # Should only scan up to 3 files
        assert files_scanned <= max_files_limit
        """Test that repository scan respects max_files limit."""
        mock_parse_url.return_value = ("owner", "repo")

        # Create 10 files
        mock_get_tree.return_value = [
            {"type": "blob", "path": f"file{i}.py", "size": 1000} for i in range(10)
        ]

        mock_get_content.return_value = GitHubFile(
            path="file.py",
            content="print('test')",
            size=1000,
            sha="abc123",
        )

        # Scan with max_files=3
        max_files_limit = 3
        _matches, files_scanned = scanner.scan_repository(
            "https://github.com/owner/repo",
            max_files=max_files_limit,
        )

        # Should only scan up to 3 files
        assert files_scanned <= max_files_limit

    @patch.object(GitHubClient, "parse_repo_url")
    @patch.object(GitHubClient, "get_repository_tree")
    @patch.object(GitHubClient, "get_file_content")
    def test_scan_repository_handles_none_content(
        self,
        mock_get_content,
        mock_get_tree,
        mock_parse_url,
        scanner,
    ):
        """Test that scanner handles files that can't be fetched."""
        mock_parse_url.return_value = ("owner", "repo")
        mock_get_tree.return_value = [
            {"type": "blob", "path": "config.py", "size": 1000},
        ]

        # Simulate file fetch failure
        mock_get_content.return_value = None

        matches, files_scanned = scanner.scan_repository(
            "https://github.com/owner/repo",
        )

        # Should handle gracefully
        assert files_scanned == 0
        assert len(matches) == 0
