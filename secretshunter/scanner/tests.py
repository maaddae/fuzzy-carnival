"""Tests for scanner core functionality."""

from unittest.mock import Mock
from unittest.mock import patch

import pytest

from secretshunter.scanner.detectors.github_client import GitHubClient
from secretshunter.scanner.detectors.github_client import GitHubFile
from secretshunter.scanner.detectors.patterns import SecretPattern
from secretshunter.scanner.detectors.patterns import SecretPatterns
from secretshunter.scanner.detectors.scanner import SecretMatch
from secretshunter.scanner.detectors.scanner import SecretScanner


class TestSecretPatterns:
    """Test secret detection patterns."""

    def test_aws_access_key_pattern(self):
        """Test AWS Access Key ID detection."""
        pattern = SecretPatterns.AWS_ACCESS_KEY

        # Valid AWS keys
        assert pattern.pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert pattern.pattern.search("ASIAIOSFODNN7EXAMPLE")
        assert pattern.pattern.search("AIDAIOSFODNN7EXAMPLE")

        # Invalid keys
        assert not pattern.pattern.search("NOTAKEY123456789012")
        assert not pattern.pattern.search("AKI123")  # Too short

    def test_github_token_pattern(self):
        """Test GitHub token detection."""
        pattern = SecretPatterns.GITHUB_TOKEN

        # Valid GitHub tokens
        assert pattern.pattern.search("ghp_" + "A" * 36)
        assert pattern.pattern.search(
            "github_pat_" + "A" * 22 + "_" + "B" * 59,
        )

        # Invalid tokens
        assert not pattern.pattern.search("ghp_short")
        assert not pattern.pattern.search("not_a_token")

    def test_private_key_pattern(self):
        """Test private key detection."""
        pattern = SecretPatterns.PRIVATE_KEY

        # Valid private key headers
        assert pattern.pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert pattern.pattern.search("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert pattern.pattern.search("-----BEGIN EC PRIVATE KEY-----")

        # Invalid
        assert not pattern.pattern.search("-----BEGIN PUBLIC KEY-----")
        assert not pattern.pattern.search("BEGIN PRIVATE KEY")

    def test_password_pattern(self):
        """Test password detection."""
        pattern = SecretPatterns.PASSWORD

        # Valid password patterns
        assert pattern.pattern.search('password = "mypassword123"')
        assert pattern.pattern.search("PASSWORD='longsecret'")
        assert pattern.pattern.search('pwd: "secret123"')

        # Invalid (too short or no match)
        assert not pattern.pattern.search('password = "short"')
        assert not pattern.pattern.search("password")

    def test_get_all_patterns(self):
        """Test getting all patterns."""
        patterns = SecretPatterns.get_all_patterns()

        assert len(patterns) > 0
        assert all(isinstance(p, SecretPattern) for p in patterns)

        # Check that common patterns are included
        pattern_types = {p.secret_type for p in patterns}
        assert "aws_access_key" in pattern_types
        assert "github_token" in pattern_types
        assert "private_key" in pattern_types


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


class TestSecretMatch:
    """Test SecretMatch dataclass."""

    def test_secret_match_creation(self):
        """Test creating a SecretMatch."""
        test_line_number = 10
        match = SecretMatch(
            file_path="config.py",
            line_number=test_line_number,
            secret_type="aws_access_key",  # noqa: S106
            matched_pattern="AWS Access Key ID",
            context_snippet="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            severity="high",
            line_content="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        )

        assert match.file_path == "config.py"
        assert match.line_number == test_line_number
        assert match.secret_type == "aws_access_key"  # noqa: S105
        assert match.severity == "high"

    def test_secret_match_fields(self):
        """Test that SecretMatch has all required fields."""
        match = SecretMatch(
            file_path="test.py",
            line_number=1,
            secret_type="test",  # noqa: S106
            matched_pattern="Test Pattern",
            context_snippet="context",
            severity="low",
            line_content="line",
        )

        # Verify all fields exist
        assert hasattr(match, "file_path")
        assert hasattr(match, "line_number")
        assert hasattr(match, "secret_type")
        assert hasattr(match, "matched_pattern")
        assert hasattr(match, "context_snippet")
        assert hasattr(match, "severity")
        assert hasattr(match, "line_content")
