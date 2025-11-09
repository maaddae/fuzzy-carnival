"""Tests for SecretMatch dataclass."""

from secretshunter.scanner.detectors.scanner import SecretMatch


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
