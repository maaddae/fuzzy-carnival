"""Tests for secret detection patterns."""

from secretshunter.scanner.detectors.patterns import SecretPattern
from secretshunter.scanner.detectors.patterns import SecretPatterns


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
