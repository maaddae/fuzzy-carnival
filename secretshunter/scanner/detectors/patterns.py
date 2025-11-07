"""Secret detection pattern library."""

import re
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class SecretPattern:
    """Represents a secret detection pattern."""

    name: str
    pattern: re.Pattern
    secret_type: str
    severity: str
    description: str


class SecretPatterns:
    """Collection of regex patterns for detecting secrets in code."""

    # AWS Access Key ID
    AWS_ACCESS_KEY: ClassVar[SecretPattern] = SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        ),
        secret_type="aws_access_key",  # noqa: S106
        severity="high",
        description="AWS Access Key ID",
    )

    # AWS Secret Access Key
    AWS_SECRET_KEY: ClassVar[SecretPattern] = SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        ),
        secret_type="aws_secret_key",  # noqa: S106
        severity="high",
        description="AWS Secret Access Key",
    )

    # GitHub Personal Access Token
    GITHUB_TOKEN: ClassVar[SecretPattern] = SecretPattern(
        name="GitHub Token",
        pattern=re.compile(
            r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        ),
        secret_type="github_token",  # noqa: S106
        severity="high",
        description="GitHub Personal Access Token",
    )

    # Generic API Key patterns
    GENERIC_API_KEY: ClassVar[SecretPattern] = SecretPattern(
        name="Generic API Key",
        pattern=re.compile(
            r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        ),
        secret_type="generic_api_key",  # noqa: S106
        severity="medium",
        description="Generic API Key",
    )

    # Private SSH/RSA Keys
    PRIVATE_KEY: ClassVar[SecretPattern] = SecretPattern(
        name="Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        secret_type="private_key",  # noqa: S106
        severity="high",
        description="Private SSH/RSA/PGP Key",
    )

    # Password in code
    PASSWORD: ClassVar[SecretPattern] = SecretPattern(
        name="Password",
        pattern=re.compile(
            r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        ),
        secret_type="password",  # noqa: S106
        severity="medium",
        description="Hardcoded Password",
    )

    # Slack Token
    SLACK_TOKEN: ClassVar[SecretPattern] = SecretPattern(
        name="Slack Token",
        pattern=re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}"),
        secret_type="slack_token",  # noqa: S106
        severity="high",
        description="Slack Token",
    )

    # Stripe API Key
    STRIPE_KEY: ClassVar[SecretPattern] = SecretPattern(
        name="Stripe API Key",
        pattern=re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
        secret_type="stripe_key",  # noqa: S106
        severity="high",
        description="Stripe API Key",
    )

    # Google API Key
    GOOGLE_API_KEY: ClassVar[SecretPattern] = SecretPattern(
        name="Google API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        secret_type="google_api_key",  # noqa: S106
        severity="high",
        description="Google API Key",
    )

    # JWT Token
    JWT_TOKEN: ClassVar[SecretPattern] = SecretPattern(
        name="JWT Token",
        pattern=re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        ),
        secret_type="jwt_token",  # noqa: S106
        severity="medium",
        description="JWT Token",
    )

    # Database Connection String
    DATABASE_URL: ClassVar[SecretPattern] = SecretPattern(
        name="Database URL",
        pattern=re.compile(
            r"(?i)(?:postgres|mysql|mongodb|redis)://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\-\.]+(?::\d+)?/?",
        ),
        secret_type="database_url",  # noqa: S106
        severity="high",
        description="Database Connection String with Credentials",
    )

    # OAuth Token
    OAUTH_TOKEN: ClassVar[SecretPattern] = SecretPattern(
        name="OAuth Token",
        pattern=re.compile(
            r"(?i)(?:oauth[_-]?token|access[_-]?token|bearer)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",
        ),
        secret_type="oauth_token",  # noqa: S106
        severity="medium",
        description="OAuth/Bearer Token",
    )

    # Generic Secret (high entropy strings)
    GENERIC_SECRET: ClassVar[SecretPattern] = SecretPattern(
        name="Generic Secret",
        pattern=re.compile(
            r"(?i)(?:secret|token|key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.!@#$%^&*()]{16,})['\"]",
        ),
        secret_type="generic_secret",  # noqa: S106
        severity="low",
        description="Generic Secret/Token",
    )

    @classmethod
    def get_all_patterns(cls) -> list[SecretPattern]:
        """Get all secret patterns.

        Returns:
            List of all SecretPattern objects.

        """
        return [
            cls.AWS_ACCESS_KEY,
            cls.AWS_SECRET_KEY,
            cls.GITHUB_TOKEN,
            cls.PRIVATE_KEY,
            cls.SLACK_TOKEN,
            cls.STRIPE_KEY,
            cls.GOOGLE_API_KEY,
            cls.DATABASE_URL,
            cls.JWT_TOKEN,
            cls.GENERIC_API_KEY,
            cls.PASSWORD,
            cls.OAUTH_TOKEN,
            cls.GENERIC_SECRET,
        ]

    @classmethod
    def get_high_priority_patterns(cls) -> list[SecretPattern]:
        """Get high severity patterns only.

        Returns:
            List of high severity SecretPattern objects.

        """
        return [p for p in cls.get_all_patterns() if p.severity == "high"]


# File extensions to skip (binary/generated files)
SKIP_FILE_EXTENSIONS = {
    # Images
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".webp",
    # Videos
    ".mp4",
    ".avi",
    ".mov",
    ".wmv",
    ".flv",
    ".webm",
    # Audio
    ".mp3",
    ".wav",
    ".ogg",
    ".flac",
    ".aac",
    # Archives
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".rar",
    # Executables
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    # Documents
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    # Compiled
    ".pyc",
    ".pyo",
    ".class",
    ".o",
    ".a",
    # Package managers
    ".lock",
    ".sum",
    # Other binary
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
}

# Directories to skip
SKIP_DIRECTORIES = {
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "virtualenv",
    "__pycache__",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "htmlcov",
    "coverage",
    ".idea",
    ".vscode",
    "tmp",
    "temp",
}

# Files to skip
SKIP_FILES = {
    "package-lock.json",
    "yarn.lock",
    "composer.lock",
    "Gemfile.lock",
    "poetry.lock",
    "Pipfile.lock",
}

# Maximum file size to scan (1MB)
MAX_FILE_SIZE_BYTES = 1024 * 1024

# Maximum number of files to scan in a repository
MAX_FILES_TO_SCAN = 5000
