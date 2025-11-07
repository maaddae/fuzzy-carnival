"""Core secret scanning engine."""

import logging
from dataclasses import dataclass
from pathlib import Path

from .github_client import GitHubClient
from .patterns import MAX_FILE_SIZE_BYTES
from .patterns import MAX_FILES_TO_SCAN
from .patterns import SKIP_DIRECTORIES
from .patterns import SKIP_FILE_EXTENSIONS
from .patterns import SKIP_FILES
from .patterns import SecretPatterns

logger = logging.getLogger(__name__)


@dataclass
class SecretMatch:
    """Represents a detected secret in a file."""

    file_path: str
    line_number: int
    secret_type: str
    matched_pattern: str
    context_snippet: str
    severity: str
    line_content: str


class SecretScanner:
    """Scanner for detecting secrets in code."""

    def __init__(self, github_client: GitHubClient | None = None):
        """Initialize scanner.

        Args:
            github_client: GitHubClient instance (creates new one if not provided).

        """
        self.github_client = github_client or GitHubClient()
        self.patterns = SecretPatterns.get_all_patterns()

    def should_skip_file(self, file_path: str, file_size: int = 0) -> bool:
        """Determine if a file should be skipped.

        Args:
            file_path: Path to the file.
            file_size: Size of file in bytes.

        Returns:
            True if file should be skipped, False otherwise.

        """
        path = Path(file_path)

        # Skip if file is too large
        if file_size > MAX_FILE_SIZE_BYTES:
            return True

        # Skip by extension
        if path.suffix.lower() in SKIP_FILE_EXTENSIONS:
            return True

        # Skip by filename
        if path.name in SKIP_FILES:
            return True

        # Skip if in excluded directory
        return any(part in SKIP_DIRECTORIES for part in path.parts)

    def scan_content(
        self,
        content: str,
        file_path: str,
    ) -> list[SecretMatch]:
        """Scan file content for secrets.

        Args:
            content: File content to scan.
            file_path: Path of the file being scanned.

        Returns:
            List of SecretMatch objects.

        """
        matches = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and very long lines (likely minified)
            if not line.strip() or len(line) > 5000:  # noqa: PLR2004
                continue

            # Check against all patterns
            for pattern in self.patterns:
                if pattern.pattern.search(line):
                    # Get context (line before and after if available)
                    context_lines = []

                    if line_num > 1:
                        context_lines.append(lines[line_num - 2])

                    context_lines.append(line)

                    if line_num < len(lines):
                        context_lines.append(lines[line_num])

                    context = "\n".join(context_lines)

                    matches.append(
                        SecretMatch(
                            file_path=file_path,
                            line_number=line_num,
                            secret_type=pattern.secret_type,
                            matched_pattern=pattern.name,
                            context_snippet=context[:500],  # Limit context size
                            severity=pattern.severity,
                            line_content=line[:200],  # Store partial line
                        ),
                    )

                    # Only report one match per line to avoid duplicates
                    break

        return matches

    def scan_repository(
        self,
        repo_url: str,
        branch: str = "main",
        max_files: int = MAX_FILES_TO_SCAN,
    ) -> tuple[list[SecretMatch], int]:
        """Scan an entire GitHub repository for secrets.

        Args:
            repo_url: Full GitHub repository URL.
            branch: Branch to scan (default: main).
            max_files: Maximum number of files to scan.

        Returns:
            Tuple of (list of SecretMatch objects, total files scanned).

        Raises:
            GitHubClientError: If repository cannot be accessed.

        """
        logger.info("Starting scan of repository: %s", repo_url)

        # Parse repository URL
        owner, repo = self.github_client.parse_repo_url(repo_url)

        logger.info("Parsed repository: %s/%s", owner, repo)

        # Get repository file tree
        tree = self.github_client.get_repository_tree(owner, repo, branch)

        logger.info("Found %s items in repository tree", len(tree))

        # Filter to only files (not directories/submodules)
        files = [item for item in tree if item.get("type") == "blob"]

        logger.info("Found %s files to potentially scan", len(files))

        all_matches = []
        files_scanned = 0

        # Scan each file
        for file_item in files[:max_files]:
            file_path = file_item.get("path", "")
            file_size = file_item.get("size", 0)

            # Skip files based on filters
            if self.should_skip_file(file_path, file_size):
                logger.debug("Skipping file: %s", file_path)
                continue

            # Fetch file content
            github_file = self.github_client.get_file_content(
                owner,
                repo,
                file_path,
                ref=branch,
            )

            if github_file is None:
                logger.debug("Could not fetch content for: %s", file_path)
                continue

            # Scan the content
            matches = self.scan_content(github_file.content, file_path)

            if matches:
                logger.info(
                    "Found %s potential secret(s) in %s",
                    len(matches),
                    file_path,
                )
                all_matches.extend(matches)

            files_scanned += 1

            # Log progress every 50 files
            if files_scanned % 50 == 0:
                logger.info(
                    "Progress: Scanned %s files, found %s potential secrets",
                    files_scanned,
                    len(all_matches),
                )

        logger.info(
            "Scan complete. Scanned %s files, found %s potential secrets",
            files_scanned,
            len(all_matches),
        )

        return all_matches, files_scanned

    def scan_file(self, file_path: str, content: str) -> list[SecretMatch]:
        """Scan a single file's content.

        Args:
            file_path: Path of the file.
            content: Content to scan.

        Returns:
            List of SecretMatch objects.

        """
        return self.scan_content(content, file_path)
