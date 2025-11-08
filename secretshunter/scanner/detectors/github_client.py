"""GitHub API client for fetching repository content."""

import base64
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


@dataclass
class GitHubFile:
    """Represents a file in a GitHub repository."""

    path: str
    content: str
    size: int
    sha: str


class GitHubClientError(Exception):
    """Base exception for GitHub client errors."""


class RateLimitError(GitHubClientError):
    """Raised when GitHub API rate limit is exceeded."""


class RepositoryNotFoundError(GitHubClientError):
    """Raised when repository is not found or not accessible."""


class GitHubClient:
    """Client for interacting with GitHub API."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str | None = None):
        """Initialize GitHub client.

        Args:
            token: GitHub personal access token (optional but recommended).

        """
        self.token = token or getattr(settings, "GITHUB_TOKEN", None)
        self.session = requests.Session()

        if self.token:
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})

        self.session.headers.update(
            {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "SecretHunter-Scanner/1.0",
            },
        )

    def parse_repo_url(self, repo_url: str) -> tuple[str, str]:
        """Parse GitHub repository URL to extract owner and repo name.

        Args:
            repo_url: Full GitHub repository URL.

        Returns:
            Tuple of (owner, repo_name).

        Raises:
            GitHubClientError: If URL is invalid.

        """
        try:
            parsed = urlparse(repo_url)

            # Handle different URL formats
            # https://github.com/owner/repo
            # https://github.com/owner/repo.git
            # github.com/owner/repo

            if parsed.netloc not in ("github.com", "www.github.com", ""):
                msg = f"Not a GitHub URL: {repo_url}"
                raise GitHubClientError(msg)

            path_parts = parsed.path.strip("/").split("/")

            if len(path_parts) < 2:  # noqa: PLR2004
                msg = f"Invalid GitHub repository URL: {repo_url}"
                raise GitHubClientError(msg)

            owner = path_parts[0]
            repo = path_parts[1].removesuffix(".git")

        except (AttributeError, IndexError) as exc:
            msg = f"Failed to parse repository URL: {repo_url}"
            raise GitHubClientError(msg) from exc
        else:
            return owner, repo

    def get_repository_tree(
        self,
        owner: str,
        repo: str,
        branch: str = "main",
    ) -> list[dict[str, Any]]:
        """Get the file tree of a repository.

        Args:
            owner: Repository owner.
            repo: Repository name.
            branch: Branch name (default: main).

        Returns:
            List of file/directory items.

        Raises:
            RepositoryNotFoundError: If repository is not found.
            RateLimitError: If rate limit is exceeded.
            GitHubClientError: For other API errors.

        """
        # Try main first, then master if main fails
        branches_to_try = [branch]
        if branch == "main":
            branches_to_try.append("master")

        for branch_name in branches_to_try:
            try:
                url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/trees/{branch_name}"
                params = {"recursive": "1"}

                response = self.session.get(url, params=params, timeout=30)

                if response.status_code == 404:  # noqa: PLR2004
                    continue

                if response.status_code == 403:  # noqa: PLR2004
                    if "rate limit" in response.text.lower():
                        msg = "GitHub API rate limit exceeded"
                        raise RateLimitError(msg)
                    msg = f"Access forbidden: {response.text}"
                    raise GitHubClientError(msg)

                response.raise_for_status()

                data = response.json()
                return data.get("tree", [])

            except requests.RequestException as exc:
                if "404" not in str(exc):
                    msg = f"Failed to fetch repository tree: {exc}"
                    raise GitHubClientError(msg) from exc

        # If we tried all branches and none worked
        msg = f"Repository not found: {owner}/{repo}"
        raise RepositoryNotFoundError(msg)

    def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str = "main",
    ) -> GitHubFile | None:
        """Get the content of a specific file.

        Args:
            owner: Repository owner.
            repo: Repository name.
            path: File path in repository.
            ref: Git reference (branch, tag, or commit SHA).

        Returns:
            GitHubFile object or None if file is binary/too large.

        Raises:
            GitHubClientError: For API errors.

        """
        try:
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
            params = {"ref": ref}

            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 403:  # noqa: PLR2004
                if "rate limit" in response.text.lower():
                    msg = "GitHub API rate limit exceeded"
                    raise RateLimitError(msg)

            response.raise_for_status()

            data = response.json()

            # Check if it's a file (not a directory)
            if data.get("type") != "file":
                return None

            # Check file size
            size = data.get("size", 0)
            if size > 1024 * 1024:  # 1MB limit
                logger.debug("Skipping large file: %s (%s bytes)", path, size)
                return None

            # Decode base64 content
            content_b64 = data.get("content", "")
            if not content_b64:
                return None

            try:
                content = base64.b64decode(content_b64).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                # Binary file or encoding issue
                logger.debug("Skipping binary/undecodable file: %s", path)
                return None

            return GitHubFile(
                path=path,
                content=content,
                size=size,
                sha=data.get("sha", ""),
            )

        except requests.RequestException as exc:
            logger.warning("Failed to fetch file %s: %s", path, exc)
            return None

    def check_rate_limit(self) -> dict[str, Any]:
        """Check current GitHub API rate limit status.

        Returns:
            Dictionary with rate limit information.

        """
        try:
            url = f"{self.BASE_URL}/rate_limit"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            logger.warning("Failed to check rate limit: %s", exc)
            return {}

    def get_latest_commit_sha(
        self,
        owner: str,
        repo: str,
        branch: str = "main",
    ) -> tuple[str, str] | None:
        """Get the latest commit SHA for a repository branch.

        Args:
            owner: Repository owner.
            repo: Repository name.
            branch: Branch name (default: main).

        Returns:
            Tuple of (commit_sha, commit_date) or None if error.

        Raises:
            RepositoryNotFoundError: If repository is not found.
            RateLimitError: If rate limit is exceeded.
            GitHubClientError: For other API errors.

        """
        # Try main first, then master if main fails
        branches_to_try = [branch]
        if branch == "main":
            branches_to_try.append("master")

        for branch_name in branches_to_try:
            try:
                url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{branch_name}"
                response = self.session.get(url, timeout=10)

                if response.status_code == 404:  # noqa: PLR2004
                    continue

                if response.status_code == 403:  # noqa: PLR2004
                    if "rate limit" in response.text.lower():
                        msg = "GitHub API rate limit exceeded"
                        raise RateLimitError(msg)
                    msg = f"Access forbidden: {response.text}"
                    raise GitHubClientError(msg)

                response.raise_for_status()

                data = response.json()
                commit_sha = data.get("sha")
                commit_date = data.get("commit", {}).get("author", {}).get("date")

                if commit_sha:
                    logger.info(
                        "Retrieved commit SHA for %s/%s: %s",
                        owner,
                        repo,
                        commit_sha[:7],
                    )
                    return commit_sha, commit_date

            except requests.RequestException as exc:
                if "404" not in str(exc):
                    logger.warning(
                        "Failed to fetch commit SHA for %s/%s: %s",
                        owner,
                        repo,
                        exc,
                    )
                    msg = f"Failed to fetch commit information: {exc}"
                    raise GitHubClientError(msg) from exc

        # If we tried all branches and none worked
        msg = f"Repository not found: {owner}/{repo}"
        raise RepositoryNotFoundError(msg)

    def create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a GitHub issue in the repository.

        Args:
            owner: Repository owner.
            repo: Repository name.
            title: Issue title.
            body: Issue body/description.
            labels: List of label names to apply (optional).

        Returns:
            Dictionary with issue details (number, url, etc).

        Raises:
            GitHubClientError: If issue creation fails.
            RateLimitError: If rate limit is exceeded.

        """
        if not self.token:
            msg = "GitHub token required to create issues"
            raise GitHubClientError(msg)

        try:
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues"
            payload = {
                "title": title,
                "body": body,
            }

            if labels:
                payload["labels"] = labels

            response = self.session.post(url, json=payload, timeout=30)

            if response.status_code == 403:  # noqa: PLR2004
                if "rate limit" in response.text.lower():
                    msg = "GitHub API rate limit exceeded"
                    raise RateLimitError(msg)
                msg = f"Access forbidden: {response.text}"
                raise GitHubClientError(msg)

            if response.status_code == 410:  # noqa: PLR2004
                msg = "Issues are disabled for this repository"
                raise GitHubClientError(msg)

            if response.status_code == 404:  # noqa: PLR2004
                msg = f"Repository not found: {owner}/{repo}"
                raise RepositoryNotFoundError(msg)

            response.raise_for_status()

            data = response.json()
            logger.info(
                "Created issue #%s in %s/%s: %s",
                data.get("number"),
                owner,
                repo,
                title,
            )

            return {
                "number": data.get("number"),
                "url": data.get("html_url"),
                "api_url": data.get("url"),
                "state": data.get("state"),
                "title": data.get("title"),
            }

        except requests.RequestException as exc:
            logger.warning(
                "Failed to create issue in %s/%s: %s",
                owner,
                repo,
                exc,
            )
            msg = f"Failed to create issue: {exc}"
            raise GitHubClientError(msg) from exc

    def check_issues_enabled(self, owner: str, repo: str) -> bool:
        """Check if issues are enabled for a repository.

        Args:
            owner: Repository owner.
            repo: Repository name.

        Returns:
            True if issues are enabled, False otherwise.

        """
        try:
            url = f"{self.BASE_URL}/repos/{owner}/{repo}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 404:  # noqa: PLR2004
                return False

            response.raise_for_status()
            data = response.json()
            return data.get("has_issues", False)

        except requests.RequestException as exc:
            logger.warning(
                "Failed to check issues status for %s/%s: %s",
                owner,
                repo,
                exc,
            )
            return False
