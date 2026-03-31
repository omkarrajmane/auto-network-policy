"""
Git Tracker - Git operations wrapper for autoresearch experiments.

This module provides a clean interface for git operations used in
the AutoNetworkPolicy autoresearch system.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class GitError(Exception):
    """Exception raised for git operation errors."""

    pass


class GitTracker:
    """
    Wrapper for git operations in autoresearch experiments.

    This class provides a clean interface for common git operations
    used in the autoresearch loop, including branch creation, commits,
    resets, and tagging.

    Attributes:
        repo_path: Path to the git repository
    """

    def __init__(self, repo_path: str = "."):
        """
        Initialize the GitTracker.

        Args:
            repo_path: Path to the git repository (default: current directory)

        Raises:
            GitError: If the path is not a valid git repository
        """
        self.repo_path = Path(repo_path).resolve()

        if not self._is_git_repo():
            raise GitError(
                f"Not a git repository: {self.repo_path}. Please initialize a git repository first."
            )

        logger.debug(f"GitTracker initialized: {self.repo_path}")

    def _run_git_command(
        self,
        args: list[str],
        check: bool = True,
        capture_output: bool = True,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a git command and return the result.

        Args:
            args: List of git arguments
            check: Whether to raise on non-zero exit code
            capture_output: Whether to capture stdout/stderr
            timeout: Timeout in seconds (None for no timeout)

        Returns:
            CompletedProcess instance with stdout, stderr, and returncode

        Raises:
            GitError: If the command fails and check=True
        """
        cmd = ["git"] + args
        logger.debug(f"Running: {' '.join(cmd)} in {self.repo_path}")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=capture_output,
                text=True,
                check=False,
                timeout=timeout,
            )

            if check and result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else "Unknown error"
                raise GitError(f"Git command failed: {' '.join(args)} - {stderr}")

            return result

        except FileNotFoundError as e:
            raise GitError("Git not found. Please install git.") from e
        except subprocess.TimeoutExpired as e:
            raise GitError(f"Git command timed out after {timeout}s: {' '.join(args)}") from e
        except Exception as e:
            raise GitError(f"Git error: {e}") from e

    def _is_git_repo(self) -> bool:
        """
        Check if the working directory is a git repository.

        Returns:
            True if the path is a git repository, False otherwise
        """
        try:
            result = self._run_git_command(["rev-parse", "--git-dir"], check=False)
            return result.returncode == 0
        except GitError:
            return False

    def has_uncommitted_changes(self) -> bool:
        """
        Check if there are uncommitted changes.

        Returns:
            True if there are uncommitted changes, False otherwise
        """
        result = self._run_git_command(["status", "--porcelain"], check=False)
        return len(result.stdout.strip()) > 0

    def create_branch(self, name: str) -> bool:
        """
        Create and checkout a new branch.

        Args:
            name: Name of the branch to create

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Creating and checking out branch: {name}")

        try:
            self._run_git_command(["checkout", "-b", name])
            logger.info(f"Successfully created branch: {name}")
            return True
        except GitError as e:
            logger.error(f"Failed to create branch: {e}")
            return False

    def commit_mutation(
        self,
        policy_file: str,
        mutation_desc: str,
        metrics: dict,
    ) -> str:
        """
        Commit a policy mutation with metrics in the commit message.

        Args:
            policy_file: Path to the policy file to commit
            mutation_desc: Description of the mutation
            metrics: Dictionary of metrics to include in commit message
                     Expected keys: iteration, mutation_type, operation,
                     score, throughput_gbps (optional)

        Returns:
            The commit hash of the new commit

        Raises:
            GitError: If the commit fails
        """
        policy_path = Path(policy_file)
        if not policy_path.is_absolute():
            policy_path = policy_path.relative_to(self.repo_path)

        # Stage the policy file
        logger.debug(f"Staging file: {policy_path}")
        self._run_git_command(["add", str(policy_path)])

        # Build commit message
        iteration = metrics.get("iteration", "N/A")
        mutation_type = metrics.get("mutation_type", "unknown")
        operation = metrics.get("operation", "unknown")
        score = metrics.get("score", 0.0)
        throughput = metrics.get("throughput_gbps", 0.0)

        commit_msg = (
            f"Iteration {iteration}: {mutation_type}\n\n"
            f"Description: {mutation_desc}\n"
            f"Operation: {operation}\n"
            f"Score: {score:.4f}\n"
            f"Throughput: {throughput:.2f} Gbps"
        )

        # Commit
        logger.debug(f"Committing with message:\n{commit_msg}")
        self._run_git_command(["commit", "-m", commit_msg])

        commit_hash = self.get_current_commit()
        logger.info(f"Committed mutation: {commit_hash[:8]}")

        return commit_hash

    def reset_to_commit(self, commit_hash: str) -> bool:
        """
        Hard reset to a specific commit.

        Args:
            commit_hash: The commit hash to reset to

        Returns:
            True if successful, False otherwise

        Warning:
            This performs a hard reset - uncommitted changes will be lost!
        """
        logger.info(f"Hard resetting to commit: {commit_hash[:8]}")

        try:
            self._run_git_command(["reset", "--hard", commit_hash])
            logger.info(f"Successfully reset to: {commit_hash[:8]}")
            return True
        except GitError as e:
            logger.error(f"Failed to reset: {e}")
            return False

    def get_current_commit(self) -> str:
        """
        Get the current commit hash.

        Returns:
            The full commit hash of HEAD

        Raises:
            GitError: If unable to get the current commit
        """
        result = self._run_git_command(["rev-parse", "HEAD"])
        return result.stdout.strip()

    def tag_commit(self, tag: str, message: str = "") -> bool:
        """
        Tag the current commit.

        Args:
            tag: The tag name
            message: Optional annotation message for the tag

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Tagging current commit with: {tag}")

        try:
            if message:
                self._run_git_command(["tag", "-a", tag, "-m", message])
            else:
                self._run_git_command(["tag", tag])

            logger.info(f"Successfully tagged: {tag}")
            return True
        except GitError as e:
            logger.error(f"Failed to tag: {e}")
            return False

    def get_branch_name(self) -> Optional[str]:
        """
        Get the current branch name.

        Returns:
            The current branch name, or None if in detached HEAD state
        """
        try:
            result = self._run_git_command(["rev-parse", "--abbrev-ref", "HEAD"])
            branch = result.stdout.strip()
            return None if branch == "HEAD" else branch
        except GitError:
            return None

    def is_clean(self) -> bool:
        """
        Check if the working directory is clean (no uncommitted changes).

        Returns:
            True if clean, False otherwise
        """
        return not self.has_uncommitted_changes()
