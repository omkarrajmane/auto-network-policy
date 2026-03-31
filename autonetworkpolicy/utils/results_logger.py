"""
Results Logger - TSV format logging for experiment results.

This module provides logging functionality for autoresearch experiments,
storing results in tab-separated format (TSV) for easy analysis.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ResultsLoggerError(Exception):
    """Exception raised for results logging errors."""

    pass


class ResultsLogger:
    """
    Logger for experiment results in TSV format.

    This class manages logging of experiment iteration results to a TSV file,
    providing methods for logging individual iterations, baselines, and
    retrieving summary statistics.

    The TSV format includes columns:
        commit, score, throughput_gbps, rule_count, status, description

    Note:
        ``throughput_gbps`` is a placeholder column and is always written as
        0.00. Real throughput measurement requires live traffic tests that
        are not yet wired into the autoresearch loop.

    Attributes:
        log_file: Path to the TSV log file
    """

    # TSV column headers
    FIELDNAMES = [
        "commit",
        "score",
        "throughput_gbps",
        "rule_count",
        "status",
        "description",
    ]

    def __init__(self, log_file: str = "results.tsv"):
        """
        Initialize the ResultsLogger.

        Args:
            log_file: Path to the TSV log file (default: results.tsv)

        Raises:
            ResultsLoggerError: If the log file cannot be created or accessed
        """
        self.log_file = Path(log_file)

        # Ensure parent directory exists
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise ResultsLoggerError(
                f"Failed to create log directory: {self.log_file.parent}"
            ) from e

        # Create file with header if it doesn't exist
        if not self.log_file.exists():
            try:
                with open(self.log_file, "w", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=self.FIELDNAMES,
                        delimiter="\t",
                        lineterminator="\n",
                    )
                    writer.writeheader()
                logger.debug(f"Created new results log: {self.log_file}")
            except OSError as e:
                raise ResultsLoggerError(f"Failed to create log file: {self.log_file}") from e

        logger.debug(f"ResultsLogger initialized: {self.log_file}")

    def _validate_status(self, status: str) -> str:
        """
        Validate and normalize the status string.

        Args:
            status: Status string to validate

        Returns:
            Normalized status string
        """
        valid_statuses = {"keep", "reject", "error", "baseline"}
        normalized = status.lower().strip()

        if normalized not in valid_statuses:
            logger.warning(f"Unknown status '{status}', using as-is")

        return normalized

    def log_iteration(
        self,
        commit: str,
        score: float,
        throughput_gbps: float,
        rule_count: int,
        status: str,
        description: str,
    ) -> None:
        """
        Log a single iteration result.

        Args:
            commit: Git commit hash (abbreviated or full)
            score: Evaluation score (higher is better)
            throughput_gbps: Throughput in Gbps
            rule_count: Number of rules in the policy
            status: Status of the iteration (keep/reject/error/baseline)
            description: Description of the mutation or event

        Raises:
            ResultsLoggerError: If writing to the log file fails
        """
        normalized_status = self._validate_status(status)

        row = {
            "commit": commit[:8] if len(commit) > 8 else commit,
            "score": f"{score:.4f}",
            "throughput_gbps": f"{throughput_gbps:.2f}",
            "rule_count": rule_count,
            "status": normalized_status,
            "description": description,
        }

        try:
            with open(self.log_file, "a", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=self.FIELDNAMES,
                    delimiter="\t",
                    lineterminator="\n",
                )
                writer.writerow(row)

            logger.debug(
                f"Logged result: {commit[:8] if len(commit) > 8 else commit} - "
                f"{normalized_status} - score={score:.4f}"
            )

        except OSError as e:
            raise ResultsLoggerError(f"Failed to write to log file: {e}") from e

    def log_baseline(
        self,
        commit: str,
        score: float,
        throughput_gbps: float,
        rule_count: int,
    ) -> None:
        """
        Log a baseline measurement.

        This is a convenience method for logging the initial baseline
        before any mutations are applied.

        Args:
            commit: Git commit hash of the baseline
            score: Baseline evaluation score
            throughput_gbps: Baseline throughput in Gbps
            rule_count: Number of rules in the baseline policy

        Raises:
            ResultsLoggerError: If writing to the log file fails
        """
        self.log_iteration(
            commit=commit,
            score=score,
            throughput_gbps=throughput_gbps,
            rule_count=rule_count,
            status="baseline",
            description="Initial policy baseline",
        )

        logger.info(f"Logged baseline: {commit[:8]} - score={score:.4f}")

    def _parse_row(self, row: dict) -> dict:
        """
        Parse a row from the TSV file into typed values.

        Args:
            row: Dictionary of string values from TSV

        Returns:
            Dictionary with properly typed values
        """
        return {
            "commit": row["commit"],
            "score": float(row["score"]),
            "throughput_gbps": float(row["throughput_gbps"]),
            "rule_count": int(row["rule_count"]),
            "status": row["status"],
            "description": row["description"],
        }

    def get_all_results(self) -> list[dict]:
        """
        Get all results from the log file.

        Returns:
            List of result dictionaries

        Raises:
            ResultsLoggerError: If reading the log file fails
        """
        results = []

        try:
            with open(self.log_file, "r", newline="") as f:
                reader = csv.DictReader(f, delimiter="\t")
                for row in reader:
                    if row:  # Skip empty rows
                        results.append(self._parse_row(row))

        except OSError as e:
            raise ResultsLoggerError(f"Failed to read log file: {e}") from e
        except (ValueError, KeyError) as e:
            raise ResultsLoggerError(f"Failed to parse log file: {e}") from e

        return results

    def get_best_result(self) -> Optional[dict]:
        """
        Get the best result from the log.

        The best result is defined as the entry with the highest score
        that has status 'keep' or 'baseline'.

        Returns:
            Dictionary with the best result, or None if no valid results

        Raises:
            ResultsLoggerError: If reading the log file fails
        """
        results = self.get_all_results()

        # Filter for accepted results only
        valid_results = [r for r in results if r["status"] in ("keep", "baseline")]

        if not valid_results:
            logger.warning("No valid results found in log")
            return None

        # Find the result with highest score
        best = max(valid_results, key=lambda x: x["score"])

        logger.debug(f"Best result: {best['commit']} with score={best['score']:.4f}")

        return best

    def get_iteration_count(self) -> int:
        """
        Get the total number of iterations logged.

        Returns:
            Number of iterations (excluding header)
        """
        try:
            results = self.get_all_results()
            return len(results)
        except ResultsLoggerError:
            return 0

    def get_success_count(self) -> int:
        """
        Get the number of successful (kept) iterations.

        Returns:
            Number of iterations with status 'keep'
        """
        try:
            results = self.get_all_results()
            return len([r for r in results if r["status"] == "keep"])
        except ResultsLoggerError:
            return 0

    def summary(self) -> dict:
        """
        Get summary statistics from the log.

        Returns:
            Dictionary with summary statistics:
                - total_iterations: Total number of iterations
                - successful_mutations: Number of kept mutations
                - best_score: Best score achieved
                - best_commit: Commit hash of best result
                - best_throughput: Throughput of best result
                - baseline_score: Baseline score (if available)
                - improvement_percent: Percentage improvement from baseline

        Raises:
            ResultsLoggerError: If reading the log file fails
        """
        results = self.get_all_results()

        if not results:
            return {
                "total_iterations": 0,
                "successful_mutations": 0,
                "best_score": 0.0,
                "best_commit": None,
                "best_throughput": 0.0,
                "baseline_score": 0.0,
                "improvement_percent": 0.0,
            }

        # Count iterations
        total_iterations = len(results)
        successful_mutations = len([r for r in results if r["status"] == "keep"])

        # Find best result
        best_result = self.get_best_result()
        best_score = best_result["score"] if best_result else 0.0
        best_commit = best_result["commit"] if best_result else None
        best_throughput = best_result["throughput_gbps"] if best_result else 0.0

        # Find baseline
        baseline_results = [r for r in results if r["status"] == "baseline"]
        baseline_score = baseline_results[0]["score"] if baseline_results else 0.0

        # Calculate improvement
        if baseline_score > 0:
            improvement_percent = (best_score - baseline_score) / baseline_score * 100
        else:
            improvement_percent = 0.0

        summary = {
            "total_iterations": total_iterations,
            "successful_mutations": successful_mutations,
            "best_score": best_score,
            "best_commit": best_commit,
            "best_throughput": best_throughput,
            "baseline_score": baseline_score,
            "improvement_percent": improvement_percent,
        }

        logger.debug(f"Summary: {summary}")

        return summary

    def _rewrite(self, rows: list[dict]) -> None:
        """Rewrite the TSV file with the given rows (preserves header).

        Args:
            rows: List of row dicts to write
        """
        try:
            with open(self.log_file, "w", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=self.FIELDNAMES,
                    delimiter="\t",
                    lineterminator="\n",
                )
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
        except OSError as e:
            raise ResultsLoggerError(f"Failed to rewrite log file: {e}") from e

    def deduplicate(self) -> int:
        """Remove exact duplicate rows from the log file.

        Rows are keyed on all columns. Only the first occurrence is kept.

        Returns:
            Number of duplicate rows removed
        """
        rows = self.get_all_results()
        seen: set[tuple] = set()
        unique: list[dict] = []

        for row in rows:
            key = tuple(str(row[f]) for f in self.FIELDNAMES)
            if key not in seen:
                seen.add(key)
                unique.append(row)

        removed = len(rows) - len(unique)
        if removed > 0:
            self._rewrite(unique)
            logger.info(f"Removed {removed} duplicate rows from {self.log_file}")

        return removed

    def remove_by_status(self, status: str) -> int:
        """Remove all rows with the given status from the log file.

        Args:
            status: Status value to match (e.g. "baseline")

        Returns:
            Number of rows removed
        """
        rows = self.get_all_results()
        kept = [r for r in rows if r["status"] != status]
        removed = len(rows) - len(kept)

        if removed > 0:
            self._rewrite(kept)
            logger.info(f"Removed {removed} rows with status='{status}' from {self.log_file}")

        return removed

    def has_entry(self, description: str, status: str) -> bool:
        """Check if an entry with the given description and status exists.

        Args:
            description: Description to match exactly
            status: Status to match exactly

        Returns:
            True if a matching entry exists
        """
        rows = self.get_all_results()
        return any(r["description"] == description and r["status"] == status for r in rows)

    def export_to_csv(self, output_file: str) -> None:
        """
        Export the TSV log to CSV format.

        Args:
            output_file: Path to the output CSV file

        Raises:
            ResultsLoggerError: If export fails
        """
        output_path = Path(output_file)

        try:
            results = self.get_all_results()

            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writeheader()
                for result in results:
                    writer.writerow(result)

            logger.info(f"Exported {len(results)} results to {output_path}")

        except OSError as e:
            raise ResultsLoggerError(f"Failed to export to CSV: {e}") from e
