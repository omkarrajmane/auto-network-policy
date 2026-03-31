#!/usr/bin/env python3
"""
================================================================================
Experiment Logger - High-Fidelity Telemetry for AutoNetworkPolicy Experiments
================================================================================

This module provides structured logging and export capabilities for capturing
experiment metrics in Phase 10. Outputs timestamped JSON files with comprehensive
telemetry for analysis.

Metrics Captured:
    - Rule delta (before/after rule count)
    - Reachability matrix changes
    - LLM latency (per mutation proposal)
    - Token usage (if available from provider)
    - Mutation type distribution
    - Score progression
    - Verification pass/fail rates

Usage:
    from experiment_logger import ExperimentLogger

    logger = ExperimentLogger("experiment_name")
    logger.log_iteration(iteration_data)
    logger.export_results()

================================================================================
"""

from __future__ import annotations

import json
import csv
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class IterationMetrics:
    """Metrics captured for each iteration."""

    iteration: int
    timestamp: str
    mutation_type: str
    mutation_description: str
    rule_count_before: int
    rule_count_after: int
    rule_delta: int
    score_before: float
    score_after: float
    score_delta: float
    throughput_gbps: float
    latency_ms: float
    tokens_used: int = 0
    llm_latency_ms: float = 0.0
    verification_passed: bool = False
    verification_time_ms: float = 0.0
    status: str = ""  # keep, reject, error
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class ExperimentSummary:
    """Summary statistics for the entire experiment."""

    experiment_name: str
    start_time: str
    end_time: Optional[str] = None
    total_iterations: int = 0
    successful_mutations: int = 0
    failed_mutations: int = 0
    rejected_mutations: int = 0
    baseline_score: float = 0.0
    best_score: float = 0.0
    improvement_pct: float = 0.0
    total_tokens_used: int = 0
    total_llm_latency_ms: float = 0.0
    avg_iteration_time_ms: float = 0.0
    mutation_type_distribution: dict[str, int] = field(default_factory=dict)
    verification_pass_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class ExperimentLogger:
    """
    High-fidelity experiment logger for Phase 10 data collection.

    Captures comprehensive telemetry during experiment execution and exports
    structured data in JSON and CSV formats for analysis.

    Attributes:
        experiment_name: Name of the experiment
        base_dir: Base directory for results (default: results/experiments/)
        iteration_metrics: List of metrics for each iteration
        summary: Summary statistics

    Example:
        >>> logger = ExperimentLogger("llm_cold_start_scenario1")
        >>> logger.log_iteration({
        ...     "iteration": 1,
        ...     "mutation_type": "swap",
        ...     "rule_count_before": 100,
        ...     "rule_count_after": 100,
        ...     "score_before": 1.5,
        ...     "score_after": 1.6,
        ... })
        >>> logger.finalize()
        >>> logger.export_results()
    """

    def __init__(
        self,
        experiment_name: str,
        base_dir: Optional[str | Path] = None,
        scenario: Optional[str] = None,
        algorithm: Optional[str] = None,
    ):
        """
        Initialize the experiment logger.

        Args:
            experiment_name: Name of the experiment
            base_dir: Base directory for results (default: results/experiments/)
            scenario: Optional scenario name (e.g., "over_permissive_legacy")
            algorithm: Optional algorithm name (e.g., "llm_guided", "random_reorder")
        """
        self.experiment_name = experiment_name
        self.scenario = scenario
        self.algorithm = algorithm

        # Set up directory structure
        if base_dir is None:
            base_dir = Path(__file__).parent.parent / "results" / "experiments"
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Create experiment-specific directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.experiment_dir = self.base_dir / f"{experiment_name}_{timestamp}"
        self.experiment_dir.mkdir(exist_ok=True)

        # Initialize data structures
        self.iteration_metrics: list[IterationMetrics] = []
        self.summary = ExperimentSummary(
            experiment_name=experiment_name,
            start_time=datetime.now().isoformat(),
        )

        # Track mutation types for distribution
        self._mutation_counts: dict[str, int] = {}
        self._start_time = time.time()

    def log_iteration(self, data: dict[str, Any]) -> None:
        """
        Log metrics for a single iteration.

        Args:
            data: Dictionary containing iteration metrics. Expected keys:
                - iteration: int
                - mutation_type: str
                - mutation_description: str (optional)
                - rule_count_before: int
                - rule_count_after: int
                - score_before: float
                - score_after: float
                - throughput_gbps: float (optional)
                - latency_ms: float (optional)
                - tokens_used: int (optional)
                - llm_latency_ms: float (optional)
                - verification_passed: bool (optional)
                - verification_time_ms: float (optional)
                - status: str (keep/reject/error)
                - error_message: str (optional)
        """
        # Calculate derived metrics
        rule_delta = data.get("rule_count_after", 0) - data.get("rule_count_before", 0)
        score_delta = data.get("score_after", 0.0) - data.get("score_before", 0.0)

        metrics = IterationMetrics(
            iteration=data.get("iteration", len(self.iteration_metrics) + 1),
            timestamp=datetime.now().isoformat(),
            mutation_type=data.get("mutation_type", "unknown"),
            mutation_description=data.get("mutation_description", ""),
            rule_count_before=data.get("rule_count_before", 0),
            rule_count_after=data.get("rule_count_after", 0),
            rule_delta=rule_delta,
            score_before=data.get("score_before", 0.0),
            score_after=data.get("score_after", 0.0),
            score_delta=score_delta,
            throughput_gbps=data.get("throughput_gbps", 0.0),
            latency_ms=data.get("latency_ms", 0.0),
            tokens_used=data.get("tokens_used", 0),
            llm_latency_ms=data.get("llm_latency_ms", 0.0),
            verification_passed=data.get("verification_passed", False),
            verification_time_ms=data.get("verification_time_ms", 0.0),
            status=data.get("status", ""),
            error_message=data.get("error_message"),
        )

        self.iteration_metrics.append(metrics)

        # Update mutation type distribution
        mutation_type = metrics.mutation_type
        self._mutation_counts[mutation_type] = self._mutation_counts.get(mutation_type, 0) + 1

        # Update summary statistics
        self.summary.total_iterations = len(self.iteration_metrics)
        if metrics.status == "keep":
            self.summary.successful_mutations += 1
        elif metrics.status == "reject":
            self.summary.rejected_mutations += 1
        elif metrics.status == "error":
            self.summary.failed_mutations += 1

        self.summary.total_tokens_used += metrics.tokens_used
        self.summary.total_llm_latency_ms += metrics.llm_latency_ms

    def set_baseline(self, score: float, rule_count: int) -> None:
        """
        Set the baseline score for the experiment.

        Args:
            score: Baseline score
            rule_count: Initial rule count
        """
        self.summary.baseline_score = score
        self._baseline_rule_count = rule_count

    def set_best_score(self, score: float) -> None:
        """
        Set the best score achieved during the experiment.

        Args:
            score: Best score
        """
        self.summary.best_score = score
        if self.summary.baseline_score > 0:
            self.summary.improvement_pct = (
                (score - self.summary.baseline_score) / self.summary.baseline_score * 100
            )

    def finalize(self) -> None:
        """
        Finalize the experiment and calculate summary statistics.
        """
        self.summary.end_time = datetime.now().isoformat()
        self.summary.mutation_type_distribution = self._mutation_counts.copy()

        # Calculate verification pass rate
        if self.iteration_metrics:
            passed = sum(1 for m in self.iteration_metrics if m.verification_passed)
            self.summary.verification_pass_rate = passed / len(self.iteration_metrics)

        # Calculate average iteration time
        elapsed_ms = (time.time() - self._start_time) * 1000
        if self.iteration_metrics:
            self.summary.avg_iteration_time_ms = elapsed_ms / len(self.iteration_metrics)

        # Write summary row to results.tsv
        try:
            from pathlib import Path as _Path
            from utils.results_logger import ResultsLogger as _ResultsLogger

            _tsv_path = _Path(__file__).parent.parent / "results.tsv"
            _results_logger = _ResultsLogger(log_file=str(_tsv_path))
            _results_logger.log_iteration(
                commit="experiment",
                score=self.summary.best_score,
                throughput_gbps=0.0,
                rule_count=getattr(self, "_baseline_rule_count", 0),
                status="keep",
                description=f"{self.experiment_name}: {self.summary.improvement_pct:.1f}% improvement",
            )
        except Exception:
            pass  # Don't fail finalize() due to TSV logging errors

    def export_results(self) -> dict[str, Path]:
        """
        Export all experiment results to JSON and CSV formats.

        Returns:
            Dictionary mapping file types to file paths

        Files created:
            - {experiment_name}_metrics.json: Full iteration metrics
            - {experiment_name}_summary.json: Experiment summary
            - {experiment_name}_metrics.csv: CSV version of metrics
        """
        files = {}

        # Export full metrics as JSON
        metrics_file = self.experiment_dir / f"{self.experiment_name}_metrics.json"
        metrics_data = {
            "experiment_name": self.experiment_name,
            "scenario": self.scenario,
            "algorithm": self.algorithm,
            "timestamp": datetime.now().isoformat(),
            "iterations": [m.to_dict() for m in self.iteration_metrics],
        }
        with open(metrics_file, "w") as f:
            json.dump(metrics_data, f, indent=2)
        files["metrics_json"] = metrics_file

        # Export summary as JSON
        summary_file = self.experiment_dir / f"{self.experiment_name}_summary.json"
        summary_data = {
            "experiment_name": self.experiment_name,
            "scenario": self.scenario,
            "algorithm": self.algorithm,
            **self.summary.to_dict(),
        }
        with open(summary_file, "w") as f:
            json.dump(summary_data, f, indent=2)
        files["summary_json"] = summary_file

        # Export metrics as CSV
        csv_file = self.experiment_dir / f"{self.experiment_name}_metrics.csv"
        if self.iteration_metrics:
            with open(csv_file, "w", newline="") as f:
                fieldnames = list(self.iteration_metrics[0].to_dict().keys())
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for metrics in self.iteration_metrics:
                    writer.writerow(metrics.to_dict())
            files["metrics_csv"] = csv_file

        return files

    def get_summary_dict(self) -> dict[str, Any]:
        """
        Get the experiment summary as a dictionary.

        Returns:
            Dictionary with summary statistics
        """
        return {
            "experiment_name": self.experiment_name,
            "scenario": self.scenario,
            "algorithm": self.algorithm,
            **self.summary.to_dict(),
        }


class ExperimentAggregator:
    """
    Aggregates results from multiple experiments for comparative analysis.

    Useful for comparing baselines vs LLM-guided approaches across scenarios.

    Example:
        >>> aggregator = ExperimentAggregator()
        >>> aggregator.add_experiment(logger1)
        >>> aggregator.add_experiment(logger2)
        >>> comparison = aggregator.compare_algorithms()
    """

    def __init__(self):
        """Initialize the aggregator."""
        self.experiments: list[ExperimentLogger] = []

    def add_experiment(self, logger: ExperimentLogger) -> None:
        """
        Add an experiment to the aggregation.

        Args:
            logger: ExperimentLogger instance
        """
        self.experiments.append(logger)

    def compare_algorithms(self) -> dict[str, Any]:
        """
        Compare results across different algorithms.

        Returns:
            Dictionary with comparative statistics
        """
        results: dict[str, Any] = {
            "by_algorithm": {},
            "by_scenario": {},
            "overall": {},
        }

        # Group by algorithm
        for exp in self.experiments:
            algo = exp.algorithm or "unknown"
            if algo not in results["by_algorithm"]:
                results["by_algorithm"][algo] = []
            results["by_algorithm"][algo].append(exp.get_summary_dict())

        # Group by scenario
        for exp in self.experiments:
            scenario = exp.scenario or "unknown"
            if scenario not in results["by_scenario"]:
                results["by_scenario"][scenario] = []
            results["by_scenario"][scenario].append(exp.get_summary_dict())

        return results

    def export_comparison(self, output_file: str | Path) -> None:
        """
        Export comparison results to a JSON file.

        Args:
            output_file: Path to the output file
        """
        comparison = self.compare_algorithms()
        with open(output_file, "w") as f:
            json.dump(comparison, f, indent=2)


def load_experiment_results(experiment_dir: str | Path) -> dict[str, Any]:
    """
    Load experiment results from a directory.

    Args:
        experiment_dir: Path to the experiment directory

    Returns:
        Dictionary with loaded metrics and summary
    """
    experiment_dir = Path(experiment_dir)

    results = {}

    # Load metrics JSON
    metrics_file = list(experiment_dir.glob("*_metrics.json"))
    if metrics_file:
        with open(metrics_file[0]) as f:
            results["metrics"] = json.load(f)

    # Load summary JSON
    summary_file = list(experiment_dir.glob("*_summary.json"))
    if summary_file:
        with open(summary_file[0]) as f:
            results["summary"] = json.load(f)

    return results


def list_experiments(base_dir: Optional[str | Path] = None) -> list[Path]:
    """
    List all experiment directories.

    Args:
        base_dir: Base directory for experiments (default: results/experiments/)

    Returns:
        List of experiment directory paths
    """
    if base_dir is None:
        base_dir = Path(__file__).parent.parent / "results" / "experiments"
    base_dir = Path(base_dir)

    if not base_dir.exists():
        return []

    return [d for d in base_dir.iterdir() if d.is_dir()]


# Convenience function for quick logging
def create_logger(
    experiment_name: str,
    scenario: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> ExperimentLogger:
    """
    Create and return an ExperimentLogger instance.

    Args:
        experiment_name: Name of the experiment
        scenario: Optional scenario name
        algorithm: Optional algorithm name

    Returns:
        ExperimentLogger instance
    """
    return ExperimentLogger(
        experiment_name=experiment_name,
        scenario=scenario,
        algorithm=algorithm,
    )


if __name__ == "__main__":
    # Demo usage
    print("Experiment Logger Demo")
    print("=" * 50)

    logger = ExperimentLogger(
        experiment_name="demo_experiment",
        scenario="test_scenario",
        algorithm="llm_guided",
    )

    # Simulate some iterations
    for i in range(5):
        logger.log_iteration(
            {
                "iteration": i + 1,
                "mutation_type": "swap" if i % 2 == 0 else "move_before",
                "mutation_description": f"Test mutation {i + 1}",
                "rule_count_before": 100,
                "rule_count_after": 100,
                "score_before": 1.0 + (i * 0.1),
                "score_after": 1.1 + (i * 0.1),
                "throughput_gbps": 2.5,
                "tokens_used": 150,
                "llm_latency_ms": 500.0,
                "verification_passed": True,
                "verification_time_ms": 100.0,
                "status": "keep" if i % 3 != 0 else "reject",
            }
        )

    logger.set_baseline(1.0, 100)
    logger.set_best_score(1.5)
    logger.finalize()

    files = logger.export_results()

    print(f"\nExported results to:")
    for file_type, file_path in files.items():
        print(f"  {file_type}: {file_path}")

    summary = logger.get_summary_dict()
    print(f"\nSummary:")
    print(f"  Total iterations: {summary['total_iterations']}")
    print(f"  Successful mutations: {summary['successful_mutations']}")
    print(f"  Baseline score: {summary['baseline_score']}")
    print(f"  Best score: {summary['best_score']}")
    print(f"  Improvement: {summary['improvement_pct']:.1f}%")
