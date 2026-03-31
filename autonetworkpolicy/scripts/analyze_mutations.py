#!/usr/bin/env python3
"""Analyze mutation effectiveness from LLM experiment runs."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

DEFAULT_RESULTS_DIR = Path(__file__).parent.parent / "results"
DEFAULT_EXPERIMENTS_DIR = DEFAULT_RESULTS_DIR / "experiments"
DEFAULT_REPORT_PATH = DEFAULT_RESULTS_DIR / "mutation_effectiveness_report.json"
DEFAULT_FIGURE_PATH = DEFAULT_RESULTS_DIR / "figures" / "mutation_effectiveness.png"


def _new_stat_bucket():
    return {
        "attempts": 0,
        "keep": 0,
        "reject": 0,
        "error": 0,
        "score_delta_sum": 0.0,
        "rule_delta_sum": 0.0,
    }


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def load_experiment_data(experiments_dir):
    metrics_data = []
    summaries_data = []

    if not experiments_dir.exists():
        return metrics_data, summaries_data

    for exp_dir in sorted(experiments_dir.iterdir()):
        if not exp_dir.is_dir():
            continue

        for metrics_path in sorted(exp_dir.glob("*_metrics.json")):
            try:
                with open(metrics_path) as f:
                    metrics_data.append(json.load(f))
            except Exception as e:
                print(f"Warning: Failed to load {metrics_path}: {e}")

        for summary_path in sorted(exp_dir.glob("*_summary.json")):
            try:
                with open(summary_path) as f:
                    summaries_data.append(json.load(f))
            except Exception as e:
                print(f"Warning: Failed to load {summary_path}: {e}")

    return metrics_data, summaries_data


def analyze_mutation_effectiveness(metrics_data, summaries_data):
    mutation_stats = defaultdict(_new_stat_bucket)
    scenario_mutation_stats = defaultdict(lambda: defaultdict(_new_stat_bucket))
    failure_reasons = defaultdict(int)
    summary_totals = defaultdict(float)

    behavioral_patterns = []

    for summary in summaries_data:
        summary_totals["total_iterations"] += _safe_float(summary.get("total_iterations", 0))
        summary_totals["successful_mutations"] += _safe_float(
            summary.get("successful_mutations", 0)
        )
        summary_totals["failed_mutations"] += _safe_float(summary.get("failed_mutations", 0))
        summary_totals["rejected_mutations"] += _safe_float(summary.get("rejected_mutations", 0))

    for metrics in metrics_data:
        scenario = str(metrics.get("scenario", "unknown"))
        experiment_name = str(metrics.get("experiment_name", "unknown"))
        iterations = metrics.get("iterations", [])

        if not isinstance(iterations, list):
            continue

        ordered_iterations = sorted(
            [it for it in iterations if isinstance(it, dict)],
            key=lambda item: int(item.get("iteration", 0) or 0),
        )

        mutation_sequence = []

        for item in ordered_iterations:
            mutation_type = str(item.get("mutation_type", "unknown"))
            status = str(item.get("status", "unknown"))
            verification_passed = bool(item.get("verification_passed", False))
            score_delta = _safe_float(item.get("score_delta", 0.0))
            rule_delta = _safe_float(item.get("rule_delta", 0.0))

            mutation_sequence.append(mutation_type)

            for bucket in (
                mutation_stats[mutation_type],
                scenario_mutation_stats[scenario][mutation_type],
            ):
                bucket["attempts"] += 1
                bucket["score_delta_sum"] += score_delta
                bucket["rule_delta_sum"] += rule_delta
                if status == "keep":
                    bucket["keep"] += 1
                elif status == "reject":
                    bucket["reject"] += 1
                else:
                    bucket["error"] += 1

            if status != "keep":
                if status == "error":
                    failure_reasons["invalid"] += 1
                elif not verification_passed:
                    failure_reasons["verification_failed"] += 1
                elif score_delta <= 0:
                    failure_reasons["no_improvement"] += 1
                else:
                    failure_reasons["rejected_other"] += 1

        if mutation_sequence:
            counts = Counter(mutation_sequence)
            dominant_mutation, dominant_count = counts.most_common(1)[0]
            dominant_ratio = dominant_count / len(mutation_sequence)

            tail_length = 1
            for i in range(len(mutation_sequence) - 2, -1, -1):
                if mutation_sequence[i] == mutation_sequence[-1]:
                    tail_length += 1
                else:
                    break

            behavioral_patterns.append(
                {
                    "experiment_name": experiment_name,
                    "scenario": scenario,
                    "iterations": len(mutation_sequence),
                    "dominant_mutation": dominant_mutation,
                    "dominant_ratio": dominant_ratio,
                    "final_streak_mutation": mutation_sequence[-1],
                    "final_streak_length": tail_length,
                    "converged": dominant_ratio >= 0.7 or tail_length >= 3,
                }
            )

    mutation_effectiveness = {}
    for mutation_type, bucket in mutation_stats.items():
        attempts = int(bucket["attempts"])
        keep = int(bucket["keep"])
        mutation_effectiveness[mutation_type] = {
            "attempts": attempts,
            "accepted": keep,
            "rejected": int(bucket["reject"]),
            "errors": int(bucket["error"]),
            "acceptance_rate": (keep / attempts) if attempts else 0.0,
            "avg_score_delta": (bucket["score_delta_sum"] / attempts) if attempts else 0.0,
            "avg_rule_delta": (bucket["rule_delta_sum"] / attempts) if attempts else 0.0,
        }

    scenario_effectiveness = {}
    for scenario, by_mutation in scenario_mutation_stats.items():
        mutation_rows = []

        for mutation_type, bucket in by_mutation.items():
            attempts = int(bucket["attempts"])
            keep = int(bucket["keep"])
            mutation_rows.append(
                {
                    "mutation_type": mutation_type,
                    "attempts": attempts,
                    "accepted": keep,
                    "acceptance_rate": (keep / attempts) if attempts else 0.0,
                    "avg_score_delta": (bucket["score_delta_sum"] / attempts) if attempts else 0.0,
                    "avg_rule_delta": (bucket["rule_delta_sum"] / attempts) if attempts else 0.0,
                }
            )

        mutation_rows.sort(
            key=lambda row: (
                row["acceptance_rate"],
                row["avg_score_delta"],
                -row["avg_rule_delta"],
                row["attempts"],
            ),
            reverse=True,
        )

        scenario_effectiveness[scenario] = {
            "best_mutation_type": mutation_rows[0]["mutation_type"] if mutation_rows else None,
            "mutation_rankings": mutation_rows,
        }

    total_failures = sum(failure_reasons.values())
    failure_analysis = {
        "total_failures": total_failures,
        "reasons": {
            reason: {
                "count": count,
                "percentage": (count / total_failures) if total_failures else 0.0,
            }
            for reason, count in sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True)
        },
    }

    converged = [pattern for pattern in behavioral_patterns if pattern["converged"]]
    dominant_counts = Counter(pattern["dominant_mutation"] for pattern in behavioral_patterns)

    llm_behavior = {
        "experiments_analyzed": len(behavioral_patterns),
        "converged_experiments": len(converged),
        "convergence_rate": (
            len(converged) / len(behavioral_patterns) if behavioral_patterns else 0.0
        ),
        "avg_dominant_ratio": (
            sum(pattern["dominant_ratio"] for pattern in behavioral_patterns)
            / len(behavioral_patterns)
            if behavioral_patterns
            else 0.0
        ),
        "dominant_mutation_distribution": dict(dominant_counts),
        "experiments": behavioral_patterns,
    }

    return {
        "generated_at": datetime.now().isoformat(),
        "paths": {
            "experiments_dir": str(DEFAULT_EXPERIMENTS_DIR),
        },
        "overview": {
            "experiments": len(metrics_data),
            "summaries": len(summaries_data),
            "total_iterations_from_metrics": int(
                sum(len(metrics.get("iterations", [])) for metrics in metrics_data)
            ),
            "total_iterations_from_summaries": int(summary_totals["total_iterations"]),
            "successful_mutations": int(summary_totals["successful_mutations"]),
            "failed_mutations": int(summary_totals["failed_mutations"]),
            "rejected_mutations": int(summary_totals["rejected_mutations"]),
        },
        "mutation_effectiveness": mutation_effectiveness,
        "scenario_effectiveness": scenario_effectiveness,
        "failure_analysis": failure_analysis,
        "llm_behavior": llm_behavior,
    }


def _print_table(title, headers, rows):
    print(f"\n{title}")
    if not rows:
        print("  No data")
        return

    widths = [len(header) for header in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))

    line = " ".join("-" * width for width in widths)
    header_line = " ".join(header.ljust(widths[i]) for i, header in enumerate(headers))

    print(line)
    print(header_line)
    print(line)
    for row in rows:
        print(" ".join(value.ljust(widths[i]) for i, value in enumerate(row)))
    print(line)


def print_terminal_summary(report):
    print("=" * 90)
    print("AutoNetworkPolicy Mutation Effectiveness Analysis")
    print("=" * 90)

    overview = report["overview"]
    print(f"Experiments: {overview['experiments']}")
    print(f"Summaries: {overview['summaries']}")
    print(f"Iterations (metrics): {overview['total_iterations_from_metrics']}")

    mutation_rows = []
    for mutation_type, stats in sorted(
        report["mutation_effectiveness"].items(),
        key=lambda item: (item[1]["acceptance_rate"], item[1]["avg_score_delta"]),
        reverse=True,
    ):
        mutation_rows.append(
            [
                mutation_type,
                str(stats["attempts"]),
                str(stats["accepted"]),
                str(stats["rejected"]),
                str(stats["errors"]),
                f"{stats['acceptance_rate'] * 100:.1f}%",
                f"{stats['avg_score_delta']:.3f}",
                f"{stats['avg_rule_delta']:.3f}",
            ]
        )

    _print_table(
        "Mutation Type Effectiveness",
        [
            "Mutation",
            "Attempts",
            "Keep",
            "Reject",
            "Error",
            "Accept%",
            "AvgScoreDelta",
            "AvgRuleDelta",
        ],
        mutation_rows,
    )

    scenario_rows = []
    for scenario, data in sorted(report["scenario_effectiveness"].items()):
        best = data.get("mutation_rankings", [])
        if not best:
            continue
        top = best[0]
        scenario_rows.append(
            [
                scenario,
                str(top["mutation_type"]),
                f"{top['acceptance_rate'] * 100:.1f}%",
                f"{top['avg_score_delta']:.3f}",
                f"{top['avg_rule_delta']:.3f}",
                str(top["attempts"]),
            ]
        )

    _print_table(
        "Best Mutation Type Per Scenario",
        ["Scenario", "BestMutation", "Accept%", "AvgScoreDelta", "AvgRuleDelta", "Attempts"],
        scenario_rows,
    )

    failure_rows = []
    for reason, data in report["failure_analysis"]["reasons"].items():
        failure_rows.append(
            [
                reason,
                str(data["count"]),
                f"{data['percentage'] * 100:.1f}%",
            ]
        )

    _print_table("Failure Analysis", ["Reason", "Count", "Share"], failure_rows)

    behavior = report["llm_behavior"]
    print("\nLLM Behavioral Patterns")
    print(f"  Experiments analyzed: {behavior['experiments_analyzed']}")
    print(f"  Converged experiments: {behavior['converged_experiments']}")
    print(f"  Convergence rate: {behavior['convergence_rate'] * 100:.1f}%")
    print(f"  Average dominant ratio: {behavior['avg_dominant_ratio'] * 100:.1f}%")

    dominant_rows = [
        [mutation_type, str(count)]
        for mutation_type, count in sorted(
            behavior["dominant_mutation_distribution"].items(),
            key=lambda item: item[1],
            reverse=True,
        )
    ]
    _print_table("Dominant Mutation Distribution", ["Mutation", "Experiments"], dominant_rows)


def save_report(report, output_file):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)


def generate_chart(report, output_file):
    if importlib.util.find_spec("matplotlib") is None:
        return False

    mutation_data = report["mutation_effectiveness"]
    if not mutation_data:
        return False

    matplotlib = importlib.import_module("matplotlib")
    matplotlib.use("Agg")
    plt = importlib.import_module("matplotlib.pyplot")

    sorted_items = sorted(
        mutation_data.items(), key=lambda item: item[1]["acceptance_rate"], reverse=True
    )
    labels = [item[0] for item in sorted_items]
    acceptance_rates = [item[1]["acceptance_rate"] * 100 for item in sorted_items]
    score_deltas = [item[1]["avg_score_delta"] for item in sorted_items]

    output_file.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(labels, acceptance_rates, color=["#4C72B0", "#55A868", "#C44E52", "#8172B3"])

    for i, bar in enumerate(bars):
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            f"{height:.1f}%\nDelta {score_deltas[i]:.2f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    ax.set_title("Mutation Type Effectiveness (Acceptance Rate)")
    ax.set_xlabel("Mutation Type")
    ax.set_ylabel("Acceptance Rate (%)")
    ax.set_ylim(0, max(100.0, max(acceptance_rates) + 10.0))
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True


def main() -> int:
    """CLI entry point for mutation effectiveness analysis."""
    parser = argparse.ArgumentParser(
        description="Analyze mutation effectiveness from experiment metrics",
    )
    _ = parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_RESULTS_DIR),
        help="Output directory for report and figures (default: results/)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    experiments_dir = output_dir / "experiments"
    report_path = output_dir / DEFAULT_REPORT_PATH.name
    figure_path = output_dir / "figures" / DEFAULT_FIGURE_PATH.name

    metrics_data, summaries_data = load_experiment_data(experiments_dir)
    report = analyze_mutation_effectiveness(metrics_data, summaries_data)

    print_terminal_summary(report)

    save_report(report, report_path)
    print(f"\nJSON report saved to: {report_path}")

    if generate_chart(report, figure_path):
        print(f"Chart saved to: {figure_path}")
    else:
        if importlib.util.find_spec("matplotlib") is None:
            print("Chart skipped: matplotlib not available")
        else:
            print("Chart skipped: no mutation data available")

    print("=" * 90)
    return 0


if __name__ == "__main__":
    sys.exit(main())
