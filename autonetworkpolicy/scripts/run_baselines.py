#!/usr/bin/env python3
"""
================================================================================
Baseline Execution Suite - Phase 10.2.1
================================================================================

Executes all 4 baseline algorithms on all 3 benchmark scenarios:

Baseline Algorithms:
    1. Random Reorder
    2. Greedy Hitcount
    3. Static Analysis
    4. Simulated Annealing

Benchmark Scenarios:
    1. Over-permissive Legacy (500 rules)
    2. Broken Segmentation (300 rules)
    3. Redundant Shadowing (400 rules)

Records metrics:
    - Rules Reduced (count and percentage)
    - Time to Convergence
    - Final rule count
    - Algorithm-specific metrics

Output:
    results/baselines_comparison.csv
    results/experiments/baseline_*/

Usage:
    python run_baselines.py --all
    python run_baselines.py --algorithm random_reorder --scenario over_permissive
    python run_baselines.py --list-scenarios

================================================================================
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.classbench_to_nft import Rule, load_nft_as_rules, rules_to_nft
from baselines.greedy_hitcount import optimize as greedy_optimize
from baselines.random_reorder import optimize as random_optimize
from baselines.simulated_annealing import optimize as sa_optimize
from baselines.static_analysis import optimize as static_optimize
from baselines.static_analysis import optimize_fixpoint as static_fixpoint_optimize


# Benchmark scenarios
BENCHMARK_SCENARIOS = {
    "over_permissive": "over_permissive_legacy_500.nft",
    "broken_segmentation": "broken_segmentation_300.nft",
    "redundant_shadowing": "redundant_shadowing_400.nft",
    "port_heavy_enterprise": "port_heavy_enterprise_500.nft",
    "mixed_protocol": "mixed_protocol_400.nft",
    "k8s_microservices": "semantic/k8s_microservices_200.nft",
    "enterprise_departments": "semantic/enterprise_departments_500.nft",
    "three_tier_app": "semantic/three_tier_app_300.nft",
    "vlan_segmentation": "semantic/vlan_segmentation_400.nft",
}

# Baseline algorithms
BASELINE_ALGORITHMS = {
    "random_reorder": "Random Reorder",
    "greedy_hitcount": "Greedy Hitcount",
    "static_analysis": "Static Analysis",
    "simulated_annealing": "Simulated Annealing",
    "fixpoint_static_analysis": "Fixpoint Static Analysis",
}


def run_random_reorder(
    rules: list[Rule], iterations: int = 50, seed: int = 42
) -> tuple[list[Rule], dict[str, Any]]:
    """
    Run Random Reorder baseline.

    Args:
        rules: Input ruleset
        iterations: Number of random shuffles to try
        seed: Random seed

    Returns:
        Tuple of (optimized rules, metrics dict)
    """
    start_time = time.time()

    # Simple heuristic evaluation (no traffic test needed for baseline comparison)
    def evaluate(rules: list[Rule]) -> float:
        # Prefer fewer rules and higher specificity
        return 1000.0 - len(rules) * 2

    optimized = random_optimize(
        rules,
        iterations=iterations,
        evaluate_fn=evaluate,
        remove_shadowed=True,
        seed=seed,
    )

    elapsed = time.time() - start_time

    metrics = {
        "iterations": iterations,
        "time_seconds": elapsed,
        "rules_before": len(rules),
        "rules_after": len(optimized),
        "rules_reduced": len(rules) - len(optimized),
        "reduction_percentage": ((len(rules) - len(optimized)) / len(rules) * 100) if rules else 0,
    }

    return optimized, metrics


def run_greedy_hitcount(rules: list[Rule]) -> tuple[list[Rule], dict[str, Any]]:
    """
    Run Greedy Hitcount baseline.

    Sorts by specificity since we don't have actual hit counts.

    Args:
        rules: Input ruleset

    Returns:
        Tuple of (optimized rules, metrics dict)
    """
    start_time = time.time()

    optimized = greedy_optimize(rules, hit_counts=None)

    elapsed = time.time() - start_time

    metrics = {
        "time_seconds": elapsed,
        "rules_before": len(rules),
        "rules_after": len(optimized),
        "rules_reduced": len(rules) - len(optimized),
        "reduction_percentage": ((len(rules) - len(optimized)) / len(rules) * 100) if rules else 0,
        "note": "Sorted by specificity (no hit counts available)",
    }

    return optimized, metrics


def run_static_analysis(rules: list[Rule]) -> tuple[list[Rule], dict[str, Any]]:
    """
    Run Static Analysis baseline.

    Args:
        rules: Input ruleset

    Returns:
        Tuple of (optimized rules, metrics dict)
    """
    start_time = time.time()

    from baselines.static_analysis import analyze

    # Get analysis stats before optimization
    stats = analyze(rules)

    optimized = static_optimize(
        rules,
        remove_duplicates=True,
        remove_shadowed=True,
    )

    elapsed = time.time() - start_time

    metrics = {
        "time_seconds": elapsed,
        "rules_before": len(rules),
        "rules_after": len(optimized),
        "rules_reduced": len(rules) - len(optimized),
        "reduction_percentage": ((len(rules) - len(optimized)) / len(rules) * 100) if rules else 0,
        "duplicates_found": stats["duplicate_count"],
        "shadowed_found": stats["shadowed_count"],
    }

    return optimized, metrics


def run_fixpoint_static_analysis(rules: list[Rule]) -> tuple[list[Rule], dict[str, Any]]:
    start_time = time.time()

    optimized = static_fixpoint_optimize(
        rules,
        remove_duplicates=True,
        max_passes=100,
    )

    elapsed = time.time() - start_time

    metrics = {
        "time_seconds": elapsed,
        "rules_before": len(rules),
        "rules_after": len(optimized),
        "rules_reduced": len(rules) - len(optimized),
        "reduction_percentage": ((len(rules) - len(optimized)) / len(rules) * 100) if rules else 0,
    }

    return optimized, metrics


def run_simulated_annealing(
    rules: list[Rule],
    iterations: int = 100,
    seed: int = 42,
    initial_temperature: float = 100.0,
    cooling_rate: float = 0.95,
) -> tuple[list[Rule], dict[str, Any]]:
    """
    Run Simulated Annealing baseline.

    Args:
        rules: Input ruleset
        iterations: Maximum iterations
        seed: Random seed

    Returns:
        Tuple of (optimized rules, metrics dict)
    """
    start_time = time.time()

    original_count = len(rules)

    def evaluate(rules_to_eval: list[Rule]) -> float:
        rule_score = (original_count - len(rules_to_eval)) * 10.0
        from baselines.greedy_hitcount import _calculate_specificity

        order_score = (
            sum(
                _calculate_specificity(r) * (len(rules_to_eval) - i)
                for i, r in enumerate(rules_to_eval)
            )
            / len(rules_to_eval)
            if rules_to_eval
            else 0
        )
        return rule_score + order_score * 0.1

    optimized = sa_optimize(
        rules,
        evaluate_fn=evaluate,
        max_iterations=iterations,
        initial_temperature=initial_temperature,
        cooling_rate=cooling_rate,
        seed=seed,
    )

    elapsed = time.time() - start_time

    metrics = {
        "iterations": iterations,
        "initial_temperature": initial_temperature,
        "cooling_rate": cooling_rate,
        "time_seconds": elapsed,
        "rules_before": len(rules),
        "rules_after": len(optimized),
        "rules_reduced": len(rules) - len(optimized),
        "reduction_percentage": ((len(rules) - len(optimized)) / len(rules) * 100) if rules else 0,
    }

    return optimized, metrics


def run_baseline(
    algorithm: str,
    scenario_path: Path,
    output_dir: Path,
    iterations: int = 100,
    seed: int = 42,
    sa_temperature: float = 100.0,
    sa_cooling: float = 0.95,
) -> dict[str, Any]:
    """
    Run a single baseline algorithm on a scenario.

    Args:
        algorithm: Algorithm name (random_reorder, greedy_hitcount, static_analysis, simulated_annealing)
        scenario_path: Path to the scenario file
        output_dir: Directory for output files
        iterations: Number of iterations (for applicable algorithms)
        seed: Random seed

    Returns:
        Dictionary with results
    """
    print(f"  Running {BASELINE_ALGORITHMS[algorithm]}...")

    # Load rules
    rules = load_nft_as_rules(scenario_path)
    print(f"    Loaded {len(rules)} rules")

    # Run algorithm
    if algorithm == "random_reorder":
        optimized, metrics = run_random_reorder(rules, iterations=iterations, seed=seed)
    elif algorithm == "greedy_hitcount":
        optimized, metrics = run_greedy_hitcount(rules)
    elif algorithm == "static_analysis":
        optimized, metrics = run_static_analysis(rules)
    elif algorithm == "simulated_annealing":
        optimized, metrics = run_simulated_annealing(
            rules,
            iterations=iterations,
            seed=seed,
            initial_temperature=sa_temperature,
            cooling_rate=sa_cooling,
        )
    elif algorithm == "fixpoint_static_analysis":
        optimized, metrics = run_fixpoint_static_analysis(rules)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    # Save optimized rules
    scenario_name = scenario_path.stem
    output_file = output_dir / f"{algorithm}_{scenario_name}_optimized.nft"
    nft_config = rules_to_nft(optimized)
    with open(output_file, "w") as f:
        f.write(nft_config)

    metrics["output_file"] = str(output_file)

    print(
        f"    Rules: {metrics['rules_before']} → {metrics['rules_after']} "
        f"(-{metrics['rules_reduced']}, {metrics['reduction_percentage']:.1f}%)"
    )
    print(f"    Time: {metrics['time_seconds']:.3f}s")

    return metrics


def run_all_baselines(
    scenarios: dict[str, str],
    output_dir: Path,
    iterations: int = 100,
    seed: int = 42,
    sa_temperature: float = 100.0,
    sa_cooling: float = 0.95,
) -> list[dict[str, Any]]:
    """
    Run all baseline algorithms on all scenarios.

    Args:
        scenarios: Dictionary mapping scenario names to file paths
        output_dir: Directory for output files
        iterations: Number of iterations for applicable algorithms
        seed: Random seed
        sa_temperature: Initial temperature for simulated annealing
        sa_cooling: Cooling rate for simulated annealing

    Returns:
        List of result dictionaries
    """
    results = []

    benchmarks_dir = Path(__file__).parent.parent / "benchmarks"

    for scenario_name, scenario_file in scenarios.items():
        scenario_path = benchmarks_dir / scenario_file

        if not scenario_path.exists():
            print(f"Warning: Scenario file not found: {scenario_path}")
            continue

        print(f"\nScenario: {scenario_name}")
        print(f"  File: {scenario_file}")

        for algorithm in BASELINE_ALGORITHMS.keys():
            try:
                metrics = run_baseline(
                    algorithm=algorithm,
                    scenario_path=scenario_path,
                    output_dir=output_dir,
                    iterations=iterations,
                    seed=seed,
                    sa_temperature=sa_temperature,
                    sa_cooling=sa_cooling,
                )

                results.append(
                    {
                        "scenario": scenario_name,
                        "algorithm": algorithm,
                        **metrics,
                    }
                )

            except Exception as e:
                print(f"    Error: {e}")
                results.append(
                    {
                        "scenario": scenario_name,
                        "algorithm": algorithm,
                        "error": str(e),
                    }
                )

    return results


def export_results_csv(results: list[dict[str, Any]], output_file: Path) -> None:
    """
    Export results to CSV file.

    Args:
        results: List of result dictionaries
        output_file: Output CSV file path
    """
    if not results:
        return

    # Determine fieldnames from first result
    fieldnames = [
        "scenario",
        "algorithm",
        "rules_before",
        "rules_after",
        "rules_reduced",
        "reduction_percentage",
        "time_seconds",
    ]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            writer.writerow(result)

    print(f"\nResults exported to: {output_file}")


def export_results_json(results: list[dict[str, Any]], output_file: Path) -> None:
    """
    Export results to JSON file.

    Args:
        results: List of result dictionaries
        output_file: Output JSON file path
    """
    data = {
        "timestamp": datetime.now().isoformat(),
        "total_runs": len(results),
        "results": results,
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Results exported to: {output_file}")


def print_comparison_table(results: list[dict[str, Any]]) -> None:
    """
    Print a comparison table of all results.

    Args:
        results: List of result dictionaries
    """
    print("\n" + "=" * 80)
    print("Baseline Comparison Summary")
    print("=" * 80)

    # Group by scenario
    by_scenario = {}
    for result in results:
        scenario = result.get("scenario", "unknown")
        if scenario not in by_scenario:
            by_scenario[scenario] = []
        by_scenario[scenario].append(result)

    for scenario, scenario_results in by_scenario.items():
        print(f"\n{scenario.upper()}:")
        print("-" * 80)
        print(
            f"{'Algorithm':<25} {'Before':>8} {'After':>8} {'Reduced':>8} {'%':>8} {'Time(s)':>10}"
        )
        print("-" * 80)

        # Sort by reduction percentage
        sorted_results = sorted(
            scenario_results,
            key=lambda x: x.get("reduction_percentage", 0),
            reverse=True,
        )

        for result in sorted_results:
            algo = BASELINE_ALGORITHMS.get(result.get("algorithm", "unknown"), "Unknown")
            before = result.get("rules_before", 0)
            after = result.get("rules_after", 0)
            reduced = result.get("rules_reduced", 0)
            pct = result.get("reduction_percentage", 0.0)
            time_s = result.get("time_seconds", 0.0)

            print(f"{algo:<25} {before:>8} {after:>8} {reduced:>8} {pct:>7.1f}% {time_s:>10.3f}")

        print("-" * 80)

    print(
        "\nNote: throughput_gbps is a placeholder (always 0.00); live traffic tests not yet wired in."
    )


def main():
    """CLI entry point for baseline execution suite."""
    parser = argparse.ArgumentParser(
        description="Run baseline algorithms on benchmark scenarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run all baselines on all scenarios
    %(prog)s --all
    
    # Run specific algorithm on specific scenario
    %(prog)s --algorithm random_reorder --scenario over_permissive
    
    # List available scenarios
    %(prog)s --list-scenarios
    
    # Run with custom iterations
    %(prog)s --all --iterations 200
        """,
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all baselines on all scenarios",
    )

    parser.add_argument(
        "--algorithm",
        choices=list(BASELINE_ALGORITHMS.keys()),
        help="Run specific algorithm",
    )

    parser.add_argument(
        "--scenario",
        choices=list(BENCHMARK_SCENARIOS.keys()),
        help="Run on specific scenario",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=200,
        help="Number of iterations (default: 200)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )

    parser.add_argument(
        "--sa-temperature",
        type=float,
        default=100.0,
        help="Initial temperature for simulated annealing (default: 100.0)",
    )

    parser.add_argument(
        "--sa-cooling",
        type=float,
        default=0.95,
        help="Cooling rate for simulated annealing, must be in (0, 1) (default: 0.95)",
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove existing baseline rows from results.tsv before running",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory (default: results/baselines/)",
    )

    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List available scenarios and exit",
    )

    args = parser.parse_args()

    if args.list_scenarios:
        print("Available scenarios:")
        for name, filename in BENCHMARK_SCENARIOS.items():
            print(f"  {name}: {filename}")
        return 0

    if not args.all and not (args.algorithm and args.scenario):
        parser.error("Must specify --all OR both --algorithm and --scenario")

    if not (0 < args.sa_cooling < 1):
        parser.error("--sa-cooling must be in (0, 1)")

    # Set up output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(__file__).parent.parent / "results" / "baselines"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("AutoNetworkPolicy Baseline Execution Suite")
    print("=" * 80)
    print(f"Output directory: {output_dir}")
    print(f"Iterations: {args.iterations}")
    print(f"Seed: {args.seed}")
    print(f"SA temperature: {args.sa_temperature}, cooling: {args.sa_cooling}")

    start_time = time.time()

    if args.all:
        results = run_all_baselines(
            scenarios=BENCHMARK_SCENARIOS,
            output_dir=output_dir,
            iterations=args.iterations,
            seed=args.seed,
            sa_temperature=args.sa_temperature,
            sa_cooling=args.sa_cooling,
        )
    else:
        # Run single algorithm on single scenario
        benchmarks_dir = Path(__file__).parent.parent / "benchmarks"
        scenario_path = benchmarks_dir / BENCHMARK_SCENARIOS[args.scenario]

        results = [
            {
                "scenario": args.scenario,
                **run_baseline(
                    algorithm=args.algorithm,
                    scenario_path=scenario_path,
                    output_dir=output_dir,
                    iterations=args.iterations,
                    seed=args.seed,
                    sa_temperature=args.sa_temperature,
                    sa_cooling=args.sa_cooling,
                ),
            }
        ]

    total_time = time.time() - start_time

    # Export results
    csv_file = output_dir / "baselines_comparison.csv"
    export_results_csv(results, csv_file)

    json_file = output_dir / "baselines_comparison.json"
    export_results_json(results, json_file)

    # Log to results.tsv
    try:
        from pathlib import Path as _rPath
        from utils.results_logger import ResultsLogger as _RLogger

        _tsv_path = _rPath(__file__).parent.parent / "results.tsv"
        _results_logger = _RLogger(log_file=str(_tsv_path))

        if args.clean:
            removed = _results_logger.remove_by_status("baseline")
            print(f"\nCleaned {removed} existing baseline rows from results.tsv")

        for result in results:
            if "error" not in result:
                description = (
                    f"{result.get('algorithm', 'unknown')} on "
                    f"{result.get('scenario', 'unknown')}: "
                    f"{result.get('reduction_percentage', 0):.1f}% reduction"
                )
                if not _results_logger.has_entry(description, "baseline"):
                    _results_logger.log_iteration(
                        commit="baseline",
                        score=result.get("reduction_percentage", 0.0),
                        throughput_gbps=0.0,
                        rule_count=result.get("rules_after", 0),
                        status="baseline",
                        description=description,
                    )
    except Exception:
        pass  # Don't fail main() due to TSV logging errors

    # Print summary table
    print_comparison_table(results)

    print(f"\nTotal execution time: {total_time:.1f}s")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
