#!/usr/bin/env python3
"""
BDD Verification Benchmark Script

Measures BDD verification performance for different rule set sizes.
Tests self-verification (ruleset vs itself) with multiple iterations.

Usage:
    python verify/benchmark_bdd.py
    python verify/benchmark_bdd.py --output results/custom.json
    python verify/benchmark_bdd.py --max-rules 500 --iterations 5

Success Criteria:
    - 500 rules must verify in < 5 seconds (IP-only mode)
    - Exit code 0 if all benchmarks pass, 1 otherwise
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Add parent directory to path for imports (need parent of autonetworkpolicy)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from autonetworkpolicy.data.classbench_to_nft import load_nft_as_rules
from autonetworkpolicy.verify.bdd_verify import BDDVerifier


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run.

    Attributes:
        rule_count: Number of rules tested
        median_time: Median verification time in seconds
        min_time: Minimum verification time in seconds
        max_time: Maximum verification time in seconds
        mean_time: Mean verification time in seconds
        iterations: Number of iterations run
        passed: Whether the benchmark met performance criteria
    """

    rule_count: int
    median_time: float
    min_time: float
    max_time: float
    mean_time: float
    iterations: int
    passed: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "rule_count": self.rule_count,
            "median_time": round(self.median_time, 6),
            "min_time": round(self.min_time, 6),
            "max_time": round(self.max_time, 6),
            "mean_time": round(self.mean_time, 6),
            "iterations": self.iterations,
            "passed": self.passed,
        }


@dataclass
class BenchmarkSuite:
    """Complete benchmark results."""

    timestamp: str
    target_seconds: float
    iterations_per_test: int
    results: list[BenchmarkResult] = field(default_factory=list)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert suite to dictionary."""
        return {
            "timestamp": self.timestamp,
            "target_seconds": self.target_seconds,
            "iterations_per_test": self.iterations_per_test,
            "results": [r.to_dict() for r in self.results],
            "passed": self.passed,
        }


def load_rules_from_nft(filepath: Path, max_rules: int | None = None) -> list[Any]:
    """Load rules from nftables file.

    Args:
        filepath: Path to the nftables file
        max_rules: Maximum number of rules to load (None for all)

    Returns:
        List of Rule objects
    """
    rules = load_nft_as_rules(filepath)
    if max_rules is not None:
        rules = rules[:max_rules]
    return rules


def run_single_benchmark(
    rules: list[Any],
    verifier: BDDVerifier,
    iterations: int = 3,
) -> tuple[list[float], bool]:
    """Run a single benchmark with multiple iterations.

    Args:
        rules: List of rules to verify
        verifier: BDDVerifier instance
        iterations: Number of iterations to run

    Returns:
        Tuple of (list of times, all passed)
    """
    times = []
    all_passed = True

    for _ in range(iterations):
        start_time = time.perf_counter()
        result = verifier.verify(rules, rules)
        elapsed = time.perf_counter() - start_time

        times.append(elapsed)

        # Check if verification succeeded
        if not result.get("equivalent", False):
            # Self-verification should always pass
            all_passed = False

    return times, all_passed


def format_time(seconds: float) -> str:
    """Format time in seconds for display.

    Args:
        seconds: Time in seconds

    Returns:
        Formatted string (e.g., "0.023s" or "1.234s")
    """
    if seconds < 0.001:
        return f"{seconds * 1000:.3f}ms"
    elif seconds < 1.0:
        return f"{seconds * 1000:.1f}ms"
    else:
        return f"{seconds:.3f}s"


def print_results_table(results: list[BenchmarkResult], target: float) -> None:
    """Print benchmark results as a formatted table.

    Args:
        results: List of benchmark results
        target: Target time in seconds
    """
    print("\nBDD Verification Benchmark")
    print("=" * 60)
    print(f"{'Rule Count':<12} | {'Median Time':<12} | {'Min':<10} | {'Max':<10} | Status")
    print("-" * 12 + "+" + "-" * 13 + "+" + "-" * 11 + "+" + "-" * 11 + "+" + "-" * 6)

    for result in results:
        status = "✓" if result.passed else "✗"
        median_str = format_time(result.median_time)
        min_str = format_time(result.min_time)
        max_str = format_time(result.max_time)

        print(
            f"{result.rule_count:<12} | {median_str:<12} | {min_str:<10} | {max_str:<10} | {status}"
        )

    print("-" * 60)
    print(f"\nTarget: <{target}s at 500 rules")

    # Check overall pass/fail
    all_passed = all(r.passed for r in results)
    if all_passed:
        print("Result: PASS ✓")
    else:
        print("Result: FAIL ✗")
        failed = [r for r in results if not r.passed]
        for f in failed:
            print(f"  - {f.rule_count} rules: {format_time(f.median_time)} (target: <{target}s)")


def save_results_json(suite: BenchmarkSuite, output_path: Path) -> None:
    """Save benchmark results to JSON file.

    Args:
        suite: BenchmarkSuite to save
        output_path: Path to output file
    """
    # Create parent directory if needed
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(suite.to_dict(), f, indent=2)

    print(f"\nResults saved to: {output_path}")


def run_benchmarks(
    rule_counts: list[int],
    iterations: int,
    target_seconds: float,
    nft_file: Path,
    backend: str = "autoref",
) -> BenchmarkSuite:
    """Run all benchmarks.

    Args:
        rule_counts: List of rule counts to test
        iterations: Number of iterations per test
        target_seconds: Target time limit for 500 rules
        nft_file: Path to the nftables file with rules
        backend: BDD backend to use

    Returns:
        BenchmarkSuite with all results
    """
    timestamp = datetime.now().isoformat()
    suite = BenchmarkSuite(
        timestamp=timestamp,
        target_seconds=target_seconds,
        iterations_per_test=iterations,
    )

    # Load all rules once
    print(f"Loading rules from {nft_file}...")
    all_rules = load_rules_from_nft(nft_file)
    print(f"Loaded {len(all_rules)} total rules")

    # Create verifier
    verifier = BDDVerifier(backend=backend, mode="ip_only", timeout_seconds=60.0)
    print(f"Using BDD backend: {backend}")
    print(f"Running {iterations} iteration(s) per test...")

    # Run benchmarks for each rule count
    for rule_count in rule_counts:
        if rule_count > len(all_rules):
            print(f"Warning: Requested {rule_count} rules but only {len(all_rules)} available")
            continue

        rules = all_rules[:rule_count]
        print(f"\nBenchmarking {rule_count} rules...", end=" ")

        times, verification_passed = run_single_benchmark(rules, verifier, iterations)

        # Calculate statistics
        median_time = statistics.median(times)
        min_time = min(times)
        max_time = max(times)
        mean_time = statistics.mean(times)

        # Check if passed target (only enforce for 500 rules)
        passed = verification_passed
        if rule_count == 500:
            passed = passed and median_time < target_seconds

        result = BenchmarkResult(
            rule_count=rule_count,
            median_time=median_time,
            min_time=min_time,
            max_time=max_time,
            mean_time=mean_time,
            iterations=iterations,
            passed=passed,
        )
        suite.results.append(result)

        print(f"median={format_time(median_time)}")

    # Determine overall pass/fail
    # Must pass 500-rule benchmark to be considered successful
    rule_500_result = next((r for r in suite.results if r.rule_count == 500), None)
    if rule_500_result:
        suite.passed = rule_500_result.passed and rule_500_result.median_time < target_seconds
    else:
        suite.passed = all(r.passed for r in suite.results)

    return suite


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="BDD Verification Performance Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                          # Run default benchmarks
    %(prog)s --output custom.json     # Save to custom file
    %(prog)s --max-rules 250          # Test up to 250 rules
    %(prog)s --iterations 5           # Run 5 iterations per test
        """,
    )

    parser.add_argument(
        "--output",
        type=str,
        default="results/bdd_benchmark.json",
        help="Output JSON file path (default: results/bdd_benchmark.json)",
    )

    parser.add_argument(
        "--max-rules",
        type=int,
        default=500,
        help="Maximum number of rules to test (default: 500)",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations per test (default: 3)",
    )

    parser.add_argument(
        "--target",
        type=float,
        default=5.0,
        help="Target time in seconds for 500 rules (default: 5.0)",
    )

    parser.add_argument(
        "--backend",
        type=str,
        default="autoref",
        choices=["autoref", "cudd"],
        help="BDD backend to use (default: autoref)",
    )

    parser.add_argument(
        "--rule-counts",
        type=int,
        nargs="+",
        default=None,
        help="Custom rule counts to test (default: 10 50 100 250 500)",
    )

    args = parser.parse_args()

    # Determine rule counts to test
    if args.rule_counts:
        rule_counts = sorted(args.rule_counts)
    else:
        # Default rule counts, filtered by max-rules
        default_counts = [10, 50, 100, 250, 500]
        rule_counts = [c for c in default_counts if c <= args.max_rules]
        # Always include max-rules if not in default set
        if args.max_rules not in rule_counts and args.max_rules <= 500:
            rule_counts.append(args.max_rules)
            rule_counts = sorted(rule_counts)

    # Find nftables file
    script_dir = Path(__file__).parent
    nft_file = script_dir.parent / "data" / "generated" / "acl1_500.nft"

    if not nft_file.exists():
        print(f"Error: Rules file not found: {nft_file}")
        print("Please ensure the test data file exists.")
        sys.exit(1)

    # Run benchmarks
    try:
        suite = run_benchmarks(
            rule_counts=rule_counts,
            iterations=args.iterations,
            target_seconds=args.target,
            nft_file=nft_file,
            backend=args.backend,
        )

        # Print results
        print_results_table(suite.results, args.target)

        # Save results
        output_path = Path(args.output)
        save_results_json(suite, output_path)

        # Exit with appropriate code
        if suite.passed:
            print("\n✓ All benchmarks passed")
            sys.exit(0)
        else:
            print("\n✗ Some benchmarks failed")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError during benchmark: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
