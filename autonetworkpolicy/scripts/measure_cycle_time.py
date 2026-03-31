#!/usr/bin/env python3
"""
AutoNetworkPolicy v2.1 - Cycle Time Measurement Script

Measures the full cycle time for one complete iteration of the optimization loop.

Steps measured:
    1. Load rules from file
    2. BDD verification (self-verify)
    3. Apply sample mutation
    4. BDD verification (post-mutation)
    5. Save policy to file

Usage:
    python scripts/measure_cycle_time.py
    python scripts/measure_cycle_time.py --verbose
    python scripts/measure_cycle_time.py --rules data/generated/acl1_500.nft

Success Criteria:
    - Full cycle < 120 seconds per iteration
    - Exit code 0 if under target, 1 otherwise

Exit Codes:
    0 - Cycle time under target (< 120s)
    1 - Cycle time exceeded target
    2 - Error during measurement
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class StepResult:
    """Result of a single measurement step."""

    name: str
    duration_seconds: float
    success: bool
    details: str = ""


@dataclass
class CycleMeasurement:
    """Complete cycle time measurement results."""

    total_seconds: float = 0.0
    steps: list[StepResult] = field(default_factory=list)
    target_seconds: float = 120.0
    success: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "total_seconds": round(self.total_seconds, 3),
            "target_seconds": self.target_seconds,
            "success": self.success,
            "steps": [
                {
                    "name": s.name,
                    "duration_seconds": round(s.duration_seconds, 3),
                    "success": s.success,
                    "details": s.details,
                }
                for s in self.steps
            ],
        }


def format_time(seconds: float) -> str:
    """Format time in seconds for display."""
    if seconds < 1.0:
        return f"{seconds * 1000:.1f}ms"
    else:
        return f"{seconds:.3f}s"


def measure_step(name: str, fn: Callable[[], Any], verbose: bool = False) -> StepResult:
    """Measure the time taken by a single step."""
    if verbose:
        print(f"  Running: {name}...", end=" ", flush=True)

    start_time = time.perf_counter()

    try:
        result = fn()
        elapsed = time.perf_counter() - start_time

        if verbose:
            print(f"{format_time(elapsed)}")

        return StepResult(
            name=name, duration_seconds=elapsed, success=True, details=str(result) if result else ""
        )
    except Exception as e:
        elapsed = time.perf_counter() - start_time

        if verbose:
            print(f"FAILED ({format_time(elapsed)})")

        return StepResult(name=name, duration_seconds=elapsed, success=False, details=str(e))


def load_rules_step(nft_file: Path, project_root: Path) -> Callable[[], list]:
    """Create a step function for loading rules."""

    def _load() -> list:
        sys.path.insert(0, str(project_root))
        from data.classbench_to_nft import load_nft_as_rules

        if not nft_file.exists():
            raise FileNotFoundError(f"Rules file not found: {nft_file}")

        rules = load_nft_as_rules(nft_file)
        return f"Loaded {len(rules)} rules"

    return _load


def bdd_verify_step(project_root: Path, rules: list) -> Callable[[], str]:
    """Create a step function for BDD verification."""

    def _verify() -> str:
        sys.path.insert(0, str(project_root))
        from verify.bdd_verify import BDDVerifier

        verifier = BDDVerifier(backend="autoref", mode="ip_only", timeout_seconds=60)
        result = verifier.verify(rules, rules)

        if not result.get("equivalent", False):
            raise RuntimeError("Self-verification failed")

        return f"Verified {len(rules)} rules in {result.get('time_seconds', 0):.3f}s"

    return _verify


def apply_mutation_step(project_root: Path, rules: list) -> Callable[[], str]:
    """Create a step function for applying a mutation."""

    def _mutate() -> str:
        sys.path.insert(0, str(project_root))
        from mutations import MutationEngine
        import copy

        engine = MutationEngine()

        # Create a copy to avoid modifying original during timing
        rules_copy = copy.deepcopy(rules)

        # Apply a simple swap mutation
        if len(rules_copy) >= 2:
            new_rules = engine.apply_mutation(rules_copy, {"name": "swap", "args": [0, 1]})
            return f"Applied swap mutation: {len(rules_copy)} -> {len(new_rules)} rules"
        else:
            return "Not enough rules to mutate"

    return _mutate


def save_policy_step(project_root: Path, rules: list, output_file: Path) -> Callable[[], str]:
    """Create a step function for saving policy."""

    def _save() -> str:
        sys.path.insert(0, str(project_root))
        from data.classbench_to_nft import rules_to_nft

        nft_config = rules_to_nft(rules)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            f.write(nft_config)

        return f"Saved {len(rules)} rules to {output_file.name}"

    return _save


def measure_cycle(
    nft_file: Path,
    output_file: Path,
    project_root: Path,
    target_seconds: float = 120.0,
    verbose: bool = False,
) -> CycleMeasurement:
    """Measure time for one complete iteration cycle.

    Steps:
        1. Load rules from file
        2. BDD verification (self-verify)
        3. Apply sample mutation
        4. BDD verification (post-mutation)
        5. Save policy to file

    Args:
        nft_file: Path to the input nftables rules file
        output_file: Path to save the output policy
        project_root: Root directory of the project
        target_seconds: Target time for full cycle
        verbose: Whether to print progress

    Returns:
        CycleMeasurement with timing breakdown
    """
    measurement = CycleMeasurement(target_seconds=target_seconds)

    print("=" * 70)
    print("AutoNetworkPolicy v2.1 - Cycle Time Measurement")
    print("=" * 70)
    print()

    if verbose:
        print(f"Input:  {nft_file}")
        print(f"Output: {output_file}")
        print(f"Target: <{target_seconds}s")
        print()

    cycle_start = time.perf_counter()

    # Step 1: Load rules
    step1 = measure_step("Load rules", load_rules_step(nft_file, project_root), verbose)
    measurement.steps.append(step1)

    if not step1.success:
        measurement.error = f"Failed to load rules: {step1.details}"
        measurement.total_seconds = time.perf_counter() - cycle_start
        return measurement

    # Parse the result to get rule count
    # We need to actually load the rules for subsequent steps
    sys.path.insert(0, str(project_root))
    from data.classbench_to_nft import load_nft_as_rules

    rules = load_nft_as_rules(nft_file)

    if verbose:
        print(f"         Loaded {len(rules)} rules")

    # Step 2: BDD verification (self-verify)
    step2 = measure_step("BDD verify (pre)", bdd_verify_step(project_root, rules), verbose)
    measurement.steps.append(step2)

    if not step2.success:
        measurement.error = f"BDD verification failed: {step2.details}"
        measurement.total_seconds = time.perf_counter() - cycle_start
        return measurement

    # Step 3: Apply sample mutation
    step3 = measure_step("Apply mutation", apply_mutation_step(project_root, rules), verbose)
    measurement.steps.append(step3)

    if not step3.success:
        measurement.error = f"Mutation failed: {step3.details}"
        measurement.total_seconds = time.perf_counter() - cycle_start
        return measurement

    # Actually apply the mutation for post-mutation verification
    import copy
    from mutations import MutationEngine

    engine = MutationEngine()
    rules_copy = copy.deepcopy(rules)
    mutated_rules = engine.apply_mutation(rules_copy, {"name": "swap", "args": [0, 1]})

    # Step 4: BDD verification (post-mutation)
    step4 = measure_step("BDD verify (post)", bdd_verify_step(project_root, mutated_rules), verbose)
    measurement.steps.append(step4)

    if not step4.success:
        measurement.error = f"Post-mutation verification failed: {step4.details}"
        measurement.total_seconds = time.perf_counter() - cycle_start
        return measurement

    # Step 5: Save policy
    step5 = measure_step(
        "Save policy", save_policy_step(project_root, mutated_rules, output_file), verbose
    )
    measurement.steps.append(step5)

    if not step5.success:
        measurement.error = f"Failed to save policy: {step5.details}"
        measurement.total_seconds = time.perf_counter() - cycle_start
        return measurement

    # Calculate total
    measurement.total_seconds = time.perf_counter() - cycle_start
    measurement.success = all(step.success for step in measurement.steps)

    return measurement


def print_results(measurement: CycleMeasurement) -> None:
    """Print measurement results in a formatted table."""
    print()
    print("=" * 70)
    print("Cycle Time Results")
    print("=" * 70)
    print()
    print(f"{'Step':<25} | {'Time':<12} | Status")
    print("-" * 25 + "+" + "-" * 13 + "+" + "-" * 10)

    for step in measurement.steps:
        status = "✓" if step.success else "✗"
        time_str = format_time(step.duration_seconds)
        print(f"{step.name:<25} | {time_str:<12} | {status}")

    print("-" * 25 + "+" + "-" * 13 + "+" + "-" * 10)
    print(f"{'TOTAL':<25} | {format_time(measurement.total_seconds):<12} | ", end="")

    if measurement.total_seconds < measurement.target_seconds:
        print("✓")
    else:
        print("✗")

    print()
    print(f"Target: <{measurement.target_seconds}s per iteration")

    if measurement.total_seconds < measurement.target_seconds:
        margin = measurement.target_seconds - measurement.total_seconds
        print(f"Result: PASS ✓ (under target by {format_time(margin)})")
    else:
        excess = measurement.total_seconds - measurement.target_seconds
        print(f"Result: FAIL ✗ (over target by {format_time(excess)})")

    if measurement.error:
        print()
        print(f"Error: {measurement.error}")

    print("=" * 70)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AutoNetworkPolicy v2.1 - Cycle Time Measurement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/measure_cycle_time.py
    python scripts/measure_cycle_time.py --verbose
    python scripts/measure_cycle_time.py --rules data/generated/acl1_500.nft
    python scripts/measure_cycle_time.py --target 90

Exit Codes:
    0 - Cycle time under target
    1 - Cycle time exceeded target
    2 - Error during measurement
        """,
    )

    parser.add_argument(
        "--rules",
        "-r",
        type=str,
        default="data/generated/acl1_500.nft",
        help="Path to input nftables rules file (default: data/generated/acl1_500.nft)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="/tmp/cycle_test_output.nft",
        help="Path for temporary output file (default: /tmp/cycle_test_output.nft)",
    )

    parser.add_argument(
        "--target",
        "-t",
        type=float,
        default=120.0,
        help="Target cycle time in seconds (default: 120)",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed progress")

    args = parser.parse_args()

    # Resolve paths
    project_root = Path(__file__).parent.parent.resolve()

    # Handle relative paths
    nft_file = Path(args.rules)
    if not nft_file.is_absolute():
        nft_file = project_root / nft_file

    output_file = Path(args.output)

    try:
        measurement = measure_cycle(
            nft_file=nft_file,
            output_file=output_file,
            project_root=project_root,
            target_seconds=args.target,
            verbose=args.verbose,
        )

        print_results(measurement)

        # Determine exit code
        if measurement.error:
            print("\n✗ Measurement failed with errors")
            sys.exit(2)
        elif measurement.total_seconds < measurement.target_seconds:
            print("\n✓ Cycle time under target")
            sys.exit(0)
        else:
            print("\n✗ Cycle time exceeded target")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nMeasurement interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
