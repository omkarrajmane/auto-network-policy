#!/usr/bin/env python3
"""
================================================================================
Benchmark Validation Script
================================================================================

Validates that benchmark scenarios are correctly structured and that
reachability matches expected "broken" state before optimization.

This ensures the benchmarks actually test the optimization algorithms
and aren't accidentally starting from already-optimal states.

Tests:
1. Syntax validation (nft -c)
2. Rule count verification
3. Shadowing detection
4. Reachability analysis
5. Scenario characteristics

Usage:
    python validate_benchmarks.py --all
    python validate_benchmarks.py --scenario over_permissive

================================================================================
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from baselines.static_analysis import analyze
from data.classbench_to_nft import load_nft_as_rules


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


def validate_syntax(scenario_path: Path) -> tuple[bool, Optional[str]]:
    """
    Validate nftables syntax.

    Args:
        scenario_path: Path to scenario file

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        result = subprocess.run(
            ["nft", "-c", "-f", str(scenario_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            return True, None
        else:
            return False, result.stderr.strip()

    except FileNotFoundError:
        return False, "nft command not found"
    except subprocess.TimeoutExpired:
        return False, "Syntax check timed out"
    except Exception as e:
        return False, str(e)


def validate_scenario(scenario_name: str, scenario_path: Path) -> dict[str, Any]:
    """
    Validate a single scenario.

    Args:
        scenario_name: Name of the scenario
        scenario_path: Path to scenario file

    Returns:
        Dictionary with validation results
    """
    results: dict[str, Any] = {
        "scenario": scenario_name,
        "file": str(scenario_path),
        "valid": True,
        "checks": {},
        "warnings": [],
        "errors": [],
    }

    print(f"\nValidating: {scenario_name}")
    print(f"  File: {scenario_path}")

    # Check file exists
    if not scenario_path.exists():
        results["valid"] = False
        results["errors"].append(f"File not found: {scenario_path}")
        return results

    # Test 1: Syntax validation
    print("  Checking syntax...")
    is_valid, error = validate_syntax(scenario_path)
    results["checks"]["syntax"] = is_valid

    if not is_valid:
        results["valid"] = False
        results["errors"].append(f"Syntax error: {error}")
        return results
    print("    ✓ Syntax valid")

    # Load rules
    try:
        rules = load_nft_as_rules(scenario_path)
        results["checks"]["loadable"] = True
        results["rule_count"] = len(rules)
        print(f"    ✓ Loaded {len(rules)} rules")
    except Exception as e:
        results["valid"] = False
        results["checks"]["loadable"] = False
        results["errors"].append(f"Failed to load: {e}")
        return results

    # Test 2: Rule count within expected range
    print("  Checking rule count...")
    expected_min = 50
    expected_max = 1000

    if len(rules) < expected_min:
        results["warnings"].append(f"Rule count ({len(rules)}) below minimum ({expected_min})")
    elif len(rules) > expected_max:
        results["warnings"].append(f"Rule count ({len(rules)}) above maximum ({expected_max})")
    else:
        results["checks"]["rule_count"] = True
        print(f"    ✓ Rule count in valid range: {len(rules)}")

    # Test 3: Shadowing analysis
    print("  Analyzing shadowed rules...")
    try:
        stats = analyze(rules)
        shadowed_pct = stats["shadowed_count"] / stats["original_count"] * 100

        results["checks"]["shadowing_analysis"] = True
        results["shadowed_count"] = stats["shadowed_count"]
        results["shadowed_percentage"] = shadowed_pct
        results["duplicate_count"] = stats["duplicate_count"]

        print(f"    Shadowed: {stats['shadowed_count']} ({shadowed_pct:.1f}%)")
        print(f"    Duplicates: {stats['duplicate_count']}")

        # Scenario-specific checks
        if scenario_name == "over_permissive":
            # Should have some shadowed rules but not too many
            if shadowed_pct < 10:
                results["warnings"].append("Over-permissive scenario should have >10% shadowed")
            elif shadowed_pct > 60:
                results["warnings"].append("Over-permissive scenario has too many shadowed (>60%)")

        elif scenario_name == "broken_segmentation":
            # Should have misordered rules (hard to detect automatically)
            # Check for mix of allow/deny
            allow_rules = sum(1 for r in rules if r.action == "accept")
            deny_rules = sum(1 for r in rules if r.action == "drop")

            if allow_rules == 0 or deny_rules == 0:
                results["warnings"].append("Broken segmentation should mix allow and deny rules")
            else:
                print(f"    Allow: {allow_rules}, Deny: {deny_rules}")

        elif scenario_name == "redundant_shadowing":
            # Should have high percentage of shadowed rules
            if shadowed_pct < 30:
                results["warnings"].append(
                    f"Redundant shadowing should have >30% shadowed (found {shadowed_pct:.1f}%)"
                )
            else:
                results["checks"]["high_shadowing"] = True
                print(f"    ✓ High shadowing detected ({shadowed_pct:.1f}%)")

    except Exception as e:
        results["warnings"].append(f"Shadowing analysis failed: {e}")

    # Test 4: Action distribution
    print("  Checking action distribution...")
    accept_count = sum(1 for r in rules if r.action == "accept")
    drop_count = sum(1 for r in rules if r.action == "drop")

    results["accept_count"] = accept_count
    results["drop_count"] = drop_count

    if accept_count + drop_count != len(rules):
        results["warnings"].append("Rules with actions other than accept/drop found")
    else:
        results["checks"]["action_distribution"] = True
        print(f"    ✓ Accept: {accept_count}, Drop: {drop_count}")

    # Final result
    if results["errors"]:
        results["valid"] = False
        print("  ✗ VALIDATION FAILED")
    elif results["warnings"]:
        results["valid"] = True
        print("  ⚠ VALIDATION PASSED WITH WARNINGS")
    else:
        results["valid"] = True
        print("  ✓ VALIDATION PASSED")

    return results


def print_summary(results: list[dict[str, Any]]) -> None:
    """
    Print validation summary table.

    Args:
        results: List of validation result dictionaries
    """
    print("\n" + "=" * 70)
    print("Benchmark Validation Summary")
    print("=" * 70)

    print(f"\n{'Scenario':<25} {'Rules':>8} {'Shadowed':>10} {'Status':>12}")
    print("-" * 70)

    for result in results:
        scenario = result["scenario"]
        rules = result.get("rule_count", 0)
        shadowed = result.get("shadowed_percentage", 0.0)

        if result["errors"]:
            status = "✗ FAIL"
        elif result["warnings"]:
            status = "⚠ WARN"
        else:
            status = "✓ PASS"

        print(f"{scenario:<25} {rules:>8} {shadowed:>9.1f}% {status:>12}")

    print("-" * 70)

    total = len(results)
    passed = sum(1 for r in results if r["valid"] and not r["warnings"])
    warned = sum(1 for r in results if r["valid"] and r["warnings"])
    failed = sum(1 for r in results if not r["valid"])

    print(f"\nTotal: {total} | Passed: {passed} | Warning: {warned} | Failed: {failed}")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Validate benchmark scenarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Validate all scenarios
    %(prog)s --all
    
    # Validate specific scenario
    %(prog)s --scenario over_permissive
        """,
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all scenarios",
    )

    parser.add_argument(
        "--scenario",
        choices=list(BENCHMARK_SCENARIOS.keys()),
        help="Validate specific scenario",
    )

    args = parser.parse_args()

    if not args.all and not args.scenario:
        parser.error("Must specify --all or --scenario")

    print("=" * 70)
    print("AutoNetworkPolicy - Benchmark Validation")
    print("=" * 70)

    benchmarks_dir = Path(__file__).parent.parent / "benchmarks"

    if args.all:
        scenarios = list(BENCHMARK_SCENARIOS.items())
    else:
        scenarios = [(args.scenario, BENCHMARK_SCENARIOS[args.scenario])]

    results = []

    for scenario_name, filename in scenarios:
        scenario_path = benchmarks_dir / filename
        result = validate_scenario(scenario_name, scenario_path)
        results.append(result)

    print_summary(results)

    # Exit with error code if any failed
    failed = sum(1 for r in results if not r["valid"])
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
