#!/usr/bin/env python3
"""
Static analysis baseline optimization algorithm.

This module provides static analysis to remove redundant and shadowed rules
from a firewall ruleset without requiring runtime evaluation. This is useful
for cleaning up obviously unnecessary rules before applying other optimizations.

Operations performed:
- Remove exact duplicate rules
- Remove shadowed rules (IP-only check for v1)
- Detect and remove redundant rules

Example usage:
    from baselines.static_analysis import optimize
    from data.classbench_to_nft import load_nft_as_rules

    rules = load_nft_as_rules('input.nft')
    optimized = optimize(rules)
    print(f'Removed {len(rules) - len(optimized)} redundant rules')

CLI usage:
    python baselines/static_analysis.py input.nft output.nft
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import sys

from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules, rules_to_nft
from autonetworkpolicy.utils.shadow import remove_shadowed_rules, is_shadowed_by, ip_contains


def optimize(
    rules: list[Rule],
    remove_duplicates: bool = True,
    remove_shadowed: bool = True,
) -> list[Rule]:
    """Remove redundant and shadowed rules via static analysis.

    This baseline performs static analysis on the ruleset to identify and
    remove rules that are redundant or shadowed by other rules. It does not
    require runtime evaluation.

    Operations (in order):
    1. Remove exact duplicate rules
    2. Remove shadowed rules (rules that can never be matched)

    Args:
        rules: List of Rule objects to optimize
        remove_duplicates: If True, remove exact duplicate rules
        remove_shadowed: If True, remove shadowed rules

    Returns:
        Optimized list of Rule objects with redundancies removed

    Example:
        >>> rules = load_nft_as_rules('input.nft')
        >>> optimized = optimize(rules)
        >>> print(f'Removed {len(rules) - len(optimized)} redundant rules')
    """
    if not rules:
        return []

    # Create a copy to avoid modifying the original
    result = copy.deepcopy(rules)

    # Step 1: Remove exact duplicates
    if remove_duplicates:
        result = _remove_duplicates(result)

    # Step 2: Remove shadowed rules
    if remove_shadowed:
        result = remove_shadowed_rules(result)

    # Update indices
    for idx, rule in enumerate(result):
        rule.index = idx

    return result


def _remove_duplicates(rules: list[Rule]) -> list[Rule]:
    """Remove exact duplicate rules.

    Two rules are considered duplicates if they have identical:
    - Source IP
    - Destination IP
    - Source port
    - Destination port
    - Protocol
    - Action

    Args:
        rules: List of Rule objects

    Returns:
        List of Rule objects with duplicates removed
    """
    seen: set[tuple[str, str, tuple[int, int] | None, tuple[int, int] | None, int, str]] = set()
    unique_rules = []

    for rule in rules:
        key = (
            rule.src_ip,
            rule.dst_ip,
            rule.src_port,
            rule.dst_port,
            rule.protocol,
            rule.action,
        )

        if key not in seen:
            seen.add(key)
            unique_rules.append(rule)

    return unique_rules


def optimize_fixpoint(
    rules: list[Rule],
    remove_duplicates: bool = True,
    max_passes: int = 100,
) -> list[Rule]:
    """Iterative fixpoint shadow removal with cross-action detection.

    Repeats duplicate + shadow removal (including cross-action shadows
    like accept hidden behind drop) until the ruleset converges.

    Args:
        rules: List of Rule objects to optimize.
        remove_duplicates: If True, remove exact duplicates on each pass.
        max_passes: Safety limit to prevent infinite loops.

    Returns:
        Optimized list of Rule objects after fixpoint convergence.
    """
    if not rules:
        return []

    import copy as _cp

    result = _cp.deepcopy(rules)

    for _ in range(max_passes):
        before_len = len(result)

        if remove_duplicates:
            result = _remove_duplicates(result)

        result = remove_shadowed_rules(result, cross_action=True)

        if len(result) == before_len:
            break

    for idx, rule in enumerate(result):
        rule.index = idx

    return result


def analyze(rules: list[Rule]) -> dict[str, int]:
    """Analyze ruleset and return statistics.

    This function performs the optimization but returns detailed statistics
    about what was removed instead of the optimized ruleset.

    Args:
        rules: List of Rule objects to analyze

    Returns:
        Dictionary with analysis results:
        {
            'original_count': int,
            'duplicate_count': int,
            'shadowed_count': int,
            'final_count': int,
            'removed_count': int,
        }
    """
    if not rules:
        return {
            "original_count": 0,
            "duplicate_count": 0,
            "shadowed_count": 0,
            "final_count": 0,
            "removed_count": 0,
        }

    original_count = len(rules)

    # Count duplicates
    seen: set[tuple[str, str, tuple[int, int] | None, tuple[int, int] | None, int, str]] = set()
    duplicate_count = 0

    for rule in rules:
        key = (
            rule.src_ip,
            rule.dst_ip,
            rule.src_port,
            rule.dst_port,
            rule.protocol,
            rule.action,
        )

        if key in seen:
            duplicate_count += 1
        else:
            seen.add(key)

    # Count shadowed (after removing duplicates)
    rules_copy = _remove_duplicates(copy.deepcopy(rules))

    filtered = []
    shadowed_count = 0

    for rule in rules_copy:
        is_shadowed = False

        for existing in filtered:
            if is_shadowed_by(rule, existing):
                is_shadowed = True
                break

        if is_shadowed:
            shadowed_count += 1
        else:
            filtered.append(rule)

    final_count = len(filtered)
    removed_count = original_count - final_count

    return {
        "original_count": original_count,
        "duplicate_count": duplicate_count,
        "shadowed_count": shadowed_count,
        "final_count": final_count,
        "removed_count": removed_count,
    }


def main():
    """CLI entry point for static analysis baseline."""
    parser = argparse.ArgumentParser(
        description="Static analysis baseline for firewall rulesets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic optimization (remove duplicates and shadowed)
    %(prog)s input.nft output.nft

    # Only remove duplicates
    %(prog)s input.nft output.nft --no-remove-shadowed

    # Only remove shadowed rules
    %(prog)s input.nft output.nft --no-remove-duplicates

    # Just analyze and show statistics
    %(prog)s input.nft --analyze
        """,
    )

    parser.add_argument("input", type=str, help="Input nftables file")
    parser.add_argument(
        "output",
        type=str,
        nargs="?",
        help="Output nftables file (optional if using --analyze)",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Only analyze, don't write output",
    )
    parser.add_argument(
        "--no-remove-duplicates",
        action="store_true",
        help="Skip duplicate removal",
    )
    parser.add_argument(
        "--no-remove-shadowed",
        action="store_true",
        help="Skip shadowed rule removal",
    )

    args = parser.parse_args()

    # Load rules
    try:
        rules = load_nft_as_rules(args.input)
        print(f"Loaded {len(rules)} rules from {args.input}")
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading rules: {e}", file=sys.stderr)
        return 1

    if not rules:
        print("Error: No rules loaded from input file", file=sys.stderr)
        return 1

    # Analyze mode
    if args.analyze:
        stats = analyze(rules)
        print("\nStatic Analysis Results:")
        print("=" * 40)
        print(f"Original rules:   {stats['original_count']}")
        print(f"Duplicate rules:  {stats['duplicate_count']}")
        print(f"Shadowed rules:   {stats['shadowed_count']}")
        print(f"Final rules:      {stats['final_count']}")
        print(f"Removed:          {stats['removed_count']}")
        return 0

    # Require output file for optimization mode
    if not args.output:
        print("Error: Output file required (unless using --analyze)", file=sys.stderr)
        return 1

    # Optimize
    try:
        optimized = optimize(
            rules,
            remove_duplicates=not args.no_remove_duplicates,
            remove_shadowed=not args.no_remove_shadowed,
        )

        removed = len(rules) - len(optimized)
        print(f"Removed {removed} redundant rules ({len(optimized)} remaining)")
    except Exception as e:
        print(f"Error during optimization: {e}", file=sys.stderr)
        return 1

    # Write output
    try:
        nft_output = rules_to_nft(optimized)
        with open(args.output, "w") as f:
            f.write(nft_output)
        print(f"Written optimized rules to {args.output}")
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
