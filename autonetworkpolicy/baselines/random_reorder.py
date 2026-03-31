#!/usr/bin/env python3
"""
Random reorder baseline optimization algorithm.

This module provides a simple baseline that randomly shuffles rules and optionally
removes shadowed rules. It can be used with an evaluation function to find better
rule orderings through random search.

Example usage:
    from baselines.random_reorder import optimize
    from data.classbench_to_nft import load_nft_as_rules

    rules = load_nft_as_rules('input.nft')
    optimized = optimize(rules, iterations=10)

CLI usage:
    python baselines/random_reorder.py input.nft output.nft --iterations 10
"""

from __future__ import annotations

import argparse
import copy
import random
import sys
from typing import Callable, Optional

from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules, rules_to_nft
from autonetworkpolicy.utils.shadow import remove_shadowed_rules, is_shadowed_by, ip_contains


def optimize(
    rules: list[Rule],
    iterations: int = 10,
    evaluate_fn: Optional[Callable[[list[Rule]], float]] = None,
    remove_shadowed: bool = False,
    seed: Optional[int] = None,
) -> list[Rule]:
    """Randomly reorder rules, keep best performing variant.

    This baseline shuffles rules randomly for a specified number of iterations
    and returns the best performing variant. If no evaluation function is
    provided, returns the result of the first shuffle.

    Args:
        rules: List of Rule objects to optimize
        iterations: Number of random shuffles to try
        evaluate_fn: Optional function to evaluate a ruleset (higher is better)
        remove_shadowed: If True, also try removing shadowed rules
        seed: Optional random seed for reproducibility

    Returns:
        Best performing ruleset found

    Example:
        >>> rules = load_nft_as_rules('input.nft')
        >>> optimized = optimize(rules, iterations=10)
        >>> print(f'Optimized {len(optimized)} rules')
    """
    if not rules:
        return []

    if seed is not None:
        random.seed(seed)

    best_rules = copy.deepcopy(rules)
    best_score = float("-inf")

    # Try the original order first if we have an evaluator
    if evaluate_fn:
        try:
            best_score = evaluate_fn(best_rules)
        except Exception:
            best_score = float("-inf")

    for i in range(iterations):
        # Create a copy and shuffle
        candidate = copy.deepcopy(rules)
        random.shuffle(candidate)

        # Update indices after shuffle
        for idx, rule in enumerate(candidate):
            rule.index = idx

        # Optionally remove shadowed rules
        if remove_shadowed:
            candidate = remove_shadowed_rules(candidate)

        # Evaluate if we have a function
        if evaluate_fn:
            try:
                score = evaluate_fn(candidate)
                if score > best_score:
                    best_score = score
                    best_rules = candidate
            except Exception:
                # Skip this iteration on evaluation failure
                continue
        else:
            # Without evaluation, just return first shuffle
            return candidate

    return best_rules


def main():
    """CLI entry point for random reorder baseline."""
    parser = argparse.ArgumentParser(
        description="Random reorder baseline for firewall rulesets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic random shuffle
    %(prog)s input.nft output.nft

    # Try 10 random shuffles and keep best
    %(prog)s input.nft output.nft --iterations 10

    # With shadowed rule removal
    %(prog)s input.nft output.nft --remove-shadowed

    # With fixed seed for reproducibility
    %(prog)s input.nft output.nft --seed 42
        """,
    )

    parser.add_argument("input", type=str, help="Input nftables file")
    parser.add_argument("output", type=str, help="Output nftables file")
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of random shuffles to try (default: 10)",
    )
    parser.add_argument(
        "--remove-shadowed",
        action="store_true",
        help="Also remove shadowed rules",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducibility",
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

    # Optimize
    try:
        optimized = optimize(
            rules,
            iterations=args.iterations,
            remove_shadowed=args.remove_shadowed,
            seed=args.seed,
        )
        print(f"Optimized to {len(optimized)} rules")
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
