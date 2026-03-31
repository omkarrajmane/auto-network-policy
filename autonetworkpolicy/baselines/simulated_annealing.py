#!/usr/bin/env python3
"""
Simulated annealing baseline optimization algorithm.

This module implements a simulated annealing metaheuristic for finding
optimal rule ordering. Simulated annealing is a probabilistic technique
for approximating the global optimum of a given function.

The algorithm:
1. Starts with an initial solution
2. Generates neighboring solutions via swap mutations
3. Accepts better solutions always
4. Accepts worse solutions with decreasing probability (temperature schedule)
5. Returns best solution found

Example usage:
    from baselines.simulated_annealing import optimize
    from data.classbench_to_nft import load_nft_as_rules

    rules = load_nft_as_rules('input.nft')

    def evaluate(rules):
        # Return throughput or other metric (higher is better)
        return run_evaluation(rules)

    optimized = optimize(rules, evaluate_fn=evaluate, max_iterations=100)

CLI usage:
    python baselines/simulated_annealing.py input.nft output.nft --iterations 100
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import math
import random
import sys
from typing import Callable, Optional, cast

from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules, rules_to_nft
from autonetworkpolicy.utils.shadow import remove_shadowed_rules, is_shadowed_by, ip_contains


def optimize(
    rules: list[Rule],
    evaluate_fn: Optional[Callable[[list[Rule]], float]] = None,
    max_iterations: int = 100,
    initial_temperature: float = 100.0,
    cooling_rate: float = 0.95,
    seed: Optional[int] = None,
) -> list[Rule]:
    """Simulated annealing to find optimal rule order.

    This metaheuristic searches for better rule orderings by generating
    neighbors via swap mutations and accepting them based on a temperature
    schedule. Better solutions are always accepted, worse solutions may be
    accepted early in the search.

    Args:
        rules: List of Rule objects to optimize
        evaluate_fn: Function to evaluate a ruleset (higher is better)
        max_iterations: Maximum number of iterations to run
        initial_temperature: Starting temperature for annealing schedule
        cooling_rate: Temperature multiplier per iteration (0-1)
        seed: Optional random seed for reproducibility

    Returns:
        Best ruleset found during the search

    Raises:
        ValueError: If no evaluate_fn is provided and max_iterations > 0

    Example:
        >>> rules = load_nft_as_rules('input.nft')
        >>> def throughput(rules):
        ...     return run_iperf3_test(rules)
        >>> optimized = optimize(rules, evaluate_fn=throughput, max_iterations=100)
    """
    if not rules:
        return []

    if max_iterations > 0 and evaluate_fn is None:
        raise ValueError("evaluate_fn is required when max_iterations > 0")

    if seed is not None:
        random.seed(seed)

    # Initialize with a copy of the input rules
    current_solution = copy.deepcopy(rules)
    for idx, rule in enumerate(current_solution):
        rule.index = idx

    best_solution = copy.deepcopy(current_solution)
    current_temperature = initial_temperature

    # Evaluate initial solution
    try:
        if evaluate_fn is not None:
            current_score = evaluate_fn(current_solution)
        else:
            current_score = 0.0
        best_score = current_score
    except Exception:
        # If evaluation fails, return original rules
        return rules

    # Simulated annealing loop
    for iteration in range(max_iterations):
        # Generate neighbor via swap mutation
        neighbor = _generate_neighbor(current_solution)

        # Evaluate neighbor
        try:
            if evaluate_fn is not None:
                neighbor_score = evaluate_fn(neighbor)
            else:
                neighbor_score = 0.0
        except Exception:
            # Skip this iteration on evaluation failure
            continue

        # Calculate acceptance probability
        delta = neighbor_score - current_score

        if delta > 0:
            # Better solution - always accept
            current_solution = neighbor
            current_score = neighbor_score

            # Update best if improved
            if neighbor_score > best_score:
                best_solution = copy.deepcopy(neighbor)
                best_score = neighbor_score
        else:
            # Worse solution - accept with probability based on temperature
            if current_temperature > 0:
                acceptance_prob = math.exp(delta / current_temperature)
                if random.random() < acceptance_prob:
                    current_solution = neighbor
                    current_score = neighbor_score

        # Cool down
        current_temperature *= cooling_rate

    return best_solution


def _generate_neighbor(rules: list[Rule]) -> list[Rule]:
    """Generate a neighboring solution via swap mutation.

    Creates a new ruleset by swapping two randomly selected rules.
    With 40% probability, also removes shadowed rules to allow rule count reduction.

    Args:
        rules: Current ruleset

    Returns:
        New ruleset - swapped only (60%) or swapped + shadow-removed (40%)
    """
    if len(rules) < 2:
        return copy.deepcopy(rules)

    neighbor = copy.deepcopy(rules)

    # Select two distinct indices to swap
    i, j = random.sample(range(len(neighbor)), 2)

    # Swap rules
    neighbor[i], neighbor[j] = neighbor[j], neighbor[i]

    for idx, rule in enumerate(neighbor):
        rule.index = idx

    if random.random() < 0.4:
        neighbor = remove_shadowed_rules(neighbor)
        for idx, rule in enumerate(neighbor):
            rule.index = idx

    return neighbor


def _simple_evaluate(rules: list[Rule]) -> float:
    """Simple evaluation function based on rule ordering heuristics.

    This is a fallback evaluation that doesn't require running actual
    traffic tests. It uses heuristics like:
    - Prefer shorter average match time (more specific rules first)
    - Prefer fewer total rules

    Args:
        rules: Ruleset to evaluate

    Returns:
        Heuristic score (higher is better)
    """
    import ipaddress

    if not rules:
        return 0.0

    # Calculate average specificity (higher = more specific rules first)
    total_specificity = 0.0

    for rule in rules:
        specificity = 0.0

        # IP prefix lengths
        try:
            src_net = ipaddress.ip_network(rule.src_ip, strict=False)
            dst_net = ipaddress.ip_network(rule.dst_ip, strict=False)
            specificity += src_net.prefixlen + dst_net.prefixlen
        except (ValueError, TypeError):
            pass

        # Port specificity
        if rule.src_port:
            specificity += 1.0
        if rule.dst_port:
            specificity += 1.0

        # Protocol specificity
        if rule.protocol != 0:
            specificity += 0.5

        total_specificity += specificity

    avg_specificity = total_specificity / len(rules)

    # Prefer rulesets with higher specificity and fewer rules
    # This is a simplified heuristic - real evaluation would measure throughput
    score = avg_specificity - (len(rules) * 0.01)

    return score


def main():
    """CLI entry point for simulated annealing baseline."""
    parser = argparse.ArgumentParser(
        description="Simulated annealing baseline for firewall rulesets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic optimization with default parameters
    %(prog)s input.nft output.nft

    # With custom iterations
    %(prog)s input.nft output.nft --iterations 200

    # With custom temperature schedule
    %(prog)s input.nft output.nft --temperature 200 --cooling 0.98

    # With fixed seed for reproducibility
    %(prog)s input.nft output.nft --seed 42

    # Using simple heuristic evaluation (no traffic test)
    %(prog)s input.nft output.nft --heuristic
        """,
    )

    parser.add_argument("input", type=str, help="Input nftables file")
    parser.add_argument("output", type=str, help="Output nftables file")
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Maximum number of iterations (default: 100)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=100.0,
        help="Initial temperature (default: 100.0)",
    )
    parser.add_argument(
        "--cooling",
        type=float,
        default=0.95,
        help="Cooling rate per iteration (default: 0.95)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--heuristic",
        action="store_true",
        help="Use simple heuristic evaluation instead of traffic tests",
    )

    args = parser.parse_args()

    # Validate cooling rate
    if args.cooling <= 0 or args.cooling >= 1:
        print("Error: Cooling rate must be between 0 and 1", file=sys.stderr)
        return 1

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

    # Select evaluation function
    evaluate_fn = _simple_evaluate if args.heuristic else None

    if not args.heuristic:
        print("Note: No evaluate_fn provided, using simple heuristic")
        evaluate_fn = _simple_evaluate

    # Optimize
    try:
        print(f"Running simulated annealing ({args.iterations} iterations)...")
        optimized = optimize(
            rules,
            evaluate_fn=evaluate_fn,
            max_iterations=args.iterations,
            initial_temperature=args.temperature,
            cooling_rate=args.cooling,
            seed=args.seed,
        )
        print(f"Optimized {len(optimized)} rules")
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
