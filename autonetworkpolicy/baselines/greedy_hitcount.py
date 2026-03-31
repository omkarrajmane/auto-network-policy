#!/usr/bin/env python3
"""
Greedy hit count baseline optimization algorithm.

This module provides a baseline that sorts rules by expected hit count,
placing frequently hit rules first. This is based on the intuition that
rules matched more often should be checked earlier to improve throughput.

If no hit counts are provided, the algorithm falls back to rule specificity
(more specific rules = higher priority).

Example usage:
    from baselines.greedy_hitcount import optimize
    from data.classbench_to_nft import load_nft_as_rules

    rules = load_nft_as_rules('input.nft')
    hit_counts = {0: 1000, 1: 500, 2: 100}  # rule_index -> hit_count
    optimized = optimize(rules, hit_counts=hit_counts)

CLI usage:
    python baselines/greedy_hitcount.py input.nft output.nft
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import sys
from typing import Optional

from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules, rules_to_nft
from autonetworkpolicy.utils.shadow import remove_shadowed_rules, is_shadowed_by, ip_contains


def optimize(
    rules: list[Rule],
    hit_counts: Optional[dict[int, int]] = None,
    remove_shadowed: bool = True,
) -> list[Rule]:
    """Sort rules by hit count (highest first).

    This greedy algorithm assumes that rules matched more frequently should
    be placed earlier in the ruleset to minimize average lookup time.

    If hit_counts is provided, rules are sorted by hit count (descending).
    If hit_counts is None, rules are sorted by specificity (most specific
    rules first, where specificity is determined by IP prefix length).

    Args:
        rules: List of Rule objects to optimize
        hit_counts: Optional dictionary mapping rule index to expected hit count

    Returns:
        Reordered list of Rule objects sorted by priority

    Example:
        >>> rules = load_nft_as_rules('input.nft')
        >>> hit_counts = {0: 1000, 1: 500}  # Expected hits per rule
        >>> optimized = optimize(rules, hit_counts=hit_counts)
        >>> print(f'Sorted {len(optimized)} rules by hit count')
    """
    if not rules:
        return []

    # Create a copy to avoid modifying the original
    rules_copy = copy.deepcopy(rules)

    if hit_counts:
        # Sort by hit count (highest first)
        sorted_rules = sorted(
            rules_copy,
            key=lambda r: hit_counts.get(r.index, 0),
            reverse=True,
        )
    else:
        # Sort by specificity (most specific first)
        sorted_rules = sorted(
            rules_copy,
            key=_calculate_specificity,
            reverse=True,
        )

    # Remove shadowed rules if requested
    if remove_shadowed:
        sorted_rules = remove_shadowed_rules(sorted_rules)

    # Update indices after sorting
    for idx, rule in enumerate(sorted_rules):
        rule.index = idx

    return sorted_rules


def _calculate_specificity(rule: Rule) -> float:
    """Calculate rule specificity score.

    More specific rules should have higher priority. Specificity is based on:
    - IP prefix lengths (longer prefixes = more specific)
    - Port specificity (specific ports = more specific than ranges)
    - Protocol specificity (specific protocols = more specific than "any")

    Args:
        rule: Rule to calculate specificity for

    Returns:
        Specificity score (higher = more specific)
    """
    score = 0.0

    # IP prefix specificity
    score += _get_prefix_length(rule.src_ip)
    score += _get_prefix_length(rule.dst_ip)

    # Port specificity
    if rule.src_port:
        # Specific port is more specific than no port (any)
        score += 16  # Bonus for having a port restriction
        # Narrower range is more specific
        port_range = rule.src_port[1] - rule.src_port[0]
        score += (65535 - port_range) / 65535 * 16

    if rule.dst_port:
        score += 16  # Bonus for having a port restriction
        port_range = rule.dst_port[1] - rule.dst_port[0]
        score += (65535 - port_range) / 65535 * 16

    # Protocol specificity
    if rule.protocol != 0:  # Not "any" protocol
        score += 8

    return score


def _get_prefix_length(ip_cidr: str) -> float:
    """Get the prefix length from a CIDR notation.

    Longer prefix = more specific network.

    Args:
        ip_cidr: IP in CIDR notation (e.g., "10.0.0.0/8")

    Returns:
        Prefix length as float (0-128 for IPv6, 0-32 for IPv4)
    """
    try:
        network = ipaddress.ip_network(ip_cidr, strict=False)
        return float(network.prefixlen)
    except (ValueError, TypeError):
        return 0.0


def _load_hit_counts(filepath: str) -> dict[int, int]:
    """Load hit counts from a TSV file.

    Expected format (per line):
        rule_index    hit_count

    Args:
        filepath: Path to hit counts file

    Returns:
        Dictionary mapping rule index to hit count

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file format is invalid
    """
    hit_counts = {}

    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                raise ValueError(f"Invalid line {line_num}: expected 2 fields, got {len(parts)}")

            try:
                rule_idx = int(parts[0])
                hit_count = int(parts[1])
                hit_counts[rule_idx] = hit_count
            except ValueError as e:
                raise ValueError(f"Invalid number on line {line_num}: {e}")

    return hit_counts


def main():
    """CLI entry point for greedy hit count baseline."""
    parser = argparse.ArgumentParser(
        description="Greedy hit count baseline for firewall rulesets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Sort by specificity (no hit counts provided)
    %(prog)s input.nft output.nft

    # Sort by provided hit counts
    %(prog)s input.nft output.nft --hit-counts hits.tsv

    # Hit counts file format (one per line):
    #   0    1000
    #   1    500
    #   2    100
        """,
    )

    parser.add_argument("input", type=str, help="Input nftables file")
    parser.add_argument("output", type=str, help="Output nftables file")
    parser.add_argument(
        "--hit-counts",
        type=str,
        metavar="FILE",
        help="TSV file with rule_index and hit_count columns",
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

    # Load hit counts if provided
    hit_counts: Optional[dict[int, int]] = None
    if args.hit_counts:
        try:
            hit_counts = _load_hit_counts(args.hit_counts)
            print(f"Loaded hit counts for {len(hit_counts)} rules")
        except FileNotFoundError:
            print(f"Error: Hit counts file not found: {args.hit_counts}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error loading hit counts: {e}", file=sys.stderr)
            return 1

    # Optimize
    try:
        optimized = optimize(rules, hit_counts=hit_counts)
        print(f"Optimized {len(optimized)} rules")

        if hit_counts:
            print("Sorted by hit count (highest first)")
        else:
            print("Sorted by specificity (most specific first)")
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
