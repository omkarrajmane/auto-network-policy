"""Tests for the match_depth module.

These tests verify that compute_match_depth correctly calculates
the average depth at which packets match rules in a ruleset.
"""

import pytest

from autonetworkpolicy.data.classbench_to_nft import Rule
from autonetworkpolicy.evaluate.match_depth import compute_match_depth


def test_catch_all_first_gives_zero_depth():
    """A catch-all rule at index 0 should match all packets immediately."""
    # Catch-all rule matches everything
    rules = [Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 0)]
    depth = compute_match_depth(rules, n_samples=100, seed=42)
    assert depth == 0.0


def test_no_matching_rules_gives_max_depth():
    """Rules that match nothing should result in depth = len(rules)."""
    # Very specific IPs that won't match random packets
    rules = [
        Rule("255.255.255.255/32", "255.255.255.255/32", None, None, 0, "accept", 0),
        Rule("255.255.255.254/32", "255.255.255.254/32", None, None, 0, "accept", 1),
        Rule("255.255.255.253/32", "255.255.255.253/32", None, None, 0, "accept", 2),
    ]
    depth = compute_match_depth(rules, n_samples=100, seed=42)
    # Since random IPs almost never match these specific addresses,
    # depth should be approximately len(rules) = 3.0
    assert depth == pytest.approx(3.0, abs=0.01)


def test_specific_before_broad_different_depth():
    """Different orderings produce different depths."""
    # Order 1: Specific first, then broad
    rules_specific_first = [
        Rule("192.168.1.0/24", "10.0.0.0/8", None, None, 0, "accept", 0),
        Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 1),
    ]

    # Order 2: Broad first, then specific
    rules_broad_first = [
        Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 0),
        Rule("192.168.1.0/24", "10.0.0.0/8", None, None, 0, "accept", 1),
    ]

    depth_specific_first = compute_match_depth(rules_specific_first, n_samples=500, seed=42)
    depth_broad_first = compute_match_depth(rules_broad_first, n_samples=500, seed=42)

    # Broad-first matches everything at index 0 (depth = 0.0)
    # Specific-first matches some at index 0, others at index 1 (depth > 0.0)
    assert depth_broad_first == 0.0
    assert depth_specific_first > depth_broad_first
    assert 0.0 < depth_specific_first <= 1.0


def test_deterministic_with_seed():
    """Same seed should produce the same result."""
    rules = [
        Rule("192.168.0.0/16", "10.0.0.0/8", None, None, 0, "accept", 0),
        Rule("172.16.0.0/12", "192.168.0.0/16", None, None, 0, "accept", 1),
        Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 2),
    ]

    depth1 = compute_match_depth(rules, n_samples=100, seed=42)
    depth2 = compute_match_depth(rules, n_samples=100, seed=42)

    # Same seed should give identical results
    assert depth1 == depth2


def test_empty_ruleset():
    """Empty ruleset should return depth of 0.0."""
    rules = []
    depth = compute_match_depth(rules, n_samples=100, seed=42)
    assert depth == 0.0
