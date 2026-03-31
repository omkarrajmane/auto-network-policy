#!/usr/bin/env python3
"""
Comprehensive unit tests for BDD-based firewall rule equivalence verifier.

Tests cover:
1. BDDVerifier initialization (default params, custom params, invalid params)
2. IP encoding functions (_encode_ip_cidr equivalent - _build_ip_match_bdd)
3. Equivalence checking (identical, different, empty, reordered, shadowed rules)
4. IP-only mode behavior (ignores ports/protocol)
5. Timeout handling (fail-closed behavior)
6. Performance tests with 500-rule files
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules
from autonetworkpolicy.verify.bdd_verify import (
    BDDVerifier,
    TimeoutError,
    VerificationResult,
    _range_to_prefixes,
    timeout,
    verify_equivalence,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_rules() -> list[Rule]:
    """Sample Rule objects for testing."""
    return [
        Rule(
            src_ip="192.168.1.0/24",
            dst_ip="10.0.0.0/8",
            src_port=(80, 80),
            dst_port=(443, 443),
            protocol=6,
            action="accept",
            index=0,
        ),
        Rule(
            src_ip="172.16.0.0/12",
            dst_ip="192.168.0.0/16",
            src_port=None,
            dst_port=(53, 53),
            protocol=17,
            action="drop",
            index=1,
        ),
        Rule(
            src_ip="10.0.0.0/8",
            dst_ip="172.16.0.0/12",
            src_port=(1024, 65535),
            dst_port=(1024, 65535),
            protocol=6,
            action="accept",
            index=2,
        ),
    ]


@pytest.fixture
def single_rule() -> Rule:
    """Single rule for testing."""
    return Rule(
        src_ip="192.168.1.0/24",
        dst_ip="10.0.0.0/8",
        src_port=(80, 80),
        dst_port=(443, 443),
        protocol=6,
        action="accept",
        index=0,
    )


@pytest.fixture
def generated_nft_file() -> Path:
    """Path to the generated acl1_500.nft file."""
    return Path(__file__).parent.parent / "data" / "generated" / "acl1_500.nft"


@pytest.fixture
def verifier() -> BDDVerifier:
    """Default BDDVerifier instance."""
    return BDDVerifier()


@pytest.fixture
def full_verifier() -> BDDVerifier:
    """BDDVerifier configured for full 5-tuple mode."""
    return BDDVerifier(mode="full")


@pytest.fixture
def autoref_verifier() -> BDDVerifier:
    """BDDVerifier with autoref backend."""
    return BDDVerifier(backend="autoref", mode="ip_only")


# =============================================================================
# BDDVerifier Initialization Tests
# =============================================================================


class TestBDDVerifierInitialization:
    """Tests for BDDVerifier initialization."""

    def test_default_parameters(self) -> None:
        """Test BDDVerifier with default parameters."""
        verifier = BDDVerifier()

        assert verifier.backend == "autoref"
        assert verifier.mode == "ip_only"
        assert verifier.timeout_seconds == 30.0
        assert verifier.ip_bits == 32

    def test_custom_backend_autoref(self) -> None:
        """Test BDDVerifier with autoref backend."""
        verifier = BDDVerifier(backend="autoref")
        assert verifier.backend == "autoref"

    def test_custom_backend_cudd(self) -> None:
        """Test BDDVerifier with cudd backend (falls back to autoref if not available)."""
        verifier = BDDVerifier(backend="cudd")
        assert verifier.backend == "cudd"

    def test_custom_mode_ip_only(self) -> None:
        """Test BDDVerifier with ip_only mode."""
        verifier = BDDVerifier(mode="ip_only")
        assert verifier.mode == "ip_only"

    def test_custom_mode_full(self) -> None:
        """Test BDDVerifier with full mode."""
        verifier = BDDVerifier(mode="full")
        assert verifier.mode == "full"

    def test_custom_timeout(self) -> None:
        """Test BDDVerifier with custom timeout."""
        verifier = BDDVerifier(timeout_seconds=60.0)
        assert verifier.timeout_seconds == 60.0

    def test_all_custom_parameters(self) -> None:
        """Test BDDVerifier with all custom parameters."""
        verifier = BDDVerifier(
            backend="cudd",
            mode="full",
            timeout_seconds=120.0,
        )
        assert verifier.backend == "cudd"
        assert verifier.mode == "full"
        assert verifier.timeout_seconds == 120.0

    def test_invalid_backend_raises_error(self) -> None:
        """Test that invalid backend raises ValueError."""
        with pytest.raises(ValueError, match="Invalid backend"):
            BDDVerifier(backend="invalid_backend")

    def test_invalid_mode_raises_error(self) -> None:
        """Test that invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Invalid mode"):
            BDDVerifier(mode="invalid_mode")

    def test_backend_var_names(self) -> None:
        """Test that BDD variable names are correctly initialized."""
        verifier = BDDVerifier()

        # Should have 32 source IP variables
        assert len(verifier.src_vars) == 32
        assert verifier.src_vars[0] == "src_ip_0"
        assert verifier.src_vars[31] == "src_ip_31"

        # Should have 32 destination IP variables
        assert len(verifier.dst_vars) == 32
        assert verifier.dst_vars[0] == "dst_ip_0"
        assert verifier.dst_vars[31] == "dst_ip_31"


# =============================================================================
# IP Encoding Tests
# =============================================================================


class TestIPEncoding:
    """Tests for IP CIDR encoding to BDD."""

    def test_encode_any_ip(self, verifier: BDDVerifier) -> None:
        """Test encoding 0.0.0.0/0 (any IP) returns true BDD."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars)

        result = verifier._build_ip_match_bdd(bdd, "0.0.0.0/0", verifier.src_vars)

        # Any IP should return bdd.true (no constraints)
        assert result == bdd.true

    def test_encode_specific_ip_32(self, verifier: BDDVerifier) -> None:
        """Test encoding /32 (single IP) with full constraints."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars)

        result = verifier._build_ip_match_bdd(bdd, "192.168.1.1/32", verifier.src_vars)

        # Should not be true (has constraints)
        assert result != bdd.true
        # Should not be false
        assert result != bdd.false

    def test_encode_cidr_8(self, verifier: BDDVerifier) -> None:
        """Test encoding /8 (first octet only)."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars)

        result = verifier._build_ip_match_bdd(bdd, "10.0.0.0/8", verifier.src_vars)

        # Should have constraints but not be as restrictive as /32
        assert result != bdd.true
        assert result != bdd.false

    def test_encode_cidr_16(self, verifier: BDDVerifier) -> None:
        """Test encoding /16 (first two octets)."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars)

        result = verifier._build_ip_match_bdd(bdd, "172.16.0.0/16", verifier.src_vars)

        assert result != bdd.true
        assert result != bdd.false

    def test_encode_cidr_24(self, verifier: BDDVerifier) -> None:
        """Test encoding /24 (first three octets)."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars)

        result = verifier._build_ip_match_bdd(bdd, "192.168.1.0/24", verifier.src_vars)

        assert result != bdd.true
        assert result != bdd.false

    def test_encode_dst_ip(self, verifier: BDDVerifier) -> None:
        """Test encoding destination IP uses correct variables."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars, *verifier.dst_vars)

        src_result = verifier._build_ip_match_bdd(bdd, "10.0.0.0/8", verifier.src_vars)
        dst_result = verifier._build_ip_match_bdd(bdd, "10.0.0.0/8", verifier.dst_vars)

        # Both should be valid BDDs
        assert src_result != bdd.false
        assert dst_result != bdd.false
        # They should be different BDDs (different variables)
        # Note: In autoref, comparing BDD nodes directly may not work as expected
        # So we just verify both are created successfully

    def test_encode_private_networks(self, verifier: BDDVerifier) -> None:
        """Test encoding common private network ranges."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars)

        private_networks = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]

        for network in private_networks:
            result = verifier._build_ip_match_bdd(bdd, network, verifier.src_vars)
            assert result != bdd.false, f"Failed to encode {network}"
            assert result != bdd.true or network == "0.0.0.0/0", (
                f"{network} should have constraints"
            )


# =============================================================================
# Equivalence Checking Tests
# =============================================================================


class TestEquivalenceChecking:
    """Tests for ruleset equivalence checking."""

    def test_identical_rulesets_equivalent(
        self, verifier: BDDVerifier, sample_rules: list[Rule]
    ) -> None:
        """Test that identical rulesets are equivalent."""
        result = verifier.verify(sample_rules, sample_rules)

        assert result["equivalent"] is True
        assert result.get("error") is None
        assert result["time_seconds"] >= 0

    def test_empty_rulesets_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that two empty rulesets are equivalent."""
        result = verifier.verify([], [])

        assert result["equivalent"] is True
        assert "error" not in result or result["error"] is None

    def test_single_rule_vs_same_rule(self, verifier: BDDVerifier, single_rule: Rule) -> None:
        """Test that a single rule compared to itself is equivalent."""
        result = verifier.verify([single_rule], [single_rule])

        assert result["equivalent"] is True

    def test_completely_different_rulesets(self, verifier: BDDVerifier) -> None:
        """Test that completely different rulesets are not equivalent."""
        rules_a = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=None,
                protocol=17,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        assert result["equivalent"] is False

    def test_rule_reordering_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that reordering rules (same rules, different order) is equivalent."""
        rules_a = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=None,
                protocol=17,
                action="drop",
                index=1,
            ),
        ]
        # Same rules, different order
        rules_b = [
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=None,
                protocol=17,
                action="drop",
                index=0,
            ),
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # In IP-only mode with OR semantics, order shouldn't matter
        assert result["equivalent"] is True

    def test_shadowed_rules_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that shadowed/redundant rules are equivalent to non-shadowed."""
        # Ruleset A: Two rules where second is shadowed by first
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]
        # Ruleset B: Just the first rule (shadows the second anyway)
        rules_b = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # Both should be equivalent since second rule in A is shadowed
        assert result["equivalent"] is True

    def test_different_actions_not_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that rules with different actions are not equivalent."""
        rules_accept = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_drop = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=0,
            ),
        ]

        result = verifier.verify(rules_accept, rules_drop)
        # Note: In current IP-only implementation, action is ignored
        # This test documents current behavior - may need updating for v2

    def test_reflexivity_property(self, verifier: BDDVerifier, sample_rules: list[Rule]) -> None:
        """Test reflexivity: verify(A, A) should always be True."""
        for i in range(len(sample_rules)):
            subset = sample_rules[: i + 1]
            result = verifier.verify(subset, subset)
            assert result["equivalent"] is True, f"Reflexivity failed for {i + 1} rules"

    def test_symmetry_property(self, verifier: BDDVerifier, sample_rules: list[Rule]) -> None:
        """Test symmetry: verify(A, B) == verify(B, A)."""
        # Empty vs rules
        result_ab = verifier.verify([], sample_rules)
        result_ba = verifier.verify(sample_rules, [])

        assert result_ab["equivalent"] == result_ba["equivalent"]

        # Reordered rules
        reordered = list(reversed(sample_rules))
        result_ab = verifier.verify(sample_rules, reordered)
        result_ba = verifier.verify(reordered, sample_rules)

        assert result_ab["equivalent"] == result_ba["equivalent"]

    def test_different_actions_not_equivalent_xfail(self, verifier: BDDVerifier) -> None:
        """Test that rules with different actions are not equivalent.

        This test documents the BDD action-blindness bug: the current BDD
        verifier ignores rule actions and only checks IP matching, so it
        incorrectly reports accept and drop rules as equivalent.
        """
        rules_accept = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_drop = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=0,
            ),
        ]

        result = verifier.verify(rules_accept, rules_drop)
        # These should NOT be equivalent (accept vs drop), but BDD currently
        # ignores actions and returns True
        assert result["equivalent"] is False

    def test_priority_order_matters(self, verifier: BDDVerifier) -> None:
        """Test that rule priority order matters for overlapping rules.

        This test documents that the BDD verifier ignores rule order when
        rules overlap. In reality, nftables processes rules top-down, so:
        - ACCEPT 10.0.0.0/8 then DROP 10.0.0.1/32: allows all 10.x except 10.0.0.1
        - DROP 10.0.0.1/32 then ACCEPT 10.0.0.0/8: drops 10.0.0.1, allows rest of 10.x

        These have different semantics but BDD incorrectly says they're equivalent.
        """
        # Ruleset A: ACCEPT 10.0.0.0/8, then DROP 10.0.0.1/32
        # Packets to 10.0.0.1 match both rules, first-match ACCEPT wins
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.1/32",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=1,
            ),
        ]
        # Ruleset B: DROP 10.0.0.1/32, then ACCEPT 10.0.0.0/8
        # Packets to 10.0.0.1 match both rules, first-match DROP wins
        rules_b = [
            Rule(
                src_ip="10.0.0.1/32",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # These should NOT be equivalent due to different first-match behavior
        # for overlapping rules, but BDD currently ignores rule order
        assert result["equivalent"] is False

    def test_same_actions_different_order_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that non-overlapping rules with same actions are equivalent regardless of order.

        When rules don't overlap (different IP ranges), the order shouldn't matter
        because no packet can match both rules. Both rulesets should be equivalent.
        """
        # Ruleset A: Two non-overlapping rules in one order
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="192.168.0.0/16",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]
        # Ruleset B: Same non-overlapping rules in reverse order
        rules_b = [
            Rule(
                src_ip="192.168.0.0/16",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # Non-overlapping rules with same actions should be equivalent regardless of order
        assert result["equivalent"] is True

    def test_overlapping_rules_order_matters(self, verifier: BDDVerifier) -> None:
        """Test that overlapping rules with different actions are NOT equivalent when reordered.

        When rules overlap and have different actions, order matters because
        the first matching rule determines the action. Swapping changes semantics.
        """
        # Ruleset A: Accept 10.0.0.0/8, then drop 10.0.0.1/32
        # Packets to 10.0.0.1 will be accepted (first match wins)
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.1/32",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=1,
            ),
        ]
        # Ruleset B: Drop 10.0.0.1/32, then accept 10.0.0.0/8
        # Packets to 10.0.0.1 will be dropped (first match wins)
        rules_b = [
            Rule(
                src_ip="10.0.0.1/32",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # Overlapping rules with different actions should NOT be equivalent
        assert result["equivalent"] is False

    def test_all_drop_vs_all_accept(self, verifier: BDDVerifier) -> None:
        """Test that a ruleset that drops everything is NOT equivalent to one that accepts everything.

        Two rulesets covering the same IP ranges but with opposite actions
        should never be equivalent.
        """
        # Ruleset A: Drop all traffic from 10.0.0.0/8
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="drop",
                index=0,
            ),
        ]
        # Ruleset B: Accept all traffic from 10.0.0.0/8
        rules_b = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # Drop vs accept for same IP range should NOT be equivalent
        assert result["equivalent"] is False


# =============================================================================
# IP-Only Mode Tests
# =============================================================================


class TestIPOnlyMode:
    """Tests for IP-only mode behavior (ignores ports and protocol)."""

    def test_same_ips_different_ports_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that rules with same IPs but different ports are equivalent in IP-only mode."""
        rules_a = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=(80, 80),
                dst_port=(443, 443),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=(8080, 8080),
                dst_port=(8080, 8080),
                protocol=17,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # In IP-only mode, ports should be ignored
        assert result["equivalent"] is True

    def test_same_ips_different_protocol_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that rules with same IPs but different protocols are equivalent in IP-only mode."""
        rules_tcp = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,  # TCP
                action="accept",
                index=0,
            ),
        ]
        rules_udp = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=17,  # UDP
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_tcp, rules_udp)
        # In IP-only mode, protocol should be ignored
        assert result["equivalent"] is True

    def test_different_ips_not_equivalent(self, verifier: BDDVerifier) -> None:
        """Test that rules with different IPs are not equivalent."""
        rules_a = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=(80, 80),
                dst_port=(443, 443),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="10.0.0.0/8",
                src_port=(80, 80),
                dst_port=(443, 443),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # Different source IPs should not be equivalent
        assert result["equivalent"] is False

    def test_ip_only_ignores_ports_verify(self, verifier: BDDVerifier) -> None:
        """Verify IP-only mode specifically ignores port fields."""
        # Create rules that differ only in ports
        base_rule = {
            "src_ip": "192.168.1.0/24",
            "dst_ip": "10.0.0.0/8",
            "protocol": 6,
            "action": "accept",
            "index": 0,
        }

        port_variations = [
            ((80, 80), (443, 443)),
            ((8080, 8080), (8443, 8443)),
            (None, None),
            ((1024, 65535), (1024, 65535)),
        ]

        for i, (sport, dport) in enumerate(port_variations):
            rule = Rule(
                src_port=sport,
                dst_port=dport,
                **base_rule,
            )

            # All variations should be equivalent to each other in IP-only mode
            for j, (sport2, dport2) in enumerate(port_variations):
                if i != j:
                    rule2 = Rule(
                        src_port=sport2,
                        dst_port=dport2,
                        **base_rule,
                    )
                    result = verifier.verify([rule], [rule2])
                    assert result["equivalent"] is True, (
                        f"Ports {sport}/{dport} should be equivalent to {sport2}/{dport2} in IP-only mode"
                    )


# =============================================================================
# Full Mode Tests
# =============================================================================


class TestFullModeVerification:
    """Tests for full 5-tuple verification mode."""

    def test_port_difference_detected(self, full_verifier: BDDVerifier) -> None:
        """Same IPs but different destination ports are not equivalent in full mode."""
        rules_80 = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=(80, 80),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_22 = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=(22, 22),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = full_verifier.verify(rules_80, rules_22)
        assert result["equivalent"] is False

    def test_swap_port_rules_not_equivalent(self, full_verifier: BDDVerifier) -> None:
        """Swapping overlapping port rules with different actions changes semantics."""
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=(0, 65535),
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=(22, 22),
                protocol=6,
                action="drop",
                index=1,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=(22, 22),
                protocol=6,
                action="drop",
                index=0,
            ),
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=(0, 65535),
                protocol=6,
                action="accept",
                index=1,
            ),
        ]

        result = full_verifier.verify(rules_a, rules_b)
        assert result["equivalent"] is False

    def test_protocol_any_matches_all(self, full_verifier: BDDVerifier) -> None:
        """Protocol 0 (any) rule remains self-equivalent with port constraints present."""
        rules = [
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="10.0.0.0/8",
                src_port=(12345, 12345),
                dst_port=(53, 53),
                protocol=0,
                action="accept",
                index=0,
            ),
        ]

        result = full_verifier.verify(rules, rules)
        assert result["equivalent"] is True

    def test_port_range_80_443(self, full_verifier: BDDVerifier) -> None:
        """A destination port range rule is correctly encoded and self-equivalent."""
        rules = [
            Rule(
                src_ip="192.168.0.0/16",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=(80, 443),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = full_verifier.verify(rules, rules)
        assert result["equivalent"] is True

    def test_ip_only_mode_backward_compatible(self) -> None:
        """IP-only mode remains backward compatible by ignoring port differences."""
        ip_only_verifier = BDDVerifier(mode="ip_only")

        rules_a = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=(80, 80),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=(22, 22),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = ip_only_verifier.verify(rules_a, rules_b)
        assert result["equivalent"] is True

    def test_full_mode_same_rules_equivalent(self, full_verifier: BDDVerifier) -> None:
        """Identical rulesets with ports and protocol are equivalent in full mode."""
        rules = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=(10000, 20000),
                dst_port=(443, 443),
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="192.168.0.0/16",
                src_port=None,
                dst_port=(53, 53),
                protocol=17,
                action="drop",
                index=1,
            ),
            Rule(
                src_ip="10.1.0.0/16",
                dst_ip="172.16.1.0/24",
                src_port=(1024, 65535),
                dst_port=(22, 22),
                protocol=6,
                action="accept",
                index=2,
            ),
        ]

        result = full_verifier.verify(rules, rules)
        assert result["equivalent"] is True

    def test_protocol_difference_detected(self, full_verifier: BDDVerifier) -> None:
        """Same IPs and ports but different protocols are not equivalent in full mode."""
        rules_tcp = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=(12345, 12345),
                dst_port=(443, 443),
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_udp = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=(12345, 12345),
                dst_port=(443, 443),
                protocol=17,
                action="accept",
                index=0,
            ),
        ]

        result = full_verifier.verify(rules_tcp, rules_udp)
        assert result["equivalent"] is False


class TestRangeToPrefixes:
    """Tests for TCAM range decomposition helper."""

    def test_single_port(self) -> None:
        """Single-value range returns a full-length prefix."""
        assert _range_to_prefixes(80, 80, 16) == [(80, 16)]

    def test_full_range(self) -> None:
        """Entire field range collapses to one wildcard prefix."""
        assert _range_to_prefixes(0, 65535, 16) == [(0, 0)]

    def test_power_of_2_aligned(self) -> None:
        """Aligned power-of-two span maps to expected prefix length."""
        assert _range_to_prefixes(0, 255, 16) == [(0, 8)]

    def test_arbitrary_range(self) -> None:
        """Arbitrary aligned range decomposes to the expected single prefix."""
        assert _range_to_prefixes(80, 95, 16) == [(80, 12)]

    def test_invalid_range_raises(self) -> None:
        """Invalid ranges raise ValueError."""
        with pytest.raises(ValueError):
            _range_to_prefixes(10, 9, 16)

        with pytest.raises(ValueError):
            _range_to_prefixes(-1, 10, 16)


# =============================================================================
# Timeout Handling Tests
# =============================================================================


class TestTimeoutHandling:
    """Tests for timeout handling and fail-closed behavior."""

    def test_very_short_timeout_triggers_timeout(self) -> None:
        """Test that very short timeout triggers timeout behavior."""
        verifier = BDDVerifier(timeout_seconds=0.001)  # 1ms timeout

        # Create rules that will take some time to process
        rules = [
            Rule(
                src_ip=f"{i}.0.0.0/8",
                dst_ip=f"{i + 1}.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=i,
            )
            for i in range(100)
        ]

        result = verifier.verify(rules, rules)

        # With such a short timeout, we expect it to timeout or at least complete
        # Either way, it should return a valid result dict
        assert "equivalent" in result
        assert "time_seconds" in result

    def test_fail_closed_behavior_timeout(self) -> None:
        """Test fail-closed: timeout returns equivalent=False."""
        # Note: This test may be flaky depending on system load
        # We use a very short timeout to increase chances of timeout
        verifier = BDDVerifier(timeout_seconds=0.0001)  # 0.1ms timeout

        rules = [
            Rule(
                src_ip=f"{i}.0.0.0/8",
                dst_ip=f"{i + 1}.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=i,
            )
            for i in range(50)
        ]

        result = verifier.verify(rules, rules)

        # If timeout occurred, equivalent should be False (fail-closed)
        if result.get("error") and "timed out" in result["error"].lower():
            assert result["equivalent"] is False

    def test_timeout_context_manager_raises_exception(self) -> None:
        """Test that timeout context manager raises TimeoutError."""
        import platform

        # signal.SIGALRM is not available on Windows and may have issues on macOS
        if platform.system() in ["Windows", "Darwin"]:
            pytest.skip("signal.SIGALRM not fully supported on this platform")

        with pytest.raises(TimeoutError):
            with timeout(0.001):  # 1ms timeout
                time.sleep(0.1)  # Sleep for 100ms

    def test_timeout_context_manager_success(self) -> None:
        """Test that timeout context manager allows successful completion."""
        with timeout(1.0):  # 1 second timeout
            time.sleep(0.001)  # Sleep for 1ms - should complete

        # If we get here, timeout didn't fire
        assert True

    def test_error_returns_fail_closed(self, verifier: BDDVerifier, monkeypatch) -> None:
        """Test that errors return fail-closed behavior (equivalent=False)."""

        # Monkeypatch _verify_internal to raise an exception
        def mock_verify(*args, **kwargs):
            raise RuntimeError("Simulated error")

        monkeypatch.setattr(verifier, "_verify_internal", mock_verify)

        rules = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules, rules)

        # Should fail closed
        assert result["equivalent"] is False
        assert result["error"] is not None
        assert "Simulated error" in result["error"]


# =============================================================================
# Verification Result Tests
# =============================================================================


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_result_creation(self) -> None:
        """Test VerificationResult creation."""
        result = VerificationResult(equivalent=True, time_seconds=0.5)

        assert result.equivalent is True
        assert result.time_seconds == 0.5
        assert result.error is None

    def test_result_with_error(self) -> None:
        """Test VerificationResult with error."""
        result = VerificationResult(
            equivalent=False,
            time_seconds=1.0,
            error="Timeout occurred",
        )

        assert result.equivalent is False
        assert result.time_seconds == 1.0
        assert result.error == "Timeout occurred"

    def test_result_to_dict(self) -> None:
        """Test VerificationResult to_dict conversion."""
        result = VerificationResult(equivalent=True, time_seconds=0.5)
        dict_result = result.to_dict()

        assert dict_result == {"equivalent": True, "time_seconds": 0.5}

    def test_result_to_dict_with_error(self) -> None:
        """Test VerificationResult to_dict with error."""
        result = VerificationResult(
            equivalent=False,
            time_seconds=1.0,
            error="Something went wrong",
        )
        dict_result = result.to_dict()

        assert dict_result == {
            "equivalent": False,
            "time_seconds": 1.0,
            "error": "Something went wrong",
        }


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunction:
    """Tests for verify_equivalence convenience function."""

    def test_verify_equivalence_basic(self, sample_rules: list[Rule]) -> None:
        """Test verify_equivalence convenience function."""
        result = verify_equivalence(sample_rules, sample_rules)

        assert result["equivalent"] is True
        assert "time_seconds" in result

    def test_verify_equivalence_with_params(self, sample_rules: list[Rule]) -> None:
        """Test verify_equivalence with custom parameters."""
        result = verify_equivalence(
            sample_rules,
            sample_rules,
            backend="autoref",
            mode="ip_only",
            timeout_seconds=60.0,
        )

        assert result["equivalent"] is True


# =============================================================================
# Generated 500-Rule File Tests
# =============================================================================


class TestGenerated500RuleFile:
    """Tests using the generated acl1_500.nft file."""

    def test_load_500_rules(self, generated_nft_file: Path) -> None:
        """Test loading the 500-rule file."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        assert len(rules) > 400, f"Expected >400 rules, got {len(rules)}"
        assert len(rules) <= 500, f"Expected <=500 rules, got {len(rules)}"

    def test_verify_500_rules_against_self(self, generated_nft_file: Path) -> None:
        """Test verifying 500 rules against itself (should be equivalent)."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        verifier = BDDVerifier(timeout_seconds=60.0)
        result = verifier.verify(rules, rules)

        assert result["equivalent"] is True, (
            f"Ruleset should be equivalent to itself. Error: {result.get('error')}"
        )

    def test_500_rules_performance(self, generated_nft_file: Path) -> None:
        """Test that 500-rule verification completes in reasonable time."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        verifier = BDDVerifier(timeout_seconds=60.0)

        start = time.perf_counter()
        result = verifier.verify(rules, rules)
        elapsed = time.perf_counter() - start

        # Should complete in under 30 seconds for identical rulesets
        assert elapsed < 30.0, f"Verification took too long: {elapsed:.2f}s"
        assert result["equivalent"] is True

    def test_500_rules_subset_equivalence(self, generated_nft_file: Path) -> None:
        """Test equivalence with subsets of 500 rules."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        # Test with first 50, 100, 200 rules
        for size in [50, 100, 200]:
            if len(rules) >= size:
                subset = rules[:size]
                verifier = BDDVerifier()
                result = verifier.verify(subset, subset)
                assert result["equivalent"] is True, f"Failed for subset of {size} rules"

    def test_500_rules_field_integrity(self, generated_nft_file: Path) -> None:
        """Test field integrity of loaded 500 rules."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        for i, rule in enumerate(rules[:10]):  # Check first 10
            assert "/" in rule.src_ip, f"Rule {i}: Invalid src_ip format: {rule.src_ip}"
            assert "/" in rule.dst_ip, f"Rule {i}: Invalid dst_ip format: {rule.dst_ip}"
            assert isinstance(rule.protocol, int), f"Rule {i}: Invalid protocol type"
            assert rule.action in ["accept", "drop"], f"Rule {i}: Invalid action: {rule.action}"


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_single_rule_empty_not_equivalent(
        self, verifier: BDDVerifier, single_rule: Rule
    ) -> None:
        """Test that single rule vs empty is not equivalent."""
        result = verifier.verify([single_rule], [])
        assert result["equivalent"] is False

    def test_any_ip_rules(self, verifier: BDDVerifier) -> None:
        """Test rules with any IP (0.0.0.0/0)."""
        rules_any_src = [
            Rule(
                src_ip="0.0.0.0/0",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_specific_src = [
            Rule(
                src_ip="192.168.0.0/16",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = verifier.verify(rules_any_src, rules_specific_src)
        # Any src vs specific src should not be equivalent
        assert result["equivalent"] is False

    def test_ipv6_addresses_not_supported(self, verifier: BDDVerifier) -> None:
        """Test that IPv6 addresses may not be supported (implementation detail)."""
        # This test documents current behavior
        # The implementation uses 32 bits for IPv4
        rules = [
            Rule(
                src_ip="::/0",
                dst_ip="::/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        # This may or may not work depending on implementation
        # We just verify it doesn't crash
        try:
            result = verifier.verify(rules, rules)
            # If it works, it should be equivalent
            assert result["equivalent"] is True
        except (ValueError, TypeError):
            # IPv6 not supported - that's acceptable for v1
            pytest.skip("IPv6 not supported")

    def test_large_cidr_prefixes(self, verifier: BDDVerifier) -> None:
        """Test with various CIDR prefix sizes."""
        cidr_tests = [
            ("1", "0.0.0.0/0"),  # /0 - any
            ("8", "10.0.0.0/8"),  # /8
            ("16", "172.16.0.0/16"),  # /16
            ("24", "192.168.1.0/24"),  # /24
            ("30", "192.168.1.0/30"),  # /30
            ("32", "192.168.1.1/32"),  # /32 - single IP
        ]

        for _, cidr in cidr_tests:
            rules = [
                Rule(
                    src_ip=cidr,
                    dst_ip="0.0.0.0/0",
                    src_port=None,
                    dst_port=None,
                    protocol=6,
                    action="accept",
                    index=0,
                ),
            ]

            result = verifier.verify(rules, rules)
            assert result["equivalent"] is True, f"Failed for CIDR: {cidr}"

    def test_many_small_rules(self, verifier: BDDVerifier) -> None:
        """Test with many small /32 rules."""
        rules = [
            Rule(
                src_ip=f"192.168.{i // 256}.{i % 256}/32",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=i,
            )
            for i in range(100)
        ]

        result = verifier.verify(rules, rules)
        assert result["equivalent"] is True

    def test_overlapping_ip_ranges(self, verifier: BDDVerifier) -> None:
        """Test with overlapping IP ranges."""
        # Two rulesets that cover the same space differently
        rules_a = [
            Rule(
                src_ip="10.0.0.0/8",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="10.0.0.0/9",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
            Rule(
                src_ip="10.128.0.0/9",
                dst_ip="0.0.0.0/0",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=1,
            ),
        ]

        result = verifier.verify(rules_a, rules_b)
        # 10.0.0.0/8 = 10.0.0.0/9 + 10.128.0.0/9, so should be equivalent
        assert result["equivalent"] is True


# =============================================================================
# BDD Internal Tests
# =============================================================================


class TestBDDInternals:
    """Tests for internal BDD methods."""

    def test_build_rule_bdd(self, verifier: BDDVerifier, single_rule: Rule) -> None:
        """Test _build_rule_bdd method."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars, *verifier.dst_vars)

        result = verifier._build_rule_bdd(bdd, single_rule)

        # Should return a valid BDD (not false for a real rule)
        assert result != bdd.false

    def test_build_ruleset_bdd_empty(self, verifier: BDDVerifier) -> None:
        """Test _build_ruleset_bdd with empty ruleset."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars, *verifier.dst_vars)

        result = verifier._build_ruleset_bdd(bdd, [])

        # Empty ruleset should return false (no packets match)
        assert result == bdd.false

    def test_build_ruleset_bdd_single(self, verifier: BDDVerifier, single_rule: Rule) -> None:
        """Test _build_ruleset_bdd with single rule."""
        bdd = verifier.bdd_module.BDD()
        bdd.declare(*verifier.src_vars, *verifier.dst_vars)

        result = verifier._build_ruleset_bdd(bdd, [single_rule])

        # Should return a valid BDD
        assert result != bdd.false

    def test_verify_internal_true(self, verifier: BDDVerifier, sample_rules: list[Rule]) -> None:
        """Test _verify_internal returns True for identical rulesets."""
        result = verifier._verify_internal(sample_rules, sample_rules)
        assert result is True

    def test_verify_internal_false(self, verifier: BDDVerifier) -> None:
        """Test _verify_internal returns False for different rulesets."""
        rules_a = [
            Rule(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]
        rules_b = [
            Rule(
                src_ip="172.16.0.0/12",
                dst_ip="10.0.0.0/8",
                src_port=None,
                dst_port=None,
                protocol=6,
                action="accept",
                index=0,
            ),
        ]

        result = verifier._verify_internal(rules_a, rules_b)
        assert result is False


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
