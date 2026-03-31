#!/usr/bin/env python3
"""
Tests for consolidate and split mutations.

This module tests the MutationEngine's consolidate and split operations
to ensure they behave correctly according to the specification.
"""

import pytest
from autonetworkpolicy.mutations import MutationEngine, InvalidMutation
from autonetworkpolicy.data.classbench_to_nft import Rule


class TestConsolidateMutation:
    """Tests for the consolidate mutation operation."""

    def test_consolidate_adjacent_same_action(self):
        """
        Test that two adjacent rules with complementary CIDRs and same action
        are merged to a single broader rule.

        Two rules with src_ip 10.0.0.0/9 and 10.128.0.0/9 (complementary /9s
        that form 10.0.0.0/8) should merge into a single rule with 10.0.0.0/8.
        """
        engine = MutationEngine()

        # Create two adjacent rules with complementary CIDRs and same action
        rules = [
            Rule("10.0.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 0),
            Rule("10.128.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 1),
        ]

        operation = {"name": "consolidate", "args": [0, 1]}

        # Apply the consolidate mutation
        new_rules = engine.apply_mutation(rules, operation)

        # Should have 1 rule after consolidation
        assert len(new_rules) == 1

        # The consolidated rule should have the broader CIDR (10.0.0.0/8)
        assert new_rules[0].src_ip == "10.0.0.0/8"
        assert new_rules[0].dst_ip == "192.168.0.0/16"
        assert new_rules[0].action == "accept"
        assert new_rules[0].protocol == 6

    def test_consolidate_non_adjacent_raises(self):
        """
        Test that non-adjacent indices (e.g., [0, 2]) raise InvalidMutation.

        Consolidation requires rules to be adjacent in the ruleset.
        """
        engine = MutationEngine()

        # Create three rules where 0 and 2 are not adjacent
        rules = [
            Rule("10.0.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 0),
            Rule("172.16.0.0/12", "192.168.0.0/16", None, None, 6, "accept", 1),
            Rule("10.128.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 2),
        ]

        operation = {"name": "consolidate", "args": [0, 2]}

        # Should raise InvalidMutation for non-adjacent indices
        with pytest.raises(InvalidMutation):
            engine.apply_mutation(rules, operation)

    def test_consolidate_different_actions_raises(self):
        """
        Test that adjacent rules with different actions raise InvalidMutation.

        Rules with different actions (e.g., accept vs drop) cannot be consolidated
        because they would change the semantic meaning of the ruleset.
        """
        engine = MutationEngine()

        # Create two adjacent rules with complementary CIDRs but different actions
        rules = [
            Rule("10.0.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 0),
            Rule("10.128.0.0/9", "192.168.0.0/16", None, None, 6, "drop", 1),
        ]

        operation = {"name": "consolidate", "args": [0, 1]}

        # Should raise InvalidMutation for different actions
        with pytest.raises(InvalidMutation):
            engine.apply_mutation(rules, operation)

    def test_consolidate_non_complementary_cidrs_raises(self):
        """
        Test that adjacent same-action rules with non-complementary CIDRs
        raise InvalidMutation.

        CIDRs like 10.0.0.0/9 and 192.168.0.0/9 do not form a valid supernet
        and cannot be consolidated.
        """
        engine = MutationEngine()

        # Create two adjacent rules with non-complementary CIDRs
        rules = [
            Rule("10.0.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 0),
            Rule("192.168.0.0/9", "192.168.0.0/16", None, None, 6, "accept", 1),
        ]

        operation = {"name": "consolidate", "args": [0, 1]}

        # Should raise InvalidMutation for non-complementary CIDRs
        with pytest.raises(InvalidMutation):
            engine.apply_mutation(rules, operation)


class TestSplitMutation:
    """Tests for the split mutation operation."""

    def test_split_into_subnets_succeeds(self):
        """
        Test that splitting a /8 rule into two /9 rules succeeds.

        A rule with 10.0.0.0/8 should be replaceable by two rules with
        10.0.0.0/9 and 10.128.0.0/9. The result should have 1 more rule
        than the original.
        """
        engine = MutationEngine()

        # Create a single rule that will be split
        rules = [
            Rule("10.0.0.0/8", "192.168.0.0/16", None, None, 6, "accept", 0),
        ]

        operation = {
            "name": "split",
            "args": [0],
            "replacements": [
                {"src_ip": "10.0.0.0/9", "dst_ip": "192.168.0.0/16", "action": "accept"},
                {"src_ip": "10.128.0.0/9", "dst_ip": "192.168.0.0/16", "action": "accept"},
            ],
        }

        # Apply the split mutation
        new_rules = engine.apply_mutation(rules, operation)

        # Should have 2 rules after splitting (1 original replaced by 2)
        assert len(new_rules) == 2

        # Verify the replacement rules
        assert new_rules[0].src_ip == "10.0.0.0/9"
        assert new_rules[1].src_ip == "10.128.0.0/9"
        assert all(r.dst_ip == "192.168.0.0/16" for r in new_rules)
        assert all(r.action == "accept" for r in new_rules)

    def test_split_out_of_range_raises(self):
        """
        Test that replacement rules outside the original range raise InvalidMutation.

        A replacement with 192.168.0.0/16 cannot replace a rule with 10.0.0.0/8
        because 192.168.0.0/16 is not a subset of 10.0.0.0/8.
        """
        engine = MutationEngine()

        # Create a rule that will be split
        rules = [
            Rule("10.0.0.0/8", "10.0.0.0/8", None, None, 6, "accept", 0),
        ]

        operation = {
            "name": "split",
            "args": [0],
            "replacements": [
                {"src_ip": "192.168.0.0/16", "dst_ip": "192.168.0.0/16"},
                {"src_ip": "192.168.128.0/17", "dst_ip": "192.168.128.0/17"},
            ],
        }

        # Should raise InvalidMutation for out-of-range replacements
        with pytest.raises(InvalidMutation):
            engine.apply_mutation(rules, operation)

    def test_split_too_many_replacements_raises(self):
        """
        Test that more than 5 replacement rules raise InvalidMutation.

        The split operation is limited to a maximum of 5 replacements
        to prevent excessive rule explosion.
        """
        engine = MutationEngine()

        # Create a rule that will be split
        rules = [
            Rule("10.0.0.0/8", "192.168.0.0/16", None, None, 6, "accept", 0),
        ]

        # Try to split into 6 replacements (exceeds the limit of 5)
        operation = {
            "name": "split",
            "args": [0],
            "replacements": [
                {"src_ip": "10.0.0.0/11", "dst_ip": "192.168.0.0/16"},
                {"src_ip": "10.32.0.0/11", "dst_ip": "192.168.0.0/16"},
                {"src_ip": "10.64.0.0/11", "dst_ip": "192.168.0.0/16"},
                {"src_ip": "10.96.0.0/11", "dst_ip": "192.168.0.0/16"},
                {"src_ip": "10.128.0.0/11", "dst_ip": "192.168.0.0/16"},
                {"src_ip": "10.160.0.0/11", "dst_ip": "192.168.0.0/16"},  # 6th replacement
            ],
        }

        # Should raise InvalidMutation for too many replacements
        with pytest.raises(InvalidMutation):
            engine.apply_mutation(rules, operation)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
