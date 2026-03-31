#!/usr/bin/env python3
"""
Mutation engine for applying deterministic mutations to firewall rulesets.

This module provides the MutationEngine class that applies mutations to lists of Rule
objects in a deterministic, safe manner. All operations return new lists and do not
modify the original ruleset.

Example usage:
    from mutations import MutationEngine
    from data.classbench_to_nft import load_nft_as_rules

    engine = MutationEngine()
    rules = load_nft_as_rules('data/generated/acl1_500.nft')

    # Apply a swap mutation
    new_rules = engine.apply_mutation(rules, {'name': 'swap', 'args': [5, 10]})

    # Validate before applying
    if engine.validate_mutation(rules, {'name': 'swap', 'args': [5, 10]}):
        new_rules = engine.apply_mutation(rules, operation)
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import sys
from typing import Any, Optional, Tuple

from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules
from autonetworkpolicy.utils.shadow import ip_contains


class InvalidMutation(Exception):
    """Raised when a mutation operation is invalid or cannot be applied.

    Attributes:
        message: Explanation of why the mutation is invalid
        operation: The operation that failed validation
    """

    def __init__(self, message: str, operation: Optional[dict[str, Any]] = None):
        self.message = message
        self.operation = operation
        super().__init__(self.message)


class MutationEngine:
    """Engine for applying deterministic mutations to firewall rulesets.

    This class provides methods to apply and validate mutation operations on
    lists of Rule objects. All operations are deterministic and return new
    rule lists without modifying the original.

    Supported operations:
        - swap(i, j): Swap rules at indices i and j
        - move_before(i, j): Move rule i before rule j
        - merge_adjacent(i): Merge rule i with rule i+1 if compatible
        - remove_shadowed(i): Remove rule at index i

    Example:
        >>> engine = MutationEngine()
        >>> rules = [rule1, rule2, rule3]
        >>> new_rules = engine.apply_mutation(rules, {'name': 'swap', 'args': [0, 2]})
        >>> len(new_rules)
        3
    """

    # Valid mutation operation names
    VALID_OPERATIONS = {
        "swap",
        "move_before",
        "merge_adjacent",
        "remove_shadowed",
        "consolidate",
        "split",
    }

    # Required argument counts for each operation
    ARG_COUNTS = {
        "swap": 2,
        "move_before": 2,
        "merge_adjacent": 1,
        "remove_shadowed": 1,
        "consolidate": None,  # Variable: 2+ indices
        "split": 1,  # Single index argument; replacements in operation["replacements"]
    }

    def __init__(self):
        """Initialize the mutation engine."""
        pass

    def apply_mutation(self, rules: list[Rule], operation: dict[str, Any]) -> list[Rule]:
        """Apply a mutation operation to a ruleset and return a new ruleset.

        This method validates the operation first, then applies it to create
        a new list of rules. The original rules list is not modified.

        Args:
            rules: List of Rule objects to mutate
            operation: Dictionary with 'name' and 'args' keys describing the operation
                Example: {'name': 'swap', 'args': [5, 10]}

        Returns:
            New list of Rule objects with the mutation applied

        Raises:
            InvalidMutation: If the operation is invalid or cannot be applied

        Example:
            >>> engine = MutationEngine()
            >>> rules = load_nft_as_rules('rules.nft')
            >>> new_rules = engine.apply_mutation(rules, {'name': 'swap', 'args': [0, 1]})
        """
        # Validate first
        if not self.validate_mutation(rules, operation):
            raise InvalidMutation(f"Mutation validation failed: {operation}", operation)

        # Create a deep copy of rules to avoid modifying the original
        new_rules = copy.deepcopy(rules)

        op_name = operation["name"]
        args = operation["args"]

        # Apply the appropriate operation
        if op_name == "swap":
            return self._apply_swap(new_rules, args)
        elif op_name == "move_before":
            return self._apply_move_before(new_rules, args)
        elif op_name == "merge_adjacent":
            return self._apply_merge_adjacent(new_rules, args)
        elif op_name == "remove_shadowed":
            return self._apply_remove_shadowed(new_rules, args)
        elif op_name == "consolidate":
            return self._apply_consolidate(new_rules, args)
        elif op_name == "split":
            return self._apply_split(new_rules, args, operation)
        else:
            # This should never happen if validation passed
            raise InvalidMutation(f"Unknown operation: {op_name}", operation)

    def validate_mutation(self, rules: list[Rule], operation: dict[str, Any]) -> bool:
        """Check if a mutation operation is valid for the given ruleset.

        Performs comprehensive validation including:
        - Operation name is valid
        - Arguments have correct count and types
        - Indices are within bounds
        - For merge: rules are compatible

        Args:
            rules: List of Rule objects to validate against
            operation: Dictionary with 'name' and 'args' keys

        Returns:
            True if the mutation is valid, False otherwise

        Example:
            >>> engine = MutationEngine()
            >>> engine.validate_mutation(rules, {'name': 'swap', 'args': [0, 1]})
            True
            >>> engine.validate_mutation(rules, {'name': 'swap', 'args': [0, 100]})
            False
        """
        # Check operation is a dict with required keys
        if not isinstance(operation, dict):
            return False

        if "name" not in operation or "args" not in operation:
            return False

        op_name = operation["name"]
        args = operation["args"]
        rule_count = len(rules)

        # Check operation name is valid
        if op_name not in self.VALID_OPERATIONS:
            return False

        # Check args is a list
        if not isinstance(args, list):
            return False

        # Check argument count
        expected_count = self.ARG_COUNTS[op_name]
        if expected_count is not None and len(args) != expected_count:
            return False
        # Variable-arg operations must have minimum args
        if expected_count is None and len(args) < 2:
            return False

        # Check all args are integers
        if not all(isinstance(arg, int) for arg in args):
            return False

        # Validate based on operation type
        if op_name == "swap":
            return self._validate_swap(args, rule_count)
        elif op_name == "move_before":
            return self._validate_move_before(args, rule_count)
        elif op_name == "merge_adjacent":
            return self._validate_merge_adjacent(args, rule_count, rules)
        elif op_name == "remove_shadowed":
            return self._validate_remove_shadowed(args, rule_count)
        elif op_name == "consolidate":
            return self._validate_consolidate(args, rule_count, rules)
        elif op_name == "split":
            return self._validate_split(args, rule_count, rules, operation)

        return False

    def _validate_swap(self, args: list[int], rule_count: int) -> bool:
        """Validate swap operation arguments.

        Args:
            args: List of two indices [i, j]
            rule_count: Total number of rules

        Returns:
            True if valid, False otherwise
        """
        i, j = args[0], args[1]

        # Check indices are within bounds
        if not (0 <= i < rule_count and 0 <= j < rule_count):
            return False

        # Check indices are different
        if i == j:
            return False

        return True

    def _validate_move_before(self, args: list[int], rule_count: int) -> bool:
        """Validate move_before operation arguments.

        Args:
            args: List of two indices [i, j]
            rule_count: Total number of rules

        Returns:
            True if valid, False otherwise
        """
        i, j = args[0], args[1]

        # Check indices are within bounds
        if not (0 <= i < rule_count and 0 <= j < rule_count):
            return False

        # Check indices are different
        if i == j:
            return False

        return True

    def _validate_merge_adjacent(self, args: list[int], rule_count: int, rules: list[Rule]) -> bool:
        """Validate merge_adjacent operation arguments and compatibility.

        Args:
            args: List with single index [i]
            rule_count: Total number of rules
            rules: List of Rule objects

        Returns:
            True if valid and rules are compatible, False otherwise
        """
        i = args[0]

        # Check index is within bounds (need i+1 to exist)
        if not (0 <= i < rule_count - 1):
            return False

        # Check if rules are compatible for merging
        rule_i = rules[i]
        rule_j = rules[i + 1]

        # Rules must have the same action
        if rule_i.action != rule_j.action:
            return False

        # Rules must have the same protocol
        if rule_i.protocol != rule_j.protocol:
            return False

        # Rules must have the same port ranges to avoid broadening scope
        if rule_i.src_port != rule_j.src_port:
            return False

        if rule_i.dst_port != rule_j.dst_port:
            return False

        # Check if IP ranges can be merged
        # For v1: rules can be merged if one contains the other or they are adjacent
        if not self._can_merge_ips(rule_i.src_ip, rule_j.src_ip):
            return False

        if not self._can_merge_ips(rule_i.dst_ip, rule_j.dst_ip):
            return False

        return True

    def _validate_remove_shadowed(self, args: list[int], rule_count: int) -> bool:
        """Validate remove_shadowed operation arguments.

        Args:
            args: List with single index [i]
            rule_count: Total number of rules

        Returns:
            True if valid, False otherwise
        """
        i = args[0]

        # Check index is within bounds
        if not (0 <= i < rule_count):
            return False

        return True

    def _validate_consolidate(self, args: list[int], rule_count: int, rules: list[Rule]) -> bool:
        """Validate consolidate operation arguments and compatibility.

        Args:
            args: List of indices to consolidate (must be 2+ consecutive indices)
            rule_count: Total number of rules
            rules: List of Rule objects

        Returns:
            True if valid and rules can be consolidated, False otherwise
        """
        # Need at least 2 indices
        if len(args) < 2:
            return False

        # Check all indices are within bounds
        if not all(0 <= i < rule_count for i in args):
            return False

        # Check indices are sorted
        sorted_args = sorted(args)
        if sorted_args != args:
            return False

        # Check indices are consecutive (adjacent)
        for i in range(len(args) - 1):
            if args[i + 1] != args[i] + 1:
                return False

        # Check all rules have the same action
        first_action = rules[args[0]].action
        if not all(rules[i].action == first_action for i in args):
            return False

        # Check all rules have the same dst_ip
        first_dst_ip = rules[args[0]].dst_ip
        if not all(rules[i].dst_ip == first_dst_ip for i in args):
            return False

        # Check all rules have the same protocol
        first_protocol = rules[args[0]].protocol
        if not all(rules[i].protocol == first_protocol for i in args):
            return False

        # Check all rules have the same src_port
        first_src_port = rules[args[0]].src_port
        if not all(rules[i].src_port == first_src_port for i in args):
            return False

        # Check all rules have the same dst_port
        first_dst_port = rules[args[0]].dst_port
        if not all(rules[i].dst_port == first_dst_port for i in args):
            return False

        # Try to consolidate src_ip ranges using CIDR supernetting
        src_ips = [rules[i].src_ip for i in args]
        try:
            networks = [ipaddress.ip_network(ip, strict=False) for ip in src_ips]
            collapsed = list(ipaddress.collapse_addresses(networks))
            # If we can't collapse to a single network, consolidation isn't possible
            if len(collapsed) != 1:
                return False
        except (ValueError, TypeError):
            return False

        return True

    def _validate_split(
        self, args: list[int], rule_count: int, rules: list[Rule], operation: dict[str, Any]
    ) -> bool:
        """Validate split operation arguments and replacement rules.

        Args:
            args: List with single index [i]
            rule_count: Total number of rules
            rules: List of Rule objects
            operation: Full operation dict containing 'replacements' key

        Returns:
            True if valid and all replacements are subsets of the original rule
        """
        i = args[0]

        # Check index is within bounds
        if not (0 <= i < rule_count):
            return False

        # Check replacements exist
        if "replacements" not in operation:
            return False

        replacements = operation["replacements"]

        # Must have at least 2 replacements to split
        if not isinstance(replacements, list) or len(replacements) < 2:
            return False

        # Maximum 5 replacement rules
        if len(replacements) > 5:
            return False

        original_rule = rules[i]

        # Validate each replacement rule
        for repl in replacements:
            if not isinstance(repl, dict):
                return False

            # Check required fields exist
            if "src_ip" not in repl or "dst_ip" not in repl:
                return False

            # Validate src_ip is subset of original
            if not ip_contains(original_rule.src_ip, repl["src_ip"]):
                return False

            # Validate dst_ip is subset of original
            if not ip_contains(original_rule.dst_ip, repl["dst_ip"]):
                return False

        return True

    def _can_merge_ips(self, ip1: str, ip2: str) -> bool:
        """Check if two IP ranges can be merged.

        For v1, IP ranges can be merged if:
        - One contains the other
        - They are adjacent (one starts where the other ends)

        Args:
            ip1: First IP in CIDR notation (e.g., "10.0.0.0/8")
            ip2: Second IP in CIDR notation

        Returns:
            True if the IPs can be merged, False otherwise
        """
        try:
            network1 = ipaddress.ip_network(ip1, strict=False)
            network2 = ipaddress.ip_network(ip2, strict=False)

            # Must be same IP version to compare
            if type(network1) != type(network2):
                return False

            # Handle IPv4 networks
            if isinstance(network1, ipaddress.IPv4Network) and isinstance(
                network2, ipaddress.IPv4Network
            ):
                if network1.supernet_of(network2) or network2.supernet_of(network1):
                    return True
                if network1.broadcast_address + 1 == network2.network_address:
                    return True
                if network2.broadcast_address + 1 == network1.network_address:
                    return True
                if network1.overlaps(network2):
                    return True
                return False

            # Handle IPv6 networks
            if isinstance(network1, ipaddress.IPv6Network) and isinstance(
                network2, ipaddress.IPv6Network
            ):
                if network1.supernet_of(network2) or network2.supernet_of(network1):
                    return True
                if network1.broadcast_address + 1 == network2.network_address:
                    return True
                if network2.broadcast_address + 1 == network1.network_address:
                    return True
                if network1.overlaps(network2):
                    return True
                return False

            return False
        except (ValueError, TypeError):
            return False

    def _apply_swap(self, rules: list[Rule], args: list[int]) -> list[Rule]:
        """Apply swap operation to rules.

        Swaps rules at indices i and j.

        Args:
            rules: List of Rule objects (will be modified)
            args: List of two indices [i, j]

        Returns:
            Modified rules list
        """
        i, j = args[0], args[1]
        rules[i], rules[j] = rules[j], rules[i]

        # Update indices
        rules[i].index = i
        rules[j].index = j

        return rules

    def _apply_move_before(self, rules: list[Rule], args: list[int]) -> list[Rule]:
        """Apply move_before operation to rules.

        Moves rule at index i to before rule at index j.

        Args:
            rules: List of Rule objects (will be modified)
            args: List of two indices [i, j]

        Returns:
            Modified rules list
        """
        i, j = args[0], args[1]

        # Remove rule at i
        rule = rules.pop(i)

        # Calculate new position
        # If j < i, insert at j
        # If j > i, insert at j - 1 (because we removed one element)
        new_pos = j if j < i else j - 1
        rules.insert(new_pos, rule)

        # Update all indices
        for idx, r in enumerate(rules):
            r.index = idx

        return rules

    def _apply_merge_adjacent(self, rules: list[Rule], args: list[int]) -> list[Rule]:
        """Apply merge_adjacent operation to rules.

        Merges rule at index i with rule at index i+1.

        Args:
            rules: List of Rule objects (will be modified)
            args: List with single index [i]

        Returns:
            Modified rules list with merged rule
        """
        i = args[0]

        rule1 = rules[i]
        rule2 = rules[i + 1]

        # Create merged IP ranges
        merged_src_ip = self._merge_ip_ranges(rule1.src_ip, rule2.src_ip)
        merged_dst_ip = self._merge_ip_ranges(rule1.dst_ip, rule2.dst_ip)

        # Port ranges must match exactly; mismatches would broaden rule scope
        if rule1.src_port != rule2.src_port:
            raise InvalidMutation(
                f"Cannot merge rules with different src_port: {rule1.src_port} vs {rule2.src_port}"
            )

        if rule1.dst_port != rule2.dst_port:
            raise InvalidMutation(
                f"Cannot merge rules with different dst_port: {rule1.dst_port} vs {rule2.dst_port}"
            )

        # Create merged rule
        merged_rule = Rule(
            src_ip=merged_src_ip,
            dst_ip=merged_dst_ip,
            src_port=rule1.src_port,
            dst_port=rule1.dst_port,
            protocol=rule1.protocol,
            action=rule1.action,
            index=i,
            comment=rule1.comment,
        )

        # Remove both original rules and insert merged
        del rules[i : i + 2]
        rules.insert(i, merged_rule)

        # Update all indices
        for idx, r in enumerate(rules):
            r.index = idx

        return rules

    def _merge_ip_ranges(self, ip1: str, ip2: str) -> str:
        """Merge two IP ranges into a single range.

        Returns the smallest network that contains both IP ranges.

        Args:
            ip1: First IP in CIDR notation
            ip2: Second IP in CIDR notation

        Returns:
            Merged IP range in CIDR notation
        """
        try:
            network1 = ipaddress.ip_network(ip1, strict=False)
            network2 = ipaddress.ip_network(ip2, strict=False)

            # Find the smallest supernet containing both
            # Get the first and last addresses
            first = min(network1.network_address, network2.network_address)
            last = max(network1.broadcast_address, network2.broadcast_address)

            # Calculate required prefix length
            # We need to find the largest prefix that contains both
            if isinstance(first, ipaddress.IPv4Address):
                # IPv4
                total_addrs = int(last) - int(first) + 1
                # Find the smallest power of 2 that fits
                import math

                prefix = 32 - int(math.ceil(math.log2(total_addrs)))
                prefix = max(0, prefix)
                merged_network = ipaddress.ip_network(f"{first}/{prefix}", strict=False)
            else:
                # IPv6
                total_addrs = int(last) - int(first) + 1
                import math

                prefix = 128 - int(math.ceil(math.log2(total_addrs)))
                prefix = max(0, prefix)
                merged_network = ipaddress.ip_network(f"{first}/{prefix}", strict=False)

            return str(merged_network)
        except (ValueError, TypeError):
            # If we can't merge, return the broader of the two
            return ip1 if ip1 > ip2 else ip2

    def _apply_remove_shadowed(self, rules: list[Rule], args: list[int]) -> list[Rule]:
        """Apply remove_shadowed operation to rules.

        Removes rule at index i. In v1, this is deterministic with no IP overlap checking.
        In v2, this would check if the rule is actually shadowed.

        Args:
            rules: List of Rule objects (will be modified)
            args: List with single index [i]

        Returns:
            Modified rules list with rule removed
        """
        i = args[0]
        del rules[i]

        # Update all indices
        for idx, r in enumerate(rules):
            r.index = idx

        return rules

    def _apply_consolidate(self, rules: list[Rule], args: list[int]) -> list[Rule]:
        """Apply consolidate operation to rules.

        Merges 2+ adjacent rules with same action and compatible IP ranges
        into a single broader rule. Uses CIDR supernetting for src_ip consolidation.

        Args:
            rules: List of Rule objects (will be modified)
            args: List of indices to consolidate (must be consecutive)

        Returns:
            Modified rules list with consolidated rule

        Raises:
            InvalidMutation: If indices are not adjacent, actions differ,
                or CIDR ranges cannot be consolidated
        """
        # Validate adjacency (indices must be consecutive)
        sorted_args = sorted(args)
        for i in range(len(sorted_args) - 1):
            if sorted_args[i + 1] != sorted_args[i] + 1:
                raise InvalidMutation(f"Cannot consolidate non-adjacent indices: {sorted_args}")

        # Get the rules to consolidate
        rules_to_merge = [rules[i] for i in sorted_args]

        # Validate same action
        first_action = rules_to_merge[0].action
        if not all(r.action == first_action for r in rules_to_merge):
            raise InvalidMutation(
                f"Cannot consolidate rules with different actions: "
                f"{[r.action for r in rules_to_merge]}"
            )

        # Validate same dst_ip
        first_dst_ip = rules_to_merge[0].dst_ip
        if not all(r.dst_ip == first_dst_ip for r in rules_to_merge):
            raise InvalidMutation("Cannot consolidate rules with different destination IPs")

        # Try CIDR supernetting on src_ip ranges
        src_ips = [r.src_ip for r in rules_to_merge]
        try:
            networks = [ipaddress.ip_network(ip, strict=False) for ip in src_ips]
            collapsed = list(ipaddress.collapse_addresses(networks))

            if len(collapsed) != 1:
                raise InvalidMutation("Cannot consolidate non-complementary CIDR ranges")

            merged_src_ip = str(collapsed[0])
        except (ValueError, TypeError) as e:
            raise InvalidMutation(f"Cannot consolidate non-complementary CIDR ranges: {e}")

        # Create consolidated rule (use values from first rule for ports/protocol)
        first_rule = rules_to_merge[0]
        consolidated_rule = Rule(
            src_ip=merged_src_ip,
            dst_ip=first_dst_ip,
            src_port=first_rule.src_port,
            dst_port=first_rule.dst_port,
            protocol=first_rule.protocol,
            action=first_action,
            index=sorted_args[0],
            comment=first_rule.comment,
        )

        # Remove original rules (in reverse order to maintain indices)
        for i in reversed(sorted_args):
            del rules[i]

        # Insert consolidated rule at the position of the first removed rule
        insert_pos = sorted_args[0]
        rules.insert(insert_pos, consolidated_rule)

        # Update all indices
        for idx, r in enumerate(rules):
            r.index = idx

        return rules

    def _apply_split(
        self, rules: list[Rule], args: list[int], operation: dict[str, Any]
    ) -> list[Rule]:
        """Apply split operation to rules.

        Replaces rule at index i with multiple more specific replacement rules.
        Each replacement must have src_ip and dst_ip that are subsets of the original.

        Args:
            rules: List of Rule objects (will be modified)
            args: List with single index [i]
            operation: Full operation dict containing 'replacements' key

        Returns:
            Modified rules list with original rule replaced by replacements
        """
        i = args[0]
        replacements = operation["replacements"]
        original_rule = rules[i]

        # Build replacement Rule objects
        replacement_rules = []
        for repl in replacements:
            # Get values from replacement dict, using original as default
            src_ip = repl.get("src_ip", original_rule.src_ip)
            dst_ip = repl.get("dst_ip", original_rule.dst_ip)
            src_port = repl.get("src_port", original_rule.src_port)
            dst_port = repl.get("dst_port", original_rule.dst_port)
            protocol = repl.get("protocol", original_rule.protocol)
            action = repl.get("action", original_rule.action)

            new_rule = Rule(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                action=action,
                index=0,  # Will be updated
                comment=original_rule.comment,
            )
            replacement_rules.append(new_rule)

        # Remove original rule and insert replacements at the same position
        del rules[i]
        for j, new_rule in enumerate(replacement_rules):
            rules.insert(i + j, new_rule)

        # Update all indices
        for idx, r in enumerate(rules):
            r.index = idx

        return rules


def apply_mutation(rules: list[Rule], operation: dict[str, Any]) -> list[Rule]:
    """Convenience function to apply a mutation without creating an engine.

    This is a standalone function that creates a MutationEngine and applies
    the mutation in one call.

    Args:
        rules: List of Rule objects to mutate
        operation: Dictionary with 'name' and 'args' keys

    Returns:
        New list of Rule objects with the mutation applied

    Raises:
        InvalidMutation: If the operation is invalid

    Example:
        >>> from data.classbench_to_nft import load_nft_as_rules
        >>> rules = load_nft_as_rules('data/generated/acl1_500.nft')
        >>> new_rules = apply_mutation(rules, {'name': 'swap', 'args': [5, 10]})
        >>> print(f'Rules before: {len(rules)}, after: {len(new_rules)}')
        Rules before: 500, after: 500
    """
    engine = MutationEngine()
    return engine.apply_mutation(rules, operation)


def test_mutations():
    """Test the mutation engine with example operations.

    This function tests all mutation operations and prints results.
    """
    print("Testing MutationEngine")
    print("=" * 50)

    engine = MutationEngine()

    # Create test rules
    rules = [
        Rule("10.0.0.0/8", "192.168.0.0/16", None, None, 6, "accept", 0),
        Rule("10.1.0.0/16", "192.168.1.0/24", None, None, 6, "accept", 1),
        Rule("172.16.0.0/12", "10.0.0.0/8", None, None, 17, "drop", 2),
        Rule("192.168.0.0/16", "172.16.0.0/12", None, None, 6, "accept", 3),
    ]

    print(f"\nOriginal rules ({len(rules)}):")
    for r in rules:
        print(f"  [{r.index}] {r.src_ip} -> {r.dst_ip} {r.action}")

    # Test swap
    print("\n--- Testing swap(0, 2) ---")
    try:
        new_rules = engine.apply_mutation(rules, {"name": "swap", "args": [0, 2]})
        print(f"After swap ({len(new_rules)}):")
        for r in new_rules:
            print(f"  [{r.index}] {r.src_ip} -> {r.dst_ip} {r.action}")
    except InvalidMutation as e:
        print(f"Error: {e}")

    # Test move_before
    print("\n--- Testing move_before(3, 0) ---")
    try:
        new_rules = engine.apply_mutation(rules, {"name": "move_before", "args": [3, 0]})
        print(f"After move_before ({len(new_rules)}):")
        for r in new_rules:
            print(f"  [{r.index}] {r.src_ip} -> {r.dst_ip} {r.action}")
    except InvalidMutation as e:
        print(f"Error: {e}")

    # Test merge_adjacent (rules 0 and 1 have same action)
    print("\n--- Testing merge_adjacent(0) ---")
    try:
        new_rules = engine.apply_mutation(rules, {"name": "merge_adjacent", "args": [0]})
        print(f"After merge ({len(new_rules)}):")
        for r in new_rules:
            print(f"  [{r.index}] {r.src_ip} -> {r.dst_ip} {r.action}")
    except InvalidMutation as e:
        print(f"Error: {e}")

    # Test remove_shadowed
    print("\n--- Testing remove_shadowed(1) ---")
    try:
        new_rules = engine.apply_mutation(rules, {"name": "remove_shadowed", "args": [1]})
        print(f"After remove ({len(new_rules)}):")
        for r in new_rules:
            print(f"  [{r.index}] {r.src_ip} -> {r.dst_ip} {r.action}")
    except InvalidMutation as e:
        print(f"Error: {e}")

    # Test validation failures
    print("\n--- Testing validation failures ---")

    test_cases = [
        ({"name": "swap", "args": [0, 0]}, "Same index"),
        ({"name": "swap", "args": [0, 10]}, "Out of bounds"),
        ({"name": "swap", "args": [0]}, "Wrong arg count"),
        ({"name": "merge_adjacent", "args": [2]}, "Different actions"),
        ({"name": "merge_adjacent", "args": [3]}, "No rule 4"),
        ({"name": "invalid_op", "args": [0]}, "Invalid operation"),
    ]

    for op, description in test_cases:
        is_valid = engine.validate_mutation(rules, op)
        status = "✓" if not is_valid else "✗"
        print(f"  {status} {description}: {op}")

    print("\nAll tests completed!")


def main():
    """CLI entry point for testing mutations."""
    parser = argparse.ArgumentParser(
        description="Mutation engine for firewall rulesets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run built-in tests
    %(prog)s --test
    
    # Load rules from nftables file and apply mutation
    %(prog)s --file data/generated/acl1_500.nft --mutation swap --args 5 10
    
    # Apply move_before mutation
    %(prog)s --file rules.nft --mutation move_before --args 8 3
    
    # Apply merge_adjacent mutation
    %(prog)s --file rules.nft --mutation merge_adjacent --args 10
    
    # Apply remove_shadowed mutation
    %(prog)s --file rules.nft --mutation remove_shadowed --args 15
        """,
    )

    parser.add_argument("--test", action="store_true", help="Run built-in tests")

    parser.add_argument("--file", type=str, help="Path to nftables file to load")

    parser.add_argument(
        "--mutation",
        type=str,
        choices=["swap", "move_before", "merge_adjacent", "remove_shadowed"],
        help="Mutation operation to apply",
    )

    parser.add_argument("--args", type=int, nargs="+", help="Arguments for the mutation (indices)")

    parser.add_argument("--output", type=str, help="Output file for mutated rules (optional)")

    args = parser.parse_args()

    # Run tests mode
    if args.test:
        test_mutations()
        return 0

    # Validate arguments for file mode
    if not args.file:
        parser.error("--file is required (unless using --test)")

    if not args.mutation:
        parser.error("--mutation is required")

    if not args.args:
        parser.error("--args is required")

    # Load rules
    try:
        rules = load_nft_as_rules(args.file)
        print(f"Loaded {len(rules)} rules from {args.file}")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading rules: {e}", file=sys.stderr)
        return 1

    # Create operation dict
    operation = {"name": args.mutation, "args": args.args}

    # Apply mutation
    engine = MutationEngine()

    if not engine.validate_mutation(rules, operation):
        print(f"Error: Invalid mutation {operation}", file=sys.stderr)
        return 1

    try:
        new_rules = engine.apply_mutation(rules, operation)
        print(f"Applied {args.mutation} with args {args.args}")
        print(f"Rules before: {len(rules)}, after: {len(new_rules)}")

        # Show affected rules
        if args.mutation == "swap":
            print(f"  Swapped rules at indices {args.args[0]} and {args.args[1]}")
        elif args.mutation == "move_before":
            print(f"  Moved rule {args.args[0]} before rule {args.args[1]}")
        elif args.mutation == "merge_adjacent":
            print(f"  Merged rules at indices {args.args[0]} and {args.args[0] + 1}")
        elif args.mutation == "remove_shadowed":
            print(f"  Removed rule at index {args.args[0]}")

        # Write output if requested
        if args.output:
            from data.classbench_to_nft import rules_to_nft

            nft_output = rules_to_nft(new_rules)
            with open(args.output, "w") as f:
                f.write(nft_output)
            print(f"Written mutated rules to {args.output}")

        return 0

    except InvalidMutation as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
