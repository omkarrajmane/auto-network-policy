"""
Shared shadow detection utilities for firewall rule optimization.

Provides functions to detect and remove rules that are shadowed by
earlier rules in a ruleset. A rule is shadowed when an earlier rule
matches a superset of the same traffic with the same action.

Supports IP containment, protocol matching, and port-range containment.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from autonetworkpolicy.data.classbench_to_nft import Rule


def remove_shadowed_rules(
    rules: list[Rule],
    cross_action: bool = False,
) -> list[Rule]:
    """Remove rules that are shadowed by earlier rules.

    Args:
        rules: List of Rule objects.
        cross_action: If True, also remove rules shadowed by earlier rules
            with a different action (e.g. accept hidden behind a drop).

    Returns:
        List of Rule objects with shadowed rules removed.
    """
    if not rules:
        return []

    filtered: list[Rule] = []

    for rule in rules:
        shadowed = False

        for existing in filtered:
            if is_shadowed_by(rule, existing, cross_action=cross_action):
                shadowed = True
                break

        if not shadowed:
            filtered.append(rule)

    return filtered


def is_shadowed_by(
    rule: Rule,
    shadowing_rule: Rule,
    cross_action: bool = False,
) -> bool:
    """Check if rule is shadowed by shadowing_rule.

    A rule is shadowed when an earlier rule matches a superset of the same
    traffic.  With ``cross_action=False`` (default, backward-compatible)
    both rules must share the same action.  With ``cross_action=True`` an
    earlier rule with a *different* action also counts — e.g. a broad
    ``drop`` preceding a narrow ``accept`` makes the accept unreachable.

    Args:
        rule: Rule that might be shadowed.
        shadowing_rule: Rule that might be doing the shadowing.
        cross_action: If True, allow different actions (default False).

    Returns:
        True if rule is shadowed by shadowing_rule.
    """
    if not cross_action and rule.action != shadowing_rule.action:
        return False

    # Protocol check
    if shadowing_rule.protocol != 0 and rule.protocol != shadowing_rule.protocol:
        return False

    # Check IP overlap
    if not ip_contains(shadowing_rule.src_ip, rule.src_ip):
        return False

    if not ip_contains(shadowing_rule.dst_ip, rule.dst_ip):
        return False

    # Check port overlap
    if not _port_contains(shadowing_rule.src_port, rule.src_port):
        return False

    if not _port_contains(shadowing_rule.dst_port, rule.dst_port):
        return False

    return True


def ip_contains(container: str, contained: str) -> bool:
    """Check if container IP/network contains contained IP/network.

    Args:
        container: Container IP in CIDR notation
        contained: Contained IP in CIDR notation

    Returns:
        True if container contains or equals contained
    """
    try:
        container_net = ipaddress.ip_network(container, strict=False)
        contained_net = ipaddress.ip_network(contained, strict=False)

        # Must be same IP version
        if isinstance(container_net, ipaddress.IPv4Network) != isinstance(
            contained_net, ipaddress.IPv4Network
        ):
            return False

        # Check if container supernet of contained
        return bool(container_net.supernet_of(contained_net))  # type: ignore
    except (ValueError, TypeError):
        return False


def _port_contains(
    container_port: Optional[tuple[int, int]],
    contained_port: Optional[tuple[int, int]],
) -> bool:
    """Check if container port range contains contained port range.

    Args:
        container_port: Container port range as (low, high), or None for any
        contained_port: Contained port range as (low, high), or None for any

    Returns:
        True if container covers contained
    """
    # Any port (None) contains everything
    if container_port is None:
        return True

    # Specific port cannot contain "any"
    if contained_port is None:
        return False

    # Range containment check
    return container_port[0] <= contained_port[0] and container_port[1] >= contained_port[1]
