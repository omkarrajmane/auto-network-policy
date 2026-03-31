#!/usr/bin/env python3
"""Semantic firewall ruleset generator with injected optimization opportunities."""

from __future__ import annotations

import ipaddress
import random
from typing import Any, Optional, cast

from .classbench_to_nft import Rule


DEPARTMENTS = {
    "hr": {"subnet": "10.1.0.0/16", "ports": [80, 443, 8080]},
    "finance": {"subnet": "10.2.0.0/16", "ports": [80, 443, 1433]},
    "engineering": {"subnet": "10.3.0.0/16", "ports": [80, 443, 22, 5432, 8080, 3000]},
    "executive": {"subnet": "10.4.0.0/16", "ports": [80, 443]},
    "guest": {"subnet": "10.5.0.0/16", "ports": [80, 443]},
}

CROSS_DEPARTMENT_POLICIES = {
    ("hr", "finance"): "deny",
    ("guest", "*"): "deny",
    ("engineering", "engineering"): "allow",
    ("*", "hr"): "deny",
}

ZONES = {
    "dmz": {"subnet": "172.16.0.0/16", "trust": "low"},
    "internal": {"subnet": "10.0.0.0/8", "trust": "medium"},
    "servers": {"subnet": "192.168.0.0/16", "trust": "high"},
    "management": {"subnet": "10.255.0.0/16", "trust": "admin"},
}

ZONE_POLICIES = {
    ("dmz", "internal"): "deny",
    ("dmz", "servers"): "deny",
    ("internal", "servers"): "allow",
    ("management", "*"): "allow",
}

TIERS = {
    "web": {"subnet": "10.10.0.0/16", "ports": [80, 443]},
    "app": {"subnet": "10.20.0.0/16", "ports": [8080, 8443]},
    "database": {"subnet": "10.30.0.0/16", "ports": [5432, 3306, 27017]},
    "cache": {"subnet": "10.40.0.0/16", "ports": [6379, 11211]},
}

TIER_POLICIES = {
    ("web", "app"): "allow",
    ("app", "database"): "allow",
    ("app", "cache"): "allow",
    ("web", "database"): "deny",
    ("*", "database"): "deny",
}


def _reindex(rules: list[Rule]) -> list[Rule]:
    for idx, rule in enumerate(rules):
        rule.index = idx
    return rules


def _to_action(policy_action: str) -> str:
    return "accept" if policy_action.lower() == "allow" else "drop"


def _lookup_policy(
    src_name: str,
    dst_name: str,
    policies: dict[tuple[str, str], str],
    default: str = "allow",
) -> str:
    checks = [
        (src_name, dst_name),
        (src_name, "*"),
        ("*", dst_name),
        ("*", "*"),
    ]
    for key in checks:
        if key in policies:
            return policies[key]
    return default


def _sample_subnet(parent_cidr: str, rng: random.Random, target_prefix: int = 24) -> str:
    network = ipaddress.ip_network(parent_cidr, strict=False)
    if network.prefixlen >= target_prefix:
        return str(network)

    new_subnets = list(network.subnets(new_prefix=target_prefix))
    return str(rng.choice(new_subnets))


def _random_protocol(rng: random.Random) -> int:
    return rng.choices([6, 17, 1], weights=[0.7, 0.2, 0.1], k=1)[0]


def _port_tuple(port: int) -> tuple[int, int]:
    return (port, port)


def _random_noise_rule(
    rng: random.Random, subnets: list[str], ports: list[int], index: int
) -> Rule:
    src = _sample_subnet(rng.choice(subnets), rng)
    dst = _sample_subnet(rng.choice(subnets), rng)
    proto = _random_protocol(rng)
    dst_port = _port_tuple(rng.choice(ports)) if proto in (6, 17) else None
    return Rule(
        src_ip=src,
        dst_ip=dst,
        src_port=None,
        dst_port=dst_port,
        protocol=proto,
        action=rng.choice(["accept", "drop"]),
        index=index,
        comment=None,
    )


def generate_department_ruleset(
    departments: dict[str, dict[str, Any]],
    policies: dict[tuple[str, str], str],
    rules_per_department: int = 20,
    noise_ratio: float = 0.1,
    seed: int = 42,
) -> list[Rule]:
    rng = random.Random(seed)
    rules: list[Rule] = []
    department_names = list(departments.keys())
    all_subnets = [str(departments[name]["subnet"]) for name in department_names]
    all_ports = sorted(
        {p for name in department_names for p in cast(list[int], departments[name]["ports"])}
    )

    for dept_name in department_names:
        dept_subnet = str(departments[dept_name]["subnet"])
        dept_ports = list(cast(list[int], departments[dept_name]["ports"]))
        for _ in range(rules_per_department):
            if rng.random() < noise_ratio:
                rules.append(_random_noise_rule(rng, all_subnets, all_ports, len(rules)))
                continue

            dst_dept = rng.choice(department_names)
            policy = _lookup_policy(dept_name, dst_dept, policies, default="allow")
            action = _to_action(policy)
            port = rng.choice(dept_ports)
            src = _sample_subnet(dept_subnet, rng)
            dst = _sample_subnet(str(departments[dst_dept]["subnet"]), rng)
            rules.append(
                Rule(
                    src_ip=src,
                    dst_ip=dst,
                    src_port=None,
                    dst_port=_port_tuple(port),
                    protocol=6,
                    action=action,
                    index=len(rules),
                    comment=f"# Department: {dept_name} - {action} {src} -> {dst} port {port}",
                )
            )

    for (src_dept, dst_dept), policy in policies.items():
        src_candidates = department_names if src_dept == "*" else [src_dept]
        dst_candidates = department_names if dst_dept == "*" else [dst_dept]
        for src_name in src_candidates:
            for dst_name in dst_candidates:
                src = _sample_subnet(str(departments[src_name]["subnet"]), rng)
                dst = _sample_subnet(str(departments[dst_name]["subnet"]), rng)
                port = rng.choice(list(cast(list[int], departments[src_name]["ports"])))
                action = _to_action(policy)
                rules.append(
                    Rule(
                        src_ip=src,
                        dst_ip=dst,
                        src_port=None,
                        dst_port=_port_tuple(port),
                        protocol=6,
                        action=action,
                        index=len(rules),
                        comment=f"# Policy: Department {src_name} -> {dst_name} - {action} port {port}",
                    )
                )

    return _reindex(rules)


def generate_zone_ruleset(
    zones: dict[str, dict[str, Any]],
    policies: dict[tuple[str, str], str],
    rules_per_zone: int = 25,
    noise_ratio: float = 0.1,
    seed: int = 42,
) -> list[Rule]:
    rng = random.Random(seed)
    rules: list[Rule] = []
    zone_names = list(zones.keys())
    all_subnets = [str(zones[name]["subnet"]) for name in zone_names]
    common_ports = [22, 53, 80, 443, 8080, 8443, 3306, 5432]

    for zone_name in zone_names:
        trust = str(zones[zone_name]["trust"])
        src_subnet = str(zones[zone_name]["subnet"])
        for _ in range(rules_per_zone):
            if rng.random() < noise_ratio:
                rules.append(_random_noise_rule(rng, all_subnets, common_ports, len(rules)))
                continue

            dst_zone = rng.choice(zone_names)
            policy = _lookup_policy(zone_name, dst_zone, policies, default="deny")
            action = _to_action(policy)
            src = _sample_subnet(src_subnet, rng)
            dst = _sample_subnet(str(zones[dst_zone]["subnet"]), rng)
            port = rng.choice(common_ports)
            proto = 6 if port not in (53,) else rng.choice([6, 17])
            rules.append(
                Rule(
                    src_ip=src,
                    dst_ip=dst,
                    src_port=None,
                    dst_port=_port_tuple(port),
                    protocol=proto,
                    action=action,
                    index=len(rules),
                    comment=f"# Zone: {zone_name} (trust={trust}) - {action} to {dst_zone}",
                )
            )

    for (src_zone, dst_zone), policy in policies.items():
        src_candidates = zone_names if src_zone == "*" else [src_zone]
        dst_candidates = zone_names if dst_zone == "*" else [dst_zone]
        for src_name in src_candidates:
            for dst_name in dst_candidates:
                src = _sample_subnet(str(zones[src_name]["subnet"]), rng)
                dst = _sample_subnet(str(zones[dst_name]["subnet"]), rng)
                action = _to_action(policy)
                rules.append(
                    Rule(
                        src_ip=src,
                        dst_ip=dst,
                        src_port=None,
                        dst_port=None,
                        protocol=0,
                        action=action,
                        index=len(rules),
                        comment=f"# Policy: Zone {src_name} -> {dst_name} - {action}",
                    )
                )

    return _reindex(rules)


def generate_tiered_ruleset(
    tiers: dict[str, dict[str, Any]],
    policies: dict[tuple[str, str], str],
    rules_per_tier: int = 25,
    noise_ratio: float = 0.1,
    seed: int = 42,
) -> list[Rule]:
    rng = random.Random(seed)
    rules: list[Rule] = []
    tier_names = list(tiers.keys())
    all_subnets = [str(tiers[name]["subnet"]) for name in tier_names]
    all_ports = sorted({p for name in tier_names for p in cast(list[int], tiers[name]["ports"])})

    for src_tier in tier_names:
        src_subnet = str(tiers[src_tier]["subnet"])
        for _ in range(rules_per_tier):
            if rng.random() < noise_ratio:
                rules.append(_random_noise_rule(rng, all_subnets, all_ports, len(rules)))
                continue

            dst_tier = rng.choice(tier_names)
            policy = _lookup_policy(src_tier, dst_tier, policies, default="deny")
            action = _to_action(policy)
            src = _sample_subnet(src_subnet, rng)
            dst = _sample_subnet(str(tiers[dst_tier]["subnet"]), rng)
            port = rng.choice(list(cast(list[int], tiers[dst_tier]["ports"])))
            proto = 6 if port not in (53,) else rng.choice([6, 17])
            rules.append(
                Rule(
                    src_ip=src,
                    dst_ip=dst,
                    src_port=None,
                    dst_port=_port_tuple(port),
                    protocol=proto,
                    action=action,
                    index=len(rules),
                    comment=f"# Tier: {src_tier} -> {dst_tier} - {action} port {port}",
                )
            )

    for (src_tier, dst_tier), policy in policies.items():
        src_candidates = tier_names if src_tier == "*" else [src_tier]
        dst_candidates = tier_names if dst_tier == "*" else [dst_tier]
        for src_name in src_candidates:
            for dst_name in dst_candidates:
                src = _sample_subnet(str(tiers[src_name]["subnet"]), rng)
                dst = _sample_subnet(str(tiers[dst_name]["subnet"]), rng)
                port = rng.choice(list(cast(list[int], tiers[dst_name]["ports"])))
                action = _to_action(policy)
                rules.append(
                    Rule(
                        src_ip=src,
                        dst_ip=dst,
                        src_port=None,
                        dst_port=_port_tuple(port),
                        protocol=6,
                        action=action,
                        index=len(rules),
                        comment=f"# Policy: Tier {src_name} -> {dst_name} - {action} port {port}",
                    )
                )

    return _reindex(rules)


def _clone_rule(rule: Rule, comment: Optional[str] = None) -> Rule:
    return Rule(
        src_ip=rule.src_ip,
        dst_ip=rule.dst_ip,
        src_port=rule.src_port,
        dst_port=rule.dst_port,
        protocol=rule.protocol,
        action=rule.action,
        index=rule.index,
        comment=rule.comment if comment is None else comment,
    )


def _broaden_subnet(cidr: str, rng: random.Random) -> str:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.prefixlen == 0:
        return str(network)
    step = rng.choice([2, 4, 8])
    new_prefix = max(0, network.prefixlen - step)
    supernet = network.supernet(new_prefix=new_prefix)
    return str(supernet)


def _broaden_port_range(
    port_range: Optional[tuple[int, int]], rng: random.Random
) -> Optional[tuple[int, int]]:
    if port_range is None:
        return None
    low, high = port_range
    widened_low = max(0, low - rng.randint(0, min(1024, low)))
    widened_high = min(65535, high + rng.randint(0, min(2048, 65535 - high)))
    if widened_low == 0 and widened_high == 65535:
        return None
    return (widened_low, widened_high)


def _network_contains(container: str, contained: str) -> bool:
    contained_net = ipaddress.ip_network(contained, strict=False)
    container_net = ipaddress.ip_network(container, strict=False)
    if contained_net.version != container_net.version:
        return False
    return cast(Any, contained_net).subnet_of(container_net)


def _port_contains(
    container: Optional[tuple[int, int]],
    contained: Optional[tuple[int, int]],
) -> bool:
    if container is None:
        return True
    if contained is None:
        return False
    return container[0] <= contained[0] and container[1] >= contained[1]


def _rule_contains(lhs: Rule, rhs: Rule) -> bool:
    if lhs.action != rhs.action:
        return False
    if lhs.protocol not in (0, rhs.protocol):
        return False
    return (
        _network_contains(lhs.src_ip, rhs.src_ip)
        and _network_contains(lhs.dst_ip, rhs.dst_ip)
        and _port_contains(lhs.src_port, rhs.src_port)
        and _port_contains(lhs.dst_port, rhs.dst_port)
    )


def _same_action_spans(rules: list[Rule]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    if not rules:
        return spans

    start = 0
    current_action = rules[0].action
    for idx in range(1, len(rules)):
        if rules[idx].action != current_action:
            if idx - start > 1:
                spans.append((start, idx))
            start = idx
            current_action = rules[idx].action
    if len(rules) - start > 1:
        spans.append((start, len(rules)))
    return spans


def _append_injected_marker(comment: Optional[str], marker: str) -> str:
    if comment:
        return f"{comment} [{marker}]"
    return f"# {marker}"


def inject_optimization_opportunities(
    rules: list[Rule],
    shadow_ratio: float = 0.15,
    duplicate_ratio: float = 0.05,
    misordered_ratio: float = 0.20,
    seed: int = 42,
) -> list[Rule]:
    rng = random.Random(seed)
    injected_rules = [_clone_rule(rule) for rule in rules]

    base_count = len(injected_rules)
    shadow_count = int(base_count * shadow_ratio)
    duplicate_count = int(base_count * duplicate_ratio)
    misordered_count = int(base_count * misordered_ratio)

    for _ in range(shadow_count):
        if not injected_rules:
            break
        target_idx = rng.randrange(len(injected_rules))
        target_rule = injected_rules[target_idx]
        shadow_rule = Rule(
            src_ip=_broaden_subnet(target_rule.src_ip, rng),
            dst_ip=_broaden_subnet(target_rule.dst_ip, rng),
            src_port=_broaden_port_range(target_rule.src_port, rng),
            dst_port=_broaden_port_range(target_rule.dst_port, rng),
            protocol=0
            if target_rule.protocol != 0 and rng.random() < 0.5
            else target_rule.protocol,
            action=target_rule.action,
            index=-1,
            comment=f"# Injected: shadow candidate for original rule {target_rule.index}",
        )
        inserted = False
        for insert_at in range(target_idx, -1, -1):
            if injected_rules[insert_at].action == target_rule.action:
                injected_rules.insert(insert_at, shadow_rule)
                inserted = True
                break
        if not inserted:
            injected_rules.insert(target_idx, shadow_rule)

    for _ in range(duplicate_count):
        if not injected_rules:
            break
        source_idx = rng.randrange(len(injected_rules))
        source_rule = injected_rules[source_idx]
        duplicate_rule = _clone_rule(
            source_rule,
            comment=f"# Injected: duplicate candidate of original rule {source_rule.index}",
        )
        insert_at = rng.randint(0, len(injected_rules))
        injected_rules.insert(insert_at, duplicate_rule)

    for _ in range(misordered_count):
        spans = _same_action_spans(injected_rules)
        if not spans:
            break

        span_start, span_end = rng.choice(spans)
        if span_end - span_start < 2:
            continue

        chosen_pair: Optional[tuple[int, int]] = None
        indices = list(range(span_start, span_end))
        rng.shuffle(indices)
        for i in indices:
            for j in indices:
                if i == j:
                    continue
                if _rule_contains(injected_rules[j], injected_rules[i]):
                    chosen_pair = (j, i)
                    break
            if chosen_pair is not None:
                break

        if chosen_pair is None:
            src_idx = rng.randrange(span_start, span_end)
            dst_idx = rng.randrange(span_start, span_end)
            if src_idx == dst_idx:
                continue
        else:
            src_idx, dst_idx = chosen_pair

        moved_rule = injected_rules.pop(src_idx)
        if src_idx < dst_idx:
            dst_idx -= 1
        injected_rules.insert(dst_idx, moved_rule)
        injected_rules[dst_idx].comment = _append_injected_marker(
            injected_rules[dst_idx].comment,
            "Injected: misordered move",
        )

    return _reindex(injected_rules)
