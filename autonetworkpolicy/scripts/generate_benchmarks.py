#!/usr/bin/env python3
"""
================================================================================
Benchmark Scenario Generator - Phase 10.1.2
================================================================================

Generates three "Policy Debt" benchmark scenarios for evaluating firewall
optimization algorithms:

1. "Over-permissive Legacy" - Too many broad rules allowing excess traffic
2. "Broken Segmentation" - Misordered rules allowing wrong traffic patterns
3. "Redundant Shadowing" - Many rules shadowed by early broad rules

Each scenario has unique characteristics designed to test different aspects
of optimization algorithms.

Usage:
    python generate_benchmarks.py --all
    python generate_benchmarks.py --scenario over_permissive --rules 500
    python generate_benchmarks.py --scenario broken_segmentation --rules 300
    python generate_benchmarks.py --scenario redundant_shadowing --rules 400

Output:
    benchmarks/over_permissive_legacy_500.nft
    benchmarks/broken_segmentation_300.nft
    benchmarks/redundant_shadowing_400.nft

================================================================================
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from autonetworkpolicy.data.classbench_to_nft import Rule, rules_to_nft


# IP network ranges for realistic scenarios
PRIVATE_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

SUBNETS_24 = [
    "10.1.1.0/24",
    "10.1.2.0/24",
    "10.1.3.0/24",
    "10.2.1.0/24",
    "10.2.2.0/24",
    "10.2.3.0/24",
    "172.16.1.0/24",
    "172.16.2.0/24",
    "172.16.3.0/24",
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.3.0/24",
]

SUBNETS_16 = [
    "10.10.0.0/16",
    "10.20.0.0/16",
    "10.30.0.0/16",
    "172.20.0.0/16",
    "172.30.0.0/16",
    "192.168.10.0/16",
    "192.168.20.0/16",
]

# Common service ports
SERVICE_PORTS = {
    "ssh": (22, 22),
    "http": (80, 80),
    "https": (443, 443),
    "dns": (53, 53),
    "smtp": (25, 25),
    "pop3": (110, 110),
    "imap": (143, 143),
    "mysql": (3306, 3306),
    "postgres": (5432, 5432),
    "mongo": (27017, 27017),
    "redis": (6379, 6379),
    "ldap": (389, 389),
}

# Protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1


def generate_over_permissive_legacy(num_rules: int = 500, seed: Optional[int] = None) -> list[Rule]:
    """
    Generate "Over-permissive Legacy" scenario.

    Characteristics:
        - Too many broad rules allowing excess traffic
        - Early rules are very permissive (large IP ranges)
        - Later rules try to restrict but are rarely reached
        - Many redundant rules that overlap significantly

    Optimization opportunity:
        - Reorder to put specific deny rules early
        - Remove redundant broad allow rules
        - Merge overlapping rules with same action

    Args:
        num_rules: Number of rules to generate (default: 500)
        seed: Random seed for reproducibility

    Returns:
        List of Rule objects
    """
    if seed is not None:
        random.seed(seed)

    rules = []

    # Start with very broad permissive rules (the "legacy" problem)
    # These allow way too much traffic
    broad_allows = min(num_rules // 5, 50)
    for i in range(broad_allows):
        src = random.choice(PRIVATE_NETWORKS)
        dst = random.choice(PRIVATE_NETWORKS)
        # Broad port ranges
        sport = (1024, 65535) if random.random() > 0.3 else None
        dport = (1, 65535) if random.random() > 0.2 else None

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol=random.choice([PROTO_TCP, PROTO_UDP, 0]),
                action="accept",
                index=len(rules),
            )
        )

    # Add some specific deny rules that are shadowed by the broad allows
    specific_denies = min(num_rules // 10, 30)
    for i in range(specific_denies):
        src = random.choice(SUBNETS_24)
        dst = random.choice(SUBNETS_24)
        service = random.choice(list(SERVICE_PORTS.keys()))

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=SERVICE_PORTS[service],
                protocol=PROTO_TCP,
                action="drop",
                index=len(rules),
            )
        )

    # Fill remaining with mixed specific rules
    remaining = num_rules - len(rules) - 1  # -1 for final drop

    for i in range(remaining):
        # Mix of specific and somewhat broad rules
        if random.random() > 0.6:
            src = random.choice(SUBNETS_24)
            dst = random.choice(SUBNETS_24)
        else:
            src = random.choice(SUBNETS_16)
            dst = random.choice(SUBNETS_16)

        action = "accept" if random.random() > 0.3 else "drop"

        # Sometimes specific ports, sometimes broad
        if random.random() > 0.5:
            service = random.choice(list(SERVICE_PORTS.keys()))
            dport = SERVICE_PORTS[service]
        else:
            dport = None

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=dport,
                protocol=random.choice([PROTO_TCP, PROTO_UDP]),
                action=action,
                index=len(rules),
            )
        )

    # Add final default drop
    rules.append(
        Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        )
    )

    return rules


def generate_broken_segmentation(num_rules: int = 300, seed: Optional[int] = None) -> list[Rule]:
    """
    Generate "Broken Segmentation" scenario.

    Characteristics:
        - Misordered rules allowing traffic between segments that should be isolated
        - DMZ → Internal traffic allowed when it shouldn't be
        - Guest network can access production services
        - Rules exist to segment but are in wrong order

    Optimization opportunity:
        - Reorder to enforce proper segmentation
        - Move deny rules before allow rules for cross-segment traffic
        - Group related rules together

    Args:
        num_rules: Number of rules to generate (default: 300)
        seed: Random seed for reproducibility

    Returns:
        List of Rule objects
    """
    if seed is not None:
        random.seed(seed)

    rules = []

    # Define network segments
    dmz_nets = ["10.0.1.0/24", "10.0.2.0/24"]
    internal_nets = ["10.10.0.0/16", "10.20.0.0/16"]
    guest_nets = ["172.16.1.0/24", "172.16.2.0/24"]
    prod_nets = ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]

    # Problem: Broad allows first (wrong!)
    # These should come after segment-specific rules
    broad_allows = min(num_rules // 8, 25)
    for i in range(broad_allows):
        # DMZ → Internal (should be restricted but is allowed early)
        rules.append(
            Rule(
                src_ip=random.choice(dmz_nets),
                dst_ip=random.choice(internal_nets),
                src_port=None,
                dst_port=SERVICE_PORTS["https"] if random.random() > 0.5 else None,
                protocol=PROTO_TCP,
                action="accept",
                index=len(rules),
            )
        )

    # Guest → Production (should never be allowed!)
    guest_prod_rules = min(num_rules // 10, 20)
    for i in range(guest_prod_rules):
        rules.append(
            Rule(
                src_ip=random.choice(guest_nets),
                dst_ip=random.choice(prod_nets),
                src_port=None,
                dst_port=random.choice(list(SERVICE_PORTS.values())),
                protocol=PROTO_TCP,
                action="accept",  # This is the vulnerability!
                index=len(rules),
            )
        )

    # Now add the proper deny rules (but they're too late!)
    # These should have been first
    deny_rules = [
        Rule(
            src_ip="172.16.0.0/16",  # Guest
            dst_ip="192.168.0.0/16",  # Prod
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        ),
        Rule(
            src_ip="10.0.0.0/16",  # DMZ
            dst_ip="10.10.0.0/15",  # Internal
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        ),
    ]
    rules.extend(deny_rules)

    # Fill remaining with intra-segment rules (correctly ordered)
    remaining = num_rules - len(rules) - 1

    for i in range(remaining):
        # Random within-segment traffic (these are fine)
        segment = random.choice([dmz_nets, internal_nets, guest_nets, prod_nets])
        src = random.choice(segment)
        dst = random.choice(segment)

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=random.choice(list(SERVICE_PORTS.values()))
                if random.random() > 0.3
                else None,
                protocol=random.choice([PROTO_TCP, PROTO_UDP]),
                action="accept" if random.random() > 0.2 else "drop",
                index=len(rules),
            )
        )

    # Add final default drop
    rules.append(
        Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        )
    )

    return rules


def generate_redundant_shadowing(num_rules: int = 400, seed: Optional[int] = None) -> list[Rule]:
    """
    Generate "Redundant Shadowing" scenario.

    Characteristics:
        - Many rules completely shadowed by early broad rules
        - 30-50% of rules are unreachable
        - Early rules are very broad (e.g., 10.0.0.0/8 → 192.168.0.0/16 accept)
        - Later rules are specific subsets of the early broad rules

    Optimization opportunity:
        - Remove shadowed rules (significant reduction possible)
        - Or reorder to make specific rules reachable first
        - Ideal for testing static analysis + reordering

    Args:
        num_rules: Number of rules to generate (default: 400)
        seed: Random seed for reproducibility

    Returns:
        List of Rule objects
    """
    if seed is not None:
        random.seed(seed)

    rules = []

    # Early broad rules that will shadow many later rules
    broad_rules = min(num_rules // 10, 20)
    for i in range(broad_rules):
        src = random.choice(PRIVATE_NETWORKS)
        dst = random.choice(PRIVATE_NETWORKS)

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=None,
                protocol=0,  # Any protocol
                action="accept" if random.random() > 0.3 else "drop",
                index=len(rules),
            )
        )

    # Now add many rules that are subsets (shadowed)
    shadowed_count = int(num_rules * 0.4)  # 40% shadowed

    for i in range(shadowed_count):
        # Create rules that are subsets of the broad rules above
        # Use /24 subnets within the /8 or /12 networks
        broad_src = rules[i % broad_rules].src_ip
        broad_dst = rules[i % broad_rules].dst_ip

        # Extract base network and create subnet
        if "10." in broad_src:
            src = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"
        elif "172." in broad_src:
            src = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.0/24"
        else:
            src = f"192.168.{random.randint(0, 255)}.0/24"

        if "10." in broad_dst:
            dst = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"
        elif "172." in broad_dst:
            dst = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.0/24"
        else:
            dst = f"192.168.{random.randint(0, 255)}.0/24"

        # Same action as the broad rule (ensures shadowing)
        action = rules[i % broad_rules].action

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=random.choice(list(SERVICE_PORTS.values()))
                if random.random() > 0.5
                else None,
                protocol=random.choice([PROTO_TCP, PROTO_UDP, 0]),
                action=action,
                index=len(rules),
            )
        )

    # Add some non-shadowed specific rules
    non_shadowed = num_rules - len(rules) - 1

    for i in range(non_shadowed):
        # Use different network ranges to avoid shadowing
        src = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"
        dst = f"192.168.{random.randint(0, 255)}.0/24"

        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=random.choice(list(SERVICE_PORTS.values())),
                protocol=random.choice([PROTO_TCP, PROTO_UDP]),
                action="accept" if random.random() > 0.4 else "drop",
                index=len(rules),
            )
        )

    # Add final default drop
    rules.append(
        Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        )
    )

    return rules


def generate_port_heavy_enterprise(num_rules: int = 500, seed: Optional[int] = None) -> list[Rule]:
    """Generate port-heavy enterprise scenario with realistic port distributions.

    500 rules covering common enterprise services (HTTP, HTTPS, SSH, DNS, SMTP,
    RDP, database ports) with a mix of TCP and UDP, including ephemeral port
    ranges. Designed to stress-test port-range BDD encoding.
    """
    if seed is not None:
        random.seed(seed)

    rules = []

    ENTERPRISE_SERVICES: list[Tuple[str, Tuple[int, int], int]] = [
        ("http", (80, 80), PROTO_TCP),
        ("https", (443, 443), PROTO_TCP),
        ("ssh", (22, 22), PROTO_TCP),
        ("dns_tcp", (53, 53), PROTO_TCP),
        ("dns_udp", (53, 53), PROTO_UDP),
        ("smtp", (25, 25), PROTO_TCP),
        ("rdp", (3389, 3389), PROTO_TCP),
        ("postgres", (5432, 5432), PROTO_TCP),
        ("mysql", (3306, 3306), PROTO_TCP),
        ("redis", (6379, 6379), PROTO_TCP),
        ("mongo", (27017, 27017), PROTO_TCP),
        ("ldap", (389, 389), PROTO_TCP),
        ("ntp", (123, 123), PROTO_UDP),
        ("syslog", (514, 514), PROTO_UDP),
        ("snmp", (161, 161), PROTO_UDP),
    ]

    DEPARTMENTS = [
        ("engineering", "10.1.0.0/16"),
        ("finance", "10.2.0.0/16"),
        ("hr", "10.3.0.0/16"),
        ("marketing", "10.4.0.0/16"),
        ("operations", "10.5.0.0/16"),
    ]

    SERVER_SUBNETS = [
        "192.168.1.0/24",
        "192.168.2.0/24",
        "192.168.3.0/24",
        "192.168.10.0/24",
        "192.168.20.0/24",
    ]

    # Department → server service access rules (bulk)
    for dept_name, dept_subnet in DEPARTMENTS:
        num_dept_rules = min(num_rules // 8, 40)
        for _ in range(num_dept_rules):
            svc_name, dport, proto = random.choice(ENTERPRISE_SERVICES)
            dst = random.choice(SERVER_SUBNETS)
            sport = (1024, 65535) if random.random() > 0.4 else None
            rules.append(
                Rule(
                    src_ip=dept_subnet,
                    dst_ip=dst,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    action="accept" if random.random() > 0.15 else "drop",
                    index=len(rules),
                )
            )

    # Cross-department deny rules
    for i, (_, src_sub) in enumerate(DEPARTMENTS):
        for j, (_, dst_sub) in enumerate(DEPARTMENTS):
            if i != j and random.random() > 0.6:
                svc_name, dport, proto = random.choice(ENTERPRISE_SERVICES)
                rules.append(
                    Rule(
                        src_ip=src_sub,
                        dst_ip=dst_sub,
                        src_port=None,
                        dst_port=dport,
                        protocol=proto,
                        action="drop",
                        index=len(rules),
                    )
                )

    # Fill remaining with mixed port-specific rules
    remaining = num_rules - len(rules) - 1
    for _ in range(remaining):
        svc_name, dport, proto = random.choice(ENTERPRISE_SERVICES)
        src = random.choice([d[1] for d in DEPARTMENTS] + SUBNETS_24)
        dst = random.choice(SERVER_SUBNETS + SUBNETS_24)
        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=(1024, 65535) if random.random() > 0.5 else None,
                dst_port=dport,
                protocol=proto,
                action="accept" if random.random() > 0.3 else "drop",
                index=len(rules),
            )
        )

    rules.append(
        Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        )
    )

    return rules


def generate_mixed_protocol(num_rules: int = 400, seed: Optional[int] = None) -> list[Rule]:
    """Generate mixed-protocol scenario with TCP, UDP, and ICMP rules.

    400 rules mixing protocols with protocol-specific shadowing (e.g., a TCP
    rule shadowed by a broader any-protocol rule). Designed to test protocol-
    aware BDD verification and shadow detection.
    """
    if seed is not None:
        random.seed(seed)

    rules = []

    # Broad any-protocol rules that shadow later protocol-specific rules
    broad_any = min(num_rules // 10, 15)
    for _ in range(broad_any):
        src = random.choice(PRIVATE_NETWORKS)
        dst = random.choice(PRIVATE_NETWORKS)
        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=None,
                protocol=0,
                action="accept" if random.random() > 0.3 else "drop",
                index=len(rules),
            )
        )

    # TCP-specific rules (many will be shadowed by above any-protocol)
    tcp_count = int(num_rules * 0.35)
    for _ in range(tcp_count):
        src = random.choice(SUBNETS_24 + SUBNETS_16)
        dst = random.choice(SUBNETS_24 + SUBNETS_16)
        service = random.choice(list(SERVICE_PORTS.keys()))
        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=SERVICE_PORTS[service],
                protocol=PROTO_TCP,
                action="accept" if random.random() > 0.25 else "drop",
                index=len(rules),
            )
        )

    # UDP-specific rules
    udp_count = int(num_rules * 0.2)
    UDP_SERVICES = [
        (53, 53),  # DNS
        (123, 123),  # NTP
        (161, 161),  # SNMP
        (514, 514),  # Syslog
        (1194, 1194),  # OpenVPN
        (500, 500),  # IKE
    ]
    for _ in range(udp_count):
        src = random.choice(SUBNETS_24 + SUBNETS_16)
        dst = random.choice(SUBNETS_24 + SUBNETS_16)
        dport = random.choice(UDP_SERVICES)
        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=dport,
                protocol=PROTO_UDP,
                action="accept" if random.random() > 0.2 else "drop",
                index=len(rules),
            )
        )

    # ICMP rules
    icmp_count = int(num_rules * 0.1)
    for _ in range(icmp_count):
        src = random.choice(SUBNETS_24 + PRIVATE_NETWORKS)
        dst = random.choice(SUBNETS_24 + PRIVATE_NETWORKS)
        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=None,
                protocol=PROTO_ICMP,
                action="accept" if random.random() > 0.3 else "drop",
                index=len(rules),
            )
        )

    # Fill remaining with mixed
    remaining = num_rules - len(rules) - 1
    for _ in range(remaining):
        src = random.choice(SUBNETS_24)
        dst = random.choice(SUBNETS_24)
        proto = random.choice([PROTO_TCP, PROTO_UDP, PROTO_ICMP])
        if proto == PROTO_ICMP:
            dport = None
        elif proto == PROTO_UDP:
            dport = random.choice(UDP_SERVICES)
        else:
            dport = random.choice(list(SERVICE_PORTS.values()))
        rules.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=None,
                dst_port=dport,
                protocol=proto,
                action="accept" if random.random() > 0.35 else "drop",
                index=len(rules),
            )
        )

    rules.append(
        Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
        )
    )

    return rules


def save_scenario(rules: list[Rule], filename: str, output_dir: Optional[str] = None) -> Path:
    """
    Save a scenario to an nftables file.

    Args:
        rules: List of Rule objects
        filename: Output filename
        output_dir: Output directory (default: benchmarks/)

    Returns:
        Path to the output file
    """
    if output_dir is None:
        output_dir = Path(__file__).parent.parent / "benchmarks"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / filename
    nft_config = rules_to_nft(rules)

    with open(output_file, "w") as f:
        f.write(nft_config)

    return output_file


def analyze_scenario(rules: list[Rule]) -> dict:
    """
    Analyze a scenario and return statistics.

    Args:
        rules: List of Rule objects

    Returns:
        Dictionary with scenario statistics
    """
    accept_rules = [r for r in rules if r.action == "accept"]
    drop_rules = [r for r in rules if r.action == "drop"]

    # Count by protocol
    tcp_rules = [r for r in rules if r.protocol == PROTO_TCP]
    udp_rules = [r for r in rules if r.protocol == PROTO_UDP]
    icmp_rules = [r for r in rules if r.protocol == PROTO_ICMP]
    any_proto = [r for r in rules if r.protocol == 0]

    # Count rules with specific ports
    with_ports = [r for r in rules if r.src_port or r.dst_port]

    # Estimate potential shadowed rules (simplified check)
    # A rule might be shadowed if an earlier rule has broader IPs and same action
    potential_shadowed = 0
    for i, rule in enumerate(rules):
        for earlier in rules[:i]:
            if earlier.action == rule.action and earlier.protocol in [0, rule.protocol]:
                # Simplified: if earlier rule uses /8 and current uses /24
                if "/8" in earlier.src_ip or "/12" in earlier.src_ip or "/16" in earlier.src_ip:
                    if "/24" in rule.src_ip or "/32" in rule.src_ip:
                        potential_shadowed += 1
                        break

    return {
        "total_rules": len(rules),
        "accept_rules": len(accept_rules),
        "drop_rules": len(drop_rules),
        "tcp_rules": len(tcp_rules),
        "udp_rules": len(udp_rules),
        "icmp_rules": len(icmp_rules),
        "any_protocol": len(any_proto),
        "with_specific_ports": len(with_ports),
        "potential_shadowed": potential_shadowed,
        "shadowed_percentage": (potential_shadowed / len(rules) * 100) if rules else 0,
    }


def main():
    """CLI entry point for benchmark scenario generator."""
    parser = argparse.ArgumentParser(
        description="Generate benchmark scenarios for AutoNetworkPolicy experiments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate all scenarios with default sizes
    %(prog)s --all
    
    # Generate specific scenario
    %(prog)s --scenario over_permissive --rules 500
    %(prog)s --scenario broken_segmentation --rules 300
    %(prog)s --scenario redundant_shadowing --rules 400
    
    # Generate with specific seed for reproducibility
    %(prog)s --all --seed 42
        """,
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate all three scenarios with default sizes",
    )

    parser.add_argument(
        "--scenario",
        choices=[
            "over_permissive",
            "broken_segmentation",
            "redundant_shadowing",
            "port_heavy_enterprise",
            "mixed_protocol",
        ],
        help="Generate specific scenario",
    )

    parser.add_argument(
        "--rules",
        type=int,
        default=300,
        help="Number of rules to generate (default: 300)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory (default: benchmarks/)",
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze and print scenario statistics",
    )

    args = parser.parse_args()

    if not args.all and not args.scenario:
        parser.error("Must specify --all or --scenario")

    scenarios_to_generate = []

    if args.all:
        scenarios_to_generate = [
            ("over_permissive", 500, "over_permissive_legacy_500.nft"),
            ("broken_segmentation", 300, "broken_segmentation_300.nft"),
            ("redundant_shadowing", 400, "redundant_shadowing_400.nft"),
            ("port_heavy_enterprise", 500, "port_heavy_enterprise_500.nft"),
            ("mixed_protocol", 400, "mixed_protocol_400.nft"),
        ]
    else:
        scenario_map = {
            "over_permissive": f"over_permissive_legacy_{args.rules}.nft",
            "broken_segmentation": f"broken_segmentation_{args.rules}.nft",
            "redundant_shadowing": f"redundant_shadowing_{args.rules}.nft",
            "port_heavy_enterprise": f"port_heavy_enterprise_{args.rules}.nft",
            "mixed_protocol": f"mixed_protocol_{args.rules}.nft",
        }
        scenarios_to_generate = [(args.scenario, args.rules, scenario_map[args.scenario])]

    print("=" * 70)
    print("AutoNetworkPolicy Benchmark Scenario Generator")
    print("=" * 70)
    print()

    for scenario_name, num_rules, filename in scenarios_to_generate:
        print(f"Generating: {scenario_name} ({num_rules} rules)")
        print(f"  Seed: {args.seed}")

        # Generate scenario
        if scenario_name == "over_permissive":
            rules = generate_over_permissive_legacy(num_rules, args.seed)
        elif scenario_name == "broken_segmentation":
            rules = generate_broken_segmentation(num_rules, args.seed)
        elif scenario_name == "port_heavy_enterprise":
            rules = generate_port_heavy_enterprise(num_rules, args.seed)
        elif scenario_name == "mixed_protocol":
            rules = generate_mixed_protocol(num_rules, args.seed)
        else:  # redundant_shadowing
            rules = generate_redundant_shadowing(num_rules, args.seed)

        # Save to file
        output_file = save_scenario(rules, filename, args.output_dir)
        print(f"  Output: {output_file}")

        # Analyze if requested
        if args.analyze:
            stats = analyze_scenario(rules)
            print(f"  Statistics:")
            for key, value in stats.items():
                if isinstance(value, float):
                    print(f"    {key}: {value:.2f}")
                else:
                    print(f"    {key}: {value}")

        print()

    print("Done!")
    print(f"Scenarios saved to: {args.output_dir or 'benchmarks/'}")


if __name__ == "__main__":
    main()
