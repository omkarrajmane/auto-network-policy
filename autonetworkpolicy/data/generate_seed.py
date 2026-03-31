#!/usr/bin/env python3
"""
Synthetic ClassBench seed file generator.

Generates realistic synthetic firewall rules in ClassBench ACL format.
Uses RFC 1918 private networks and common service ports.

Example usage:
    python generate_seed.py --count 500 --output data/seeds/acl1_500.txt --seed 42
    python generate_seed.py --count 1000 --output data/seeds/large_acl.txt
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Optional, Tuple


# RFC 1918 private networks
PRIVATE_NETWORKS = [
    ("10.0.0.0", 8),  # 10.0.0.0/8
    ("172.16.0.0", 12),  # 172.16.0.0/12
    ("192.168.0.0", 16),  # 192.168.0.0/16
]

# Common service ports
COMMON_PORTS = {
    "ssh": 22,
    "dns": 53,
    "http": 80,
    "https": 443,
    "http_alt": 8080,
    "mysql": 3306,
    "postgres": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "smtp": 25,
    "smtps": 465,
    "imap": 143,
    "imaps": 993,
    "pop3": 110,
    "pop3s": 995,
}

# Protocols
PROTOCOLS = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
}


class SeedGenerator:
    """Generator for synthetic ClassBench-style firewall rules."""

    def __init__(self, seed: Optional[int] = None):
        """Initialize generator with optional random seed for reproducibility."""
        self.rng = random.Random(seed)
        self.rule_count = 0

    def _generate_ip_in_network(self, network_prefix: str, network_bits: int) -> str:
        """Generate a random IP within a given network."""
        parts = network_prefix.split(".")
        base_octets = [int(p) for p in parts]
        host_bits = 32 - network_bits
        max_host = (1 << host_bits) - 1
        host = self.rng.randint(0, max_host)
        base_int = (
            (base_octets[0] << 24) | (base_octets[1] << 16) | (base_octets[2] << 8) | base_octets[3]
        )
        ip_int = (base_int & (0xFFFFFFFF << host_bits)) | host
        ip = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
        prefix_weights = [
            (network_bits + 8, 0.3),
            (network_bits + 16, 0.4),
            (32, 0.2),
            (network_bits, 0.1),
        ]
        rand = self.rng.random()
        cumulative = 0.0
        selected_prefix = network_bits + 8
        for prefix, weight in prefix_weights:
            cumulative += weight
            if rand <= cumulative:
                selected_prefix = min(prefix, 32)
                break
        return f"{ip}/{selected_prefix}"

    def _generate_random_ip(self) -> str:
        """Generate a random IP in RFC 1918 space."""
        network_prefix, network_bits = self.rng.choice(PRIVATE_NETWORKS)
        return self._generate_ip_in_network(network_prefix, network_bits)

    def _generate_broad_ip(self) -> str:
        """Generate a broad IP range that can shadow other rules."""
        network_prefix, network_bits = self.rng.choice(PRIVATE_NETWORKS)
        return f"{network_prefix}/{network_bits}"

    def _generate_port_range(self, broad: bool = False) -> Tuple[int, int]:
        """Generate a port range."""
        if broad:
            broad_ranges = [(0, 65535), (1, 1023), (1024, 65535), (1, 49151)]
            return self.rng.choice(broad_ranges)
        rand = self.rng.random()
        if rand < 0.4:
            port = self.rng.choice(list(COMMON_PORTS.values()))
            return (port, port)
        elif rand < 0.7:
            base_port = self.rng.choice([80, 443, 8000, 8080, 9000])
            offset = self.rng.randint(0, 100)
            return (base_port, base_port + offset)
        else:
            min_port = self.rng.choice([0, 1024, 8000, 10000, 30000])
            max_port = self.rng.randint(min_port, 65535)
            return (min_port, max_port)

    def _format_port_range(self, port_range: Tuple[int, int]) -> str:
        """Format port range for ClassBench format."""
        min_port, max_port = port_range
        if min_port == max_port:
            return f"{min_port} {max_port}"
        else:
            return f"{min_port} : {max_port}"

    def _generate_protocol(self) -> int:
        """Generate a random protocol number."""
        weights = [(PROTOCOLS["tcp"], 0.6), (PROTOCOLS["udp"], 0.3), (PROTOCOLS["icmp"], 0.1)]
        rand = self.rng.random()
        cumulative = 0.0
        for proto, weight in weights:
            cumulative += weight
            if rand <= cumulative:
                return proto
        return PROTOCOLS["tcp"]

    def _generate_action(self) -> str:
        """Generate a random action."""
        return "accept" if self.rng.random() < 0.7 else "drop"

    def generate_rule(self, broad: bool = False) -> str:
        """Generate a single ClassBench rule."""
        if broad:
            src_ip = self._generate_broad_ip()
            dst_ip = self._generate_broad_ip()
        else:
            src_ip = self._generate_random_ip()
            dst_ip = self._generate_random_ip()
        src_port = self._generate_port_range(broad=broad)
        dst_port = self._generate_port_range(broad=broad)
        protocol = self._generate_protocol()
        if broad:
            action = "drop" if self.rng.random() < 0.6 else "accept"
        else:
            action = self._generate_action()
        src_port_str = self._format_port_range(src_port)
        dst_port_str = self._format_port_range(dst_port)
        protocol_hex = f"0x{protocol:02X}/0xFF"
        rule = f"@{src_ip} {dst_ip} {src_port_str} {dst_port_str} {protocol_hex} {action}"
        self.rule_count += 1
        return rule

    def generate_rules(self, count: int, shadow_ratio: float = 0.15) -> list[str]:
        """Generate a list of ClassBench rules."""
        rules = []
        num_shadow = int(count * shadow_ratio)
        num_specific = count - num_shadow
        for _ in range(num_specific):
            rules.append(self.generate_rule(broad=False))
        for _ in range(num_shadow):
            broad_rule = self.generate_rule(broad=True)
            insert_pos = self.rng.randint(0, len(rules))
            rules.insert(insert_pos, broad_rule)
        return rules

    def generate_ruleset(
        self, count: int, shadow_ratio: float = 0.15, include_any_rules: bool = True
    ) -> list[str]:
        """Generate a complete ruleset with realistic patterns."""
        rules = []
        reserved = 5 if include_any_rules else 0
        main_count = count - reserved
        main_rules = self.generate_rules(main_count, shadow_ratio)
        rules.extend(main_rules)
        admin_rules = [
            f"@{self._generate_random_ip()} {self._generate_random_ip()} 0 : 65535 22 22 0x06/0xFF accept",
        ]
        dns_rules = [
            f"@{self._generate_random_ip()} {self._generate_random_ip()} 0 : 65535 53 53 0x11/0xFF accept",
        ]
        web_rules = [
            f"@0.0.0.0/0 10.0.0.0/8 0 : 65535 80 80 0x06/0xFF accept",
            f"@0.0.0.0/0 10.0.0.0/8 0 : 65535 443 443 0x06/0xFF accept",
        ]
        for rule in admin_rules + dns_rules:
            if len(rules) > 10:
                insert_pos = self.rng.randint(0, min(10, len(rules)))
                rules.insert(insert_pos, rule)
            else:
                rules.append(rule)
        for rule in web_rules:
            rules.append(rule)
        if include_any_rules:
            rules.append("@0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x06/0xFF accept")
            rules.append("@0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x00/0xFF drop")
        return rules[:count]


def write_rules_to_file(rules: list[str], filepath: Path) -> None:
    """Write rules to a ClassBench seed file."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        f.write("# Synthetic ClassBench ACL rules\n")
        f.write(f"# Total rules: {len(rules)}\n")
        f.write("# Generated by generate_seed.py\n")
        f.write("#\n")
        f.write("# Format: @src_ip dst_ip src_port dst_port protocol action\n")
        f.write("#\n")
        for rule in rules:
            f.write(rule + "\n")


def main():
    """CLI entry point for seed file generation."""
    parser = argparse.ArgumentParser(
        description="Generate synthetic ClassBench seed files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --count 500 --output data/seeds/acl1_500.txt --seed 42
    %(prog)s --count 1000 --output data/seeds/large_acl.txt
    %(prog)s --count 100 --shadow-ratio 0.2 --output data/seeds/test.txt
        """,
    )
    parser.add_argument(
        "--count",
        type=int,
        default=500,
        help="Number of rules to generate (default: 500)",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output file path",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--shadow-ratio",
        type=float,
        default=0.15,
        help="Ratio of broad shadow rules (default: 0.15)",
    )
    parser.add_argument(
        "--no-default-rules",
        action="store_true",
        help="Don't add default any-any rules",
    )
    args = parser.parse_args()
    if args.count < 1:
        print("Error: Count must be at least 1", file=sys.stderr)
        return 1
    if args.shadow_ratio < 0 or args.shadow_ratio > 1:
        print("Error: Shadow ratio must be between 0 and 1", file=sys.stderr)
        return 1
    generator = SeedGenerator(seed=args.seed)
    print(f"Generating {args.count} rules with seed={args.seed}...")
    rules = generator.generate_ruleset(
        count=args.count,
        shadow_ratio=args.shadow_ratio,
        include_any_rules=not args.no_default_rules,
    )
    output_path = Path(args.output)
    write_rules_to_file(rules, output_path)
    print(f"Generated {len(rules)} rules to {output_path}")
    accept_count = sum(1 for r in rules if "accept" in r)
    drop_count = sum(1 for r in rules if "drop" in r)
    broad_count = sum(1 for r in rules if "/8" in r or "/12" in r or "/16" in r)
    print(f"\nStatistics:")
    print(f"  Accept rules: {accept_count}")
    print(f"  Drop rules: {drop_count}")
    print(f"  Broad rules (/8, /12, /16): {broad_count}")
    print(f"  Specific rules: {len(rules) - broad_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
