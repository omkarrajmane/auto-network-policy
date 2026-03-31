#!/usr/bin/env python3
"""
ClassBench to nftables converter with round-trip parsing capability.

Converts ClassBench seed files (ACL format) to nftables rules and provides
round-trip parsing to load nftables files back into Python objects.

Example usage:
    python classbench_to_nft.py input.seed output.nft

    # Or as a module
    from classbench_to_nft import parse_classbench, rules_to_nft, load_nft_as_rules
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass
class Rule:
    """Represents a firewall rule parsed from ClassBench or nftables format.

    Attributes:
        src_ip: Source IP in CIDR notation (e.g., "10.0.0.0/8")
        dst_ip: Destination IP in CIDR notation
        src_port: Tuple of (min, max) port range, or None for any port
        dst_port: Tuple of (min, max) port range, or None for any port
        protocol: Protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
        action: Rule action ("accept" or "drop")
        index: Rule position/index in the ruleset
        comment: Optional semantic context comment for the rule
    """

    src_ip: str
    dst_ip: str
    src_port: Optional[Tuple[int, int]]
    dst_port: Optional[Tuple[int, int]]
    protocol: int
    action: str
    index: int
    comment: Optional[str] = None  # Semantic context (e.g., "# Policy: web-access")


def parse_port_range(port_field: str) -> Optional[Tuple[int, int]]:
    """Parse a ClassBench port field into a (min, max) tuple.

    ClassBench port fields can be:
    - "0 : 65535" - range format (any port)
    - "80 80" - single port written twice
    - "1024 : 65535" - specific range

    Args:
        port_field: Port field string from ClassBench

    Returns:
        Tuple of (min_port, max_port) or None if any port (0-65535)
    """
    port_field = port_field.strip()

    # Check for range format: "min : max"
    if " : " in port_field:
        parts = port_field.split(" : ")
        if len(parts) == 2:
            min_port = int(parts[0].strip())
            max_port = int(parts[1].strip())
            # Return None for full range (any port)
            if min_port == 0 and max_port == 65535:
                return None
            return (min_port, max_port)

    # Check for single port format: "port port"
    parts = port_field.split()
    if len(parts) == 2:
        port1 = int(parts[0].strip())
        port2 = int(parts[1].strip())
        if port1 == port2:
            return (port1, port2)
        # Different values - treat as range
        return (min(port1, port2), max(port1, port2))

    # Single value
    try:
        port = int(port_field)
        return (port, port)
    except ValueError:
        pass

    return None


def parse_protocol(proto_field: str) -> int:
    """Parse a ClassBench protocol field into protocol number.

    ClassBench format: "0x06/0xFF" for TCP, "0x11/0xFF" for UDP, etc.
    The mask should always be 0xFF for exact matching.

    Args:
        proto_field: Protocol field string (e.g., "0x06/0xFF")

    Returns:
        Protocol number as integer

    Raises:
        ValueError: If the protocol format is invalid
    """
    proto_field = proto_field.strip()

    # Handle hex format: "0x06/0xFF"
    if proto_field.startswith("0x"):
        match = re.match(r"0x([0-9a-fA-F]+)(?:/0x([0-9a-fA-F]+))?", proto_field)
        if match:
            proto_num = int(match.group(1), 16)
            return proto_num

    # Handle decimal format
    try:
        return int(proto_field)
    except ValueError:
        pass

    raise ValueError(f"Invalid protocol format: {proto_field}")


def protocol_to_name(protocol: int) -> str:
    """Convert protocol number to nftables protocol name.

    Args:
        protocol: Protocol number

    Returns:
        Protocol name for nftables (tcp, udp, icmp, ip)
    """
    protocol_names = {
        1: "icmp",
        6: "tcp",
        17: "udp",
        47: "gre",
    }
    return protocol_names.get(protocol, "ip")


def parse_classbench(filepath: str | Path) -> list[Rule]:
    """Parse a ClassBench seed file into a list of Rule objects.

    ClassBench ACL format:
    @<src_ip> <dst_ip> <src_port> <dst_port> <protocol> <action>

    Example:
    @10.0.0.0/8 192.168.0.0/16 0 : 80 80 0x06/0xFF accept

    Args:
        filepath: Path to the ClassBench seed file

    Returns:
        List of Rule objects

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file format is invalid
    """
    filepath = Path(filepath)

    if not filepath.exists():
        raise FileNotFoundError(f"ClassBench file not found: {filepath}")

    rules = []

    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Remove leading @ if present
            if line.startswith("@"):
                line = line[1:]

            # Parse the line
            # Format: src_ip dst_ip src_port dst_port protocol action
            # But port fields may contain spaces (e.g., "0 : 65535")
            parts = line.split()

            if len(parts) < 6:
                raise ValueError(
                    f"Invalid line {line_num}: expected at least 6 fields, got {len(parts)}"
                )

            # Extract fields
            src_ip = parts[0]
            dst_ip = parts[1]

            # Find protocol and action (last two fields)
            action = parts[-1].lower()
            proto_field = parts[-2]

            # Everything between dst_ip and protocol is port fields
            # We need to parse port fields which may have 2-4 tokens
            middle_parts = parts[2:-2]

            # Parse port fields
            # Format is: src_port_range dst_port_range
            # Each range can be: "min : max" (3 tokens) or "port port" (2 tokens)
            src_port = None
            dst_port = None

            # Find split point by looking for colon patterns
            # "min : max" contains a colon, so find the boundary between port ranges
            # Strategy: Find all possible split points and try each
            split_points = []

            # A port range can be 2 tokens ("p p") or 3 tokens ("min : max")
            # Valid splits are after 2, 3, or 4 tokens
            for split_idx in [2, 3, 4]:
                if len(middle_parts) >= split_idx:
                    split_points.append(split_idx)

            # Try each split point
            for split_idx in split_points:
                src_port_str = " ".join(middle_parts[:split_idx])
                dst_port_str = " ".join(middle_parts[split_idx:])

                try:
                    src_port = parse_port_range(src_port_str)
                    dst_port = parse_port_range(dst_port_str)
                    if src_port is not None or dst_port is not None:
                        break
                except (ValueError, IndexError):
                    continue

            # Parse protocol
            protocol = parse_protocol(proto_field)

            # Create rule
            rule = Rule(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                action=action,
                index=len(rules),
            )
            rules.append(rule)

    return rules


def port_range_to_nft(port_range: Optional[Tuple[int, int]], direction: str) -> str:
    """Convert a port range to nftables syntax.

    Args:
        port_range: Tuple of (min, max) or None for any port
        direction: "sport" or "dport"

    Returns:
        nftables port match string
    """
    if port_range is None:
        return ""

    min_port, max_port = port_range

    if min_port == max_port:
        return f"{direction} {min_port}"
    elif min_port == 0 and max_port == 65535:
        return ""  # Any port - no match needed
    else:
        return f"{direction} {min_port}-{max_port}"


def rule_to_nft(rule: Rule) -> str:
    """Convert a single Rule to nftables syntax.

    Args:
        rule: Rule object to convert

    Returns:
        nftables rule string
    """
    parts = []

    # Add IP matches
    if rule.src_ip != "0.0.0.0/0" and rule.src_ip != "::/0":
        parts.append(f"ip saddr {rule.src_ip}")

    if rule.dst_ip != "0.0.0.0/0" and rule.dst_ip != "::/0":
        parts.append(f"ip daddr {rule.dst_ip}")

    # Add protocol match
    proto_name = protocol_to_name(rule.protocol)
    if proto_name != "ip":
        parts.append(f"ip protocol {rule.protocol}")

    # Add port matches (only for TCP/UDP)
    if rule.protocol in [6, 17]:  # TCP or UDP
        if rule.src_port:
            src_port_nft = port_range_to_nft(rule.src_port, "sport")
            if src_port_nft:
                parts.append(src_port_nft)

        if rule.dst_port:
            dst_port_nft = port_range_to_nft(rule.dst_port, "dport")
            if dst_port_nft:
                parts.append(dst_port_nft)

    # Add action
    parts.append(rule.action)

    return " ".join(parts)


def rules_to_nft(rules: list[Rule]) -> str:
    """Convert a list of Rules to complete nftables configuration.

    Generates a complete nftables table with filter chain in the format:
    table inet filter {
        chain forward {
            type filter hook forward priority 0; policy drop;

            ip saddr 10.0.0.0/8 ip daddr 192.168.0.0/16 tcp dport 80 accept
            ...

            drop
        }
    }

    Args:
        rules: List of Rule objects

    Returns:
        Complete nftables configuration as string
    """
    lines = [
        "table inet filter {",
        "    chain forward {",
        "        type filter hook forward priority 0; policy drop;",
        "",
    ]

    # Add rules with indentation
    for rule in rules:
        nft_rule = rule_to_nft(rule)
        if rule.comment:
            lines.append(f"        {rule.comment}")
        lines.append(f"        {nft_rule}")

    # Add default drop (already have policy drop, but explicit is clearer)
    if rules and rules[-1].action != "drop":
        lines.append("        drop")

    lines.extend(["    }", "}"])

    return "\n".join(lines)


def parse_nft_rule(line: str) -> Optional[Rule]:
    """Parse a single nftables rule line into a Rule object.

    Args:
        line: Single nftables rule line

    Returns:
        Rule object or None if the line is not a valid rule
    """
    line = line.strip()

    # Skip non-rule lines
    if not line or line.startswith("#"):
        return None

    if any(keyword in line for keyword in ["table", "chain", "type", "policy", "{", "}"]):
        return None

    # Remove leading/trailing whitespace and common prefixes
    line = line.strip()

    # Skip the final default drop rule
    if line == "drop":
        return None

    # Initialize default values
    src_ip = "0.0.0.0/0"
    dst_ip = "0.0.0.0/0"
    src_port = None
    dst_port = None
    protocol = 0  # IP (any protocol)
    action = "drop"

    # Parse action (last word)
    parts = line.split()
    if not parts:
        return None

    action = parts[-1].lower()
    if action not in ["accept", "drop", "reject"]:
        action = "drop"

    # Parse remaining parts
    i = 0
    while i < len(parts) - 1:  # Skip action
        part = parts[i]

        if part == "ip" and i + 2 < len(parts):
            next_part = parts[i + 1]
            if next_part == "saddr" and i + 2 < len(parts):
                src_ip = parts[i + 2]
                i += 3
            elif next_part == "daddr" and i + 2 < len(parts):
                dst_ip = parts[i + 2]
                i += 3
            elif next_part == "protocol" and i + 2 < len(parts):
                proto_val = parts[i + 2]
                try:
                    protocol = int(proto_val)
                except ValueError:
                    # Try to parse protocol name
                    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                    protocol = proto_map.get(proto_val.lower(), 0)
                i += 3
            else:
                i += 1
        elif part in ["sport", "dport", "tcp", "udp"] and i + 1 < len(parts):
            # Handle different port syntaxes
            # sport/dport can appear as: "sport 80" or "tcp sport 80" or "tcp dport 80"
            if part in ["tcp", "udp"]:
                # Next should be sport/dport
                if i + 2 < len(parts) and parts[i + 1] in ["sport", "dport"]:
                    port_str = parts[i + 2]
                    port_range = parse_port_range_from_nft(port_str)
                    if parts[i + 1] == "sport":
                        src_port = port_range
                    else:
                        dst_port = port_range
                    i += 3
                else:
                    i += 1
            else:  # sport or dport directly
                port_str = parts[i + 1]
                port_range = parse_port_range_from_nft(port_str)
                if part == "sport":
                    src_port = port_range
                else:
                    dst_port = port_range
                i += 2
        elif part in ["saddr", "daddr"] and i + 1 < len(parts):
            # Handle nftables compact format
            if part == "saddr":
                src_ip = parts[i + 1]
            else:
                dst_ip = parts[i + 1]
            i += 2
        else:
            i += 1

    return Rule(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        action=action,
        index=0,  # Will be set by caller
    )


def parse_port_range_from_nft(port_str: str) -> Optional[Tuple[int, int]]:
    """Parse a port range string from nftables format.

    Args:
        port_str: Port string (e.g., "80", "1024-65535")

    Returns:
        Tuple of (min, max) or None
    """
    port_str = port_str.strip()

    # Check for range format: "1024-65535"
    if "-" in port_str:
        parts = port_str.split("-")
        if len(parts) == 2:
            try:
                min_port = int(parts[0].strip())
                max_port = int(parts[1].strip())
                return (min_port, max_port)
            except ValueError:
                pass

    # Single port
    try:
        port = int(port_str)
        return (port, port)
    except ValueError:
        pass

    return None


def load_nft_as_rules(filepath: str | Path) -> list[Rule]:
    """Load nftables file and parse rules back into Rule objects.

    This is the round-trip parser that can load nftables configuration
    files generated by rules_to_nft() back into Python Rule objects.

    Args:
        filepath: Path to the nftables file

    Returns:
        List of Rule objects with their index field set

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file format is invalid

    Example:
        >>> rules = load_nft_as_rules('data/generated/acl1_500.nft')
        >>> print(f'Loaded {len(rules)} rules')
    """
    filepath = Path(filepath)

    if not filepath.exists():
        raise FileNotFoundError(f"nftables file not found: {filepath}")

    rules = []
    pending_comment: Optional[str] = None

    with open(filepath, "r") as f:
        for line in f:
            stripped = line.strip()

            if stripped.startswith("#"):
                pending_comment = stripped
                continue

            rule = parse_nft_rule(line)
            if rule:
                rule.comment = pending_comment
                pending_comment = None
                rule.index = len(rules)
                rules.append(rule)

    return rules


def main():
    """CLI entry point for ClassBench to nftables conversion."""
    parser = argparse.ArgumentParser(
        description="Convert ClassBench seed files to nftables format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s input.seed output.nft
    %(prog)s --verify output.nft
        """,
    )

    parser.add_argument("input", type=str, nargs="?", help="Input ClassBench seed file")

    parser.add_argument("output", type=str, nargs="?", help="Output nftables file")

    parser.add_argument(
        "--verify",
        type=str,
        metavar="NFT_FILE",
        help="Load nftables file and verify round-trip parsing",
    )

    parser.add_argument("--count", action="store_true", help="Only count rules, don't write output")

    args = parser.parse_args()

    # Handle verify mode
    if args.verify:
        try:
            rules = load_nft_as_rules(args.verify)
            print(f"Loaded {len(rules)} rules from {args.verify}")

            # Print first few rules for verification
            for i, rule in enumerate(rules[:5]):
                print(f"  Rule {i}: {rule}")

            if len(rules) > 5:
                print(f"  ... and {len(rules) - 5} more")

            return 0
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # Validate input/output arguments
    if not args.input:
        parser.error("Input file is required (unless using --verify)")

    if not args.output and not args.count:
        parser.error("Output file is required (unless using --count or --verify)")

    # Parse ClassBench file
    try:
        rules = parse_classbench(args.input)
        print(f"Parsed {len(rules)} rules from {args.input}")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1

    # Count-only mode
    if args.count:
        print(f"Total rules: {len(rules)}")
        return 0

    # Generate nftables output
    nft_config = rules_to_nft(rules)

    # Write output file
    try:
        with open(args.output, "w") as f:
            f.write(nft_config)
        print(f"Written nftables configuration to {args.output}")
    except IOError as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
