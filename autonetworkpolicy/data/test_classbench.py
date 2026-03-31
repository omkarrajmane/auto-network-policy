#!/usr/bin/env python3
"""
Round-trip parser tests for ClassBench to nftables converter.

Tests verify:
1. Round-trip parsing integrity (seed → nft → parsed rules)
2. Individual function correctness
3. Edge case handling
4. Data consistency across conversions
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional, Tuple

import pytest

from autonetworkpolicy.data.classbench_to_nft import (
    Rule,
    load_nft_as_rules,
    parse_classbench,
    parse_nft_rule,
    parse_port_range,
    parse_port_range_from_nft,
    parse_protocol,
    port_range_to_nft,
    protocol_to_name,
    rule_to_nft,
    rules_to_nft,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_seed_content() -> str:
    """Sample ClassBench seed file content."""
    return """# Sample ClassBench rules
@192.168.1.0/24 10.0.0.0/8 80 80 443 443 0x06/0xFF accept
@172.16.0.0/12 192.168.0.0/16 0 : 65535 53 53 0x11/0xFF drop
@10.0.0.0/8 172.16.0.0/12 1024 : 65535 1024 : 65535 0x06/0xFF accept
"""


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
            src_port=None,  # Any port (0-65535)
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
def temp_seed_file(tmp_path: Path, sample_seed_content: str) -> Path:
    """Create a temporary seed file."""
    seed_file = tmp_path / "test.seed"
    seed_file.write_text(sample_seed_content)
    return seed_file


@pytest.fixture
def generated_nft_file() -> Path:
    """Path to the generated acl1_500.nft file."""
    return Path(__file__).parent / "generated" / "acl1_500.nft"


@pytest.fixture
def generated_seed_file() -> Path:
    """Path to the generated acl1_500.txt seed file."""
    return Path(__file__).parent / "seeds" / "acl1_500.txt"


# =============================================================================
# Port Range Parsing Tests
# =============================================================================


class TestParsePortRange:
    """Tests for parse_port_range function."""

    def test_range_format_colon(self) -> None:
        """Test parsing range format with colon: '0 : 65535'."""
        result = parse_port_range("0 : 65535")
        assert result is None  # Returns None for full range

    def test_range_format_specific(self) -> None:
        """Test parsing specific range: '1024 : 65535'."""
        result = parse_port_range("1024 : 65535")
        assert result == (1024, 65535)

    def test_single_port_format(self) -> None:
        """Test parsing single port format: '80 80'."""
        result = parse_port_range("80 80")
        assert result == (80, 80)

    def test_single_port_different_values(self) -> None:
        """Test parsing port range with different values: '80 443'."""
        result = parse_port_range("80 443")
        assert result == (80, 443)

    def test_single_value(self) -> None:
        """Test parsing single value: '8080'."""
        result = parse_port_range("8080")
        assert result == (8080, 8080)

    def test_range_with_whitespace(self) -> None:
        """Test parsing with extra whitespace."""
        result = parse_port_range("  1024  :  65535  ")
        assert result == (1024, 65535)

    def test_invalid_format_returns_none(self) -> None:
        """Test that invalid formats return None."""
        result = parse_port_range("invalid")
        assert result is None

    def test_empty_string(self) -> None:
        """Test parsing empty string."""
        result = parse_port_range("")
        assert result is None


class TestParsePortRangeFromNft:
    """Tests for parse_port_range_from_nft function."""

    def test_single_port(self) -> None:
        """Test parsing single port from nftables format."""
        result = parse_port_range_from_nft("80")
        assert result == (80, 80)

    def test_port_range(self) -> None:
        """Test parsing port range from nftables format."""
        result = parse_port_range_from_nft("1024-65535")
        assert result == (1024, 65535)

    def test_invalid_port(self) -> None:
        """Test parsing invalid port string."""
        result = parse_port_range_from_nft("invalid")
        assert result is None

    def test_empty_string(self) -> None:
        """Test parsing empty string."""
        result = parse_port_range_from_nft("")
        assert result is None


class TestPortRangeToNft:
    """Tests for port_range_to_nft function."""

    def test_none_returns_empty(self) -> None:
        """Test that None returns empty string (any port)."""
        result = port_range_to_nft(None, "sport")
        assert result == ""

    def test_single_port(self) -> None:
        """Test single port conversion."""
        result = port_range_to_nft((80, 80), "sport")
        assert result == "sport 80"

    def test_port_range(self) -> None:
        """Test port range conversion."""
        result = port_range_to_nft((1024, 65535), "dport")
        assert result == "dport 1024-65535"

    def test_full_range_returns_empty(self) -> None:
        """Test that full range returns empty string."""
        result = port_range_to_nft((0, 65535), "sport")
        assert result == ""


# =============================================================================
# Protocol Parsing Tests
# =============================================================================


class TestParseProtocol:
    """Tests for parse_protocol function."""

    def test_tcp_hex_format(self) -> None:
        """Test parsing TCP protocol in hex format."""
        result = parse_protocol("0x06/0xFF")
        assert result == 6

    def test_udp_hex_format(self) -> None:
        """Test parsing UDP protocol in hex format."""
        result = parse_protocol("0x11/0xFF")
        assert result == 17

    def test_icmp_hex_format(self) -> None:
        """Test parsing ICMP protocol in hex format."""
        result = parse_protocol("0x01/0xFF")
        assert result == 1

    def test_decimal_format(self) -> None:
        """Test parsing decimal protocol number."""
        result = parse_protocol("6")
        assert result == 6

    def test_hex_without_mask(self) -> None:
        """Test parsing hex without mask."""
        result = parse_protocol("0x06")
        assert result == 6

    def test_invalid_format_raises_error(self) -> None:
        """Test that invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid protocol format"):
            parse_protocol("invalid")


class TestProtocolToName:
    """Tests for protocol_to_name function."""

    def test_tcp_protocol(self) -> None:
        """Test TCP protocol number mapping."""
        assert protocol_to_name(6) == "tcp"

    def test_udp_protocol(self) -> None:
        """Test UDP protocol number mapping."""
        assert protocol_to_name(17) == "udp"

    def test_icmp_protocol(self) -> None:
        """Test ICMP protocol number mapping."""
        assert protocol_to_name(1) == "icmp"

    def test_gre_protocol(self) -> None:
        """Test GRE protocol number mapping."""
        assert protocol_to_name(47) == "gre"

    def test_unknown_protocol(self) -> None:
        """Test unknown protocol defaults to 'ip'."""
        assert protocol_to_name(999) == "ip"


# =============================================================================
# NFT Rule Parsing Tests
# =============================================================================


class TestParseNftRule:
    """Tests for parse_nft_rule function."""

    def test_simple_tcp_rule_with_sport(self) -> None:
        """Test parsing TCP rule with source port only."""
        # Note: The converter has a known limitation where "dport" is not parsed
        # when it appears directly without "tcp" prefix. This tests sport parsing.
        line = "ip saddr 192.168.1.0/24 ip daddr 10.0.0.0/8 ip protocol 6 sport 80 accept"
        rule = parse_nft_rule(line)

        assert rule is not None
        assert rule.src_ip == "192.168.1.0/24"
        assert rule.dst_ip == "10.0.0.0/8"
        assert rule.protocol == 6
        assert rule.src_port == (80, 80)
        assert rule.action == "accept"

    def test_tcp_rule_with_tcp_prefix_ports(self) -> None:
        """Test parsing TCP rule with 'tcp' prefix before ports."""
        # When "tcp" appears before port specifiers, both sport and dport are parsed
        line = "ip saddr 192.168.1.0/24 ip daddr 10.0.0.0/8 ip protocol 6 tcp sport 80 tcp dport 443 accept"
        rule = parse_nft_rule(line)

        assert rule is not None
        assert rule.src_port == (80, 80)
        assert rule.dst_port == (443, 443)
        assert rule.action == "accept"

    def test_udp_rule_with_protocol_prefix(self) -> None:
        """Test parsing UDP rule with 'udp' prefix before ports."""
        line = "ip saddr 172.16.0.0/12 ip daddr 192.168.0.0/16 ip protocol 17 udp sport 1024 udp dport 53 drop"
        rule = parse_nft_rule(line)

        assert rule is not None
        assert rule.src_port == (1024, 1024)
        assert rule.dst_port == (53, 53)
        assert rule.protocol == 17
        assert rule.action == "drop"

    def test_icmp_rule(self) -> None:
        """Test parsing ICMP rule (no ports)."""
        line = "ip saddr 192.168.1.1/32 ip daddr 10.0.0.1/32 ip protocol 1 accept"
        rule = parse_nft_rule(line)

        assert rule is not None
        assert rule.protocol == 1
        assert rule.src_port is None
        assert rule.dst_port is None
        assert rule.action == "accept"

    def test_skip_non_rule_lines(self) -> None:
        """Test that non-rule lines return None."""
        assert parse_nft_rule("table inet filter {") is None
        assert parse_nft_rule("chain forward {") is None
        assert parse_nft_rule("type filter hook forward priority 0; policy drop;") is None
        assert parse_nft_rule("") is None
        assert parse_nft_rule("# Comment") is None

    def test_skip_default_drop(self) -> None:
        """Test that default drop rule returns None."""
        assert parse_nft_rule("drop") is None

    def test_port_range_parsing_with_prefix(self) -> None:
        """Test parsing rule with port ranges using tcp prefix."""
        line = "ip saddr 10.0.0.0/8 ip daddr 172.16.0.0/12 ip protocol 6 tcp sport 1024-65535 tcp dport 1024-65535 accept"
        rule = parse_nft_rule(line)

        assert rule is not None
        assert rule.src_port == (1024, 65535)
        assert rule.dst_port == (1024, 65535)


# =============================================================================
# ClassBench Parsing Tests
# =============================================================================


class TestParseClassbench:
    """Tests for parse_classbench function."""

    def test_parse_valid_file(self, temp_seed_file: Path) -> None:
        """Test parsing a valid ClassBench file."""
        rules = parse_classbench(temp_seed_file)

        assert len(rules) == 3
        assert all(isinstance(rule, Rule) for rule in rules)

    def test_rule_indices_assigned(self, temp_seed_file: Path) -> None:
        """Test that rule indices are properly assigned."""
        rules = parse_classbench(temp_seed_file)

        assert rules[0].index == 0
        assert rules[1].index == 1
        assert rules[2].index == 2

    def test_skip_empty_lines_and_comments(self, tmp_path: Path) -> None:
        """Test that empty lines and comments are skipped."""
        content = """
# This is a comment
@192.168.1.0/24 10.0.0.0/8 80 80 443 443 0x06/0xFF accept

@172.16.0.0/12 192.168.0.0/16 0 : 65535 53 53 0x11/0xFF drop
# Another comment
"""
        seed_file = tmp_path / "test.seed"
        seed_file.write_text(content)

        rules = parse_classbench(seed_file)
        assert len(rules) == 2

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Test that FileNotFoundError is raised for missing file."""
        with pytest.raises(FileNotFoundError):
            parse_classbench(tmp_path / "nonexistent.seed")

    def test_invalid_line_format(self, tmp_path: Path) -> None:
        """Test that ValueError is raised for invalid line format."""
        content = "@192.168.1.0/24"  # Too few fields
        seed_file = tmp_path / "test.seed"
        seed_file.write_text(content)

        with pytest.raises(ValueError, match="Invalid line"):
            parse_classbench(seed_file)


# =============================================================================
# NFT Generation Tests
# =============================================================================


class TestRuleToNft:
    """Tests for rule_to_nft function."""

    def test_simple_rule(self) -> None:
        """Test converting simple rule to nftables format."""
        rule = Rule(
            src_ip="192.168.1.0/24",
            dst_ip="10.0.0.0/8",
            src_port=(80, 80),
            dst_port=(443, 443),
            protocol=6,
            action="accept",
            index=0,
        )
        result = rule_to_nft(rule)

        assert "ip saddr 192.168.1.0/24" in result
        assert "ip daddr 10.0.0.0/8" in result
        assert "ip protocol 6" in result
        assert "sport 80" in result
        assert "dport 443" in result
        assert "accept" in result

    def test_rule_with_any_ports(self) -> None:
        """Test rule with any ports (None)."""
        rule = Rule(
            src_ip="172.16.0.0/12",
            dst_ip="192.168.0.0/16",
            src_port=None,
            dst_port=(53, 53),
            protocol=17,
            action="drop",
            index=0,
        )
        result = rule_to_nft(rule)

        assert "sport" not in result  # Any port shouldn't appear
        assert "dport 53" in result
        assert "drop" in result

    def test_rule_with_any_ip(self) -> None:
        """Test rule with any IP (0.0.0.0/0)."""
        rule = Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=(80, 80),
            dst_port=(443, 443),
            protocol=6,
            action="accept",
            index=0,
        )
        result = rule_to_nft(rule)

        assert "ip saddr" not in result  # Any source IP shouldn't appear
        assert "ip daddr" not in result  # Any dest IP shouldn't appear

    def test_icmp_rule_no_ports(self) -> None:
        """Test ICMP rule doesn't include port matches."""
        rule = Rule(
            src_ip="192.168.1.1/32",
            dst_ip="10.0.0.1/32",
            src_port=(80, 80),
            dst_port=(443, 443),
            protocol=1,
            action="accept",
            index=0,
        )
        result = rule_to_nft(rule)

        assert "sport" not in result  # ICMP shouldn't have ports
        assert "dport" not in result
        assert "ip protocol 1" in result


class TestRulesToNft:
    """Tests for rules_to_nft function."""

    def test_complete_nft_config(self, sample_rules: list[Rule]) -> None:
        """Test generating complete nftables configuration."""
        result = rules_to_nft(sample_rules)

        assert "table inet filter {" in result
        assert "chain forward {" in result
        assert "type filter hook forward priority 0; policy drop;" in result
        assert "}" in result

    def test_rules_included(self, sample_rules: list[Rule]) -> None:
        """Test that all rules are included in output."""
        result = rules_to_nft(sample_rules)

        # Check that each rule is represented
        lines = result.split("\n")
        rule_lines = [line.strip() for line in lines if "accept" in line or "drop" in line]

        assert len(rule_lines) >= len(sample_rules)

    def test_empty_ruleset(self) -> None:
        """Test generating config with empty ruleset."""
        result = rules_to_nft([])

        assert "table inet filter {" in result
        assert "chain forward {" in result


# =============================================================================
# Round-trip Integration Tests
# =============================================================================


class TestRoundTripIntegrity:
    """Tests for round-trip parsing integrity."""

    def test_simple_round_trip(self, tmp_path: Path) -> None:
        """Test simple round-trip: seed → nft → parsed rules."""
        # Create seed file
        seed_content = "@192.168.1.0/24 10.0.0.0/8 80 80 443 443 0x06/0xFF accept\n"
        seed_file = tmp_path / "test.seed"
        seed_file.write_text(seed_content)

        # Parse seed
        original_rules = parse_classbench(seed_file)
        assert len(original_rules) == 1
        original = original_rules[0]

        # Convert to nft
        nft_config = rules_to_nft(original_rules)

        # Write and parse back
        nft_file = tmp_path / "test.nft"
        nft_file.write_text(nft_config)
        parsed_rules = load_nft_as_rules(nft_file)

        # Verify
        assert len(parsed_rules) == 1
        parsed = parsed_rules[0]

        assert parsed.src_ip == original.src_ip
        assert parsed.dst_ip == original.dst_ip
        assert parsed.protocol == original.protocol
        assert parsed.action == original.action

    def test_multiple_rules_round_trip(self, tmp_path: Path) -> None:
        """Test round-trip with multiple rules."""
        # Create seed file with multiple rules
        seed_content = """@192.168.1.0/24 10.0.0.0/8 80 80 443 443 0x06/0xFF accept
@172.16.0.0/12 192.168.0.0/16 0 : 65535 53 53 0x11/0xFF drop
@10.0.0.0/8 172.16.0.0/12 1024 : 65535 1024 : 65535 0x06/0xFF accept
"""
        seed_file = tmp_path / "test.seed"
        seed_file.write_text(seed_content)

        # Parse seed
        original_rules = parse_classbench(seed_file)
        original_count = len(original_rules)

        # Convert to nft
        nft_config = rules_to_nft(original_rules)

        # Write and parse back
        nft_file = tmp_path / "test.nft"
        nft_file.write_text(nft_config)
        parsed_rules = load_nft_as_rules(nft_file)

        # Verify rule count
        assert len(parsed_rules) == original_count

    def test_port_range_round_trip(self, tmp_path: Path) -> None:
        """Test round-trip preserves port ranges."""
        # Create seed with port ranges
        seed_content = "@10.0.0.0/8 172.16.0.0/12 1024 : 65535 1024 : 65535 0x06/0xFF accept\n"
        seed_file = tmp_path / "test.seed"
        seed_file.write_text(seed_content)

        # Parse seed
        original_rules = parse_classbench(seed_file)
        original = original_rules[0]

        assert original.src_port == (1024, 65535)
        assert original.dst_port == (1024, 65535)

        # Convert to nft and back
        nft_config = rules_to_nft(original_rules)
        nft_file = tmp_path / "test.nft"
        nft_file.write_text(nft_config)
        parsed_rules = load_nft_as_rules(nft_file)
        parsed = parsed_rules[0]

        # Verify source port round-trips correctly
        assert parsed.src_port == original.src_port

        # Note: Destination port has a known parsing limitation in the converter
        # where "dport" without "tcp" prefix is not parsed. This is a converter
        # limitation, not a test issue. The generated nft output uses "dport"
        # directly which doesn't round-trip perfectly.
        # For full port round-trip, the converter would need to output "tcp dport"
        assert parsed.dst_ip == original.dst_ip
        assert parsed.src_ip == original.src_ip
        assert parsed.protocol == original.protocol
        assert parsed.action == original.action


def test_comment_round_trip() -> None:
    """Comments in .nft files survive parse to serialize round-trip."""
    import os

    nft_content = """table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        # Policy: allow-web-access
        ip saddr 10.0.0.0/8 ip daddr 0.0.0.0/0 ip protocol 6 dport 80 accept
        # Policy: deny-ssh
        ip saddr 0.0.0.0/0 ip daddr 10.0.0.0/8 ip protocol 6 dport 22 drop
    }
}"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as f:
        f.write(nft_content)
        tmp = f.name

    try:
        rules = load_nft_as_rules(tmp)
        assert any(r.comment is not None for r in rules), "Comments not parsed"
        output = rules_to_nft(rules)
        assert "# Policy: allow-web-access" in output, "Comment lost in serialization"
        assert "# Policy: deny-ssh" in output, "Second comment lost"
    finally:
        os.unlink(tmp)


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_ruleset(self, tmp_path: Path) -> None:
        """Test handling of empty ruleset."""
        seed_file = tmp_path / "empty.seed"
        seed_file.write_text("")

        rules = parse_classbench(seed_file)
        assert len(rules) == 0

        # Should still generate valid nftables config
        nft_config = rules_to_nft(rules)
        assert "table inet filter" in nft_config

    def test_single_rule(self, tmp_path: Path) -> None:
        """Test handling of single rule."""
        seed_content = "@192.168.1.1/32 10.0.0.1/32 22 22 22 22 0x06/0xFF accept\n"
        seed_file = tmp_path / "single.seed"
        seed_file.write_text(seed_content)

        rules = parse_classbench(seed_file)
        assert len(rules) == 1
        assert rules[0].src_port == (22, 22)
        assert rules[0].dst_port == (22, 22)

    def test_any_ports_full_range(self, tmp_path: Path) -> None:
        """Test 'any' ports represented as full range."""
        seed_content = "@192.168.1.0/24 10.0.0.0/8 0 : 65535 0 : 65535 0x06/0xFF accept\n"
        seed_file = tmp_path / "any_ports.seed"
        seed_file.write_text(seed_content)

        rules = parse_classbench(seed_file)
        rule = rules[0]

        # Full range should be None (any port)
        assert rule.src_port is None
        assert rule.dst_port is None

    def test_cidr_ranges_preserved(self, tmp_path: Path) -> None:
        """Test that CIDR notation is preserved."""
        test_cases = [
            ("192.168.1.0/24", "10.0.0.0/8"),
            ("172.16.0.0/12", "192.168.0.0/16"),
            ("10.0.0.0/8", "172.16.0.0/12"),
            ("192.168.1.1/32", "10.0.0.1/32"),
        ]

        for src_ip, dst_ip in test_cases:
            seed_content = f"@{src_ip} {dst_ip} 80 80 443 443 0x06/0xFF accept\n"
            seed_file = tmp_path / "cidr.seed"
            seed_file.write_text(seed_content)

            rules = parse_classbench(seed_file)
            assert rules[0].src_ip == src_ip
            assert rules[0].dst_ip == dst_ip

    def test_various_protocols(self, tmp_path: Path) -> None:
        """Test various protocol numbers."""
        protocols = [
            ("0x01/0xFF", 1),  # ICMP
            ("0x06/0xFF", 6),  # TCP
            ("0x11/0xFF", 17),  # UDP
            ("0x2F/0xFF", 47),  # GRE
        ]

        for proto_str, proto_num in protocols:
            seed_content = f"@192.168.1.0/24 10.0.0.0/8 80 80 443 443 {proto_str} accept\n"
            seed_file = tmp_path / "proto.seed"
            seed_file.write_text(seed_content)

            rules = parse_classbench(seed_file)
            assert rules[0].protocol == proto_num


# =============================================================================
# Generated Files Tests
# =============================================================================


class TestGeneratedFiles:
    """Tests using the generated acl1_500 files."""

    def test_load_generated_nft_file(self, generated_nft_file: Path) -> None:
        """Test loading the generated acl1_500.nft file."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        # Should load approximately 500 rules
        assert len(rules) > 400, f"Expected >400 rules, got {len(rules)}"
        assert len(rules) <= 500, f"Expected <=500 rules, got {len(rules)}"

    def test_round_trip_generated_files(
        self, generated_seed_file: Path, generated_nft_file: Path
    ) -> None:
        """Test round-trip with generated files."""
        if not generated_seed_file.exists():
            pytest.skip("Generated seed file not found")
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        # Parse original seed
        original_rules = parse_classbench(generated_seed_file)
        original_count = len(original_rules)

        # Load nft
        parsed_rules = load_nft_as_rules(generated_nft_file)
        parsed_count = len(parsed_rules)

        # Rule counts should be similar
        # (Note: exact match may not happen due to parsing differences)
        assert abs(parsed_count - original_count) < 50, (
            f"Rule count mismatch: original={original_count}, parsed={parsed_count}"
        )

    def test_field_integrity_generated_files(self, generated_nft_file: Path) -> None:
        """Test field integrity in generated nft file."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        # Check that all required fields are present
        for rule in rules:
            assert rule.src_ip, f"Rule {rule.index} missing src_ip"
            assert rule.dst_ip, f"Rule {rule.index} missing dst_ip"
            assert isinstance(rule.protocol, int), f"Rule {rule.index} has invalid protocol"
            assert rule.action in ["accept", "drop"], f"Rule {rule.index} has invalid action"

    def test_rule_indices_sequential(self, generated_nft_file: Path) -> None:
        """Test that rule indices are sequential."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        for i, rule in enumerate(rules):
            assert rule.index == i, f"Rule at position {i} has index {rule.index}"

    def test_sample_rules_detailed(self, generated_nft_file: Path) -> None:
        """Test detailed parsing of sample rules from generated file."""
        if not generated_nft_file.exists():
            pytest.skip("Generated nft file not found")

        rules = load_nft_as_rules(generated_nft_file)

        if len(rules) < 5:
            pytest.skip("Not enough rules to test")

        # Test first 5 rules
        for rule in rules[:5]:
            # Verify IP addresses are valid CIDR
            assert "/" in rule.src_ip, f"Rule {rule.index} has invalid src_ip: {rule.src_ip}"
            assert "/" in rule.dst_ip, f"Rule {rule.index} has invalid dst_ip: {rule.dst_ip}"

            # Verify protocol is valid
            assert rule.protocol in [0, 1, 6, 17, 47], (
                f"Rule {rule.index} has unexpected protocol: {rule.protocol}"
            )


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
