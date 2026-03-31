"""NOTE: This module is DEPRECATED(v2.2). See autoresearch.py for the active loop."""

"""
===============================================================================
Counter Reader - nftables Rule Statistics Module
===============================================================================

Purpose: Read and analyze nftables counter statistics from firewall container.

This module provides:
  - CounterReader class for reading nftables counters
  - Parse nftables output with regex
  - Calculate hit rates and statistics
  - Reset counters functionality

Usage:
    reader = CounterReader(container_name="clab-autonp-fw")

    # Read all counters
    counters = reader.read_counters()

    # Get hit rates
    hit_rates = reader.get_hit_rates()

    # Reset counters
    success = reader.reset_counters()

Examples:
    >>> reader = CounterReader()
    >>> data = reader.read_counters()
    >>> print(f"Total packets: {data['total_packets']}")
    >>> print(f"Rule 0 hits: {data['rules'][0]['packets']}")

===============================================================================
"""

import logging
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class CounterReader:
    """
    Read and analyze nftables counter statistics from a container.

    This class provides methods to:
    - Read counter values from nftables ruleset
    - Parse rule handles, packet counts, and byte counts
    - Calculate hit rates and statistics
    - Reset counters to zero

    Attributes:
        container_name: Name of the Docker container running nftables
        timeout_seconds: Timeout for subprocess commands
    """

    # Regex pattern to parse counter lines from nft output
    # Matches: "... counter packets N bytes M ... # handle X"
    COUNTER_PATTERN = re.compile(
        r"counter\s+packets\s+(\d+)\s+bytes\s+(\d+).*#\s*handle\s+(\d+)", re.IGNORECASE
    )

    # Regex pattern for lines without explicit handle (fallback)
    COUNTER_PATTERN_NO_HANDLE = re.compile(
        r"counter\s+packets\s+(\d+)\s+bytes\s+(\d+)", re.IGNORECASE
    )

    DEFAULT_TIMEOUT: int = 30

    def __init__(self, container_name: str = "clab-autonp-fw", timeout_seconds: int = 30):
        """
        Initialize the CounterReader.

        Args:
            container_name: Name of the Docker container running nftables.
                          Default: "clab-autonp-fw"
            timeout_seconds: Timeout for subprocess commands in seconds.
                           Default: 30
        """
        self.container_name = container_name
        self.timeout_seconds = timeout_seconds
        self._last_counters: dict[str, Any] | None = None

        logger.debug(
            f"CounterReader initialized: container={container_name}, timeout={timeout_seconds}s"
        )

    def _run_nft_command(self, args: list[str]) -> tuple[bool, str]:
        """
        Run an nft command in the container.

        Args:
            args: List of arguments for the nft command

        Returns:
            Tuple of (success, output_or_error)
        """
        cmd = ["docker", "exec", self.container_name, "nft"] + args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                logger.error(f"nft command failed: {error_msg}")
                return False, error_msg

        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {self.timeout_seconds}s"
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = "Docker command not found. Is Docker installed?"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Command failed: {e}"
            logger.error(error_msg)
            return False, error_msg

    # DEPRECATED(v2.2): read_counters — iperf3/Containerlab not wired. Kept for future integration.
    def read_counters(self) -> dict[str, Any]:
        """
        Read all counter values from the nftables ruleset.

        Uses 'nft list ruleset -a' to get counters with rule handles.
        Parses output to extract packets, bytes, and handles for each rule.

        Returns:
            Dictionary containing:
                - rules: List of rule counter data, each with:
                    - index: Rule index (0-based)
                    - packets: Packet count
                    - bytes: Byte count
                    - handle: Rule handle ID
                - total_packets: Sum of all packet counts
                - total_bytes: Sum of all byte counts
                - rule_count: Total number of rules with counters

        Example:
            {
                "rules": [
                    {"index": 0, "packets": 1000, "bytes": 50000, "handle": 10},
                    {"index": 1, "packets": 500, "bytes": 25000, "handle": 11},
                ],
                "total_packets": 1500,
                "total_bytes": 75000,
                "rule_count": 2
            }
        """
        logger.info(f"Reading counters from {self.container_name}")

        # Get ruleset with handles (-a flag)
        success, output = self._run_nft_command(["list", "ruleset", "-a"])

        if not success:
            logger.error(f"Failed to read counters: {output}")
            self._last_counters = self._empty_counters()
            return self._last_counters

        # Parse counters from output
        rules = []
        total_packets = 0
        total_bytes = 0

        lines = output.split("\n")
        rule_index = 0

        for line in lines:
            line = line.strip()

            # Skip empty lines, comments, and non-rule lines
            if not line or line.startswith("#"):
                continue

            # Skip structural lines (table, chain definitions)
            if any(keyword in line for keyword in ["table", "chain", "type", "hook", "policy"]):
                continue

            # Look for counter pattern with handle
            match = self.COUNTER_PATTERN.search(line)

            if match:
                packets = int(match.group(1))
                bytes_count = int(match.group(2))
                handle = int(match.group(3))

                rules.append(
                    {
                        "index": rule_index,
                        "packets": packets,
                        "bytes": bytes_count,
                        "handle": handle,
                    }
                )

                total_packets += packets
                total_bytes += bytes_count
                rule_index += 1

            else:
                # Fallback: try pattern without explicit handle
                match = self.COUNTER_PATTERN_NO_HANDLE.search(line)
                if match:
                    packets = int(match.group(1))
                    bytes_count = int(match.group(2))

                    rules.append(
                        {
                            "index": rule_index,
                            "packets": packets,
                            "bytes": bytes_count,
                            "handle": None,  # Handle not available
                        }
                    )

                    total_packets += packets
                    total_bytes += bytes_count
                    rule_index += 1

        result = {
            "rules": rules,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "rule_count": len(rules),
        }

        self._last_counters = result

        logger.info(
            f"Read {len(rules)} rules: {total_packets} total packets, {total_bytes} total bytes"
        )

        return result

    def _empty_counters(self) -> dict[str, Any]:
        """Return empty counters structure."""
        return {
            "rules": [],
            "total_packets": 0,
            "total_bytes": 0,
            "rule_count": 0,
        }

    # DEPRECATED(v2.2): get_hit_rates — iperf3/Containerlab not wired. Kept for future integration.
    def get_hit_rates(self) -> dict[int, float]:
        """
        Calculate hit rate for each rule as a proportion of total traffic.

        Hit rate is calculated as: rule_packets / total_packets
        Returns 0.0 for rules if total_packets is 0.

        Returns:
            Dictionary mapping rule index -> hit rate (0.0 to 1.0)

        Example:
            {0: 0.5, 1: 0.3, 2: 0.2}  # Rule 0 got 50% of hits
        """
        # Get current counters if not already read
        if self._last_counters is None:
            self.read_counters()

        counters = self._last_counters or self._empty_counters()
        total_packets = counters.get("total_packets", 0)
        rules = counters.get("rules", [])

        hit_rates = {}

        if total_packets == 0:
            # No traffic recorded, all rates are 0
            for rule in rules:
                hit_rates[rule["index"]] = 0.0
        else:
            for rule in rules:
                index = rule["index"]
                packets = rule["packets"]
                hit_rates[index] = packets / total_packets

        logger.debug(f"Calculated hit rates for {len(hit_rates)} rules")
        return hit_rates

    # DEPRECATED(v2.2): get_statistics — iperf3/Containerlab not wired. Kept for future integration.
    def get_statistics(self) -> dict[str, Any]:
        """
        Calculate comprehensive counter statistics.

        Returns:
            Dictionary containing:
                - total_packets: Total packets across all rules
                - total_bytes: Total bytes across all rules
                - rule_count: Number of rules
                - most_hit_rule: Index of rule with most hits (or None)
                - least_hit_rule: Index of rule with least hits (or None)
                - avg_packets_per_rule: Average packets per rule
                - max_packets: Maximum packets on any single rule
                - min_packets: Minimum packets on any single rule
                - zero_hit_rules: List of rule indices with zero hits

        Example:
            {
                "total_packets": 10000,
                "total_bytes": 500000,
                "rule_count": 100,
                "most_hit_rule": 0,
                "least_hit_rule": 99,
                "avg_packets_per_rule": 100.0,
                "max_packets": 5000,
                "min_packets": 0,
                "zero_hit_rules": [45, 67, 89]
            }
        """
        # Get current counters if not already read
        if self._last_counters is None:
            self.read_counters()

        counters = self._last_counters or self._empty_counters()
        rules = counters.get("rules", [])
        total_packets = counters.get("total_packets", 0)
        total_bytes = counters.get("total_bytes", 0)
        rule_count = len(rules)

        if rule_count == 0:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "rule_count": 0,
                "most_hit_rule": None,
                "least_hit_rule": None,
                "avg_packets_per_rule": 0.0,
                "max_packets": 0,
                "min_packets": 0,
                "zero_hit_rules": [],
            }

        # Find most/least hit rules
        packet_counts = [(r["index"], r["packets"]) for r in rules]
        packet_counts.sort(key=lambda x: x[1], reverse=True)

        most_hit_rule = packet_counts[0][0] if packet_counts else None
        least_hit_rule = packet_counts[-1][0] if packet_counts else None

        max_packets = packet_counts[0][1] if packet_counts else 0
        min_packets = packet_counts[-1][1] if packet_counts else 0

        avg_packets = total_packets / rule_count if rule_count > 0 else 0.0

        zero_hit_rules = [idx for idx, count in packet_counts if count == 0]

        result = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "rule_count": rule_count,
            "most_hit_rule": most_hit_rule,
            "least_hit_rule": least_hit_rule,
            "avg_packets_per_rule": avg_packets,
            "max_packets": max_packets,
            "min_packets": min_packets,
            "zero_hit_rules": zero_hit_rules,
        }

        logger.debug(
            f"Statistics: most_hit={most_hit_rule}, least_hit={least_hit_rule}, "
            f"zero_hit_count={len(zero_hit_rules)}"
        )

        return result

    # DEPRECATED(v2.2): reset_counters — iperf3/Containerlab not wired. Kept for future integration.
    def reset_counters(self) -> bool:
        """
        Reset all nftables counters to zero.

        Uses 'nft reset counters table inet filter' to reset all counters
        in the filter table. Falls back to resetting all counters if
        specific table reset fails.

        Returns:
            True if counters were reset successfully, False otherwise
        """
        logger.info(f"Resetting counters in {self.container_name}")

        # Try to reset counters in the filter table first
        success, output = self._run_nft_command(["reset", "counters", "table", "inet", "filter"])

        if success:
            logger.info("Counters reset successfully")
            # Clear cached counters
            self._last_counters = None
            return True

        # Fallback: try resetting all counters
        logger.warning(f"Table-specific reset failed, trying global reset: {output}")
        success, output = self._run_nft_command(["reset", "counters"])

        if success:
            logger.info("Counters reset successfully (global)")
            self._last_counters = None
            return True

        logger.error(f"Failed to reset counters: {output}")
        return False

    # DEPRECATED(v2.2): get_counter_by_handle — iperf3/Containerlab not wired. Kept for future integration.
    def get_counter_by_handle(self, handle: int) -> dict[str, Any] | None:
        """
        Get counter data for a specific rule handle.

        Args:
            handle: The rule handle ID to look up

        Returns:
            Counter data dict if found, None otherwise
        """
        # Get current counters if not already read
        if self._last_counters is None:
            self.read_counters()

        counters = self._last_counters or self._empty_counters()
        rules = counters.get("rules", [])

        for rule in rules:
            if rule.get("handle") == handle:
                return rule.copy()

        return None

    # DEPRECATED(v2.2): get_counter_by_index — iperf3/Containerlab not wired. Kept for future integration.
    def get_counter_by_index(self, index: int) -> dict[str, Any] | None:
        """
        Get counter data for a specific rule index.

        Args:
            index: The rule index (0-based) to look up

        Returns:
            Counter data dict if found, None otherwise
        """
        # Get current counters if not already read
        if self._last_counters is None:
            self.read_counters()

        counters = self._last_counters or self._empty_counters()
        rules = counters.get("rules", [])

        for rule in rules:
            if rule["index"] == index:
                return rule.copy()

        return None


# DEPRECATED(v2.2): main — iperf3/Containerlab not wired. Kept for future integration.
def main():
    """CLI entry point for counter reading."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Read nftables counters from firewall container",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python counter_reader.py
    python counter_reader.py --container clab-autonp-fw
    python counter_reader.py --stats
    python counter_reader.py --reset
    python counter_reader.py --output counters.json
        """,
    )

    parser.add_argument(
        "--container",
        "-c",
        default="clab-autonp-fw",
        help="Container name (default: clab-autonp-fw)",
    )

    parser.add_argument(
        "--stats",
        "-s",
        action="store_true",
        help="Show detailed statistics",
    )

    parser.add_argument(
        "--reset",
        "-r",
        action="store_true",
        help="Reset counters",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output file for results (JSON format)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create reader
    reader = CounterReader(container_name=args.container)

    # Handle reset command
    if args.reset:
        success = reader.reset_counters()
        if success:
            print("Counters reset successfully")
            sys.exit(0)
        else:
            print("Failed to reset counters", file=sys.stderr)
            sys.exit(1)

    # Read counters
    counters = reader.read_counters()

    # Build output
    output_data = dict(counters)

    if args.stats:
        output_data["statistics"] = reader.get_statistics()
        output_data["hit_rates"] = reader.get_hit_rates()

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Results written to: {args.output}")
    else:
        print(json.dumps(output_data, indent=2))

    sys.exit(0)


if __name__ == "__main__":
    main()
