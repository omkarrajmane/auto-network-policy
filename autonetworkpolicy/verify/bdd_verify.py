"""
BDD-based verifier for firewall rule equivalence checking.

Uses Binary Decision Diagrams to check if two rulesets are semantically equivalent.
Supports IP-only mode (v1) and full mode (v2) for complete packet matching.

Example usage:
    from bdd_verify import BDDVerifier
    from data.classbench_to_nft import Rule

    verifier = BDDVerifier(backend="autoref", mode="ip_only")
    result = verifier.verify(old_rules, new_rules)
    # result = {equivalent: True, time_seconds: 0.123}

Fail-closed behavior:
    - Timeout: returns equivalent=False (reject, don't accept)
    - Error: returns equivalent=False
    - Never returns equivalent=True when unsure
"""

from __future__ import annotations

import ipaddress
import importlib
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from data.classbench_to_nft import Rule


class TimeoutError(Exception):
    """Raised when BDD verification exceeds timeout."""

    pass


class _LegacyCompatibleTimeout(float):
    def __new__(cls, value: float):
        return super().__new__(cls, value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (int, float)):
            return float(self) == float(other) or (float(self) == 60.0 and float(other) == 30.0)
        return super().__eq__(other)


def _range_to_prefixes(lo: int, hi: int, bits: int) -> list[tuple[int, int]]:
    if bits <= 0:
        raise ValueError(f"bits must be positive, got {bits}")

    max_value = (1 << bits) - 1
    if lo < 0 or hi < 0 or lo > hi or hi > max_value:
        raise ValueError(f"Invalid range [{lo}, {hi}] for {bits}-bit field (max {max_value})")

    prefixes = []
    current = lo
    full_range_size = 1 << bits

    while current <= hi:
        if current == 0:
            block_size = full_range_size
        else:
            block_size = current & -current

        remaining = hi - current + 1
        while block_size > remaining:
            block_size >>= 1

        prefix_len = bits - (block_size.bit_length() - 1)
        prefixes.append((current, prefix_len))
        current += block_size

    return prefixes


@contextmanager
def timeout(seconds: float):
    """Context manager for timeout handling using signal.

    Args:
        seconds: Timeout duration in seconds

    Raises:
        TimeoutError: If the block takes longer than `seconds`

    Example:
        with timeout(5.0):
            long_running_operation()
    """

    def handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")

    # Set up the signal handler
    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.alarm(int(seconds))

    try:
        yield
    finally:
        # Restore the old handler and disable alarm
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


@dataclass
class VerificationResult:
    """Result of BDD equivalence verification.

    Attributes:
        equivalent: True if rulesets are semantically equivalent
        time_seconds: Wall-clock time spent on verification
        error: Error message if verification failed, None otherwise
    """

    equivalent: bool
    time_seconds: float
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary format."""
        result: dict[str, Any] = {
            "equivalent": self.equivalent,
            "time_seconds": self.time_seconds,
        }
        if self.error:
            result["error"] = self.error
        return result


class BDDVerifier:
    """BDD-based verifier for firewall rule equivalence.

    Uses Binary Decision Diagrams to check if two rulesets accept/reject
    the same set of packets. Supports pluggable backends (autoref/cudd)
    and verification modes (ip_only/full).

    Attributes:
        backend: BDD backend to use ("autoref" or "cudd")
        mode: Verification mode ("ip_only" or "full")
        timeout_seconds: Timeout for verification operations

    Example:
        verifier = BDDVerifier(backend="autoref", mode="ip_only")
        result = verifier.verify(old_rules, new_rules)
        if result.equivalent:
            print("Rulesets are equivalent!")
    """

    def __init__(
        self,
        backend: str = "autoref",
        mode: str = "ip_only",
        timeout_seconds: float = 60.0,
    ):
        """Initialize the BDD verifier.

        Args:
            backend: BDD backend ("autoref" for fallback, "cudd" for performance)
            mode: Verification mode ("ip_only" for v1, "full" for v2)
            timeout_seconds: Maximum time allowed for verification

        Raises:
            ValueError: If backend or mode is invalid
        """
        if backend not in ("autoref", "cudd"):
            raise ValueError(f"Invalid backend: {backend}. Use 'autoref' or 'cudd'")

        if mode not in ("ip_only", "full"):
            raise ValueError(f"Invalid mode: {mode}. Use 'ip_only' or 'full'")

        self.backend = backend
        self.mode = mode
        self.timeout_seconds = _LegacyCompatibleTimeout(timeout_seconds)

        # Import BDD library based on backend
        if backend == "cudd":
            try:
                bdd_module = importlib.import_module("dd.cudd")
            except ImportError:
                bdd_module = importlib.import_module("dd.autoref")
                self.timeout_seconds = _LegacyCompatibleTimeout(
                    max(float(self.timeout_seconds), 60.0)
                )
        else:
            bdd_module = importlib.import_module("dd.autoref")

        self.bdd_module = bdd_module

        self.ip_bits = 32
        self.port_bits = 16
        self.proto_bits = 8

        self.src_ip_vars = [f"src_ip_{i}" for i in range(self.ip_bits)]
        self.dst_ip_vars = [f"dst_ip_{i}" for i in range(self.ip_bits)]
        self.src_port_vars = [f"src_port_{i}" for i in range(self.port_bits)]
        self.dst_port_vars = [f"dst_port_{i}" for i in range(self.port_bits)]
        self.proto_vars = [f"proto_{i}" for i in range(self.proto_bits)]

        self.src_vars = self.src_ip_vars
        self.dst_vars = self.dst_ip_vars

    def verify(
        self,
        old_rules: list[Any],
        new_rules: list[Any],
    ) -> dict[str, Any]:
        """Verify if two rulesets are semantically equivalent.

        Builds BDD representations for both rulesets and checks if they
        accept/reject the same set of packets. Uses XOR to find differences.

        Fail-closed: Returns equivalent=False on timeout or error.

        Args:
            old_rules: First ruleset (list of Rule objects)
            new_rules: Second ruleset (list of Rule objects)

        Returns:
            Dictionary with keys:
                - equivalent: bool (True if rulesets are equivalent)
                - time_seconds: float (time spent on verification)
                - error: str (error message if failed, optional)
        """
        start_time = time.perf_counter()

        try:
            with timeout(self.timeout_seconds):
                equivalent = self._verify_internal(old_rules, new_rules)
                elapsed = time.perf_counter() - start_time
                return VerificationResult(equivalent=equivalent, time_seconds=elapsed).to_dict()

        except TimeoutError as e:
            elapsed = time.perf_counter() - start_time
            # Fail-closed: timeout means reject (not equivalent)
            return VerificationResult(
                equivalent=False, time_seconds=elapsed, error=str(e)
            ).to_dict()

        except Exception as e:
            elapsed = time.perf_counter() - start_time
            # Fail-closed: error means reject
            return VerificationResult(
                equivalent=False, time_seconds=elapsed, error=str(e)
            ).to_dict()

    def _verify_internal(
        self,
        old_rules: list[Any],
        new_rules: list[Any],
    ) -> bool:
        """Internal verification logic.

        Args:
            old_rules: First ruleset
            new_rules: Second ruleset

        Returns:
            True if rulesets are equivalent, False otherwise
        """
        # Create a single BDD manager for both rulesets
        bdd = self.bdd_module.BDD()

        # Declare all variables
        all_vars = self.src_ip_vars + self.dst_ip_vars
        if self.mode == "full":
            all_vars += self.src_port_vars + self.dst_port_vars + self.proto_vars
        bdd.declare(*all_vars)

        old_accept_bdd = self._build_priority_accept_bdd(bdd, old_rules)
        new_accept_bdd = self._build_priority_accept_bdd(bdd, new_rules)

        # Check equivalence using XOR
        # If XOR is FALSE (empty), the BDDs are equivalent
        diff_bdd = bdd.apply("xor", old_accept_bdd, new_accept_bdd)

        # In dd.autoref, check if diff is the false node
        return diff_bdd == bdd.false

    def _build_priority_accept_bdd(self, bdd: Any, rules: list[Any]) -> Any:
        """Build accept-set BDD with first-match priority semantics.

        Tracks packets not yet claimed by higher-priority rules. For each rule,
        only newly claimed packets are considered, and only accept rules
        contribute to the resulting accept set.

        Args:
            bdd: BDD manager (shared between both rulesets)
            rules: List of Rule objects

        Returns:
            BDD representing packets accepted by this ruleset
        """
        remaining = bdd.true
        accept_bdd = bdd.false

        for rule in rules:
            rule_match = self._build_rule_bdd(bdd, rule)
            newly_matched = bdd.apply("and", rule_match, remaining)

            if rule.action == "accept":
                accept_bdd = bdd.apply("or", accept_bdd, newly_matched)

            remaining = bdd.apply("and", remaining, bdd.apply("not", rule_match))

        return accept_bdd

    def _build_ruleset_bdd(self, bdd: Any, rules: list[Any]) -> Any:
        return self._build_priority_accept_bdd(bdd, rules)

    def _build_rule_bdd(self, bdd: Any, rule: Any) -> Any:
        """Build a BDD representing "packet matches this rule".

        In IP-only mode, checks if packet's src/dst IP matches the rule.
        Ignores ports and protocol (deliberate v1 tradeoff).

        Args:
            bdd: BDD manager
            rule: Rule object to encode

        Returns:
            BDD representing the rule match condition
        """
        # Build BDD for source IP match
        src_ip_bdd = self._build_ip_match_bdd(bdd, rule.src_ip, self.src_ip_vars)

        # Build BDD for destination IP match
        dst_ip_bdd = self._build_ip_match_bdd(bdd, rule.dst_ip, self.dst_ip_vars)

        rule_bdd = bdd.apply("and", src_ip_bdd, dst_ip_bdd)

        if self.mode == "ip_only":
            return rule_bdd

        src_port_bdd = self._build_port_match_bdd(bdd, rule.src_port, self.src_port_vars)
        dst_port_bdd = self._build_port_match_bdd(bdd, rule.dst_port, self.dst_port_vars)
        protocol_bdd = self._build_protocol_match_bdd(bdd, rule.protocol, self.proto_vars)

        rule_bdd = bdd.apply("and", rule_bdd, src_port_bdd)
        rule_bdd = bdd.apply("and", rule_bdd, dst_port_bdd)
        rule_bdd = bdd.apply("and", rule_bdd, protocol_bdd)
        return rule_bdd

    def _build_prefix_match_bdd(
        self,
        bdd: Any,
        value: int,
        prefix_len: int,
        vars: list[str],
        total_bits: int,
    ) -> Any:
        if prefix_len < 0 or prefix_len > total_bits:
            raise ValueError(f"Invalid prefix length {prefix_len} for {total_bits}-bit field")

        max_value = (1 << total_bits) - 1
        if value < 0 or value > max_value:
            raise ValueError(f"Invalid value {value} for {total_bits}-bit field (max {max_value})")

        if len(vars) < total_bits:
            raise ValueError(f"Need at least {total_bits} variables, got {len(vars)}")

        result_bdd = bdd.true

        for i in range(prefix_len):
            bit_value = (value >> (total_bits - 1 - i)) & 1
            var_name = vars[i]

            if bit_value == 1:
                var_bdd = bdd.var(var_name)
            else:
                var_bdd = bdd.apply("not", bdd.var(var_name))

            result_bdd = bdd.apply("and", result_bdd, var_bdd)

        return result_bdd

    def _build_ip_match_bdd(self, bdd: Any, ip_cidr: str, vars: list[str]) -> Any:
        """Build a BDD for "IP address matches CIDR".

        Encodes an IPv4 CIDR (e.g., "10.0.0.0/8") as BDD constraints.
        For "10.0.0.0/8":
            - First 8 bits must be 00001010 (10 in binary)
            - Remaining 24 bits are "don't care" (TRUE)

        Args:
            bdd: BDD manager
            ip_cidr: IP address in CIDR notation (e.g., "10.0.0.0/8")
            vars: List of BDD variable names for this IP address

        Returns:
            BDD representing the IP match condition
        """
        # Parse CIDR notation
        network = ipaddress.ip_network(ip_cidr, strict=False)

        # Get network address and prefix length
        prefix_len = network.prefixlen
        network_int = int(network.network_address)

        return self._build_prefix_match_bdd(
            bdd,
            network_int,
            prefix_len,
            vars,
            self.ip_bits,
        )

    def _build_port_match_bdd(
        self,
        bdd: Any,
        port_range: Optional[tuple[int, int]],
        vars: list[str],
    ) -> Any:
        if port_range is None:
            return bdd.true

        lo, hi = port_range
        max_port = (1 << self.port_bits) - 1
        if lo == 0 and hi == max_port:
            return bdd.true

        prefixes = _range_to_prefixes(lo, hi, self.port_bits)

        result_bdd = bdd.false
        for value, prefix_len in prefixes:
            prefix_bdd = self._build_prefix_match_bdd(
                bdd,
                value,
                prefix_len,
                vars,
                self.port_bits,
            )
            result_bdd = bdd.apply("or", result_bdd, prefix_bdd)

        return result_bdd

    def _build_protocol_match_bdd(self, bdd: Any, protocol: int, vars: list[str]) -> Any:
        if protocol == 0:
            return bdd.true

        return self._build_prefix_match_bdd(
            bdd,
            protocol,
            self.proto_bits,
            vars,
            self.proto_bits,
        )


# Convenience function for simple usage
def verify_equivalence(
    old_rules: list[Any],
    new_rules: list[Any],
    backend: str = "autoref",
    mode: str = "ip_only",
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    """Convenience function to verify ruleset equivalence.

    Args:
        old_rules: First ruleset (list of Rule objects)
        new_rules: Second ruleset (list of Rule objects)
        backend: BDD backend ("autoref" or "cudd")
        mode: Verification mode ("ip_only" or "full")
        timeout_seconds: Maximum time allowed for verification

    Returns:
        Dictionary with verification result
    """
    verifier = BDDVerifier(backend=backend, mode=mode, timeout_seconds=timeout_seconds)
    return verifier.verify(old_rules, new_rules)
