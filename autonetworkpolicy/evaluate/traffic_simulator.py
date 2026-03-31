"""NOTE: This module is DEPRECATED(v2.2). See autoresearch.py for the active loop."""

"""
===============================================================================
FIXED FILE - traffic_simulator.py
===============================================================================

⚠️  WARNING: This file is FIXED and should NEVER be modified during experiments.

Purpose: Network traffic generation and measurement using iperf3/hping3
Contract:
  - Time budget enforcement (max duration)
  - Deterministic traffic patterns (same seed = same traffic)
  - Never modified during autoresearch loop
  - Fixed iperf3 wrapper with proper error handling

This file provides:
  - TCP throughput measurement (iperf3)
  - UDP latency/packet loss measurement (iperf3)
  - Containerlab integration for command execution
  - Standardized metrics collection

===============================================================================
"""

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TrafficMetrics:
    """Standardized traffic measurement results."""

    throughput_gbps: float
    latency_ms: float
    packet_loss_percent: float
    duration_seconds: float
    test_type: str
    success: bool
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary format."""
        return {
            "throughput_gbps": self.throughput_gbps,
            "latency_ms": self.latency_ms,
            "packet_loss_percent": self.packet_loss_percent,
            "duration_seconds": self.duration_seconds,
            "test_type": self.test_type,
            "success": self.success,
            "error_message": self.error_message,
        }


class TrafficSimulator:
    """
    Fixed traffic simulator for network policy evaluation.

    Generates controlled traffic patterns between client and server containers
    and collects standardized metrics.

    ⚠️  FIXED COMPONENT: Never modify during experiments
    """

    # Containerlab container naming convention
    CONTAINER_PREFIX: str = "clab-autonp"

    # Default server IP in the lab topology
    DEFAULT_SERVER_IP: str = "10.2.0.2"

    # iperf3 server port
    IPERF3_PORT: int = 5201

    # Time buffer for subprocess timeout (seconds)
    TIMEOUT_BUFFER: int = 10

    def __init__(
        self,
        client_host: str = "client",
        server_host: str = "server",
        duration: int = 30,
        max_total_duration: int = 120,
    ) -> None:
        """
        Initialize traffic simulator.

        Args:
            client_host: Client container name (without prefix)
            server_host: Server container name (without prefix)
            duration: Default test duration in seconds
            max_total_duration: Maximum allowed total time for all tests
        """
        self.client_container: str = f"{self.CONTAINER_PREFIX}-{client_host}"
        self.server_container: str = f"{self.CONTAINER_PREFIX}-{server_host}"
        self.duration: int = duration
        self.max_total_duration: int = max_total_duration
        self.server_ip: str = self.DEFAULT_SERVER_IP
        self._start_time: float | None = None
        self._remaining_budget: float = max_total_duration

        logger.info(
            f"TrafficSimulator initialized: client={self.client_container}, server={self.server_container}, duration={duration}s, max_budget={max_total_duration}s"
        )

    def _check_time_budget(self, required_seconds: int) -> bool:
        """
        Check if remaining time budget is sufficient.

        Args:
            required_seconds: Required time for the operation

        Returns:
            True if budget is sufficient, False otherwise
        """
        if self._start_time is None:
            self._start_time = time.time()

        elapsed = time.time() - self._start_time
        self._remaining_budget = self.max_total_duration - elapsed

        if self._remaining_budget < required_seconds:
            logger.warning(
                f"Time budget insufficient: need {required_seconds}s, have {self._remaining_budget:.1f}s"
            )
            return False
        return True

    def _exec_on_container(
        self, container: str, command: list[str], timeout: int = 60, check: bool = False
    ) -> tuple[int, str, str]:
        """
        Execute command on a container using docker exec.

        Args:
            container: Container name
            command: Command and arguments as list
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        full_command = ["docker", "exec", container] + command

        logger.debug(f"Executing: {' '.join(full_command)}")

        try:
            result = subprocess.run(full_command, capture_output=True, text=True, timeout=timeout)

            if check and result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, full_command, output=result.stdout, stderr=result.stderr
                )

            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timeout on {container}: {e}")
            return -1, "", f"Timeout after {timeout}s"
        except Exception as e:
            logger.error(f"Command failed on {container}: {e}")
            return -1, "", str(e)

    def _start_iperf3_server(self) -> bool:
        """
        Start iperf3 server on the server container.

        Returns:
            True if server started successfully
        """
        logger.info(f"Starting iperf3 server on {self.server_container}")

        # Kill any existing iperf3 server first
        _ = self._exec_on_container(self.server_container, ["pkill", "-f", "iperf3 -s"], timeout=5)
        time.sleep(0.5)  # Brief pause for process termination

        # Start new iperf3 server in background
        returncode, _stdout, stderr = self._exec_on_container(
            self.server_container,
            ["sh", "-c", f"iperf3 -s -p {self.IPERF3_PORT} -D -1"],
            timeout=10,
        )

        if returncode != 0:
            logger.error(f"Failed to start iperf3 server: {stderr}")
            return False

        # Wait for server to be ready
        time.sleep(1)

        # Verify server is listening
        _returncode, _stdout, _stderr = self._exec_on_container(
            self.server_container, ["ss", "-tlnp", "|", "grep", str(self.IPERF3_PORT)], timeout=5
        )

        logger.info("iperf3 server started successfully")
        return True

    def _parse_iperf3_json(self, json_output: str) -> dict[str, Any]:
        """
        Parse iperf3 JSON output.

        Args:
            json_output: Raw JSON string from iperf3

        Returns:
            Dictionary with parsed metrics
        """
        try:
            data = json.loads(json_output)

            metrics = {
                "throughput_gbps": 0.0,
                "latency_ms": 0.0,
                "packet_loss_percent": 0.0,
                "duration_seconds": 0.0,
                "success": False,
            }

            if "error" in data:
                logger.error(f"iperf3 reported error: {data['error']}")
                return metrics

            end_data = data.get("end", {})

            # TCP test results
            if "sum_received" in end_data:
                sum_received = end_data["sum_received"]
                bits_per_second = sum_received.get("bits_per_second", 0)
                metrics["throughput_gbps"] = bits_per_second / 1e9
                metrics["success"] = True

            # UDP test results
            if "sum" in end_data:
                sum_data = end_data["sum"]

                # Throughput
                if "bits_per_second" in sum_data:
                    metrics["throughput_gbps"] = sum_data["bits_per_second"] / 1e9

                # Jitter (latency indicator)
                if "jitter_ms" in sum_data:
                    metrics["latency_ms"] = sum_data["jitter_ms"]

                # Packet loss
                if "lost_packets" in sum_data and "packets" in sum_data:
                    lost = sum_data["lost_packets"]
                    total = sum_data["packets"]
                    if total > 0:
                        metrics["packet_loss_percent"] = (lost / total) * 100

                # Loss percentage directly
                if "lost_percent" in sum_data:
                    metrics["packet_loss_percent"] = sum_data["lost_percent"]

                metrics["success"] = True

            # Duration
            if "test_start" in data.get("start", {}):
                test_start = data["start"]["test_start"]
                if "duration" in test_start:
                    metrics["duration_seconds"] = test_start["duration"]

            return metrics

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse iperf3 JSON: {e}")
            return {
                "throughput_gbps": 0.0,
                "latency_ms": 0.0,
                "packet_loss_percent": 0.0,
                "duration_seconds": 0.0,
                "success": False,
            }

    def _run_iperf3_client(
        self, protocol: str = "tcp", duration: int | None = None, bandwidth: str | None = None
    ) -> dict[str, Any]:
        """
        Run iperf3 client test.

        Args:
            protocol: 'tcp' or 'udp'
            duration: Test duration in seconds (default: self.duration)
            bandwidth: Bandwidth limit for UDP (e.g., '100M')

        Returns:
            Dictionary with test results
        """
        test_duration = duration or self.duration

        # Check time budget
        required_time = test_duration + self.TIMEOUT_BUFFER
        if not self._check_time_budget(required_time):
            return {
                "throughput_gbps": 0.0,
                "latency_ms": 0.0,
                "packet_loss_percent": 100.0,
                "duration_seconds": 0.0,
                "test_type": protocol,
                "success": False,
                "error_message": "Time budget exceeded",
            }

        # Build iperf3 command
        cmd = [
            "iperf3",
            "-c",
            self.server_ip,
            "-p",
            str(self.IPERF3_PORT),
            "-t",
            str(test_duration),
            "-J",  # JSON output
        ]

        if protocol == "udp":
            cmd.append("-u")
            if bandwidth:
                cmd.extend(["-b", bandwidth])
            else:
                cmd.extend(["-b", "1G"])  # Default UDP bandwidth

        logger.info(f"Running iperf3 {protocol} test for {test_duration}s")

        returncode, stdout, stderr = self._exec_on_container(
            self.client_container, cmd, timeout=test_duration + self.TIMEOUT_BUFFER
        )

        if returncode != 0:
            logger.error(f"iperf3 client failed: {stderr}")
            return {
                "throughput_gbps": 0.0,
                "latency_ms": 0.0,
                "packet_loss_percent": 100.0,
                "duration_seconds": 0.0,
                "test_type": protocol,
                "success": False,
                "error_message": f"iperf3 failed: {stderr[:200]}",
            }

        # Parse results
        metrics = self._parse_iperf3_json(stdout)
        metrics["test_type"] = protocol

        return metrics

    # DEPRECATED(v2.2): run_tcp_test — iperf3/Containerlab not wired. Kept for future integration.
    def run_tcp_test(self, duration: int | None = None) -> dict[str, Any]:
        """
        Run TCP throughput test.

        Args:
            duration: Test duration in seconds (default: self.duration)

        Returns:
            Dictionary with metrics:
                - throughput_gbps: float
                - latency_ms: float
                - packet_loss_percent: float
                - duration_seconds: float
                - test_type: str
                - success: bool
                - error_message: str | None
        """
        logger.info("Starting TCP throughput test")

        # Ensure server is running
        if not self._start_iperf3_server():
            return TrafficMetrics(
                throughput_gbps=0.0,
                latency_ms=0.0,
                packet_loss_percent=100.0,
                duration_seconds=0.0,
                test_type="tcp",
                success=False,
                error_message="Failed to start iperf3 server",
            ).to_dict()

        # Run TCP test
        results = self._run_iperf3_client(protocol="tcp", duration=duration)

        logger.info(
            f"TCP test complete: {results.get('throughput_gbps', 0):.3f} Gbps, success={results.get('success', False)}"
        )

        return results

    # DEPRECATED(v2.2): run_udp_test — iperf3/Containerlab not wired. Kept for future integration.
    def run_udp_test(
        self, duration: int | None = None, bandwidth: str | None = None
    ) -> dict[str, Any]:
        """
        Run UDP latency and packet loss test.

        Args:
            duration: Test duration in seconds (default: self.duration)
            bandwidth: Target bandwidth (e.g., '100M', '1G')

        Returns:
            Dictionary with metrics:
                - throughput_gbps: float
                - latency_ms: float (jitter)
                - packet_loss_percent: float
                - duration_seconds: float
                - test_type: str
                - success: bool
                - error_message: str | None
        """
        logger.info("Starting UDP latency/packet loss test")

        # Ensure server is running
        if not self._start_iperf3_server():
            return TrafficMetrics(
                throughput_gbps=0.0,
                latency_ms=0.0,
                packet_loss_percent=100.0,
                duration_seconds=0.0,
                test_type="udp",
                success=False,
                error_message="Failed to start iperf3 server",
            ).to_dict()

        # Run UDP test
        results = self._run_iperf3_client(protocol="udp", duration=duration, bandwidth=bandwidth)

        logger.info(
            f"UDP test complete: jitter={results.get('latency_ms', 0):.2f}ms, loss={results.get('packet_loss_percent', 0):.2f}%, success={results.get('success', False)}"
        )

        return results

    # DEPRECATED(v2.2): run_connection_test — iperf3/Containerlab not wired. Kept for future integration.
    def run_connection_test(self, target_port: int = 80, packet_count: int = 3) -> dict[str, Any]:
        """
        Run basic connectivity test using hping3.

        Tests if connection can be established through firewall.

        Args:
            target_port: Target port to test
            packet_count: Number of packets to send

        Returns:
            Dictionary with connection test results
        """
        logger.info(f"Running connection test to port {target_port}")

        # Check time budget
        required_time = 15
        if not self._check_time_budget(required_time):
            return {
                "success": False,
                "error_message": "Time budget exceeded",
                "packets_sent": packet_count,
                "packets_received": 0,
                "success_rate": 0.0,
            }

        # Run hping3 SYN test
        cmd = [
            "hping3",
            "-S",  # SYN flag
            "-p",
            str(target_port),
            "-c",
            str(packet_count),
            self.server_ip,
        ]

        _returncode, stdout, stderr = self._exec_on_container(
            self.client_container, cmd, timeout=15
        )

        # Parse hping3 output
        received = 0
        success = False

        output = stdout + stderr

        # Look for responses in output
        if "flags=SA" in output or "flags=RA" in output:
            # Count successful responses
            received = output.count("flags=SA") + output.count("flags=RA")
            success = received > 0

        success_rate = (received / packet_count * 100) if packet_count > 0 else 0

        logger.info(
            f"Connection test: sent={packet_count}, received={received}, success_rate={success_rate:.1f}%"
        )

        return {
            "success": success,
            "packets_sent": packet_count,
            "packets_received": received,
            "success_rate": success_rate,
            "target_port": target_port,
            "raw_output": output[:500] if output else "",
        }

    # DEPRECATED(v2.2): get_remaining_budget — iperf3/Containerlab not wired. Kept for future integration.
    def get_remaining_budget(self) -> float:
        """Get remaining time budget in seconds."""
        if self._start_time is None:
            return self.max_total_duration

        elapsed = time.time() - self._start_time
        return max(0, self.max_total_duration - elapsed)

    # DEPRECATED(v2.2): reset_budget — iperf3/Containerlab not wired. Kept for future integration.
    def reset_budget(self):
        """Reset the time budget tracker."""
        self._start_time = None
        self._remaining_budget = self.max_total_duration
        logger.info("Time budget reset")


# Convenience function for quick testing
# DEPRECATED(v2.2): quick_test — iperf3/Containerlab not wired. Kept for future integration.
def quick_test(duration: int = 10, tcp: bool = True, udp: bool = True) -> dict[str, dict[str, Any]]:
    """
    Run quick traffic tests and return results.

    Args:
        duration: Test duration per test
        tcp: Run TCP test
        udp: Run UDP test

    Returns:
        Dictionary with test results
    """
    simulator = TrafficSimulator(duration=duration)
    results = {}

    if tcp:
        results["tcp"] = simulator.run_tcp_test()

    if udp:
        results["udp"] = simulator.run_udp_test()

    return results


if __name__ == "__main__":
    # Simple CLI for testing
    import sys

    logging.basicConfig(level=logging.INFO)

    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10

    print(f"Running traffic tests (duration={duration}s)...")
    results = quick_test(duration=duration)

    print("\n=== Results ===")
    print(json.dumps(results, indent=2))
