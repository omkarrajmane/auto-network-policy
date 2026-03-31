"""NOTE: This module is DEPRECATED(v2.2). See autoresearch.py for the active loop."""

"""
===============================================================================
iperf3 Wrapper Module - Standardized Network Testing
===============================================================================

Purpose: Clean abstraction for iperf3 server and client operations.

This module provides:
  - Iperf3Server: Manage iperf3 server lifecycle in containers
  - Iperf3Client: Run TCP/UDP tests and parse results
  - Iperf3Result: Structured result dataclass

Usage:
    # Server management
    server = Iperf3Server(container="clab-autonp-server")
    server.start()
    if server.is_running():
        # Run tests...
    server.stop()

    # Client testing
    client = Iperf3Client(
        client_container="clab-autonp-client",
        server_ip="10.2.0.2",
        server_port=5201
    )
    result = client.run_tcp_test(duration=30)
    print(f"Throughput: {result.throughput_mbps:.2f} Mbps")

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
class Iperf3Result:
    """
    Standardized iperf3 test result container.

    Attributes:
        throughput_mbps: Measured throughput in megabits per second
        retransmits: Number of TCP retransmissions (TCP tests only)
        jitter_ms: Jitter in milliseconds (UDP tests only)
        packet_loss_percent: Packet loss percentage (UDP tests only)
        duration_seconds: Test duration in seconds
        success: Whether the test completed successfully
        error_message: Error description if success is False
    """

    throughput_mbps: float
    retransmits: int
    jitter_ms: float
    packet_loss_percent: float
    duration_seconds: float
    success: bool
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            "throughput_mbps": self.throughput_mbps,
            "retransmits": self.retransmits,
            "jitter_ms": self.jitter_ms,
            "packet_loss_percent": self.packet_loss_percent,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Iperf3Result":
        """Create Iperf3Result from dictionary."""
        return cls(
            throughput_mbps=data.get("throughput_mbps", 0.0),
            retransmits=data.get("retransmits", 0),
            jitter_ms=data.get("jitter_ms", 0.0),
            packet_loss_percent=data.get("packet_loss_percent", 0.0),
            duration_seconds=data.get("duration_seconds", 0.0),
            success=data.get("success", False),
            error_message=data.get("error_message"),
        )


class Iperf3Server:
    """
    Manages iperf3 server lifecycle in a container.

    This class handles starting, stopping, and checking the status
    of an iperf3 server running inside a Docker container.

    Example:
        server = Iperf3Server(container="clab-autonp-server", port=5201)
        if server.start():
            # Server is ready for tests
            time.sleep(30)  # Run tests
            server.stop()
    """

    def __init__(
        self,
        container: str,
        port: int = 5201,
        bind_address: str | None = None,
    ) -> None:
        """
        Initialize iperf3 server manager.

        Args:
            container: Docker container name where server will run
            port: Port for iperf3 server to listen on
            bind_address: Optional address to bind to (default: all interfaces)
        """
        self.container = container
        self.port = port
        self.bind_address = bind_address
        self._process_running = False

        logger.debug(f"Iperf3Server initialized: container={container}, port={port}")

    def _exec_on_container(
        self, command: list[str], timeout: int = 10, check: bool = False
    ) -> tuple[int, str, str]:
        """
        Execute command on the server container.

        Args:
            command: Command and arguments as list
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        full_command = ["docker", "exec", self.container] + command

        logger.debug(f"Executing on {self.container}: {' '.join(command)}")

        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if check and result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    full_command,
                    output=result.stdout,
                    stderr=result.stderr,
                )

            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timeout on {self.container}: {e}")
            return -1, "", f"Timeout after {timeout}s"
        except Exception as e:
            logger.error(f"Command failed on {self.container}: {e}")
            return -1, "", str(e)

    # DEPRECATED(v2.2): start — iperf3/Containerlab not wired. Kept for future integration.
    def start(self, one_off: bool = True) -> bool:
        """
        Start iperf3 server in the container.

        Args:
            one_off: If True, server exits after one test (-1 flag)

        Returns:
            True if server started successfully, False otherwise
        """
        logger.info(f"Starting iperf3 server on {self.container}:{self.port}")

        # Kill any existing iperf3 server first
        self.stop()
        time.sleep(0.5)  # Brief pause for process termination

        # Build iperf3 server command
        cmd_parts = ["iperf3", "-s", "-p", str(self.port)]

        if one_off:
            cmd_parts.append("-1")  # Exit after one test

        if self.bind_address:
            cmd_parts.extend(["-B", self.bind_address])

        # Start server in background (daemon mode)
        cmd_parts.append("-D")

        returncode, stdout, stderr = self._exec_on_container(cmd_parts, timeout=10)

        if returncode != 0:
            logger.error(f"Failed to start iperf3 server: {stderr}")
            self._process_running = False
            return False

        # Wait for server to be ready
        time.sleep(1)

        # Verify server is listening
        if self.is_running():
            logger.info("iperf3 server started successfully")
            self._process_running = True
            return True
        else:
            logger.error("iperf3 server failed to start (not listening)")
            self._process_running = False
            return False

    # DEPRECATED(v2.2): stop — iperf3/Containerlab not wired. Kept for future integration.
    def stop(self) -> bool:
        """
        Stop iperf3 server in the container.

        Returns:
            True if server was stopped (or wasn't running), False on error
        """
        logger.debug(f"Stopping iperf3 server on {self.container}")

        returncode, _stdout, stderr = self._exec_on_container(
            ["pkill", "-f", f"iperf3 -s -p {self.port}"],
            timeout=5,
        )

        # pkill returns 0 if process was found and killed, 1 if not found
        if returncode == 0:
            logger.info("iperf3 server stopped")
            self._process_running = False
            return True
        elif returncode == 1:
            # Process wasn't running, which is fine
            logger.debug("iperf3 server was not running")
            self._process_running = False
            return True
        else:
            logger.warning(f"Error stopping iperf3 server: {stderr}")
            return False

    # DEPRECATED(v2.2): is_running — iperf3/Containerlab not wired. Kept for future integration.
    def is_running(self) -> bool:
        """
        Check if iperf3 server is running and listening.

        Returns:
            True if server is listening on the configured port
        """
        # Check if port is listening using ss command
        returncode, stdout, _stderr = self._exec_on_container(
            ["ss", "-tlnp"],
            timeout=5,
        )

        if returncode != 0:
            # Try netstat if ss isn't available
            returncode, stdout, _stderr = self._exec_on_container(
                ["netstat", "-tlnp"],
                timeout=5,
            )

        if returncode == 0:
            port_str = f":{self.port}"
            is_listening = port_str in stdout
            self._process_running = is_listening
            return is_listening

        return False

    # DEPRECATED(v2.2): restart — iperf3/Containerlab not wired. Kept for future integration.
    def restart(self, one_off: bool = True) -> bool:
        """
        Restart iperf3 server.

        Args:
            one_off: If True, server exits after one test

        Returns:
            True if server restarted successfully
        """
        self.stop()
        time.sleep(0.5)
        return self.start(one_off=one_off)


class Iperf3Client:
    """
    Runs iperf3 tests from a client container.

    This class handles TCP and UDP throughput/latency tests,
    parsing JSON output and returning structured results.

    Example:
        client = Iperf3Client(
            client_container="clab-autonp-client",
            server_ip="10.2.0.2",
            server_port=5201
        )

        # TCP test
        result = client.run_tcp_test(duration=30)
        print(f"TCP: {result.throughput_mbps:.2f} Mbps")

        # UDP test
        result = client.run_udp_test(duration=30, bandwidth="1G")
        print(f"UDP: {result.throughput_mbps:.2f} Mbps, "
              f"loss: {result.packet_loss_percent:.2f}%")
    """

    # Default timeout buffer for subprocess calls
    TIMEOUT_BUFFER: int = 10

    def __init__(
        self,
        client_container: str,
        server_ip: str,
        server_port: int = 5201,
    ) -> None:
        """
        Initialize iperf3 client.

        Args:
            client_container: Docker container name for client
            server_ip: IP address of the iperf3 server
            server_port: Port of the iperf3 server
        """
        self.client_container = client_container
        self.server_ip = server_ip
        self.server_port = server_port

        logger.debug(
            f"Iperf3Client initialized: client={client_container}, server={server_ip}:{server_port}"
        )

    def _exec_on_container(
        self,
        command: list[str],
        timeout: int = 60,
        check: bool = False,
    ) -> tuple[int, str, str]:
        """
        Execute command on the client container.

        Args:
            command: Command and arguments as list
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        full_command = ["docker", "exec", self.client_container] + command

        logger.debug(f"Executing on {self.client_container}: {' '.join(command)}")

        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if check and result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    full_command,
                    output=result.stdout,
                    stderr=result.stderr,
                )

            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timeout on {self.client_container}: {e}")
            return -1, "", f"Timeout after {timeout}s"
        except Exception as e:
            logger.error(f"Command failed on {self.client_container}: {e}")
            return -1, "", str(e)

    def _parse_json_output(self, json_output: str) -> Iperf3Result:
        """
        Parse iperf3 JSON output into structured result.

        Args:
            json_output: Raw JSON string from iperf3

        Returns:
            Iperf3Result with parsed metrics
        """
        try:
            data = json.loads(json_output)

            # Check for iperf3 error
            if "error" in data:
                error_msg = data["error"]
                logger.error(f"iperf3 reported error: {error_msg}")
                return Iperf3Result(
                    throughput_mbps=0.0,
                    retransmits=0,
                    jitter_ms=0.0,
                    packet_loss_percent=0.0,
                    duration_seconds=0.0,
                    success=False,
                    error_message=error_msg,
                )

            end_data = data.get("end", {})
            start_data = data.get("start", {}).get("test_start", {})

            # Initialize defaults
            throughput_mbps = 0.0
            retransmits = 0
            jitter_ms = 0.0
            packet_loss_percent = 0.0
            duration_seconds = 0.0
            success = False

            # Get duration
            if "duration" in start_data:
                duration_seconds = float(start_data["duration"])

            # TCP test results
            if "sum_received" in end_data:
                sum_received = end_data["sum_received"]
                bits_per_second = sum_received.get("bits_per_second", 0)
                throughput_mbps = bits_per_second / 1e6  # Convert to Mbps

                # Get retransmits from sum_sent
                if "sum_sent" in end_data:
                    sum_sent = end_data["sum_sent"]
                    retransmits = sum_sent.get("retransmits", 0)

                success = True

            # UDP test results
            if "sum" in end_data:
                sum_data = end_data["sum"]

                # Throughput
                if "bits_per_second" in sum_data:
                    throughput_mbps = sum_data["bits_per_second"] / 1e6

                # Jitter
                if "jitter_ms" in sum_data:
                    jitter_ms = sum_data["jitter_ms"]

                # Packet loss
                if "lost_packets" in sum_data and "packets" in sum_data:
                    lost = sum_data["lost_packets"]
                    total = sum_data["packets"]
                    if total > 0:
                        packet_loss_percent = (lost / total) * 100

                # Loss percentage directly
                if "lost_percent" in sum_data:
                    packet_loss_percent = sum_data["lost_percent"]

                success = True

            return Iperf3Result(
                throughput_mbps=throughput_mbps,
                retransmits=retransmits,
                jitter_ms=jitter_ms,
                packet_loss_percent=packet_loss_percent,
                duration_seconds=duration_seconds,
                success=success,
                error_message=None,
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse iperf3 JSON: {e}")
            return Iperf3Result(
                throughput_mbps=0.0,
                retransmits=0,
                jitter_ms=0.0,
                packet_loss_percent=0.0,
                duration_seconds=0.0,
                success=False,
                error_message=f"JSON parse error: {str(e)[:200]}",
            )
        except Exception as e:
            logger.error(f"Unexpected error parsing iperf3 output: {e}")
            return Iperf3Result(
                throughput_mbps=0.0,
                retransmits=0,
                jitter_ms=0.0,
                packet_loss_percent=0.0,
                duration_seconds=0.0,
                success=False,
                error_message=f"Parse error: {str(e)[:200]}",
            )

    def _run_iperf3(
        self,
        protocol: str,
        duration: int,
        bandwidth: str | None = None,
        additional_args: list[str] | None = None,
    ) -> Iperf3Result:
        """
        Run iperf3 test with specified parameters.

        Args:
            protocol: 'tcp' or 'udp'
            duration: Test duration in seconds
            bandwidth: Bandwidth limit for UDP (e.g., '100M', '1G')
            additional_args: Additional command line arguments

        Returns:
            Iperf3Result with test metrics
        """
        # Build iperf3 command
        cmd = [
            "iperf3",
            "-c",
            self.server_ip,
            "-p",
            str(self.server_port),
            "-t",
            str(duration),
            "-J",  # JSON output
        ]

        if protocol == "udp":
            cmd.append("-u")
            if bandwidth:
                cmd.extend(["-b", bandwidth])
            else:
                cmd.extend(["-b", "1G"])  # Default UDP bandwidth

        if additional_args:
            cmd.extend(additional_args)

        logger.info(
            f"Running iperf3 {protocol} test: duration={duration}s, "
            f"server={self.server_ip}:{self.server_port}"
        )

        timeout = duration + self.TIMEOUT_BUFFER
        returncode, stdout, stderr = self._exec_on_container(cmd, timeout=timeout)

        if returncode != 0:
            error_msg = stderr[:200] if stderr else f"Exit code {returncode}"
            logger.error(f"iperf3 client failed: {error_msg}")
            return Iperf3Result(
                throughput_mbps=0.0,
                retransmits=0,
                jitter_ms=0.0,
                packet_loss_percent=0.0,
                duration_seconds=0.0,
                success=False,
                error_message=f"iperf3 failed: {error_msg}",
            )

        # Parse results
        result = self._parse_json_output(stdout)
        logger.info(
            f"iperf3 {protocol} test complete: "
            f"throughput={result.throughput_mbps:.2f} Mbps, "
            f"success={result.success}"
        )

        return result

    # DEPRECATED(v2.2): run_tcp_test — iperf3/Containerlab not wired. Kept for future integration.
    def run_tcp_test(
        self,
        duration: int = 30,
        reverse: bool = False,
        parallel_streams: int | None = None,
    ) -> Iperf3Result:
        """
        Run TCP throughput test.

        Args:
            duration: Test duration in seconds (default: 30)
            reverse: If True, run reverse mode (server sends to client)
            parallel_streams: Number of parallel streams (default: 1)

        Returns:
            Iperf3Result with TCP test metrics:
                - throughput_mbps: Measured throughput
                - retransmits: TCP retransmission count
                - duration_seconds: Test duration
                - success: Test completion status
        """
        additional_args = []

        if reverse:
            additional_args.append("-R")

        if parallel_streams:
            additional_args.extend(["-P", str(parallel_streams)])

        return self._run_iperf3(
            protocol="tcp",
            duration=duration,
            additional_args=additional_args if additional_args else None,
        )

    # DEPRECATED(v2.2): run_udp_test — iperf3/Containerlab not wired. Kept for future integration.
    def run_udp_test(
        self,
        duration: int = 30,
        bandwidth: str = "1G",
        packet_length: int | None = None,
    ) -> Iperf3Result:
        """
        Run UDP latency and packet loss test.

        Args:
            duration: Test duration in seconds (default: 30)
            bandwidth: Target bandwidth (e.g., '100M', '1G', '10G')
            packet_length: UDP packet length in bytes (default: iperf3 default)

        Returns:
            Iperf3Result with UDP test metrics:
                - throughput_mbps: Measured throughput
                - jitter_ms: Jitter in milliseconds
                - packet_loss_percent: Packet loss percentage
                - duration_seconds: Test duration
                - success: Test completion status
        """
        additional_args = []

        if packet_length:
            additional_args.extend(["-l", str(packet_length)])

        return self._run_iperf3(
            protocol="udp",
            duration=duration,
            bandwidth=bandwidth,
            additional_args=additional_args if additional_args else None,
        )

    # DEPRECATED(v2.2): test_connectivity — iperf3/Containerlab not wired. Kept for future integration.
    def test_connectivity(self, timeout: int = 5) -> bool:
        """
        Test basic connectivity to iperf3 server.

        Args:
            timeout: Connection test timeout in seconds

        Returns:
            True if server is reachable
        """
        logger.debug(f"Testing connectivity to {self.server_ip}:{self.server_port}")

        # Use iperf3 with very short test (-t 1) to check connectivity
        cmd = [
            "iperf3",
            "-c",
            self.server_ip,
            "-p",
            str(self.server_port),
            "-t",
            "1",
        ]

        returncode, _stdout, _stderr = self._exec_on_container(cmd, timeout=timeout)

        is_reachable = returncode == 0

        if is_reachable:
            logger.debug("Server is reachable")
        else:
            logger.warning(f"Server {self.server_ip}:{self.server_port} is not reachable")

        return is_reachable


# Convenience functions for quick testing


# DEPRECATED(v2.2): quick_tcp_test — iperf3/Containerlab not wired. Kept for future integration.
def quick_tcp_test(
    client_container: str = "clab-autonp-client",
    server_ip: str = "10.2.0.2",
    duration: int = 10,
) -> Iperf3Result:
    """
    Run a quick TCP test with default settings.

    Args:
        client_container: Client container name
        server_ip: Server IP address
        duration: Test duration in seconds

    Returns:
        Iperf3Result with test metrics
    """
    client = Iperf3Client(
        client_container=client_container,
        server_ip=server_ip,
    )
    return client.run_tcp_test(duration=duration)


# DEPRECATED(v2.2): quick_udp_test — iperf3/Containerlab not wired. Kept for future integration.
def quick_udp_test(
    client_container: str = "clab-autonp-client",
    server_ip: str = "10.2.0.2",
    duration: int = 10,
    bandwidth: str = "1G",
) -> Iperf3Result:
    """
    Run a quick UDP test with default settings.

    Args:
        client_container: Client container name
        server_ip: Server IP address
        duration: Test duration in seconds
        bandwidth: Target bandwidth

    Returns:
        Iperf3Result with test metrics
    """
    client = Iperf3Client(
        client_container=client_container,
        server_ip=server_ip,
    )
    return client.run_udp_test(duration=duration, bandwidth=bandwidth)


if __name__ == "__main__":
    # Simple CLI for testing the module
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Parse arguments
    test_type = sys.argv[1] if len(sys.argv) > 1 else "tcp"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    print(f"Running iperf3 {test_type} test (duration={duration}s)...")

    # Start server first
    server = Iperf3Server(container="clab-autonp-server")
    if not server.start():
        print("Failed to start iperf3 server", file=sys.stderr)
        sys.exit(1)

    try:
        # Run test
        client = Iperf3Client(
            client_container="clab-autonp-client",
            server_ip="10.2.0.2",
        )

        if test_type == "tcp":
            result = client.run_tcp_test(duration=duration)
        elif test_type == "udp":
            result = client.run_udp_test(duration=duration)
        else:
            print(f"Unknown test type: {test_type}", file=sys.stderr)
            sys.exit(1)

        print("\n=== Results ===")
        print(json.dumps(result.to_dict(), indent=2))

        sys.exit(0 if result.success else 1)

    finally:
        server.stop()
