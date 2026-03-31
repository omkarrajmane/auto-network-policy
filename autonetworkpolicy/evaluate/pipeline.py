"""NOTE: This module is DEPRECATED(v2.2). See autoresearch.py for the active loop."""

"""
===============================================================================
Evaluation Pipeline - Firewall Policy Evaluation Orchestration
===============================================================================

Purpose: Orchestrate the complete evaluation of nftables firewall policies.

This module provides:
  - Policy validation and deployment to firewall container
  - Multi-iteration traffic testing with TrafficSimulator
  - Score calculation based on throughput and hit rates
  - Comprehensive results reporting

Usage:
    pipeline = EvaluationPipeline(config)
    results = pipeline.evaluate("policy.nft")

    # CLI usage:
    python evaluate/pipeline.py data/generated/acl1_500.nft
    python evaluate/pipeline.py --repeats 5 --output results.json policy.nft

===============================================================================
"""

import argparse
import json
import logging
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .traffic_simulator import TrafficSimulator
except ImportError:
    from traffic_simulator import TrafficSimulator

logger = logging.getLogger(__name__)


class EvaluationPipeline:
    """
    Orchestrates firewall policy evaluation from deployment to scoring.

    Pipeline steps:
        1. Validate policy syntax
        2. Deploy to firewall container
        3. Run traffic tests (multiple iterations)
        4. Collect metrics
        5. Calculate score
        6. Return comprehensive results
    """

    # Containerlab container naming convention
    CONTAINER_PREFIX: str = "clab-autonp"
    FW_CONTAINER: str = "clab-autonp-fw"

    # Default configuration
    DEFAULT_IPERF_DURATION: int = 30
    DEFAULT_REPEATS: int = 3
    DEFAULT_MAX_TOTAL_DURATION: int = 120

    def __init__(self, config: dict | None = None):
        """
        Initialize evaluation pipeline.

        Args:
            config: Configuration dictionary with optional keys:
                - iperf_duration: Duration of each iperf test (default: 30)
                - iperf_repeats: Number of test repetitions (default: 3)
                - time_budget_seconds: Max time budget per evaluation (default: 120)
                - client_host: Client container name (default: "client")
                - server_host: Server container name (default: "server")
        """
        self.config = config or {}

        self.iperf_duration = self.config.get("iperf_duration", self.DEFAULT_IPERF_DURATION)
        self.repeats = self.config.get("iperf_repeats", self.DEFAULT_REPEATS)
        self.max_duration = self.config.get("time_budget_seconds", self.DEFAULT_MAX_TOTAL_DURATION)

        self.client_host = self.config.get("client_host", "client")
        self.server_host = self.config.get("server_host", "server")

        # Initialize traffic simulator
        self.simulator = TrafficSimulator(
            client_host=self.client_host,
            server_host=self.server_host,
            duration=self.iperf_duration,
            max_total_duration=self.max_duration,
        )

        logger.info(
            f"EvaluationPipeline initialized: duration={self.iperf_duration}s, "
            f"repeats={self.repeats}, max_duration={self.max_duration}s"
        )

    def _validate_policy_syntax(self, policy_file: str) -> tuple[bool, str | None]:
        """
        Validate nftables policy syntax using nft -c.

        Args:
            policy_file: Path to the nftables policy file

        Returns:
            Tuple of (is_valid, error_message)
        """
        logger.info(f"Validating policy syntax: {policy_file}")

        try:
            result = subprocess.run(
                ["nft", "-c", "-f", policy_file],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                logger.info("Policy syntax validation passed")
                return True, None
            else:
                error = result.stderr.strip() if result.stderr else "Syntax validation failed"
                logger.error(f"Policy syntax validation failed: {error}")
                return False, error

        except subprocess.TimeoutExpired:
            error = "Syntax validation timed out"
            logger.error(error)
            return False, error
        except FileNotFoundError:
            error = "nft command not found. Is nftables installed?"
            logger.error(error)
            return False, error
        except Exception as e:
            error = f"Syntax validation error: {e}"
            logger.error(error)
            return False, error

    # DEPRECATED(v2.2): _deploy_policy — iperf3/Containerlab not wired. Kept for future integration.
    def _deploy_policy(self, policy_file: str) -> tuple[bool, str | None]:
        """
        Deploy policy to firewall container.

        Args:
            policy_file: Path to the nftables policy file

        Returns:
            Tuple of (success, error_message)
        """
        logger.info(f"Deploying policy to {self.FW_CONTAINER}")

        try:
            # Copy policy to container
            copy_result = subprocess.run(
                ["docker", "cp", policy_file, f"{self.FW_CONTAINER}:/tmp/policy.nft"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if copy_result.returncode != 0:
                error = f"Failed to copy policy: {copy_result.stderr}"
                logger.error(error)
                return False, error

            # Apply policy using nft
            apply_result = subprocess.run(
                ["docker", "exec", self.FW_CONTAINER, "nft", "-f", "/tmp/policy.nft"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if apply_result.returncode != 0:
                error = f"Failed to apply policy: {apply_result.stderr}"
                logger.error(error)
                return False, error

            logger.info("Policy deployed successfully")
            return True, None

        except subprocess.TimeoutExpired:
            error = "Policy deployment timed out"
            logger.error(error)
            return False, error
        except Exception as e:
            error = f"Policy deployment error: {e}"
            logger.error(error)
            return False, error

    def _get_firewall_counters(self) -> dict[str, Any]:
        """
        Read firewall counters from nftables.

        Returns:
            Dictionary with counter data:
                - hit_rates: dict of rule index -> hit count
                - total_packets: total packets processed
                - matched_packets: total matched packets
        """
        logger.info("Reading firewall counters")

        try:
            result = subprocess.run(
                ["docker", "exec", self.FW_CONTAINER, "nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.warning(f"Failed to read counters: {result.stderr}")
                return {
                    "hit_rates": {},
                    "total_packets": 0,
                    "matched_packets": 0,
                }

            # Parse counters from ruleset output
            hit_rates = {}
            total_packets = 0
            matched_packets = 0
            rule_idx = 0

            for line in result.stdout.split("\n"):
                line = line.strip()
                # Look for counter lines: "counter packets X bytes Y"
                if "counter packets" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "packets" and i + 1 < len(parts):
                            try:
                                count = int(parts[i + 1])
                                hit_rates[rule_idx] = count
                                total_packets += count
                                # Assume rules with accept/drop at end are matches
                                if any(a in line for a in ["accept", "drop", "reject"]):
                                    matched_packets += count
                                rule_idx += 1
                            except ValueError:
                                pass
                            break

            return {
                "hit_rates": hit_rates,
                "total_packets": total_packets,
                "matched_packets": matched_packets,
            }

        except Exception as e:
            logger.warning(f"Error reading counters: {e}")
            return {
                "hit_rates": {},
                "total_packets": 0,
                "matched_packets": 0,
            }

    def _count_rules(self, policy_file: str) -> int:
        """
        Count the number of rules in the policy file.

        Args:
            policy_file: Path to the nftables policy file

        Returns:
            Number of rules (lines containing 'accept', 'drop', or 'reject')
        """
        try:
            with open(policy_file, "r") as f:
                content = f.read()

            # Count lines with accept, drop, or reject actions
            count = 0
            for line in content.split("\n"):
                line = line.strip()
                if line and any(action in line for action in ["accept", "drop", "reject"]):
                    # Skip comments and non-rule lines
                    if not line.startswith("#") and "type" not in line and "policy" not in line:
                        count += 1

            return count

        except Exception as e:
            logger.warning(f"Error counting rules: {e}")
            return 0

    def _calculate_score(
        self,
        throughput_gbps: float,
        hit_rates: dict,
        total_packets: int,
        matched_packets: int,
        rule_count: int,
    ) -> float:
        """
        Calculate evaluation score based on throughput and hit rates.

        Formula: score = throughput_gbps * (1 + hit_rate_bonus)

        Where hit_rate_bonus is based on the proportion of matched packets:
        - Higher hit rate = better rule ordering
        - Bonus capped at 10% to keep throughput dominant

        Args:
            throughput_gbps: Measured throughput in Gbps
            hit_rates: Dictionary of rule index -> hit count
            total_packets: Total packets processed
            matched_packets: Total matched packets
            rule_count: Number of rules in policy

        Returns:
            Calculated score
        """
        # Calculate hit rate bonus (max 10%)
        if total_packets > 0:
            hit_rate = matched_packets / total_packets
            hit_rate_bonus = min(hit_rate * 0.1, 0.1)  # Cap at 10%
        else:
            hit_rate_bonus = 0.0

        # Apply rule count normalization (baseline of 100 rules)
        # Fewer rules = slightly better (optimization goal)
        rule_factor = 100 / max(rule_count, 1)
        rule_bonus = min((rule_factor - 1) * 0.05, 0.05)  # Cap at 5%

        # Final score
        score = throughput_gbps * (1 + hit_rate_bonus + rule_bonus)

        logger.info(
            f"Score calculation: {throughput_gbps:.3f} Gbps * "
            f"(1 + {hit_rate_bonus:.3f} + {rule_bonus:.3f}) = {score:.3f}"
        )

        return score

    # DEPRECATED(v2.2): _run_single_test — iperf3/Containerlab not wired. Kept for future integration.
    def _run_single_test(self) -> dict[str, Any]:
        """
        Run a single traffic test iteration.

        Returns:
            Dictionary with test metrics
        """
        logger.info("Running single test iteration")

        # Reset simulator time budget
        self.simulator.reset_budget()

        # Run TCP throughput test
        tcp_results = self.simulator.run_tcp_test(duration=self.iperf_duration)

        if not tcp_results.get("success", False):
            logger.warning(f"TCP test failed: {tcp_results.get('error_message')}")

        return tcp_results

    # DEPRECATED(v2.2): evaluate — iperf3/Containerlab not wired. Kept for future integration.
    def evaluate(self, policy_file: str) -> dict[str, Any]:
        """
        Run full evaluation pipeline on a policy file.

        Pipeline:
            1. Validate policy syntax
            2. Deploy to firewall container
            3. Run traffic tests (multiple iterations)
            4. Collect metrics
            5. Calculate score
            6. Return comprehensive results

        Args:
            policy_file: Path to the nftables policy file

        Returns:
            Dictionary with evaluation results:
                - score: float
                - throughput_gbps: float
                - latency_ms: float
                - rule_count: int
                - hit_rates: dict
                - duration_seconds: float
                - success: bool
                - error_message: str | None
        """
        start_time = time.time()

        logger.info(f"Starting evaluation pipeline for: {policy_file}")

        # Initialize results with proper typing
        results: dict[str, Any] = {
            "score": 0.0,
            "throughput_gbps": 0.0,
            "latency_ms": 0.0,
            "rule_count": 0,
            "hit_rates": {},
            "duration_seconds": 0.0,
            "success": False,
            "error_message": None,
        }

        # Step 1: Validate syntax
        is_valid, error = self._validate_policy_syntax(policy_file)
        if not is_valid:
            results["error_message"] = f"Syntax validation failed: {error}"
            results["duration_seconds"] = time.time() - start_time
            return results

        # Step 2: Deploy policy
        deployed, error = self._deploy_policy(policy_file)
        if not deployed:
            results["error_message"] = f"Deployment failed: {error}"
            results["duration_seconds"] = time.time() - start_time
            return results

        # Step 3: Count rules
        rule_count = self._count_rules(policy_file)
        results["rule_count"] = rule_count
        logger.info(f"Policy has {rule_count} rules")

        # Step 4: Run traffic tests (multiple iterations)
        test_results = []
        for i in range(self.repeats):
            logger.info(f"Test iteration {i + 1}/{self.repeats}")

            test_result = self._run_single_test()
            test_results.append(test_result)

            if not test_result.get("success", False):
                logger.warning(f"Test iteration {i + 1} failed")

            # Brief pause between iterations
            if i < self.repeats - 1:
                time.sleep(1)

        # Step 5: Calculate median metrics
        successful_tests = [r for r in test_results if r.get("success", False)]

        if not successful_tests:
            results["error_message"] = "All test iterations failed"
            results["duration_seconds"] = time.time() - start_time
            return results

        # Calculate median throughput
        throughputs = [r.get("throughput_gbps", 0.0) for r in successful_tests]
        median_throughput = statistics.median(throughputs)

        # Calculate median latency (if available)
        latencies = [
            r.get("latency_ms", 0.0) for r in successful_tests if r.get("latency_ms", 0.0) > 0
        ]
        median_latency = statistics.median(latencies) if latencies else 0.0

        # Report variance if multiple successful tests
        if len(throughputs) > 1:
            try:
                variance = statistics.variance(throughputs)
                logger.info(f"Throughput variance: {variance:.6f} (stddev: {variance**0.5:.3f})")
            except statistics.StatisticsError:
                pass

        results["throughput_gbps"] = median_throughput
        results["latency_ms"] = median_latency

        # Step 6: Read firewall counters
        counters = self._get_firewall_counters()
        results["hit_rates"] = counters["hit_rates"]

        # Step 7: Calculate score
        score = self._calculate_score(
            throughput_gbps=median_throughput,
            hit_rates=counters["hit_rates"],
            total_packets=counters["total_packets"],
            matched_packets=counters["matched_packets"],
            rule_count=rule_count,
        )
        results["score"] = score

        # Mark as successful
        results["success"] = True
        results["duration_seconds"] = time.time() - start_time

        logger.info(
            f"Evaluation complete: score={score:.3f}, "
            f"throughput={median_throughput:.3f} Gbps, "
            f"rules={rule_count}, duration={results['duration_seconds']:.1f}s"
        )

        return results


def main():
    """CLI entry point for the evaluation pipeline."""
    parser = argparse.ArgumentParser(
        description="Evaluate nftables firewall policy performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python evaluate/pipeline.py data/generated/acl1_500.nft
    python evaluate/pipeline.py --repeats 5 --output results.json policy.nft
    python evaluate/pipeline.py --duration 10 --repeats 3 --verbose policy.nft
        """,
    )

    parser.add_argument(
        "policy_file",
        help="Path to the nftables policy file to evaluate",
    )

    parser.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Number of test repetitions (default: 3)",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration of each iperf test in seconds (default: 30)",
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

    # Validate policy file exists
    policy_path = Path(args.policy_file)
    if not policy_path.exists():
        print(f"Error: Policy file not found: {args.policy_file}", file=sys.stderr)
        sys.exit(1)

    # Create pipeline with CLI config
    config = {
        "iperf_duration": args.duration,
        "iperf_repeats": args.repeats,
    }

    pipeline = EvaluationPipeline(config)

    # Run evaluation
    try:
        results = pipeline.evaluate(str(policy_path))
    except Exception as e:
        logger.exception("Evaluation failed with exception")
        results = {
            "score": 0.0,
            "throughput_gbps": 0.0,
            "latency_ms": 0.0,
            "rule_count": 0,
            "hit_rates": {},
            "duration_seconds": 0.0,
            "success": False,
            "error_message": f"Exception: {e}",
        }

    # Output results
    if args.output:
        # Write to file
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results written to: {args.output}")
    else:
        # Print to stdout
        print(json.dumps(results, indent=2))

    # Exit with error code if evaluation failed
    sys.exit(0 if results["success"] else 1)


if __name__ == "__main__":
    main()
