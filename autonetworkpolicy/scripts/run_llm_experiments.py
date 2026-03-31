#!/usr/bin/env python3
"""
================================================================================
LLM Experiment Runners - Phase 10.3
================================================================================

Implements LLM-guided mutation experiments:

1. Cold-Start Run (Task 10.3.1):
   - Temperature=0.0 for consistency
   - 5 iterations on Scenario 1
   - Records all mutations proposed

2. Comparative Trials (Task 10.3.2):
   - Run on all 3 scenarios
   - 3 iterations per scenario
   - Temperature=0.7 (default)
   - Records: score, throughput, rule count, mutations proposed

Output:
    results/experiments/llm_cold_start_*/
    results/experiments/llm_trial_*/

Usage:
    python run_llm_experiments.py --cold-start --scenario over_permissive
    python run_llm_experiments.py --trials --all-scenarios --iterations 3

================================================================================
"""

from __future__ import annotations

import argparse
import copy
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from autonetworkpolicy.data.classbench_to_nft import load_nft_as_rules, rules_to_nft, Rule
from autonetworkpolicy.agent.proposer import Proposer
from autonetworkpolicy.agent.provider import LLMProviderFactory
from autonetworkpolicy.mutations import MutationEngine, InvalidMutation
from autonetworkpolicy.verify.bdd_verify import BDDVerifier
from autonetworkpolicy.utils.experiment_logger import ExperimentLogger
from autonetworkpolicy.baselines.greedy_hitcount import _calculate_specificity


# Benchmark scenarios
BENCHMARK_SCENARIOS = {
    "over_permissive": "over_permissive_legacy_500.nft",
    "broken_segmentation": "broken_segmentation_300.nft",
    "redundant_shadowing": "redundant_shadowing_400.nft",
    "port_heavy_enterprise": "port_heavy_enterprise_500.nft",
    "mixed_protocol": "mixed_protocol_400.nft",
    "k8s_microservices": "semantic/k8s_microservices_200.nft",
    "enterprise_departments": "semantic/enterprise_departments_500.nft",
    "three_tier_app": "semantic/three_tier_app_300.nft",
    "vlan_segmentation": "semantic/vlan_segmentation_400.nft",
}


class LLMExperimentRunner:
    """
    Runner for LLM-guided mutation experiments.

    This class handles the experiment lifecycle:
    - Load initial policy
    - Initialize LLM proposer with specified temperature
    - Run iterations of mutation proposals
    - Validate and apply mutations
    - Log results with high-fidelity telemetry

    Attributes:
        scenario_name: Name of the scenario being tested
        scenario_path: Path to the scenario file
        temperature: LLM temperature setting
        max_iterations: Maximum number of iterations
        logger: ExperimentLogger instance
    """

    def __init__(
        self,
        scenario_name: str,
        scenario_path: Path,
        temperature: float = 0.7,
        max_iterations: int = 10,
        experiment_name: Optional[str] = None,
    ):
        """
        Initialize the LLM experiment runner.

        Args:
            scenario_name: Name of the scenario
            scenario_path: Path to the scenario file
            temperature: LLM temperature (0.0 for deterministic, 0.7 for default)
            max_iterations: Maximum number of iterations
            experiment_name: Optional experiment name override
        """
        self.scenario_name = scenario_name
        self.scenario_path = scenario_path
        self.temperature = temperature
        self.max_iterations = max_iterations

        # Generate experiment name if not provided
        if experiment_name is None:
            temp_str = f"temp{temperature}"
            experiment_name = f"llm_{scenario_name}_{temp_str}"
        self.experiment_name = experiment_name

        # Initialize components
        self.mutation_engine = MutationEngine()
        self.proposer: Optional[Proposer] = None
        self.verifier: Optional[BDDVerifier] = None

        # Load initial rules
        self.original_rules: list[Rule] = []
        self.current_rules: list[Rule] = []

        # Initialize logger
        self.logger = ExperimentLogger(
            experiment_name=self.experiment_name,
            scenario=scenario_name,
            algorithm="llm_guided",
        )

        # State tracking
        self.best_score = 0.0
        self.baseline_score = 0.0
        self.mutation_history: list[dict[str, Any]] = []

    def initialize(self) -> bool:
        """
        Initialize components and load policy.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Create provider using factory (auto-detects from config.yaml)
            try:
                provider = LLMProviderFactory.create()
                if not provider.validate_config():
                    print("Warning: Provider configuration is invalid")
                    print("Check config.yaml LLM section")
                    return False
            except Exception as e:
                print(f"Warning: Failed to create LLM provider: {e}")
                return False

            # Load rules
            print(f"Loading scenario: {self.scenario_path}")
            self.original_rules = load_nft_as_rules(self.scenario_path)
            self.current_rules = copy.deepcopy(self.original_rules)
            print(f"Loaded {len(self.current_rules)} rules")

            provider.config.temperature = self.temperature

            self.proposer = Proposer(provider=provider)
            print(f"Initialized LLM proposer (temperature={self.temperature})")

            # Initialize BDD verifier
            self.verifier = BDDVerifier(
                backend="autoref",
                mode="full",
                timeout_seconds=60.0,
            )
            print("Initialized BDD verifier")

            # Set baseline metrics (simplified - no actual evaluation)
            self.baseline_score = float(len(self.current_rules))
            self.best_score = self.baseline_score
            self.logger.set_baseline(self.baseline_score, len(self.current_rules))

            return True

        except Exception as e:
            print(f"Initialization error: {e}")
            traceback.print_exc()
            return False

    def run_iteration(self, iteration: int) -> dict[str, Any]:
        """
        Run a single iteration of the LLM-guided mutation loop.

        Args:
            iteration: Current iteration number (1-indexed)

        Returns:
            Dictionary with iteration results
        """
        print(f"\n--- Iteration {iteration}/{self.max_iterations} ---")

        result: dict[str, Any] = {
            "iteration": iteration,
            "success": False,
            "mutation_proposed": False,
            "mutation_applied": False,
            "verification_passed": False,
            "score_before": self.best_score,
            "score_after": self.best_score,
            "rule_count_before": len(self.current_rules),
            "rule_count_after": len(self.current_rules),
            "mutation_type": None,
            "mutation_description": None,
            "error": None,
        }

        try:
            if self.proposer is None or self.verifier is None:
                result["error"] = "Runner is not initialized"
                print("  Runner is not initialized")
                return result

            # Step 1: Build context for LLM
            context = self._build_context(iteration)

            # Step 2: Query LLM for mutation
            llm_start = time.time()
            mutation = self.proposer.propose_mutation(context)
            llm_latency_ms = (time.time() - llm_start) * 1000

            if mutation is None:
                result["error"] = "LLM failed to propose mutation"
                print("  LLM failed to propose mutation")
                return result

            result["mutation_proposed"] = True
            result["mutation_type"] = mutation.mutation_type
            result["mutation_description"] = mutation.description

            print(f"  Proposed: {mutation.mutation_type}")
            print(f"  Description: {mutation.description}")
            print(f"  Operation: {mutation.operation}")

            # Step 3: Apply mutation
            try:
                new_rules = self.mutation_engine.apply_mutation(
                    self.current_rules,
                    mutation.operation,
                )
                result["mutation_applied"] = True
                result["rule_count_after"] = len(new_rules)
                print(f"  Rules: {len(self.current_rules)} → {len(new_rules)}")

            except InvalidMutation as e:
                result["error"] = f"Invalid mutation: {e.message}"
                print(f"  Invalid mutation: {e.message}")
                return result

            # Step 4: BDD Verification
            verify_start = time.time()
            verify_result = self.verifier.verify(self.current_rules, new_rules)
            verify_time_ms = (time.time() - verify_start) * 1000

            result["verification_passed"] = verify_result.get("equivalent", False)
            result["verification_time_ms"] = verify_time_ms

            if not verify_result.get("equivalent", False):
                error_msg = verify_result.get("error", "Not equivalent")
                result["error"] = f"BDD verification failed: {error_msg}"
                print(f"  BDD verification failed: {error_msg}")
                return result

            print(f"  BDD verification passed ({verify_time_ms:.1f}ms)")

            # Step 5: Evaluate (simplified - use rule count as proxy for score)
            # In a full implementation, this would run the evaluation pipeline
            score = self._evaluate_rules(new_rules)
            result["score_after"] = score

            print(f"  Score: {result['score_before']:.2f} → {score:.2f}")

            # Step 6: Decide whether to keep
            if score > self.best_score:
                print(f"  ✓ Improved! Keeping mutation")
                self.current_rules = new_rules
                self.best_score = score
                result["success"] = True
                status = "keep"
            else:
                print(f"  ✗ No improvement. Rejecting mutation")
                status = "reject"

            # Log iteration
            self.logger.log_iteration(
                {
                    "iteration": iteration,
                    "mutation_type": mutation.mutation_type,
                    "mutation_description": mutation.description,
                    "rule_count_before": result["rule_count_before"],
                    "rule_count_after": result["rule_count_after"],
                    "score_before": result["score_before"],
                    "score_after": result["score_after"],
                    "llm_latency_ms": llm_latency_ms,
                    "verification_passed": result["verification_passed"],
                    "verification_time_ms": verify_time_ms,
                    "status": status,
                    "error_message": result.get("error"),
                }
            )

            result["success"] = True

        except Exception as e:
            error_msg = str(e)
            result["error"] = error_msg
            print(f"  Error: {error_msg}")
            traceback.print_exc()

        return result

    def _build_context(self, iteration: int) -> dict[str, Any]:
        """
        Build context for the LLM proposer.

        Args:
            iteration: Current iteration number

        Returns:
            Context dictionary
        """
        # Get recent mutations (last 5)
        recent_mutations = self.mutation_history[-5:] if self.mutation_history else []

        # Build policy context (first 50 rules)
        policy_context = []
        for rule in self.current_rules[:50]:
            ctx = {
                "index": rule.index,
                "src_ip": rule.src_ip,
                "dst_ip": rule.dst_ip,
                "src_port": rule.src_port,
                "dst_port": rule.dst_port,
                "protocol": rule.protocol,
                "action": rule.action,
            }
            if getattr(rule, "comment", None):
                ctx["comment"] = rule.comment
            policy_context.append(ctx)

        return {
            "current_policy": policy_context,
            "recent_mutations": recent_mutations,
            "performance_metrics": {
                "current_score": self.best_score,
                "baseline_score": self.baseline_score,
                "rule_count": len(self.current_rules),
            },
            "iteration": iteration,
            "max_iterations": self.max_iterations,
            "rule_count": len(self.current_rules),
        }

    def _evaluate_rules(self, rules: list[Rule]) -> float:
        """Evaluate ruleset quality using multi-component scoring.

        Components:
        1. Rule reduction (primary, 10x weight): reward fewer rules
        2. Ordering quality (secondary, 0.1x weight): reward specific rules earlier

        Returns:
            Score (higher is better)
        """
        original_count = len(self.original_rules) if self.original_rules else len(rules)

        # Component 1: Rule reduction (primary signal)
        rule_score = (original_count - len(rules)) * 10.0

        # Component 2: Ordering quality (specific rules first = better)
        if rules:
            order_score = sum(
                _calculate_specificity(r) * (len(rules) - i) for i, r in enumerate(rules)
            ) / len(rules)
        else:
            order_score = 0.0

        return rule_score + order_score * 0.1

    def run(self) -> dict[str, Any]:
        """
        Run the full experiment.

        Returns:
            Dictionary with experiment results
        """
        print(f"\n{'=' * 70}")
        print(f"Running LLM Experiment: {self.experiment_name}")
        print(f"Scenario: {self.scenario_name}")
        print(f"Temperature: {self.temperature}")
        print(f"Max iterations: {self.max_iterations}")
        print(f"{'=' * 70}")

        # Initialize
        if not self.initialize():
            return {"success": False, "error": "Initialization failed"}

        start_time = time.time()

        # Run iterations
        results = []
        for i in range(1, self.max_iterations + 1):
            iteration_result = self.run_iteration(i)
            results.append(iteration_result)

            # Check for repeated failures
            if i > 3:
                recent_failures = sum(1 for r in results[-3:] if not r.get("success"))
                if recent_failures >= 3:
                    print("\nStopping: 3 consecutive failures")
                    break

        # Finalize
        self.logger.set_best_score(self.best_score)
        self.logger.finalize()

        # Export results
        files = self.logger.export_results()

        total_time = time.time() - start_time

        # Summary
        successful = sum(1 for r in results if r.get("mutation_applied"))
        verified = sum(1 for r in results if r.get("verification_passed"))

        print(f"\n{'=' * 70}")
        print("Experiment Complete!")
        print(f"{'=' * 70}")
        print(f"Total iterations: {len(results)}")
        print(f"Mutations proposed: {sum(1 for r in results if r.get('mutation_proposed'))}")
        print(f"Mutations applied: {successful}")
        print(f"Verifications passed: {verified}")
        print(f"Best score: {self.best_score:.2f} (baseline: {self.baseline_score:.2f})")
        print(f"Final rules: {len(self.current_rules)} (was {len(self.original_rules)})")
        print(f"Total time: {total_time:.1f}s")
        print(f"Results saved to: {files.get('summary_json', 'N/A')}")

        return {
            "success": True,
            "experiment_name": self.experiment_name,
            "iterations": len(results),
            "successful_mutations": successful,
            "verification_passes": verified,
            "baseline_score": self.baseline_score,
            "best_score": self.best_score,
            "improvement": self.best_score - self.baseline_score,
            "files": {k: str(v) for k, v in files.items()},
        }


def run_cold_start(scenario: str, iterations: int = 5, seed: int = 42) -> dict[str, Any]:
    """
    Run cold-start experiment with temperature=0.0.

    Task 10.3.1: LLM Cold-Start Run

    Args:
        scenario: Scenario name
        iterations: Number of iterations (default: 5)
        seed: Random seed

    Returns:
        Experiment results
    """
    benchmarks_dir = Path(__file__).parent.parent / "benchmarks"
    scenario_path = benchmarks_dir / BENCHMARK_SCENARIOS[scenario]

    runner = LLMExperimentRunner(
        scenario_name=scenario,
        scenario_path=scenario_path,
        temperature=0.0,  # Deterministic
        max_iterations=iterations,
        experiment_name=f"llm_cold_start_{scenario}",
    )

    return runner.run()


def run_comparative_trials(
    scenarios: list[str],
    iterations_per_scenario: int = 3,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """
    Run comparative trials on multiple scenarios.

    Task 10.3.2: Comparative Performance Trials

    Args:
        scenarios: List of scenario names
        iterations_per_scenario: Iterations per scenario
        seed: Random seed

    Returns:
        List of experiment results
    """
    results = []

    for scenario in scenarios:
        benchmarks_dir = Path(__file__).parent.parent / "benchmarks"
        scenario_path = benchmarks_dir / BENCHMARK_SCENARIOS[scenario]

        for trial in range(iterations_per_scenario):
            print(f"\n{'=' * 70}")
            print(f"Scenario: {scenario} | Trial: {trial + 1}/{iterations_per_scenario}")
            print(f"{'=' * 70}")

            runner = LLMExperimentRunner(
                scenario_name=scenario,
                scenario_path=scenario_path,
                temperature=0.7,  # Default
                max_iterations=5,  # Short runs for trials
                experiment_name=f"llm_trial_{scenario}_run{trial + 1}",
            )

            result = runner.run()
            results.append(result)

    return results


def main():
    """CLI entry point for LLM experiments."""
    parser = argparse.ArgumentParser(
        description="Run LLM-guided mutation experiments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Cold-start run on scenario 1
    %(prog)s --cold-start --scenario over_permissive
    
    # Comparative trials on all scenarios
    %(prog)s --trials --all-scenarios
    
    # Custom iterations
    %(prog)s --cold-start --scenario redundant_shadowing --iterations 10
        """,
    )

    parser.add_argument(
        "--cold-start",
        action="store_true",
        help="Run cold-start experiment (temperature=0.0)",
    )

    parser.add_argument(
        "--trials",
        action="store_true",
        help="Run comparative trials (temperature=0.7)",
    )

    parser.add_argument(
        "--scenario",
        choices=list(BENCHMARK_SCENARIOS.keys()),
        help="Scenario to run",
    )

    parser.add_argument(
        "--all-scenarios",
        action="store_true",
        help="Run on all scenarios",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="Number of iterations (default: 5 for cold-start, 3 per trial)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )

    args = parser.parse_args()

    if not args.cold_start and not args.trials:
        parser.error("Must specify --cold-start OR --trials")

    if args.cold_start:
        if not args.scenario:
            parser.error("--cold-start requires --scenario")

        print("=" * 70)
        print("LLM Cold-Start Experiment (Task 10.3.1)")
        print("=" * 70)
        print(f"Temperature: 0.0 (deterministic)")
        print(f"Scenario: {args.scenario}")
        print(f"Iterations: {args.iterations}")

        result = run_cold_start(args.scenario, args.iterations, args.seed)

        if result.get("success"):
            print("\n✓ Cold-start experiment completed successfully")
            return 0
        else:
            print(f"\n✗ Experiment failed: {result.get('error')}")
            return 1

    elif args.trials:
        if args.all_scenarios:
            scenarios = list(BENCHMARK_SCENARIOS.keys())
        elif args.scenario:
            scenarios = [args.scenario]
        else:
            parser.error("--trials requires --scenario or --all-scenarios")

        print("=" * 70)
        print("LLM Comparative Trials (Task 10.3.2)")
        print("=" * 70)
        print(f"Temperature: 0.7 (default)")
        print(f"Scenarios: {', '.join(scenarios)}")
        print(f"Trials per scenario: 3")

        results = run_comparative_trials(scenarios, args.iterations, args.seed)

        successful = sum(1 for r in results if r.get("success"))
        print(f"\n{'=' * 70}")
        print("All Trials Complete!")
        print(f"{'=' * 70}")
        print(f"Successful: {successful}/{len(results)}")

        return 0 if successful == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
