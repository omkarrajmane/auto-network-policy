#!/usr/bin/env python3
"""
================================================================================
AutoResearch Loop - Main orchestration for AutoNetworkPolicy v2.1
================================================================================

This module implements the AutoResearchLoop class that orchestrates the entire
autoresearch system for AI-guided firewall policy optimization.

Execution Flow:
    1. Load config.yaml
    2. Run preflight checks (docker, containerlab, nft)
    3. Deploy Containerlab (if not running)
    4. Load initial policy from data/
    5. Establish baseline (evaluate, commit, log)
    6. For N experiments:
        a. Build context (current policy, recent history, counters)
        b. Query LLM → mutation DSL
        c. Apply mutation deterministically
        d. Syntax check (nft -c)
        e. BDD verify equivalence (exact only)
        f. If not equivalent → reject, log, continue
        g. Deploy policy to fw container
        h. Run evaluation (iperf3 × 3 repeats)
        i. Calculate score
        j. Log to results.tsv
        k. If improved: git commit, advance
        l. If not improved: git reset, revert
    7. Generate summary report

Usage:
    python run.py --input data/generated/acl1_500.nft --experiments 10
    python run.py --input policy.nft --name experiment_1 --max-iterations 50

================================================================================
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from autonetworkpolicy.agent.proposer import Proposer, Mutation
from autonetworkpolicy.agent.provider import LLMProviderFactory
from autonetworkpolicy.data.classbench_to_nft import load_nft_as_rules, rules_to_nft, Rule
from autonetworkpolicy.evaluate.pipeline import EvaluationPipeline
from autonetworkpolicy.mutations import MutationEngine, InvalidMutation
from autonetworkpolicy.verify.bdd_verify import BDDVerifier, verify_equivalence


logger = logging.getLogger(__name__)


class AutoResearchError(Exception):
    """Base exception for autoresearch errors."""

    pass


class PreflightError(AutoResearchError):
    """Raised when preflight checks fail."""

    pass


class ContainerlabError(AutoResearchError):
    """Raised when Containerlab operations fail."""

    pass


class VerificationError(AutoResearchError):
    """Raised when BDD verification fails."""

    pass


class EvaluationError(AutoResearchError):
    """Raised when evaluation fails."""

    pass


class GitError(AutoResearchError):
    """Raised when git operations fail."""

    pass


class AutoResearchLoop:
    """
    Main autoresearch loop for firewall policy optimization.

    This class orchestrates the entire experiment lifecycle:
    - Preflight checks and lab setup
    - Baseline evaluation
    - Iterative mutation and evaluation
    - Git tracking and results logging
    - Summary report generation

    Attributes:
        config: Configuration dictionary loaded from config.yaml
        experiment_name: Name of the current experiment
        max_iterations: Maximum number of mutation iterations
        current_iteration: Current iteration counter
        best_score: Best score achieved so far
        best_commit: Git commit hash of the best policy
        mutation_history: List of all mutations attempted
        results_file: Path to the results.tsv file
        working_dir: Working directory for the experiment
    """

    # Containerlab constants
    LAB_TOPOLOGY = "lab/lab.clab.yml"
    FW_CONTAINER = "clab-autonp-fw"
    CLIENT_CONTAINER = "clab-autonp-client"
    SERVER_CONTAINER = "clab-autonp-server"

    def __init__(self, config: dict, experiment_name: str = "experiment"):
        """
        Initialize the autoresearch loop.

        Args:
            config: Configuration dictionary loaded from config.yaml
            experiment_name: Name for this experiment run
        """
        self.config = config
        self.experiment_name = experiment_name
        self.max_iterations = config.get("experiment", {}).get("max_iterations", 100)

        # State tracking
        self.current_iteration = 0
        self.best_score = 0.0
        self.best_commit = None
        self.baseline_score = 0.0
        self.mutation_history: list[dict] = []
        self.current_rules: list[Rule] = []
        self.original_rules: list[Rule] = []

        # Paths
        self.working_dir = Path(__file__).parent
        self.results_dir = self.working_dir / "results"
        self.results_dir.mkdir(exist_ok=True)
        self.results_file = self.results_dir / f"{experiment_name}.tsv"
        self.current_policy_file = self.working_dir / "data" / "current_policy.nft"
        self.temp_policy_file = self.working_dir / "data" / "temp_policy.nft"

        # Components
        self.mutation_engine = MutationEngine()
        self.proposer: Optional[Proposer] = None
        self.evaluator: Optional[EvaluationPipeline] = None
        self.verifier: Optional[BDDVerifier] = None

        # Git state
        self.git_branch: Optional[str] = None
        self.initial_commit: Optional[str] = None

        logger.info(f"AutoResearchLoop initialized: {experiment_name}")
        logger.info(f"Max iterations: {self.max_iterations}")
        logger.info(f"Results file: {self.results_file}")

    def _run_git_command(
        self, args: list[str], check: bool = True, capture_output: bool = True
    ) -> subprocess.CompletedProcess:
        """
        Run a git command and return the result.

        Args:
            args: List of git arguments
            check: Whether to raise on non-zero exit
            capture_output: Whether to capture stdout/stderr

        Returns:
            CompletedProcess instance

        Raises:
            GitError: If the command fails
        """
        cmd = ["git"] + args
        logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.working_dir,
                capture_output=capture_output,
                text=True,
                check=False,
            )

            if check and result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else "Unknown error"
                raise GitError(f"Git command failed: {' '.join(args)} - {stderr}")

            return result

        except FileNotFoundError:
            raise GitError("Git not found. Please install git.")
        except Exception as e:
            raise GitError(f"Git error: {e}")

    def _is_git_repo(self) -> bool:
        """Check if the working directory is a git repository."""
        try:
            result = self._run_git_command(["rev-parse", "--git-dir"], check=False)
            return result.returncode == 0
        except GitError:
            return False

    def _has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes."""
        result = self._run_git_command(["status", "--porcelain"], check=False)
        return len(result.stdout.strip()) > 0

    def _get_current_commit(self) -> str:
        """Get the current git commit hash."""
        result = self._run_git_command(["rev-parse", "HEAD"])
        return result.stdout.strip()

    def _create_branch(self, branch_name: str) -> None:
        """Create and checkout a new git branch."""
        logger.info(f"Creating git branch: {branch_name}")

        # Create branch
        self._run_git_command(["checkout", "-b", branch_name])
        self.git_branch = branch_name

        logger.info(f"Switched to branch: {branch_name}")

    def _commit_mutation(
        self, iteration: int, mutation: Mutation, score: float, throughput: float
    ) -> str:
        """
        Commit an accepted mutation.

        Args:
            iteration: Current iteration number
            mutation: The mutation that was applied
            score: The resulting score
            throughput: The resulting throughput

        Returns:
            The commit hash
        """
        # Stage the current policy file
        self._run_git_command(["add", str(self.current_policy_file.relative_to(self.working_dir))])

        # Create commit message
        commit_msg = (
            f"Iteration {iteration}: {mutation.mutation_type}\n\n"
            f"Description: {mutation.description}\n"
            f"Operation: {mutation.operation}\n"
            f"Score: {score:.4f}\n"
            f"Throughput: {throughput:.2f} Gbps"
        )

        # Commit
        self._run_git_command(["commit", "-m", commit_msg])

        commit_hash = self._get_current_commit()
        logger.info(f"Committed mutation: {commit_hash[:8]}")

        return commit_hash

    def _reset_to_commit(self, commit_hash: str) -> None:
        """
        Reset to a specific commit (for reverting rejected mutations).

        Args:
            commit_hash: The commit hash to reset to
        """
        logger.info(f"Resetting to commit: {commit_hash[:8]}")
        self._run_git_command(["reset", "--hard", commit_hash])

    def _log_result(
        self,
        commit: str,
        score: float,
        throughput_gbps: float,
        rule_count: int,
        status: str,
        description: str,
    ) -> None:
        """
        Log a result to the results.tsv file.

        Args:
            commit: Git commit hash
            score: Evaluation score
            throughput_gbps: Throughput in Gbps
            rule_count: Number of rules
            status: Status (keep/reject/error)
            description: Description of the mutation
        """
        # Create file with header if it doesn't exist
        if not self.results_file.exists():
            with open(self.results_file, "w") as f:
                f.write("commit\tscore\tthroughput_gbps\trule_count\tstatus\tdescription\n")

        # Append result
        with open(self.results_file, "a") as f:
            f.write(
                f"{commit[:8]}\t{score:.4f}\t{throughput_gbps:.2f}\t"
                f"{rule_count}\t{status}\t{description}\n"
            )

        logger.debug(f"Logged result: {commit[:8]} - {status}")

    def _run_preflight_checks(self) -> None:
        """
        Run preflight checks to validate system requirements.

        Raises:
            PreflightError: If any critical check fails
        """
        logger.info("Running preflight checks...")

        checks = [
            ("docker", self._check_docker),
            ("containerlab", self._check_containerlab),
            ("nftables", self._check_nftables),
        ]

        failures = []
        for name, check_func in checks:
            try:
                if not check_func():
                    failures.append(name)
            except Exception as e:
                logger.error(f"Preflight check failed for {name}: {e}")
                failures.append(name)

        if failures:
            raise PreflightError(
                f"Preflight checks failed: {', '.join(failures)}. "
                "Run 'python scripts/preflight.py' for details."
            )

        logger.info("All preflight checks passed")

    def _check_docker(self) -> bool:
        """Check if Docker is running."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_containerlab(self) -> bool:
        """Check if Containerlab is available."""
        try:
            result = subprocess.run(
                ["clab", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_nftables(self) -> bool:
        """Check if nft is available."""
        try:
            result = subprocess.run(
                ["nft", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _deploy_containerlab(self) -> None:
        """
        Deploy Containerlab topology if not already running.

        Raises:
            ContainerlabError: If deployment fails
        """
        logger.info("Checking Containerlab status...")

        # Check if already running
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.FW_CONTAINER}", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if self.FW_CONTAINER in result.stdout:
                logger.info("Containerlab already running")
                return
        except Exception as e:
            logger.warning(f"Could not check container status: {e}")

        # Deploy
        logger.info("Deploying Containerlab topology...")
        topology_path = self.working_dir / self.LAB_TOPOLOGY

        if not topology_path.exists():
            raise ContainerlabError(f"Topology file not found: {topology_path}")

        try:
            result = subprocess.run(
                ["clab", "deploy", "-t", str(topology_path), "--reconfigure"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise ContainerlabError(f"Deployment failed: {result.stderr}")

            logger.info("Containerlab deployed successfully")

            # Wait for containers to be ready
            time.sleep(5)

        except subprocess.TimeoutExpired:
            raise ContainerlabError("Deployment timed out after 120 seconds")
        except FileNotFoundError:
            raise ContainerlabError("clab command not found")
        except Exception as e:
            raise ContainerlabError(f"Deployment error: {e}")

    def _syntax_check(self, policy_file: Path) -> tuple[bool, Optional[str]]:
        """
        Check nftables syntax using nft -c.

        Args:
            policy_file: Path to the policy file

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            result = subprocess.run(
                ["nft", "-c", "-f", str(policy_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                return True, None
            else:
                return False, result.stderr.strip()

        except Exception as e:
            return False, str(e)

    def _save_rules(self, rules: list[Rule], output_file: Path) -> None:
        """
        Save rules to an nftables file.

        Args:
            rules: List of Rule objects
            output_file: Path to write the nftables configuration
        """
        nft_config = rules_to_nft(rules)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            f.write(nft_config)

    def _load_rules(self, input_file: Path) -> list[Rule]:
        """
        Load rules from an nftables file.

        Args:
            input_file: Path to the nftables file

        Returns:
            List of Rule objects
        """
        return load_nft_as_rules(input_file)

    def _build_context(self) -> dict:
        """
        Build context for the LLM proposer.

        Returns:
            Dictionary with context for mutation proposal
        """
        # Get recent mutations (last 5)
        recent_mutations = self.mutation_history[-5:] if self.mutation_history else []

        # Build performance metrics
        metrics = {
            "current_score": self.best_score,
            "baseline_score": self.baseline_score,
            "rule_count": len(self.current_rules),
        }

        # Add recent hit rates if available
        if self.mutation_history:
            last_entry = self.mutation_history[-1]
            if "hit_rates" in last_entry:
                metrics["hit_rates"] = last_entry["hit_rates"]

        # Convert rules to simple dict format for context
        policy_context = []
        for rule in self.current_rules[:20]:  # Limit to first 20 for context size
            policy_context.append(
                {
                    "index": rule.index,
                    "src_ip": rule.src_ip,
                    "dst_ip": rule.dst_ip,
                    "action": rule.action,
                }
            )

        return {
            "current_policy": policy_context,
            "recent_mutations": recent_mutations,
            "performance_metrics": metrics,
            "iteration": self.current_iteration,
            "max_iterations": self.max_iterations,
            "rule_count": len(self.current_rules),
        }

    def run_iteration(self) -> dict:
        """
        Run a single iteration of the autoresearch loop.

        This method:
        1. Builds context from current state
        2. Queries LLM for a mutation
        3. Applies the mutation
        4. Verifies equivalence with BDD
        5. Evaluates the mutated policy
        6. Commits if improved, resets if not

        Returns:
            Dictionary with iteration results
        """
        iteration_start = time.time()
        self.current_iteration += 1

        logger.info(f"\n{'=' * 60}")
        logger.info(f"Starting iteration {self.current_iteration}/{self.max_iterations}")
        logger.info(f"{'=' * 60}")

        result = {
            "iteration": self.current_iteration,
            "success": False,
            "mutation_applied": False,
            "score": 0.0,
            "throughput_gbps": 0.0,
            "rule_count": len(self.current_rules),
            "status": "error",
            "description": "",
            "commit": None,
            "error": None,
            "duration_seconds": 0.0,
        }

        try:
            # Step 1: Build context and query LLM
            logger.info("Building context and querying LLM...")
            context = self._build_context()

            if self.proposer is None:
                raise AutoResearchError("Proposer not initialized")

            mutation = self.proposer.propose_mutation(context)

            if mutation is None:
                result["status"] = "error"
                result["description"] = "LLM failed to propose valid mutation"
                logger.warning("LLM failed to propose valid mutation")
                return result

            logger.info(f"Proposed mutation: {mutation.mutation_type}")
            logger.info(f"Description: {mutation.description}")
            logger.info(f"Operation: {mutation.operation}")

            result["description"] = f"{mutation.mutation_type}: {mutation.description}"

            # Step 2: Apply mutation
            logger.info("Applying mutation...")

            try:
                new_rules = self.mutation_engine.apply_mutation(
                    self.current_rules, mutation.operation
                )
            except InvalidMutation as e:
                result["status"] = "error"
                result["description"] = f"Invalid mutation: {e.message}"
                result["error"] = str(e)
                logger.error(f"Invalid mutation: {e.message}")
                return result

            logger.info(f"Mutation applied: {len(self.current_rules)} -> {len(new_rules)} rules")

            # Step 3: Syntax check
            logger.info("Running syntax check...")
            self._save_rules(new_rules, self.temp_policy_file)

            is_valid, error = self._syntax_check(self.temp_policy_file)
            if not is_valid:
                result["status"] = "reject"
                result["description"] = f"Syntax error: {error}"
                logger.error(f"Syntax check failed: {error}")
                return result

            logger.info("Syntax check passed")

            # Step 4: BDD verification
            logger.info("Running BDD verification...")

            if self.verifier is None:
                raise AutoResearchError("Verifier not initialized")

            verify_result = self.verifier.verify(self.current_rules, new_rules)

            if not verify_result.get("equivalent", False):
                result["status"] = "reject"
                result["description"] = (
                    f"BDD verification failed: {verify_result.get('error', 'Not equivalent')}"
                )
                logger.error(
                    f"BDD verification failed: {verify_result.get('error', 'Not equivalent')}"
                )
                return result

            verify_time = verify_result.get("time_seconds", 0)
            logger.info(f"BDD verification passed ({verify_time:.3f}s)")

            # Step 5: Evaluate
            logger.info("Running evaluation...")

            if self.evaluator is None:
                raise AutoResearchError("Evaluator not initialized")

            # Save mutated policy as current
            self._save_rules(new_rules, self.current_policy_file)

            eval_result = self.evaluator.evaluate(str(self.current_policy_file))

            if not eval_result.get("success", False):
                result["status"] = "error"
                result["description"] = (
                    f"Evaluation failed: {eval_result.get('error_message', 'Unknown error')}"
                )
                logger.error(
                    f"Evaluation failed: {eval_result.get('error_message', 'Unknown error')}"
                )
                return result

            score = eval_result.get("score", 0.0)
            throughput = eval_result.get("throughput_gbps", 0.0)
            rule_count = eval_result.get("rule_count", len(new_rules))

            logger.info(f"Evaluation complete: score={score:.4f}, throughput={throughput:.2f} Gbps")

            # Update result
            result["score"] = score
            result["throughput_gbps"] = throughput
            result["rule_count"] = rule_count
            result["mutation_applied"] = True

            # Step 6: Decide whether to keep or revert
            if score > self.best_score:
                # Improved! Commit and advance
                logger.info(f"Score improved: {self.best_score:.4f} -> {score:.4f}")

                commit_hash = self._commit_mutation(
                    self.current_iteration, mutation, score, throughput
                )

                self.best_score = score
                self.best_commit = commit_hash
                self.current_rules = new_rules

                result["status"] = "keep"
                result["commit"] = commit_hash

                # Record in history
                self.mutation_history.append(
                    {
                        "iteration": self.current_iteration,
                        "mutation_type": mutation.mutation_type,
                        "description": mutation.description,
                        "operation": mutation.operation,
                        "outcome": "accepted",
                        "score": score,
                        "score_change": score - self.best_score,
                        "throughput_gbps": throughput,
                        "hit_rates": eval_result.get("hit_rates", {}),
                    }
                )

            else:
                # Not improved, reset
                logger.info(f"Score not improved: {self.best_score:.4f} >= {score:.4f}")

                if self.best_commit:
                    self._reset_to_commit(self.best_commit)
                    # Reload rules after reset
                    self.current_rules = self._load_rules(self.current_policy_file)

                result["status"] = "reject"
                result["description"] = f"{result['description']} (score not improved)"

                # Record in history
                self.mutation_history.append(
                    {
                        "iteration": self.current_iteration,
                        "mutation_type": mutation.mutation_type,
                        "description": mutation.description,
                        "operation": mutation.operation,
                        "outcome": "rejected",
                        "score": score,
                        "score_change": score - self.best_score,
                        "throughput_gbps": throughput,
                    }
                )

            result["success"] = True

        except Exception as e:
            logger.exception(f"Iteration {self.current_iteration} failed")
            result["error"] = str(e)
            result["description"] = f"Error: {e}"

        finally:
            # Calculate duration
            result["duration_seconds"] = time.time() - iteration_start

            # Log to results.tsv
            self._log_result(
                commit=result.get("commit") or self.best_commit or "HEAD",
                score=result["score"],
                throughput_gbps=result["throughput_gbps"],
                rule_count=result["rule_count"],
                status=result["status"],
                description=result["description"],
            )

        return result

    def run(self, input_file: str, max_iterations: int = 100) -> dict:
        """
        Run the full autoresearch loop.

        This method orchestrates the entire experiment lifecycle:
        1. Load config and run preflight checks
        2. Deploy Containerlab
        3. Load initial policy and establish baseline
        4. Run mutation iterations
        5. Generate summary report

        Args:
            input_file: Path to the initial nftables policy file
            max_iterations: Maximum number of iterations to run

        Returns:
            Dictionary with final results and summary
        """
        start_time = time.time()
        self.max_iterations = max_iterations

        logger.info(f"\n{'=' * 70}")
        logger.info(f"Starting AutoResearch Loop: {self.experiment_name}")
        logger.info(f"Input: {input_file}")
        logger.info(f"Max iterations: {max_iterations}")
        logger.info(f"{'=' * 70}\n")

        # Step 1: Preflight checks
        try:
            self._run_preflight_checks()
        except PreflightError as e:
            logger.error(f"Preflight checks failed: {e}")
            return {"success": False, "error": str(e), "iterations_completed": 0}

        # Step 2: Initialize components
        try:
            logger.info("Initializing components...")

            # Initialize proposer
            llm_config = self.config.get("llm", {})
            provider = LLMProviderFactory.create()
            self.proposer = Proposer(provider=provider)

            # Initialize evaluator
            eval_config = self.config.get("evaluation", {})
            self.evaluator = EvaluationPipeline(config=eval_config)

            # Initialize verifier
            verifier_config = self.config.get("verifier", {})
            self.verifier = BDDVerifier(
                backend=verifier_config.get("backend", "autoref"),
                mode=verifier_config.get("mode", "ip_only"),
                timeout_seconds=verifier_config.get("timeout_seconds", 60),
            )

            logger.info("Components initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            return {
                "success": False,
                "error": f"Initialization failed: {e}",
                "iterations_completed": 0,
            }

        # Step 3: Deploy Containerlab
        try:
            self._deploy_containerlab()
        except ContainerlabError as e:
            logger.error(f"Containerlab deployment failed: {e}")
            return {"success": False, "error": str(e), "iterations_completed": 0}

        # Step 4: Load initial policy
        try:
            input_path = Path(input_file)
            if not input_path.exists():
                # Try relative to working directory
                input_path = self.working_dir / input_file

            if not input_path.exists():
                raise AutoResearchError(f"Input file not found: {input_file}")

            logger.info(f"Loading initial policy from: {input_path}")
            self.original_rules = self._load_rules(input_path)
            self.current_rules = copy.deepcopy(self.original_rules)

            logger.info(f"Loaded {len(self.current_rules)} rules")

            # Save as current policy
            self._save_rules(self.current_rules, self.current_policy_file)

        except Exception as e:
            logger.error(f"Failed to load initial policy: {e}")
            return {
                "success": False,
                "error": f"Policy load failed: {e}",
                "iterations_completed": 0,
            }

        # Step 5: Setup git tracking
        try:
            if self._is_git_repo():
                # Create experiment branch
                branch_name = f"autofw/{datetime.now().strftime('%Y-%m-%d')}-{self.experiment_name}"
                self._create_branch(branch_name)

                # Commit initial policy
                self._run_git_command(
                    ["add", str(self.current_policy_file.relative_to(self.working_dir))]
                )
                self._run_git_command(["commit", "-m", f"Initial policy: {self.experiment_name}"])
                self.initial_commit = self._get_current_commit()
                self.best_commit = self.initial_commit

                logger.info(f"Git tracking initialized on branch: {branch_name}")
            else:
                logger.warning("Not a git repository - git tracking disabled")

        except GitError as e:
            logger.warning(f"Git setup failed: {e}")
            logger.warning("Continuing without git tracking")

        # Step 6: Establish baseline
        try:
            logger.info("\nEstablishing baseline...")
            baseline_result = self.evaluator.evaluate(str(self.current_policy_file))

            if not baseline_result.get("success", False):
                raise EvaluationError(
                    f"Baseline evaluation failed: {baseline_result.get('error_message')}"
                )

            self.baseline_score = baseline_result.get("score", 0.0)
            self.best_score = self.baseline_score

            logger.info(f"Baseline established: score={self.baseline_score:.4f}")

            # Log baseline
            self._log_result(
                commit=self.initial_commit or "baseline",
                score=self.baseline_score,
                throughput_gbps=baseline_result.get("throughput_gbps", 0.0),
                rule_count=len(self.current_rules),
                status="baseline",
                description="Initial policy baseline",
            )

        except Exception as e:
            logger.error(f"Baseline establishment failed: {e}")
            return {"success": False, "error": f"Baseline failed: {e}", "iterations_completed": 0}

        # Step 7: Run iterations
        logger.info(f"\n{'=' * 70}")
        logger.info("Starting mutation iterations...")
        logger.info(f"{'=' * 70}\n")

        completed_iterations = 0
        successful_mutations = 0

        for i in range(max_iterations):
            iteration_result = self.run_iteration()
            completed_iterations += 1

            if iteration_result.get("success") and iteration_result.get("mutation_applied"):
                successful_mutations += 1

            # Progress update every 10 iterations
            if (i + 1) % 10 == 0:
                logger.info(f"\n--- Progress: {i + 1}/{max_iterations} iterations ---")
                logger.info(f"Best score: {self.best_score:.4f}")
                logger.info(f"Successful mutations: {successful_mutations}")

        # Step 8: Generate summary
        total_duration = time.time() - start_time

        summary = {
            "success": True,
            "experiment_name": self.experiment_name,
            "iterations_completed": completed_iterations,
            "successful_mutations": successful_mutations,
            "baseline_score": self.baseline_score,
            "best_score": self.best_score,
            "improvement": ((self.best_score - self.baseline_score) / self.baseline_score * 100)
            if self.baseline_score > 0
            else 0,
            "best_commit": self.best_commit,
            "final_rule_count": len(self.current_rules),
            "total_duration_seconds": total_duration,
            "results_file": str(self.results_file),
        }

        self._generate_summary_report(summary)

        logger.info(f"\n{'=' * 70}")
        logger.info("AutoResearch Loop Complete!")
        logger.info(f"{'=' * 70}")
        logger.info(
            f"Best score: {summary['best_score']:.4f} (was {summary['baseline_score']:.4f})"
        )
        logger.info(f"Improvement: {summary['improvement']:.1f}%")
        logger.info(f"Results: {self.results_file}")
        logger.info(f"Duration: {total_duration / 60:.1f} minutes")
        logger.info(f"{'=' * 70}\n")

        return summary

    def _generate_summary_report(self, summary: dict) -> None:
        """
        Generate a summary report file.

        Args:
            summary: Dictionary with summary data
        """
        report_file = self.results_dir / f"{self.experiment_name}_summary.json"

        with open(report_file, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Summary report written to: {report_file}")

        # Also generate text summary
        text_report_file = self.results_dir / f"{self.experiment_name}_summary.txt"

        with open(text_report_file, "w") as f:
            f.write(f"AutoNetworkPolicy Experiment Summary\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Experiment: {summary['experiment_name']}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Results:\n")
            f.write(f"  Iterations: {summary['iterations_completed']}\n")
            f.write(f"  Successful mutations: {summary['successful_mutations']}\n")
            f.write(f"  Baseline score: {summary['baseline_score']:.4f}\n")
            f.write(f"  Best score: {summary['best_score']:.4f}\n")
            f.write(f"  Improvement: {summary['improvement']:.1f}%\n")
            f.write(f"  Final rules: {summary['final_rule_count']}\n")
            f.write(f"\nGit:\n")
            f.write(f"  Branch: {self.git_branch or 'N/A'}\n")
            f.write(
                f"  Best commit: {summary['best_commit'][:8] if summary['best_commit'] else 'N/A'}\n"
            )
            f.write(f"\nFiles:\n")
            f.write(f"  Results: {summary['results_file']}\n")
            f.write(f"  Summary: {report_file}\n")
            f.write(f"\nDuration: {summary['total_duration_seconds'] / 60:.1f} minutes\n")


def main():
    """CLI entry point for the autoresearch loop."""
    parser = argparse.ArgumentParser(
        description="AutoNetworkPolicy - Automated firewall policy optimization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run 10 experiments on acl1_500.nft
    python run.py --input data/generated/acl1_500.nft --experiments 10

    # Run with custom name
    python run.py --input policy.nft --name experiment_1 --max-iterations 50

    # Run with verbose logging
    python run.py --input data/generated/acl1_500.nft --experiments 5 --verbose

    # Dry run (preflight only)
    python run.py --preflight
        """,
    )

    parser.add_argument(
        "--input",
        "-i",
        type=str,
        help="Path to initial nftables policy file",
    )

    parser.add_argument(
        "--experiments",
        "-e",
        type=int,
        default=10,
        help="Number of experiment iterations (default: 10)",
    )

    parser.add_argument(
        "--name",
        "-n",
        type=str,
        default=None,
        help="Experiment name (default: autofw_YYYY-MM-DD_HHMMSS)",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Maximum iterations (overrides config)",
    )

    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )

    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run preflight checks only and exit",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-error output",
    )

    args = parser.parse_args()

    # Setup logging
    if args.quiet:
        log_level = logging.WARNING
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        # Try relative to script directory
        config_path = Path(__file__).parent / args.config

    if not config_path.exists():
        logger.error(f"Config file not found: {args.config}")
        sys.exit(1)

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Preflight only mode
    if args.preflight:
        logger.info("Running preflight checks only...")
        loop = AutoResearchLoop(config, "preflight")
        try:
            loop._run_preflight_checks()
            logger.info("Preflight checks passed!")
            sys.exit(0)
        except PreflightError as e:
            logger.error(f"Preflight checks failed: {e}")
            sys.exit(1)

    # Validate required arguments
    if not args.input:
        logger.error("--input is required (unless using --preflight)")
        parser.print_help()
        sys.exit(1)

    # Generate experiment name if not provided
    experiment_name = args.name
    if not experiment_name:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        experiment_name = f"autofw_{timestamp}"

    # Determine max iterations
    max_iterations = args.max_iterations
    if max_iterations is None:
        max_iterations = config.get("experiment", {}).get("max_iterations", 100)

    # Create and run the loop
    loop = AutoResearchLoop(config, experiment_name)

    try:
        results = loop.run(args.input, max_iterations=max_iterations)

        if results.get("success"):
            logger.info(f"\nExperiment completed successfully!")
            logger.info(f"Best score: {results['best_score']:.4f}")
            logger.info(f"Improvement: {results['improvement']:.1f}%")
            sys.exit(0)
        else:
            logger.error(f"Experiment failed: {results.get('error', 'Unknown error')}")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unexpected error during experiment")
        sys.exit(1)


if __name__ == "__main__":
    main()
