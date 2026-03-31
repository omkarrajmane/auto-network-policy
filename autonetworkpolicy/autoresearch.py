#!/usr/bin/env python3
# pyright: reportMissingImports=false
"""Autonomous loop entry point for ruleset mutation search."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Any, cast

import yaml

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from autonetworkpolicy.agent.proposer import Proposer
from autonetworkpolicy.data.classbench_to_nft import load_nft_as_rules, rules_to_nft
from autonetworkpolicy.evaluate.match_depth import compute_match_depth
from autonetworkpolicy.evaluate.weighted_match_depth import (
    ENTERPRISE_TRAFFIC,
    compute_weighted_match_depth,
)
from autonetworkpolicy.mutations import InvalidMutation, MutationEngine
from autonetworkpolicy.utils.git_tracker import GitError, GitTracker
from autonetworkpolicy.utils.results_logger import ResultsLogger
from autonetworkpolicy.verify.bdd_verify import BDDVerifier


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run autonomous mutation loop")
    parser.add_argument("--input", required=True, help="Path to input .nft file")
    parser.add_argument(
        "--iterations",
        type=int,
        default=-1,
        help="Number of iterations (-1 for infinite)",
    )
    parser.add_argument(
        "--name",
        default="autoresearch",
        help="Experiment tag used in branch name",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed for match depth sampling",
    )
    parser.add_argument(
        "--traffic-profile",
        choices=["enterprise", "none"],
        default="none",
        help="Traffic profile for weighted scoring (default: none = random match depth)",
    )
    return parser.parse_args(argv)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _resolve_input_path(input_arg: str, root: Path) -> Path:
    candidate = Path(input_arg)
    if candidate.exists():
        return candidate.resolve()
    rooted = root / input_arg
    if rooted.exists():
        return rooted.resolve()
    raise FileNotFoundError(f"Input file not found: {input_arg}")


def _load_verifier_config(config_path: Path) -> tuple[str, str, float]:
    backend = "autoref"
    mode = "ip_only"
    timeout_seconds = 30.0

    if not config_path.exists():
        return backend, mode, timeout_seconds

    with open(config_path) as fh:
        config = yaml.safe_load(fh) or {}

    verifier_cfg = config.get("verifier", {})
    backend = verifier_cfg.get("backend", backend)

    if "mode" in verifier_cfg:
        mode = verifier_cfg["mode"]
    elif verifier_cfg.get("ip_only", True):
        mode = "ip_only"
    else:
        mode = "full"

    timeout_seconds = float(verifier_cfg.get("timeout_seconds", timeout_seconds))
    return backend, mode, timeout_seconds


def _rule_to_context(rule: Any) -> dict[str, Any]:
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
    return ctx


def _build_context(
    rules: list[Any],
    current_depth: float,
    recent_history: list[dict[str, Any]],
    iteration: int,
    max_iterations: int,
    traffic_profile: Any = None,
) -> dict[str, Any]:
    policy_window = rules[:80]
    ctx: dict[str, Any] = {
        "current_policy": [_rule_to_context(rule) for rule in policy_window],
        "recent_mutations": recent_history[-5:],
        "performance_metrics": {
            "match_depth": round(current_depth, 4),
            "rule_count": len(rules),
            "context_rule_window": len(policy_window),
        },
        "iteration": iteration,
        "max_iterations": max_iterations,
        "rule_count": len(rules),
    }
    if traffic_profile is not None:
        ctx["traffic_profile"] = {
            "name": traffic_profile.name,
            "flow_classes": [
                {
                    "name": fc.name,
                    "weight": fc.weight,
                    "protocol": fc.protocol,
                    "dst_port": fc.dst_port,
                }
                for fc in traffic_profile.flow_classes
            ],
            "guidance": (
                "TRAFFIC-WEIGHTED SCORING IS ACTIVE. "
                "Rules matching high-weight flow classes should be moved earlier. "
                "Focus on reducing weighted_match_depth, not just rule count. "
                "The heaviest flows are: "
                + ", ".join(
                    f"{fc.name} ({fc.weight * 100:.0f}%)"
                    for fc in sorted(traffic_profile.flow_classes, key=lambda f: -f.weight)[:4]
                )
            ),
        }
    return ctx


def _write_rules(path: Path, rules: list[Any]) -> None:
    nft_text = rules_to_nft(rules)
    with open(path, "w") as fh:
        fh.write(nft_text)


def _sanitize_branch_component(name: str) -> str:
    cleaned = "-".join(name.strip().split())
    return cleaned or "autoresearch"


def _ensure_api_key() -> bool:
    """Check that the configured provider's credentials are available."""
    config_path = Path(__file__).resolve().parent / "config.yaml"
    provider = "openrouter"  # default
    if config_path.exists():
        with open(config_path) as fh:
            config = yaml.safe_load(fh) or {}
        provider = config.get("llm", {}).get("provider", "openrouter")

    if provider == "claude_subprocess":
        if shutil.which("claude"):
            return True
        print(
            "Error: 'claude' CLI not found in PATH. "
            "Install Claude Code CLI to use claude_subprocess provider.",
            file=sys.stderr,
        )
        return False

    if provider == "opencode_subprocess":
        if shutil.which("opencode"):
            return True
        print(
            "Error: 'opencode' CLI not found in PATH. "
            "Install OpenCode CLI to use opencode_subprocess provider.",
            file=sys.stderr,
        )
        return False

    # Default: check for OPENROUTER_API_KEY
    api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if api_key:
        return True
    print(
        "Error: OPENROUTER_API_KEY is not set. "
        "Export OPENROUTER_API_KEY before running autoresearch.",
        file=sys.stderr,
    )
    return False


def _record_iteration(
    *,
    results_logger: ResultsLogger,
    git_tracker: GitTracker,
    iteration: int,
    proposed_type: str,
    verify_state: str,
    before_depth: float,
    after_depth: float,
    status: str,
    description: str,
    rule_count: int,
    history: list[dict[str, Any]],
) -> None:
    commit_ref = git_tracker.get_current_commit()
    results_logger.log_iteration(
        commit=commit_ref,
        score=before_depth if status != "keep" else after_depth,
        throughput_gbps=0.0,
        rule_count=rule_count,
        status=status,
        description=description,
    )
    print(
        f"iteration {iteration} | proposed: {proposed_type} | verify: {verify_state} | "
        f"depth: {before_depth:.2f} -> {after_depth:.2f} | status: {status}"
    )
    history.append(
        {
            "mutation_type": proposed_type,
            "description": description,
            "outcome": status,
            "verify": verify_state,
            "depth_before": round(before_depth, 4),
            "depth_after": round(after_depth, 4),
        }
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if not _ensure_api_key():
        return 1

    root = _repo_root()
    input_path = _resolve_input_path(args.input, root)

    git_tracker = GitTracker(str(root))
    branch_name = f"autoresearch/{_sanitize_branch_component(args.name)}"
    current_branch = git_tracker.get_branch_name()
    if current_branch != branch_name:
        if not git_tracker.create_branch(branch_name):
            print(
                f"Error: failed to create branch '{branch_name}'. "
                "If it already exists, checkout it and rerun.",
                file=sys.stderr,
            )
            return 1

    rules = load_nft_as_rules(input_path)
    profile = ENTERPRISE_TRAFFIC if args.traffic_profile == "enterprise" else None
    if profile is not None:
        result = compute_weighted_match_depth(rules, profile, seed=args.seed)
        current_depth = result["weighted_avg_depth"]
    else:
        current_depth = compute_match_depth(cast(Any, rules), seed=args.seed)

    backend, mode, timeout_seconds = _load_verifier_config(
        root / "autonetworkpolicy" / "config.yaml"
    )
    verifier = BDDVerifier(backend=backend, mode=mode, timeout_seconds=timeout_seconds)
    try:
        proposer = Proposer()
    except Exception as exc:
        print(f"Error: failed to initialize proposer: {exc}", file=sys.stderr)
        return 1
    mutation_engine = MutationEngine()
    results_logger = ResultsLogger(log_file=str(root / "results.tsv"))

    history: list[dict[str, Any]] = []

    iteration = 0
    while args.iterations == -1 or iteration < args.iterations:
        iteration += 1
        before_rules = rules
        before_depth = current_depth

        proposed_type = "none"
        verify_state = "fail"
        after_depth = before_depth
        status = "reject"
        description = ""

        context = _build_context(
            rules=before_rules,
            current_depth=before_depth,
            recent_history=history,
            iteration=iteration,
            max_iterations=args.iterations if args.iterations > 0 else -1,
            traffic_profile=profile,
        )

        try:
            mutation = proposer.propose_mutation(context)
        except Exception as exc:
            mutation = None
            description = f"llm error: {exc}"

        if mutation is None:
            if not description:
                description = "llm proposal failed"
            _record_iteration(
                results_logger=results_logger,
                git_tracker=git_tracker,
                iteration=iteration,
                proposed_type=proposed_type,
                verify_state=verify_state,
                before_depth=before_depth,
                after_depth=after_depth,
                status=status,
                description=description,
                rule_count=len(before_rules),
                history=history,
            )
            continue

        proposed_type = mutation.mutation_type
        description = mutation.description or str(mutation.operation)

        try:
            candidate_rules = mutation_engine.apply_mutation(before_rules, mutation.operation)
        except InvalidMutation as exc:
            description = f"invalid mutation: {exc.message}"
            _record_iteration(
                results_logger=results_logger,
                git_tracker=git_tracker,
                iteration=iteration,
                proposed_type=proposed_type,
                verify_state=verify_state,
                before_depth=before_depth,
                after_depth=after_depth,
                status=status,
                description=description,
                rule_count=len(before_rules),
                history=history,
            )
            continue

        verify_result = verifier.verify(before_rules, candidate_rules)
        if not verify_result.get("equivalent", False):
            description = f"verify failed: {verify_result.get('error', 'not equivalent')}"
            _record_iteration(
                results_logger=results_logger,
                git_tracker=git_tracker,
                iteration=iteration,
                proposed_type=proposed_type,
                verify_state=verify_state,
                before_depth=before_depth,
                after_depth=after_depth,
                status=status,
                description=description,
                rule_count=len(before_rules),
                history=history,
            )
            continue

        verify_state = "pass"
        if profile is not None:
            result = compute_weighted_match_depth(candidate_rules, profile, seed=args.seed)
            after_depth = result["weighted_avg_depth"]
        else:
            after_depth = compute_match_depth(cast(Any, candidate_rules), seed=args.seed)

        if after_depth < before_depth:
            _write_rules(input_path, candidate_rules)
            rules = candidate_rules
            current_depth = after_depth
            status = "keep"

            try:
                commit_hash = git_tracker.commit_mutation(
                    policy_file=str(input_path),
                    mutation_desc=description,
                    metrics={
                        "iteration": iteration,
                        "mutation_type": proposed_type,
                        "operation": mutation.operation,
                        "score": after_depth,
                        "throughput_gbps": 0.0,
                    },
                )
            except GitError as exc:
                _write_rules(input_path, before_rules)
                rules = before_rules
                current_depth = before_depth
                status = "reject"
                description = f"git commit failed: {exc}"
                commit_hash = git_tracker.get_current_commit()
        else:
            commit_hash = git_tracker.get_current_commit()

        results_logger.log_iteration(
            commit=commit_hash,
            score=current_depth if status == "keep" else before_depth,
            throughput_gbps=0.0,
            rule_count=len(rules) if status == "keep" else len(before_rules),
            status=status,
            description=description,
        )

        print(
            f"iteration {iteration} | proposed: {proposed_type} | verify: {verify_state} | "
            f"depth: {before_depth:.2f} -> {after_depth:.2f} | status: {status}"
        )

        history.append(
            {
                "mutation_type": proposed_type,
                "description": description,
                "outcome": status,
                "verify": verify_state,
                "depth_before": round(before_depth, 4),
                "depth_after": round(after_depth, 4),
            }
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
