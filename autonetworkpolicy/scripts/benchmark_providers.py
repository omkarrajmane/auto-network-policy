#!/usr/bin/env python3
# pyright: reportMissingImports=false

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from autonetworkpolicy.agent.provider import LLMConfig, LLMProviderFactory
from autonetworkpolicy.data.classbench_to_nft import Rule, load_nft_as_rules


@dataclass
class IterationResult:
    elapsed_seconds: float
    success: bool
    mutation_label: str
    error: str = ""


def build_context(rules: list[Rule], iterations: int) -> dict[str, Any]:
    policy_context: list[dict[str, Any]] = []
    for rule in rules[:30]:
        policy_context.append(
            {
                "index": rule.index,
                "src_ip": rule.src_ip,
                "dst_ip": rule.dst_ip,
                "src_port": rule.src_port,
                "dst_port": rule.dst_port,
                "protocol": rule.protocol,
                "action": rule.action,
            }
        )

    return {
        "current_policy": policy_context,
        "recent_mutations": [],
        "performance_metrics": {
            "match_depth": 15.5,
            "rule_count": len(rules),
        },
        "iteration": 1,
        "max_iterations": iterations,
        "rule_count": len(rules),
    }


def format_mutation_label(mutation: dict[str, Any]) -> str:
    op = mutation.get("operation", {})
    name = op.get("name", mutation.get("mutation_type", "unknown"))
    args = op.get("args", [])
    if not isinstance(args, list):
        args = []
    args_str = ",".join(str(arg) for arg in args)
    return f"{name}({args_str})"


def summarize_results(results: list[IterationResult]) -> dict[str, float | int]:
    times = [r.elapsed_seconds for r in results]
    successes = [r for r in results if r.success]
    success_times = [r.elapsed_seconds for r in successes]

    avg = statistics.mean(times) if times else 0.0
    p50 = statistics.median(times) if times else 0.0
    min_v = min(times) if times else 0.0
    max_v = max(times) if times else 0.0
    stdev = statistics.stdev(times) if len(times) > 1 else 0.0
    total = sum(times)

    return {
        "avg": avg,
        "min": min_v,
        "max": max_v,
        "p50": p50,
        "stdev": stdev,
        "success": len(successes),
        "success_avg": statistics.mean(success_times) if success_times else 0.0,
        "total": total,
        "count": len(results),
    }


def run_provider_benchmark(
    provider_label: str,
    short_label: str,
    provider_name: str,
    config: LLMConfig,
    context: dict[str, Any],
    iterations: int,
) -> list[IterationResult]:
    results: list[IterationResult] = []

    try:
        provider = LLMProviderFactory.create(provider_name=provider_name, config=config)
    except Exception as exc:
        for idx in range(1, iterations + 1):
            print(f"{short_label} [{idx}/{iterations}]: 0.00s - provider_init_failed ✗ ({exc})")
            results.append(
                IterationResult(
                    elapsed_seconds=0.0,
                    success=False,
                    mutation_label="provider_init_failed",
                    error=str(exc),
                )
            )
        return results

    for idx in range(1, iterations + 1):
        start = time.perf_counter()
        try:
            mutation = provider.generate(context)
            elapsed = time.perf_counter() - start
            label = format_mutation_label(mutation)
            results.append(
                IterationResult(elapsed_seconds=elapsed, success=True, mutation_label=label)
            )
            print(f"{short_label} [{idx}/{iterations}]: {elapsed:.2f}s - {label} ✓")
        except Exception as exc:
            elapsed = time.perf_counter() - start
            results.append(
                IterationResult(
                    elapsed_seconds=elapsed,
                    success=False,
                    mutation_label="error",
                    error=str(exc),
                )
            )
            print(f"{short_label} [{idx}/{iterations}]: {elapsed:.2f}s - error ✗ ({exc})")

    provider_summary = summarize_results(results)
    print(
        f"{provider_label} complete: {provider_summary['success']}/{provider_summary['count']} "
        f"success, avg={provider_summary['avg']:.2f}s, p50={provider_summary['p50']:.2f}s"
    )
    return results


def print_comparison_table(
    claude_results: list[IterationResult] | None,
    gemini_results: list[IterationResult] | None,
) -> None:
    print("\n============ BENCHMARK RESULTS ============")
    print("Provider          | Avg    | Min    | Max    | P50    | Success | Total")

    claude_stats = summarize_results(claude_results) if claude_results is not None else None
    gemini_stats = summarize_results(gemini_results) if gemini_results is not None else None

    if claude_stats is not None:
        print(
            "Claude Opus 4.6   "
            f"| {claude_stats['avg']:.2f}s "
            f"| {claude_stats['min']:.2f}s "
            f"| {claude_stats['max']:.2f}s "
            f"| {claude_stats['p50']:.2f}s "
            f"| {claude_stats['success']}/{claude_stats['count']}"
            f"   | {claude_stats['total']:.1f}s"
        )

    if gemini_stats is not None:
        print(
            "Gemini 3.1 Pro    "
            f"| {gemini_stats['avg']:.2f}s "
            f"| {gemini_stats['min']:.2f}s "
            f"| {gemini_stats['max']:.2f}s "
            f"| {gemini_stats['p50']:.2f}s "
            f"| {gemini_stats['success']}/{gemini_stats['count']}"
            f"   | {gemini_stats['total']:.1f}s"
        )

    if claude_stats is not None and gemini_stats is not None:
        if claude_stats["avg"] > 0 and gemini_stats["avg"] > 0:
            if claude_stats["avg"] > gemini_stats["avg"]:
                speedup = claude_stats["avg"] / gemini_stats["avg"]
                print(f"Speedup: Gemini is {speedup:.1f}x faster")
            elif gemini_stats["avg"] > claude_stats["avg"]:
                speedup = gemini_stats["avg"] / claude_stats["avg"]
                print(f"Speedup: Claude is {speedup:.1f}x faster")
            else:
                print("Speedup: Both providers have equal average latency")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark LLM provider latency")
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of iterations per provider (default: 10)",
    )
    parser.add_argument(
        "--claude-only",
        action="store_true",
        help="Run only Claude subprocess benchmark",
    )
    parser.add_argument(
        "--gemini-only",
        action="store_true",
        help="Run only OpenRouter Gemini benchmark",
    )
    args = parser.parse_args()

    if args.claude_only and args.gemini_only:
        parser.error("--claude-only and --gemini-only are mutually exclusive")
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")

    return args


def main() -> int:
    args = parse_args()

    load_dotenv(Path(__file__).parent.parent.parent / ".env")

    benchmark_path = Path(__file__).parent.parent / "benchmarks" / "broken_segmentation_300.nft"
    rules = load_nft_as_rules(benchmark_path)
    context = build_context(rules, args.iterations)

    run_claude = not args.gemini_only
    run_gemini = not args.claude_only

    claude_results: list[IterationResult] | None = None
    gemini_results: list[IterationResult] | None = None

    if run_claude:
        claude_config = LLMConfig(
            provider="claude_subprocess",
            model="claude-opus-4-6",
            api_key="",
            max_tokens=1024,
            temperature=0.7,
            timeout_seconds=120,
        )
        claude_results = run_provider_benchmark(
            provider_label="Claude Opus 4.6",
            short_label="Claude",
            provider_name="claude_subprocess",
            config=claude_config,
            context=context,
            iterations=args.iterations,
        )

    if run_gemini:
        if "OPENROUTER_API_KEY" not in os.environ:
            raise RuntimeError("OPENROUTER_API_KEY is required for Gemini benchmark")

        gemini_config = LLMConfig(
            provider="openrouter",
            model="google/gemini-3.1-pro-preview",
            api_key=os.environ["OPENROUTER_API_KEY"],
            max_tokens=1024,
            temperature=0.7,
            timeout_seconds=60,
        )
        gemini_results = run_provider_benchmark(
            provider_label="Gemini 3.1 Pro",
            short_label="Gemini",
            provider_name="openrouter",
            config=gemini_config,
            context=context,
            iterations=args.iterations,
        )

    print_comparison_table(claude_results, gemini_results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
