#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.run_baselines import export_results_json, print_comparison_table, run_all_baselines


SEMANTIC_BENCHMARK_SCENARIOS = {
    "k8s_microservices": "semantic/k8s_microservices_200.nft",
    "enterprise_departments": "semantic/enterprise_departments_500.nft",
    "three_tier_app": "semantic/three_tier_app_300.nft",
    "vlan_segmentation": "semantic/vlan_segmentation_400.nft",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run semantic benchmark experiments")
    parser.add_argument(
        "--baselines-only",
        action="store_true",
        help="Run baseline algorithms only on semantic benchmarks",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all configured semantic experiments",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200,
        help="Iteration budget for applicable algorithms (default: 200)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )
    parser.add_argument(
        "--sa-temperature",
        type=float,
        default=100.0,
        help="Initial simulated annealing temperature (default: 100.0)",
    )
    parser.add_argument(
        "--sa-cooling",
        type=float,
        default=0.95,
        help="Simulated annealing cooling rate in (0,1) (default: 0.95)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory (default: results/semantic)",
    )

    args = parser.parse_args()

    if not args.baselines_only and not args.all:
        parser.error("Specify --baselines-only or --all")

    if not (0 < args.sa_cooling < 1):
        parser.error("--sa-cooling must be in (0, 1)")

    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else Path(__file__).parent.parent / "results" / "semantic"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("AutoNetworkPolicy Semantic Experiments")
    print("=" * 80)
    print(f"Output directory: {output_dir}")
    print(f"Iterations: {args.iterations}, seed: {args.seed}")

    start = time.time()

    results = run_all_baselines(
        scenarios=SEMANTIC_BENCHMARK_SCENARIOS,
        output_dir=output_dir,
        iterations=args.iterations,
        seed=args.seed,
        sa_temperature=args.sa_temperature,
        sa_cooling=args.sa_cooling,
    )

    json_path = output_dir / "baselines_comparison.json"
    export_results_json(results, json_path)
    print_comparison_table(results)

    elapsed = time.time() - start
    print(f"\nCompleted in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
