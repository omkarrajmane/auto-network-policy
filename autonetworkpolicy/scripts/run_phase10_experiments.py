#!/usr/bin/env python3
"""
================================================================================
Master Experiment Runner - Phase 10 Orchestration
================================================================================

Orchestrates the complete Phase 10 experiment suite:

1. Generate Benchmark Scenarios (if needed)
2. Run Baseline Suite (4 algorithms × 3 scenarios)
3. Run LLM Cold-Start (Scenario 1, temperature=0.0)
4. Run LLM Comparative Trials (3 scenarios × 3 iterations)
5. Generate Comparative Report

Usage:
    python run_phase10_experiments.py --full
    python run_phase10_experiments.py --baselines-only
    python run_phase10_experiments.py --llm-only --scenario over_permissive
    python run_phase10_experiments.py --report-only

================================================================================
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Base paths
SCRIPT_DIR = Path(__file__).parent
BASE_DIR = SCRIPT_DIR.parent
RESULTS_DIR = BASE_DIR / "results"


def run_command(cmd: list[str], description: str) -> bool:
    """
    Run a shell command and report results.

    Args:
        cmd: Command and arguments as list
        description: Description of what the command does

    Returns:
        True if command succeeded, False otherwise
    """
    print(f"\n{'=' * 70}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'=' * 70}")

    try:
        result = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            capture_output=False,
            text=True,
        )

        if result.returncode == 0:
            print(f"✓ {description} completed successfully")
            return True
        else:
            print(f"✗ {description} failed with return code {result.returncode}")
            return False

    except Exception as e:
        print(f"✗ {description} failed: {e}")
        return False


def step_generate_benchmarks() -> bool:
    """Step 1: Generate benchmark scenarios."""
    return run_command(
        [sys.executable, "-m", "scripts.generate_benchmarks", "--all", "--analyze"],
        "Generate Benchmark Scenarios",
    )


def step_run_baselines() -> bool:
    """Step 2: Run baseline execution suite."""
    return run_command(
        [sys.executable, "-m", "scripts.run_baselines", "--all", "--iterations", "100"],
        "Run Baseline Suite (4 algorithms × 3 scenarios)",
    )


def step_run_llm_cold_start(scenario: str = "redundant_shadowing") -> bool:
    """Step 3: Run LLM cold-start experiment."""
    return run_command(
        [
            sys.executable,
            "-m",
            "scripts.run_llm_experiments",
            "--cold-start",
            "--scenario",
            scenario,
            "--iterations",
            "5",
        ],
        f"LLM Cold-Start ({scenario}, temperature=0.0)",
    )


def step_run_llm_trials() -> bool:
    """Step 4: Run LLM comparative trials."""
    return run_command(
        [sys.executable, "-m", "scripts.run_llm_experiments", "--trials", "--all-scenarios"],
        "LLM Comparative Trials (3 scenarios × 3 iterations)",
    )


def step_generate_report() -> bool:
    """Step 5: Generate comparative report."""
    return run_command(
        [
            sys.executable,
            "-m",
            "scripts.generate_report",
            "--with-charts",
            "--output",
            "results/report_v2.1_experiments.md",
        ],
        "Generate Report with Visualizations",
    )


def run_full_suite() -> int:
    """
    Run the complete Phase 10 experiment suite.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    print("\n" + "=" * 70)
    print("AutoNetworkPolicy Phase 10 - Full Experiment Suite")
    print("=" * 70)
    print(f"Start time: {datetime.now().isoformat()}")
    print(f"Results directory: {RESULTS_DIR}")

    results = []

    # Step 1: Generate benchmarks
    results.append(("Benchmark Generation", step_generate_benchmarks()))

    # Step 2: Run baselines
    results.append(("Baseline Suite", step_run_baselines()))

    # Step 3: LLM cold-start
    results.append(("LLM Cold-Start", step_run_llm_cold_start()))

    # Step 4: LLM trials
    results.append(("LLM Trials", step_run_llm_trials()))

    # Step 5: Generate report
    results.append(("Report Generation", step_generate_report()))

    # Summary
    print("\n" + "=" * 70)
    print("Phase 10 Suite - Execution Summary")
    print("=" * 70)

    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {name}")

    successful = sum(1 for _, success in results if success)
    total = len(results)

    print(f"\nTotal: {successful}/{total} steps completed successfully")
    print(f"End time: {datetime.now().isoformat()}")
    print("=" * 70)

    return 0 if successful == total else 1


def run_dry_run() -> int:
    """
    Run a dry-run to verify setup without executing experiments.

    Returns:
        Exit code
    """
    print("\n" + "=" * 70)
    print("AutoNetworkPolicy Phase 10 - Dry Run")
    print("=" * 70)

    checks = []

    # Check directories exist
    benchmarks_dir = BASE_DIR / "benchmarks"
    experiments_dir = RESULTS_DIR / "experiments"

    checks.append(("Benchmarks directory", benchmarks_dir.exists()))
    checks.append(("Experiments directory", experiments_dir.exists()))

    # Check benchmark files
    for scenario in ["over_permissive", "broken_segmentation", "redundant_shadowing"]:
        scenario_file = (
            benchmarks_dir / f"{scenario}_legacy_500.nft"
            if scenario == "over_permissive"
            else benchmarks_dir / f"{scenario}_300.nft"
            if scenario == "broken_segmentation"
            else benchmarks_dir / f"{scenario}_400.nft"
        )
        checks.append((f"Scenario: {scenario}", scenario_file.exists()))

    # Check scripts
    scripts = [
        "scripts/generate_benchmarks.py",
        "scripts/run_baselines.py",
        "scripts/run_llm_experiments.py",
        "scripts/generate_report.py",
    ]

    for script in scripts:
        script_path = BASE_DIR / "autonetworkpolicy" / script
        checks.append((f"Script: {script}", script_path.exists()))

    # Check API key (optional for dry-run)
    import os

    has_api_key = bool(os.environ.get("OPENROUTER_API_KEY"))
    checks.append(("OPENROUTER_API_KEY", has_api_key))

    # Print results
    print("\nSetup Checks:")
    for name, exists in checks:
        status = "✓" if exists else "✗"
        print(f"  {status} {name}")

    passed = sum(1 for _, exists in checks if exists)
    total = len(checks)

    print(f"\nChecks passed: {passed}/{total}")

    if not has_api_key:
        print("\nNote: OPENROUTER_API_KEY not set - LLM experiments will fail")

    print("=" * 70)

    return 0


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Run Phase 10 experiments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run full suite
    %(prog)s --full
    
    # Run only baselines
    %(prog)s --baselines-only
    
    # Run only LLM experiments
    %(prog)s --llm-only
    
    # Generate report from existing results
    %(prog)s --report-only
    
    # Dry-run to check setup
    %(prog)s --dry-run
        """,
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Run complete Phase 10 suite",
    )

    parser.add_argument(
        "--baselines-only",
        action="store_true",
        help="Run only baseline experiments",
    )

    parser.add_argument(
        "--llm-only",
        action="store_true",
        help="Run only LLM experiments",
    )

    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate report from existing results",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify setup without running experiments",
    )

    args = parser.parse_args()

    if args.dry_run:
        return run_dry_run()

    if args.full:
        return run_full_suite()

    if args.baselines_only:
        print("\n" + "=" * 70)
        print("Running Baselines Only")
        print("=" * 70)
        step_generate_benchmarks()
        step_run_baselines()
        return 0

    if args.llm_only:
        print("\n" + "=" * 70)
        print("Running LLM Experiments Only")
        print("=" * 70)
        step_run_llm_cold_start()
        step_run_llm_trials()
        return 0

    if args.report_only:
        print("\n" + "=" * 70)
        print("Generating Report Only")
        print("=" * 70)
        step_generate_report()
        return 0

    # Default: show help
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
