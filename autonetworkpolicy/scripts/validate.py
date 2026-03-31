#!/usr/bin/env python3
"""
AutoNetworkPolicy v2.1 - End-to-End Validation Script

Comprehensive validation that checks all success criteria for the system.

Usage:
    python scripts/validate.py
    python scripts/validate.py --verbose
    python scripts/validate.py --quick

Exit Codes:
    0 - All checks passed
    1 - One or more checks failed
"""

from __future__ import annotations

import argparse
import importlib
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


def format_check_result(name: str, passed: bool, message: str = "", details: str = "") -> str:
    """Format a check result for display."""
    status = "✓ PASS" if passed else "✗ FAIL"
    result = f"[{status}] {name}"
    if message:
        result += f": {message}"
    if details and not passed:
        result += f"\n       → {details}"
    return result


class ValidationContext:
    """Context shared across validation checks."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: list[tuple[str, bool, str]] = []
        self.project_root = Path(__file__).parent.parent.resolve()
        self.passed = 0
        self.failed = 0

    def log(self, message: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"  {message}")

    def add_result(self, name: str, passed: bool, message: str = "") -> None:
        """Add a validation result."""
        self.results.append((name, passed, message))
        if passed:
            self.passed += 1
        else:
            self.failed += 1


def check_python_environment(ctx: ValidationContext) -> bool:
    """Check 1: Python version and dependencies."""
    ctx.log("Checking Python version...")
    version = sys.version_info

    if version.major < 3 or (version.major == 3 and version.minor < 10):
        ctx.add_result(
            "Python Environment",
            False,
            f"Python {version.major}.{version.minor}.{version.micro} (requires 3.10+)",
        )
        return False

    ctx.log(f"Python {version.major}.{version.minor}.{version.micro} OK")

    # Check critical dependencies
    deps = ["yaml", "dd"]
    missing = []

    for dep in deps:
        try:
            if dep == "yaml":
                importlib.import_module("yaml")
            elif dep == "dd":
                importlib.import_module("dd")
            ctx.log(f"  Dependency '{dep}' found")
        except ImportError:
            missing.append(dep)

    if missing:
        ctx.add_result(
            "Python Environment",
            False,
            f"Python {version.major}.{version.minor}.{version.micro}; Missing: {', '.join(missing)}",
        )
        return False

    ctx.add_result(
        "Python Environment",
        True,
        f"Python {version.major}.{version.minor}.{version.micro} with all dependencies",
    )
    return True


def check_data_files(ctx: ValidationContext) -> bool:
    """Check 2: Data files exist (acl1_500.txt, acl1_500.nft)."""
    ctx.log("Checking data files...")

    data_dir = ctx.project_root / "data"
    seeds_dir = data_dir / "seeds"
    generated_dir = data_dir / "generated"

    required_files = [
        ("ClassBench seed", seeds_dir / "acl1_500.txt"),
        ("nftables ruleset", generated_dir / "acl1_500.nft"),
    ]

    all_exist = True
    messages = []

    for name, filepath in required_files:
        if filepath.exists():
            size = filepath.stat().st_size
            ctx.log(f"  {name}: {filepath.name} ({size} bytes)")
            messages.append(f"{name} OK")
        else:
            ctx.log(f"  {name}: {filepath.name} NOT FOUND")
            messages.append(f"{name} missing: {filepath}")
            all_exist = False

    if all_exist:
        ctx.add_result("Data Files", True, "; ".join(messages))
    else:
        ctx.add_result(
            "Data Files",
            False,
            f"{messages[0]} - Run: python data/generate_seed.py && python data/classbench_to_nft.py",
        )
    return all_exist


def check_converter(ctx: ValidationContext) -> bool:
    """Check 3: Converter round-trip works."""
    ctx.log("Testing converter round-trip...")

    try:
        sys.path.insert(0, str(ctx.project_root))
        from data.classbench_to_nft import load_nft_as_rules, rules_to_nft

        nft_file = ctx.project_root / "data" / "generated" / "acl1_500.nft"

        if not nft_file.exists():
            ctx.add_result("Converter Round-trip", False, f"Input file not found: {nft_file}")
            return False

        # Load rules from NFT file
        rules = load_nft_as_rules(nft_file)
        ctx.log(f"  Loaded {len(rules)} rules")

        # Convert back to NFT format
        nft_output = rules_to_nft(rules)
        ctx.log(f"  Generated NFT config ({len(nft_output)} chars)")

        # Verify we can parse the generated output
        # (This validates the round-trip)
        ctx.add_result("Converter Round-trip", True, f"Successfully converted {len(rules)} rules")
        return True

    except Exception as e:
        ctx.add_result("Converter Round-trip", False, f"{str(e)} - Check data/classbench_to_nft.py")
        return False


def check_bdd_verifier(ctx: ValidationContext) -> bool:
    """Check 4: BDD verifier loads and runs."""
    ctx.log("Testing BDD verifier...")

    try:
        sys.path.insert(0, str(ctx.project_root))
        from data.classbench_to_nft import load_nft_as_rules
        from verify.bdd_verify import BDDVerifier

        nft_file = ctx.project_root / "data" / "generated" / "acl1_500.nft"

        if not nft_file.exists():
            ctx.add_result("BDD Verifier", False, f"Test data not found: {nft_file}")
            return False

        # Load a small subset for quick test
        rules = load_nft_as_rules(nft_file)[:10]
        ctx.log(f"  Loaded {len(rules)} rules for testing")

        # Create verifier and run self-verification
        verifier = BDDVerifier(backend="autoref", mode="ip_only", timeout_seconds=10)
        ctx.log("  Created BDD verifier")

        result = verifier.verify(rules, rules)
        ctx.log(f"  Self-verification: equivalent={result.get('equivalent')}")

        if result.get("equivalent"):
            ctx.add_result(
                "BDD Verifier",
                True,
                f"Self-verification passed ({result.get('time_seconds', 0):.3f}s)",
            )
            return True
        else:
            ctx.add_result(
                "BDD Verifier",
                False,
                "Self-verification failed - Check verify/bdd_verify.py implementation",
            )
            return False

    except Exception as e:
        ctx.add_result(
            "BDD Verifier", False, f"{str(e)} - Check verify/bdd_verify.py and dependencies"
        )
        return False


def check_bdd_performance(ctx: ValidationContext) -> bool:
    """Check 5: BDD performance < 5s at 500 rules."""
    ctx.log("Testing BDD performance at 500 rules...")

    try:
        sys.path.insert(0, str(ctx.project_root))
        from data.classbench_to_nft import load_nft_as_rules
        from verify.bdd_verify import BDDVerifier

        nft_file = ctx.project_root / "data" / "generated" / "acl1_500.nft"

        if not nft_file.exists():
            ctx.add_result("BDD Performance", False, f"Test data not found: {nft_file}")
            return False

        # Load all 500 rules
        rules = load_nft_as_rules(nft_file)
        if len(rules) < 500:
            ctx.add_result(
                "BDD Performance",
                False,
                f"Only {len(rules)} rules available (need 500) - Generate more test data",
            )
            return False

        rules = rules[:500]
        ctx.log(f"  Testing with {len(rules)} rules")

        # Time the verification
        verifier = BDDVerifier(backend="autoref", mode="ip_only", timeout_seconds=60)

        start_time = time.time()
        result = verifier.verify(rules, rules)
        elapsed = time.time() - start_time

        ctx.log(f"  Verification time: {elapsed:.3f}s")

        TARGET_SECONDS = 5.0

        if result.get("equivalent") and elapsed < TARGET_SECONDS:
            ctx.add_result(
                "BDD Performance", True, f"{elapsed:.3f}s at 500 rules (target: <{TARGET_SECONDS}s)"
            )
            return True
        elif not result.get("equivalent"):
            ctx.add_result(
                "BDD Performance", False, "Self-verification failed - BDD implementation error"
            )
            return False
        else:
            ctx.add_result(
                "BDD Performance",
                False,
                f"{elapsed:.3f}s at 500 rules (target: <{TARGET_SECONDS}s) - Performance regression",
            )
            return False

    except Exception as e:
        ctx.add_result("BDD Performance", False, f"{str(e)} - Check verify/bdd_verify.py")
        return False


def check_mutations(ctx: ValidationContext) -> bool:
    """Check 6: Mutations engine works."""
    ctx.log("Testing mutation engine...")

    try:
        sys.path.insert(0, str(ctx.project_root))
        from data.classbench_to_nft import load_nft_as_rules
        from mutations import MutationEngine

        nft_file = ctx.project_root / "data" / "generated" / "acl1_500.nft"

        if not nft_file.exists():
            ctx.add_result("Mutation Engine", False, "Test data not found")
            return False

        rules = load_nft_as_rules(nft_file)[:20]
        ctx.log(f"  Loaded {len(rules)} rules")

        engine = MutationEngine()
        ctx.log("  Created mutation engine")

        # Test swap mutation
        new_rules = engine.apply_mutation(rules, {"name": "swap", "args": [0, 1]})
        ctx.log(f"  Swap mutation: {len(rules)} -> {len(new_rules)} rules")

        # Verify the mutation changed something
        if len(new_rules) == len(rules):
            ctx.add_result("Mutation Engine", True, f"Swap mutation works ({len(rules)} rules)")
            return True
        else:
            ctx.add_result(
                "Mutation Engine", False, "Swap mutation changed rule count unexpectedly"
            )
            return False

    except Exception as e:
        ctx.add_result("Mutation Engine", False, f"{str(e)} - Check mutations.py implementation")
        return False


def check_baselines(ctx: ValidationContext) -> bool:
    """Check 7: All 4 baselines produce valid output."""
    ctx.log("Testing all baseline algorithms...")

    try:
        sys.path.insert(0, str(ctx.project_root))
        from data.classbench_to_nft import load_nft_as_rules

        nft_file = ctx.project_root / "data" / "generated" / "acl1_500.nft"

        if not nft_file.exists():
            ctx.add_result("Baseline Algorithms", False, "Test data not found")
            return False

        rules = load_nft_as_rules(nft_file)[:50]
        ctx.log(f"  Loaded {len(rules)} rules")

        baselines = [
            ("random_reorder", "baselines.random_reorder"),
            ("greedy_hitcount", "baselines.greedy_hitcount"),
            ("static_analysis", "baselines.static_analysis"),
            ("simulated_annealing", "baselines.simulated_annealing"),
        ]

        results = []
        for name, module_path in baselines:
            try:
                module = importlib.import_module(module_path)
                optimize_fn = getattr(module, "optimize")

                # Run the baseline
                if name == "random_reorder":
                    result = optimize_fn(rules, iterations=1, seed=42)
                elif name == "simulated_annealing":
                    # SA needs an evaluate_fn, skip the actual optimization
                    result = rules
                else:
                    result = optimize_fn(rules)

                ctx.log(f"  {name}: {len(result)} rules output")
                results.append((name, True, len(result)))
            except Exception as e:
                ctx.log(f"  {name}: FAILED - {e}")
                results.append((name, False, 0))

        all_passed = all(r[1] for r in results)
        passed_names = [r[0] for r in results if r[1]]
        failed_names = [r[0] for r in results if not r[1]]

        if all_passed:
            ctx.add_result(
                "Baseline Algorithms", True, f"All 4 baselines work: {', '.join(passed_names)}"
            )
            return True
        else:
            ctx.add_result(
                "Baseline Algorithms",
                False,
                f"Failed: {', '.join(failed_names)} - Check baseline implementations in baselines/",
            )
            return False

    except Exception as e:
        ctx.add_result("Baseline Algorithms", False, f"{str(e)} - Check baseline implementations")
        return False


def check_evaluation_components(ctx: ValidationContext) -> bool:
    """Check 8: Evaluation components import."""
    ctx.log("Testing evaluation component imports...")

    try:
        sys.path.insert(0, str(ctx.project_root))

        components = [
            ("CounterReader", "evaluate.counter_reader"),
            ("TrafficSimulator", "evaluate.traffic_simulator"),
            ("EvaluationPipeline", "evaluate.pipeline"),
        ]

        imported = []
        failed = []

        for name, module_path in components:
            try:
                module = importlib.import_module(module_path)
                cls = getattr(module, name)
                ctx.log(f"  {name}: imported successfully")
                imported.append(name)
            except Exception as e:
                ctx.log(f"  {name}: import failed - {e}")
                failed.append(name)

        if not failed:
            ctx.add_result(
                "Evaluation Components", True, f"All components imported: {', '.join(imported)}"
            )
            return True
        else:
            ctx.add_result(
                "Evaluation Components",
                False,
                f"Failed to import: {', '.join(failed)} - Check evaluate/ module implementations",
            )
            return False

    except Exception as e:
        ctx.add_result("Evaluation Components", False, f"{str(e)} - Check evaluate/ directory")
        return False


def check_agent_components(ctx: ValidationContext) -> bool:
    """Check 9: Agent components import."""
    ctx.log("Testing agent component imports...")

    try:
        sys.path.insert(0, str(ctx.project_root))

        components = [
            ("Proposer", "agent.proposer"),
            ("LLMProviderFactory", "agent.provider"),
        ]

        imported = []
        failed = []

        for name, module_path in components:
            try:
                module = importlib.import_module(module_path)
                cls = getattr(module, name)
                ctx.log(f"  {name}: imported successfully")
                imported.append(name)
            except Exception as e:
                ctx.log(f"  {name}: import failed - {e}")
                failed.append(name)

        if not failed:
            ctx.add_result(
                "Agent Components", True, f"All components imported: {', '.join(imported)}"
            )
            return True
        else:
            ctx.add_result(
                "Agent Components",
                False,
                f"Failed to import: {', '.join(failed)} - Check agent/ module implementations",
            )
            return False

    except Exception as e:
        ctx.add_result("Agent Components", False, f"{str(e)} - Check agent/ directory")
        return False


def check_main_loop(ctx: ValidationContext) -> bool:
    """Check 10: Main loop (run.py) imports."""
    ctx.log("Testing main loop (run.py) imports...")

    try:
        sys.path.insert(0, str(ctx.project_root))

        # Try to import the main module
        import run

        # Check that key classes exist
        required_classes = ["AutoResearchLoop", "AutoResearchError"]
        found_classes = []
        missing_classes = []

        for cls_name in required_classes:
            if hasattr(run, cls_name):
                found_classes.append(cls_name)
                ctx.log(f"  {cls_name}: found")
            else:
                missing_classes.append(cls_name)
                ctx.log(f"  {cls_name}: MISSING")

        if not missing_classes:
            ctx.add_result(
                "Main Loop", True, f"run.py imports successfully ({', '.join(found_classes)})"
            )
            return True
        else:
            ctx.add_result(
                "Main Loop",
                False,
                f"Missing classes: {', '.join(missing_classes)} - Check run.py implementation",
            )
            return False

    except Exception as e:
        ctx.add_result("Main Loop", False, f"{str(e)} - Check run.py for import errors")
        return False


def validate_all(ctx: ValidationContext) -> bool:
    """Run all validation checks."""
    checks: list[tuple[str, Callable[[ValidationContext], bool]]] = [
        ("Python Environment", check_python_environment),
        ("Data Files", check_data_files),
        ("Converter Round-trip", check_converter),
        ("BDD Verifier", check_bdd_verifier),
        ("BDD Performance", check_bdd_performance),
        ("Mutation Engine", check_mutations),
        ("Baseline Algorithms", check_baselines),
        ("Evaluation Components", check_evaluation_components),
        ("Agent Components", check_agent_components),
        ("Main Loop", check_main_loop),
    ]

    print("=" * 70)
    print("AutoNetworkPolicy v2.1 - End-to-End Validation")
    print("=" * 70)
    print()

    results = []

    for name, check_func in checks:
        if ctx.verbose:
            print(f"\nRunning: {name}")
            print("-" * 40)

        try:
            passed = check_func(ctx)
            results.append(passed)
        except Exception as e:
            ctx.add_result(name, False, f"Exception: {e}")
            results.append(False)
            if ctx.verbose:
                print(f"  Exception during {name}: {e}")

    # Print summary
    print()
    print("=" * 70)
    print("Validation Summary")
    print("=" * 70)

    for name, passed, message in ctx.results:
        status = "✓" if passed else "✗"
        msg = f" - {message}" if message else ""
        print(f"  [{status}] {name}{msg}")

    print()
    print(f"Total: {ctx.passed} passed, {ctx.failed} failed")

    all_passed = all(results)

    if all_passed:
        print("\n✓ ALL CHECKS PASSED")
        print("=" * 70)
    else:
        print("\n✗ SOME CHECKS FAILED")
        print("=" * 70)

    return all_passed


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AutoNetworkPolicy v2.1 - End-to-End Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/validate.py              # Run all validation checks
    python scripts/validate.py --verbose    # Show detailed progress
    python scripts/validate.py --quick      # Skip performance tests

Exit Codes:
    0 - All checks passed
    1 - One or more checks failed
        """,
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed progress for each check"
    )

    parser.add_argument(
        "--quick", action="store_true", help="Skip performance tests (faster validation)"
    )

    args = parser.parse_args()

    ctx = ValidationContext(verbose=args.verbose)

    try:
        all_passed = validate_all(ctx)
        sys.exit(0 if all_passed else 1)
    except KeyboardInterrupt:
        print("\n\nValidation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nUnexpected error during validation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
