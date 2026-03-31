#!/usr/bin/env python3
"""
AutoNetworkPolicy v2.1 - Preflight Checks
Validates system requirements before running experiments.
"""

import subprocess
import sys
import os


def check_python_version():
    """Check if Python version >= 3.10"""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    if version.major >= 3 and version.minor >= 10:
        return True, f"Python version: {version_str}", None
    else:
        return (
            False,
            f"Python version: {version_str}",
            "Python 3.10+ required. Install from https://python.org",
        )


def check_docker():
    """Check if Docker daemon is running and accessible"""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "Docker: running", None
        else:
            return (
                False,
                "Docker: daemon not accessible",
                "Start Docker daemon or check permissions",
            )
    except FileNotFoundError:
        return False, "Docker: not found", "Install Docker: https://docs.docker.com/get-docker/"
    except subprocess.TimeoutExpired:
        return False, "Docker: timeout checking daemon", "Check if Docker daemon is responsive"
    except Exception as e:
        return False, f"Docker: error ({e})", "Check Docker installation"


def check_containerlab():
    """Check if Containerlab (clab) is available"""
    try:
        result = subprocess.run(["clab", "version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "Containerlab: installed", None
        else:
            return False, "Containerlab: not working properly", "Reinstall containerlab"
    except FileNotFoundError:
        return False, "Containerlab: not found", "Install: https://containerlab.dev/install"
    except Exception as e:
        return False, f"Containerlab: error ({e})", "Check containerlab installation"


def check_nftables():
    """Check if nft command is available (for local testing)"""
    try:
        result = subprocess.run(["nft", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "nftables: available", None
        else:
            return False, "nftables: command error", "Check nftables installation"
    except FileNotFoundError:
        return (
            False,
            "nftables: not found",
            "Install nftables: sudo apt-get install nftables (Debian/Ubuntu) or sudo yum install nftables (RHEL/CentOS)",
        )
    except Exception as e:
        return False, f"nftables: error ({e})", "Check nftables installation"


def check_openrouter_api_key():
    """Check if OPENROUTER_API_KEY is set (warning only)"""
    if os.environ.get("OPENROUTER_API_KEY"):
        return True, "OPENROUTER_API_KEY: set", None
    else:
        return (
            None,
            "OPENROUTER_API_KEY: not set",
            "Set OPENROUTER_API_KEY env var for LLM experiments (optional for Phase 1)",
        )


def main():
    """Run all preflight checks"""
    print("=" * 60)
    print("AutoNetworkPolicy v2.1 - Preflight Checks")
    print("=" * 60)
    print()

    checks = [
        ("Python", check_python_version, True),
        ("Docker", check_docker, True),
        ("Containerlab", check_containerlab, True),
        ("nftables", check_nftables, True),
        ("OPENROUTER_API_KEY", check_openrouter_api_key, False),
    ]

    critical_failures = 0
    warnings = 0

    for name, check_func, is_critical in checks:
        passed, message, remediation = check_func()

        if passed is True:
            print(f"[PASS] {message}")
        elif passed is False:
            if is_critical:
                print(f"[FAIL] {message}")
                if remediation:
                    print(f"       → {remediation}")
                critical_failures += 1
            else:
                print(f"[WARN] {message}")
                if remediation:
                    print(f"       → {remediation}")
                warnings += 1
        else:  # passed is None (warning only)
            print(f"[WARN] {message}")
            if remediation:
                print(f"       → {remediation}")
            warnings += 1

    print()
    print("=" * 60)

    if critical_failures == 0:
        print("✓ All critical checks passed!")
        if warnings > 0:
            print(f"  ({warnings} warning(s) - review above)")
        print("=" * 60)
        return 0
    else:
        print(f"✗ {critical_failures} critical check(s) failed")
        print("  Please fix the issues above before proceeding")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
