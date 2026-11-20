#!/usr/bin/env python3
"""
Unified Non-Regression & OPSEC Verification Runner (`run_all_regression_suites.py`).

Executes all 10 verification suites across the modular `tests/` and `examples/` hierarchy:
  0. 7-Gate OPSEC, Embargo, Personal-Path & Docs-Sync Pre-Commit Scanner (`.githooks/pre-commit`)
  1. Core IFC Lattice, WAL Vault, SSRF/DNS & Config Auditor Suite (`tests/unit/test_ifc_lattice_and_wal_vault.py`)
  2. Empirical Wire Guards & Latency Regression Suite (`tests/unit/test_empirical_guards.py`)
  3. Wire-DIFC, 4-Slot Canonicalizer, Line-Span WAL & Kernel Sandbox Suite (`tests/unit/test_wiredifc_canonicalizer_and_sandbox.py`)
  4. Modular Package & Declarative Enterprise Policy Suite (`tests/unit/test_modular_package_and_policy.py`)
  5. 25-Mechanism Empirical CWE Paired-Twin Matrix (`tests/cwe_catalog/test_cwe_paired_twin_matrix.py`)
  6. Agentic AI Frameworks & Stdlib Purity Non-Regression Suite (`tests/cwe_catalog/test_agentic_ai_frameworks.py`)
  7. Tier 1: 8-Plane End-to-End Security Suite (`tests/e2e/test_tier1_all_8_planes.py`)
  8. Tier 2: Official Node.js MCP + Live HTTP Canary Suite (`tests/e2e/test_tier2_real_mcp_and_canary.py`)
  9. 5-Act Interactive End-to-End Verification Demo (`examples/demo_interactive.py`)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path


PROTOTYPE_DIR = Path(__file__).resolve().parent


def build_suites() -> list[tuple[str, list[str]]]:
    suites: list[tuple[str, list[str]]] = [
        (
            "0. 7-Gate OPSEC, Embargo & Zero-Leak Pre-Commit Scanner (.githooks/pre-commit)",
            [sys.executable, str(PROTOTYPE_DIR / ".githooks" / "pre-commit")],
        ),
        (
            "1. Core IFC Lattice, WAL Vault, SSRF/DNS & Config Auditor Suite (tests/unit/test_ifc_lattice_and_wal_vault.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "unit" / "test_ifc_lattice_and_wal_vault.py")],
        ),
        (
            "2. Empirical Wire Guards & Latency Regression Suite (tests/unit/test_empirical_guards.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "unit" / "test_empirical_guards.py")],
        ),
        (
            "3. Wire-DIFC, 4-Slot Canonicalizer, Line-Span WAL & Kernel Sandbox Suite (tests/unit/test_wiredifc_canonicalizer_and_sandbox.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "unit" / "test_wiredifc_canonicalizer_and_sandbox.py")],
        ),
        (
            "4. Modular Package & Declarative Enterprise Policy Suite (tests/unit/test_modular_package_and_policy.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "unit" / "test_modular_package_and_policy.py")],
        ),
        (
            "5. 25-Mechanism Empirical CWE Paired-Twin Matrix (tests/cwe_catalog/test_cwe_paired_twin_matrix.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "cwe_catalog" / "test_cwe_paired_twin_matrix.py")],
        ),
        (
            "6. Agentic AI Frameworks & Stdlib Purity Non-Regression Suite (tests/cwe_catalog/test_agentic_ai_frameworks.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "cwe_catalog" / "test_agentic_ai_frameworks.py")],
        ),
        (
            "7. Tier 1: 8-Plane End-to-End Security Suite (tests/e2e/test_tier1_all_8_planes.py)",
            [sys.executable, str(PROTOTYPE_DIR / "tests" / "e2e" / "test_tier1_all_8_planes.py")],
        ),
    ]
    tier2_script = PROTOTYPE_DIR / "tests" / "e2e" / "test_tier2_real_mcp_and_canary.py"
    if shutil.which("npx") and tier2_script.exists():
        suites.append(
            (
                "8. Tier 2: Official Node.js MCP + Live HTTP Canary Suite (tests/e2e/test_tier2_real_mcp_and_canary.py)",
                [sys.executable, str(tier2_script)],
            )
        )
    suites.append(
        (
            "9. 5-Act Interactive End-to-End Verification Demo (examples/demo_interactive.py)",
            [sys.executable, str(PROTOTYPE_DIR / "examples" / "demo_interactive.py")],
        )
    )
    return suites


def main() -> int:
    print("=" * 88)
    print("  MCP-CAGE UNIFIED NON-REGRESSION, OPSEC & CONTINUOUS EVOLUTION TEST RUNNER")
    print("=" * 88)
    suites = build_suites()
    results: list[tuple[str, bool, float]] = []
    overall_ok = True

    for label, cmd in suites:
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, cwd=str(PROTOTYPE_DIR), capture_output=True, text=True)
        elapsed = time.perf_counter() - t0
        passed = proc.returncode == 0
        results.append((label, passed, elapsed))
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label} ({elapsed:.2f}s)")
        if not passed:
            overall_ok = False
            print("--- STDOUT ---")
            print(proc.stdout[-1500:])
            print("--- STDERR ---")
            print(proc.stderr[-1500:])

    print("-" * 88)
    passed_count = sum(1 for _, ok, _ in results if ok)
    total_time = sum(t for _, _, t in results)
    print(f"  SUMMARY: {passed_count}/{len(results)} Suites Passed in {total_time:.2f}s")
    print("=" * 88)
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
