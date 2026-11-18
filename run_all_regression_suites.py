#!/usr/bin/env python3
"""
Unified Non-Regression Verification Runner (`run_all_regression_suites.py`).

Executes all `mcp-cage` unit, empirical-guard, 8-plane E2E, Tier-2 real-MCP/Canary,
Agentic-AI-Tools, and interactive walkthrough suites in a single command to guarantee
zero regressions across versions and multi-session contributions.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


PROTOTYPE_DIR = Path(__file__).resolve().parent

SUITES: list[tuple[str, list[str]]] = [
    (
        "1. V2.2 Core IFC, WAL Vault, SSRF/DNS & Config Auditor Suite (test_mcp_cage_v21.py)",
        [sys.executable, str(PROTOTYPE_DIR / "test_mcp_cage_v21.py")],
    ),
    (
        "2. v0.3.0 Empirical Guards Regression Suite (test_mcp_cage_v30_empirical_guards.py)",
        [sys.executable, str(PROTOTYPE_DIR / "test_mcp_cage_v30_empirical_guards.py")],
    ),
    (
        "3. 8-Plane End-to-End Security Suite (test_e2e_all_8_planes.py)",
        [sys.executable, str(PROTOTYPE_DIR / "test_e2e_all_8_planes.py")],
    ),
    (
        "4. Tier 2 Official Node.js MCP + Live HTTP Canary Suite (test_tier2_real_mcp_and_canary.py)",
        [sys.executable, str(PROTOTYPE_DIR / "test_tier2_real_mcp_and_canary.py")],
    ),
    (
        "5. Agentic AI Tools (CrewAI/Smolagents/Browser-Use) & Waves 1–7 Non-Regression Suite (test_agentic_ai_tools_and_non_regression.py)",
        [sys.executable, str(PROTOTYPE_DIR / "test_agentic_ai_tools_and_non_regression.py")],
    ),
    (
        "6. 5-Act Interactive End-to-End Verification Demo (demo_interactive.py)",
        [sys.executable, str(PROTOTYPE_DIR / "demo_interactive.py")],
    ),
]


def main() -> int:
    print("=" * 88)
    print("  MCP-CAGE UNIFIED NON-REGRESSION & CONTINUOUS EVOLUTION TEST RUNNER")
    print("=" * 88)
    results: list[tuple[str, bool, float]] = []
    overall_ok = True

    for label, cmd in SUITES:
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
