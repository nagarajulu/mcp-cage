"""Empirical CWE paired-twin catalog and agentic AI framework regression suites."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tests.cwe_catalog.test_agentic_ai_frameworks import TestAgenticAiToolsAndNonRegression  # noqa: F401, E402
from tests.cwe_catalog.test_cwe_paired_twin_matrix import (  # noqa: F401, E402
    EmpiricalCWETwinSpec,
    TestEmpiricalCWECatalogMatrix,
    build_empirical_cwe_catalog,
)
