"""End-to-End (Tier 1 8-Plane & Tier 2 Real Node.js MCP + Live HTTP Canary) verification suites."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tests.e2e.test_tier1_all_8_planes import TestPlane1CognitiveAndContextLayer  # noqa: F401, E402
from tests.e2e.test_tier2_real_mcp_and_canary import TestTier2RealMcpAndCanary  # noqa: F401, E402
