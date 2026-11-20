#!/usr/bin/env python3
"""
Unit tests for `mcp_cage` modular package structure (`mcp_cage.lattice`, `mcp_cage.vault`,
`mcp_cage.schema`, `mcp_cage.guards`, `mcp_cage.surfaces`, `mcp_cage.policy`, `mcp_cage.cli`).
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

import mcp_cage
from mcp_cage import (
    EnforcementMode,
    Integrity,
    MCPCagePolicyConfig,
    ToolRole,
)
from mcp_cage.guards import StandardArgGuards, is_safe_workspace_path, validate_outbound_network_target
from mcp_cage.lattice import Confidentiality, SessionTaintStateMachine
from mcp_cage.policy import MCPCagePolicyConfig as PolicyLoader
from mcp_cage.schema import SchemaLockVerifier, ToxicFlowGraphAnalyzer, WireDIFCCanonicalizer
from mcp_cage.surfaces import MCPCageEngine, SchemaToKernelSandboxCompiler, WorkspaceMCPConfigAuditor, handle_cli_hook
from mcp_cage.vault import BidirectionalSecretScrubber, DestinationBoundFPEVault, WirePayloadSanitizer


class TestModularPackageAndDeclarativePolicy(unittest.TestCase):
    def test_01_modular_submodule_exports(self) -> None:
        """Verifies all domain submodules under `mcp_cage.*` export identical primitives to `mcp_cage.core`."""
        self.assertIn(mcp_cage.__version__, ("0.4.0", "0.4.1"))
        self.assertIsNotNone(SessionTaintStateMachine)
        self.assertIsNotNone(BidirectionalSecretScrubber)
        self.assertIsNotNone(DestinationBoundFPEVault)
        self.assertIsNotNone(WirePayloadSanitizer)
        self.assertIsNotNone(WireDIFCCanonicalizer)
        self.assertIsNotNone(SchemaLockVerifier)
        self.assertIsNotNone(ToxicFlowGraphAnalyzer)
        self.assertIsNotNone(StandardArgGuards)
        self.assertIsNotNone(is_safe_workspace_path)
        self.assertIsNotNone(validate_outbound_network_target)
        self.assertIsNotNone(MCPCageEngine)
        self.assertIsNotNone(handle_cli_hook)
        self.assertIsNotNone(WorkspaceMCPConfigAuditor)
        self.assertIsNotNone(SchemaToKernelSandboxCompiler)
        self.assertTrue(Integrity.TRUSTED > Integrity.UNTRUSTED)
        self.assertTrue(Confidentiality.SECRET > Confidentiality.PUBLIC)

    def test_02_declarative_policy_discovery_and_engine_builder(self) -> None:
        """
        Verifies `.mcp-cage/policy.json` discovery, parsing (`mode`, `allowed_orgs`,
        `trusted_endpoints`, `allow_endpoint_repoint`, `custom_tool_roles`), and
        `MCPCagePolicyConfig.build_engine()`.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td).resolve()
            policy_dir = ws / ".mcp-cage"
            policy_dir.mkdir(parents=True, exist_ok=True)
            policy_file = policy_dir / "policy.json"
            policy_file.write_text(
                json.dumps(
                    {
                        "mode": "enforce",
                        "allowed_orgs": ["acme-prod", "acme-staging"],
                        "trusted_endpoints": ["jupyter.corp.internal"],
                        "allow_endpoint_repoint": True,
                        "financial_cap_usd": 100.0,
                        "custom_tool_roles": {
                            "crm.export_customers": ["PRIVATE_SOURCE", "EXTERNAL_EGRESS_SINK"]
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            cfg = PolicyLoader.discover(ws)
            self.assertEqual(cfg.mode, EnforcementMode.ENFORCE)
            self.assertIn("acme-prod", cfg.allowed_orgs)
            self.assertIn("jupyter.corp.internal", cfg.trusted_endpoints)
            self.assertTrue(cfg.allow_endpoint_repoint)
            self.assertEqual(cfg.financial_cap_usd, 100.0)
            self.assertIn(ToolRole.PRIVATE_SOURCE, cfg.custom_tool_roles["crm.export_customers"])

            engine = cfg.build_engine(server_name="infra_srv", workspace_root=ws)

            # 1. Unauthorized org blocked by policy
            fwd_bad, imm_bad = engine.process_client_to_server(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_workspace_safely",
                        "arguments": {"workspace_id": "ws-1", "org_name": "rogue-org"},
                    },
                }
            )
            self.assertIsNone(fwd_bad)
            self.assertIn("CWE-863", imm_bad["result"]["content"][0]["text"])

            # 2. Allowlisted org permitted by policy
            fwd_ok, imm_ok = engine.process_client_to_server(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_workspace_safely",
                        "arguments": {"workspace_id": "ws-1", "org_name": "acme-prod"},
                    },
                }
            )
            self.assertIsNotNone(fwd_ok)
            self.assertIsNone(imm_ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
