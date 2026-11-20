# Contributing to `mcp-cage`

Thank you for contributing to **`mcp-cage`** — the Zero-Dependency Dual-Plane Reference Monitor & Wire-DIFC Security Firewall for Model Context Protocol (MCP) Servers and Autonomous Coding Agents.

---

## 1. Repository Architecture & Modular Package Layout

`mcp-cage` is organized so that **both** single-file air-gapped deployments (`mcp_cage_core.py`) **and** structured domain package imports (`mcp_cage.*`) work out-of-the-box with **zero third-party dependencies** (100% Python 3.10+ standard library):

```text
mcp-cage/
├── mcp_cage/                                     # Structured Modular Python Package
│   ├── __init__.py                               # Public API exports
│   ├── lattice.py                                # Dual-Axis Taint Lattice, SQLite WAL State Machine, Line-Span Provenance
│   ├── vault.py                                  # Bidirectional Secret Scrubber, FPE Vault, Covert Entropy Detectors
│   ├── schema.py                                 # 4-Slot Canonicalizer, SchemaLockVerifier, ToxicFlowGraphAnalyzer
│   ├── guards.py                                 # Empirical CWE Parameter Guards (StandardArgGuards, SSRF, Workspace Jail)
│   ├── surfaces.py                               # Plane A (MCPWireGateway), Plane B (handle_cli_hook), Kernel Sandbox Compiler
│   ├── policy.py                                 # Declarative Enterprise Policy Loader (.mcp-cage/policy.json)
│   └── cli.py                                    # Unified mcp-cage & mcp-sploit CLI entrypoint
│
├── mcp_cage_core.py                              # Zero-dependency single-file engine & PyPI entrypoint
├── mcp_cage_proxy.py                             # Subprocess stdio JSON-RPC proxy wrapper
├── mcp_cage_cli.py                               # Standalone CLI dispatcher
│
├── tests/                                        # Structured Verification & Regression Hierarchy
│   ├── unit/                                     # Unit tests for IFC lattice, WAL vault, canonicalizer & kernel sandbox
│   ├── cwe_catalog/                              # 25-Mechanism Empirical CWE Paired-Twin Matrix & Agentic Framework tests
│   └── e2e/                                      # Tier 1 (8-Plane E2E) & Tier 2 (Real Node.js MCP + Live HTTP Canary)
│
├── test_*.py                                     # Root test runners (executed by run_all_regression_suites.py & CI)
├── run_all_regression_suites.py                  # Unified 9-suite test & OPSEC verification runner
├── .githooks/pre-commit                          # Automated 7-Gate OPSEC, Embargo, Personal-Path & Docs-Sync scanner
└── docs/index.html & visualizer.html             # Interactive browser simulator & GitHub Pages showcase
```

---

## 2. The Paired-Twin CWE Promotion Contract (Mandatory for New Guards)

Whenever a new vulnerability class or bypass mechanism is discovered in an MCP server or AI agent toolkit, it **must** be added to [`test_cwe_empirical_catalog_matrix.py`](test_cwe_empirical_catalog_matrix.py) as an `EmpiricalCWETwinSpec` entry:

```python
EmpiricalCWETwinSpec(
    mechanism_id="CWE-XXX-01_DESCRIPTIVE_MECHANISM_NAME",
    cwe_id="CWE-XXX",
    description="Concise vendor-neutral description of the vulnerability mechanism",
    tool_name="generic_tool_name",
    attack_payloads=(
        {"param": "malicious_payload_1"},
    ),
    expected_block_substrings=("CWE-XXX",),
    benign_payloads=(
        {"param": "closely_shaped_legitimate_developer_payload"},
    ),
)
```

### Why Every Guard Requires a Paired Twin:
1. **Attack Twin (`attack_payloads`):** Asserts `fwd is None`, `imm["result"]["isError"] is True`, and verifies that the block reason contains one of `expected_block_substrings` (preventing **False-Negative Regressions**).
2. **Benign Twin (`benign_payloads`):** Passes a closely shaped legitimate payload to the same tool and parameter and asserts `fwd is not None and imm is None` (preventing **False-Positive Drift**).
3. **Cross-Surface Parity:** [`test_cwe_empirical_catalog_matrix.py`](test_cwe_empirical_catalog_matrix.py) automatically tests your `EmpiricalCWETwinSpec` across **both** Plane A (`MCPWireGateway`) and Plane B (`handle_cli_hook`).

---

## 3. Running the 7-Gate OPSEC Scanner & Full Regression Suite

Before committing or opening a pull request, enable the repository pre-commit hook and run the unified test runner:

```bash
git config core.hooksPath .githooks
python3 run_all_regression_suites.py
```

All **9/9 verification suites** (including `.githooks/pre-commit`, stdlib-only purity verification, and sub-1.5ms wire latency budgets) must pass with zero warnings.
