# Contributing to `mcp-cage`

Thank you for contributing to **`mcp-cage`** — the Zero-Dependency Dual-Plane Reference Monitor & Wire-DIFC Security Firewall for Model Context Protocol (MCP) Servers and Autonomous Coding Agents.

---

## 1. Repository Architecture & Modular Package Layout

`mcp-cage` is organized so that **both** single-file air-gapped deployments (`mcp_cage_core.py`) **and** structured domain package imports (`mcp_cage.*`) work out-of-the-box with **zero third-party dependencies** (100% Python 3.10+ standard library):

```text
mcp-cage/
├── mcp_cage/                                     # Structured Modular Python Package
│   ├── __init__.py                               # Public API exports
│   ├── core.py                                   # Core zero-dependency Wire-DIFC reference monitor engine
│   ├── lattice.py                                # Dual-Axis Taint Lattice, SQLite WAL State Machine, Line-Span Provenance
│   ├── vault.py                                  # Bidirectional Secret Scrubber, FPE Vault, Covert Entropy Detectors
│   ├── schema.py                                 # 4-Slot Canonicalizer, SchemaLockVerifier, ToxicFlowGraphAnalyzer
│   ├── guards.py                                 # Empirical CWE Parameter Guards (StandardArgGuards, SSRF, Workspace Jail)
│   ├── surfaces.py                               # Plane A (MCPWireGateway), Plane B (handle_cli_hook), Kernel Sandbox Compiler
│   ├── policy.py                                 # Declarative Enterprise Policy Loader (.mcp-cage/policy.json)
│   ├── proxy.py                                  # Subprocess stdio JSON-RPC proxy wrapper
│   ├── cli_runner.py                             # Standalone CLI wrapper & config generator
│   └── cli.py                                    # Unified mcp-cage & mcp-sploit CLI entrypoint
│
├── tests/                                        # Structured Verification & Regression Hierarchy
│   ├── unit/                                     # Unit tests for IFC lattice, WAL vault, canonicalizer & kernel sandbox
│   ├── cwe_catalog/                              # 25-Mechanism Empirical CWE Paired-Twin Matrix & Agentic Framework tests
│   ├── e2e/                                      # Tier 1 (8-Plane E2E) & Tier 2 (Real Node.js MCP + Live HTTP Canary)
│   └── fixtures/                                 # Deterministic mock MCP server for offline E2E tests
│
├── examples/
│   └── demo_interactive.py                       # 5-Act Interactive Verification Demo
├── run_all_regression_suites.py                  # Unified 10-suite test & OPSEC verification runner
├── .githooks/pre-commit                          # Automated 7-Gate OPSEC, Embargo, Personal-Path & Docs-Sync scanner
└── docs/index.html & visualizer.html             # Interactive browser simulator & GitHub Pages showcase
```

---

## 2. The Paired-Twin CWE Promotion Contract (Mandatory for New Guards)

Whenever a new vulnerability class or bypass mechanism is discovered in an MCP server or AI agent toolkit, it **must** be added to [`tests/cwe_catalog/test_cwe_paired_twin_matrix.py`](tests/cwe_catalog/test_cwe_paired_twin_matrix.py) as an `EmpiricalCWETwinSpec` entry:

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
3. **Cross-Surface Parity:** [`tests/cwe_catalog/test_cwe_paired_twin_matrix.py`](tests/cwe_catalog/test_cwe_paired_twin_matrix.py) automatically tests your `EmpiricalCWETwinSpec` across **both** Plane A (`MCPWireGateway`) and Plane B (`handle_cli_hook`).

---

## 3. Running the 7-Gate OPSEC Scanner & Full Regression Suite

Before committing or opening a pull request, enable the repository pre-commit hook and run the unified test runner:

```bash
git config core.hooksPath .githooks
python3 run_all_regression_suites.py
```

All **10/10 verification suites** (including `.githooks/pre-commit`, stdlib-only purity verification, and sub-1.5ms wire latency budgets) must pass with zero warnings.

---

## 4. Version Bump & GitHub Profile Bio Page (`https://github.com/nagarajulu`) Sync Checklist

Whenever `mcp-cage` bumps its version in [`pyproject.toml`](pyproject.toml) and [`mcp_cage/core.py`](mcp_cage/core.py) (automatically detected by `.githooks/pre-commit`):

1. **Update [`CHANGELOG.md`](CHANGELOG.md)** with the new version section and empirical CWE / architectural highlights.
2. **Update the GitHub Profile Bio Page ([`https://github.com/nagarajulu`](https://github.com/nagarajulu) / `nagarajulu/nagarajulu` `README.md`)** in this priority order:
   - **1st (Top Featured):** **`mcp-cage`** — Repository ([`https://github.com/nagarajulu/mcp-cage`](https://github.com/nagarajulu/mcp-cage)), Live Interactive Showcase ([`https://nagarajulu.github.io/mcp-cage/`](https://nagarajulu.github.io/mcp-cage/)), and PyPI Package ([`https://pypi.org/project/mcp-cage/`](https://pypi.org/project/mcp-cage/)) with the latest version badge (`v0.4.1+`) and 34-mechanism CWE / 7-vector Skill AST capabilities.
   - **2nd (Featured Apps):** **`kinetic-bloom`** — Repository ([`https://github.com/nagarajulu/kinetic-bloom`](https://github.com/nagarajulu/kinetic-bloom)) and Live PWA ([`https://kineticbloom.org`](https://kineticbloom.org)) (*10-Minute Home Movement & Primitive Reflex Co-Regulation Companion*), followed by other applications.
