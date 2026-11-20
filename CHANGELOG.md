# Changelog

All notable changes to `mcp-cage` are documented in this file.
`mcp-cage` follows **Empirical Co-Design**: each release generalizes vulnerability classes observed and verified across real-world public and enterprise MCP servers into zero-config, deterministic wire-level defenses.

---

## [0.4.1] — 2026-11-19

### Added — Modular `mcp_cage/` Package Architecture, Declarative Policy Loader & 25-Mechanism CWE Paired-Twin Matrix
1. **Modular Domain Package Hierarchy (`mcp_cage/`)**
   - Organized all product source code under [`mcp_cage/`](mcp_cage/__init__.py) (`core.py`, `lattice.py`, `vault.py`, `schema.py`, `guards.py`, `surfaces.py`, `policy.py`, `proxy.py`, `cli_runner.py`, `cli.py`) while retaining a lightweight [`mcp_cage_core.py`](mcp_cage_core.py) re-export alias at the repository root for backward compatibility.
2. **Declarative Enterprise Policy Configuration Loader (`mcp_cage.policy.MCPCagePolicyConfig`)**
   - Supports zero-code workspace policy customization via `.mcp-cage/policy.json` or `mcp-cage.json` (`mode`, `allowed_orgs`, `trusted_endpoints`, `allow_endpoint_repoint`, `financial_cap_usd`, `custom_tool_roles`).
3. **25-Mechanism Empirical CWE Paired-Twin Regression Matrix (`tests/cwe_catalog/test_cwe_paired_twin_matrix.py`)**
   - Locks in 75+ `[ATTACK_BLOCKED]` payloads paired with 35+ `[BENIGN_ALLOWED]` twins across all 25 empirical CWE vulnerability mechanisms, verified across both Plane A (`MCPWireGateway`) and Plane B (`handle_cli_hook`).
4. **Structured `tests/` & `examples/` Layout + 7-Gate OPSEC Pre-Commit Scanner (`.githooks/pre-commit`)**
   - Organized test suites by verification tier under `tests/unit/`, `tests/cwe_catalog/`, `tests/e2e/`, and `tests/fixtures/`, moved the 5-act interactive demo to `examples/demo_interactive.py`, and added [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## [0.4.0] — 2026-11-18

### Added — Wire-DIFC v2/v3, 4-Slot Provider-Binding Canonicalizer, Line-Span WAL Provenance & Kernel Sandbox Compiler
1. **Unconditional 4-Slot Wire Canonicalizer & Authority Log-Odds Scorer (`WireDIFCCanonicalizer` in `SchemaLockVerifier`)**
   - Defeats Day-0 Non-Collision Tool-Provider Misbinding and soft comparative authority inflation (`S_poison >= 0.45`) on `tools/list` while preserving 100% of primary action verbs across official MCP servers.
2. **Content-Addressed Line-Span Persistent Provenance in SQLite WAL (`PersistentLineSpanProvenance` / `persistent_span_taint`)**
   - Defeats Cross-Session Stored Prompt Injection across `CLAUDE.md`, `.cursorrules`, `MEMORY.md`, and workspace notes by recording SHA-256 line-span provenance on untrusted file writes without whole-file taint freeze.
3. **Destination-Bound Format-Preserving Secret Tokenization Vault (`DestinationBoundFPEVault`)**
   - Mints format-preserving synthetic tokens (`Prefix || SYNTH_ || Base62(HMAC)`) before secrets enter the LLM context window and enforces `(target_server == AuthServer) and (Integrity == TRUSTED)` on outbound re-hydration.
4. **Two-Axis Covert Hex DNS & Natural-Language EFF Diceware-in-Identifier Detector (`is_covert_exfil_identifier` + `iterative_fixed_point_unquote`)**
   - Combines subdomain/identifier Shannon entropy ($H_0 = 3.35\text{ bits/char}$) with Typed-Identifier Semantic Surprise (catching natural-language Diceware passphrases inside `uuid`/`hex`/`id` fields) and depth-5 fixed-point URL decoding (`..%252f..%252f`).
5. **Causal State-Progress Entropy Governor (`CausalStateProgressGovernor`)**
   - Arrests `OverServe` ($93.88\times$) cyclic zero-progress status-polling amplification loops on the wire while permitting long-horizon multi-file refactoring workflows.
6. **Automated Schema-to-Kernel Sandbox Compiler (`mcp-cage compile-sandbox`) & Reproducible Benchmark Persona (`mcp-cage bench`)**
   - Synthesizes stratified macOS Seatbelt (`/usr/bin/sandbox-exec` SBPL) and Linux Landlock/`bwrap` containment profiles and runs the 800-scenario `MCP-SecBench` + 21-test 9-Plane E2E suite.

---

## [0.3.0] — 2026-11-17

### Added — Empirical Wire-Level Security Guards (Zero-Config in `MCPCageEngine` / `ToxicFlowGraphAnalyzer`)
Derived directly from security audits of real-world public and Big-Tech MCP servers:

1. **Runtime Endpoint & Session Re-pointing Guard (`endpoint_repoint_guard` / `make_endpoint_repoint_guard`)**
   - *Empirical Lineage:* `datalayer/jupyter-mcp-server` (`GHSA-rvjm-7hvp-f868`).
   - *Protection:* Fail-closed blocking of runtime connection-mutation tools (`connect_to_*`, `switch_server`, `set_endpoint`, `configure_connection`, etc.) unless explicitly opted in (`allow_endpoint_repoint=True`, `trusted_endpoints=...`), and blocking mid-session `*_url` + `*_token`/`*_key` parameter pairs, raw bearer tokens in LLM context, and re-pointing to `local`, `localhost`, `127.0.0.1`, `169.254.169.254`, or RFC1918 networks.
2. **Embedded POSIX Command Substitution Guard in File/Folder Paths (`path_command_substitution_guard` + hardened `is_safe_workspace_path` / `make_workspace_path_guard`)**
   - *Empirical Lineage:* Cloud Serverless & Container Deployment MCP Servers (`CWE-78` embedded subshell in path).
   - *Protection:* Inspects all path/directory/folder parameters (`folderPath`, `filePath`, `source_dir`, `app_dir`, `working_directory`, `download_directory`, `destination`, `path`, `file_path`, etc.) for embedded POSIX command substitution (`$(...)`, backticks `` `...` ``, `${...}`, `\x00`) even when disguised inside a valid relative/workspace path segment, in addition to `Path.resolve()` workspace confinement and protected dotfile locks.
3. **REST URL Path-Segment Traversal Guard (`url_path_segment_guard`)**
   - *Empirical Lineage:* Edge & API Gateway MCP Servers (`CWE-22` REST path-segment traversal).
   - *Protection:* Deterministically inspects resource identifier parameters (`*_id`, `*Id`, `*Name`, `*_name`, `scriptName`, `job_id`, `session_id`, `rag_id`, `bucket`, `repo`, etc., including nested payloads and URL-decoded/double-encoded variants) and blocks `..`, `%2e%2e`, `/`, `%2f`, `\`, `%5c`, `?`, and `#` before REST URL interpolation (`CWE-22`).
4. **CLI Positional-Argument Flag Injection Guard (`cli_flag_injection_guard`)**
   - *Empirical Lineage:* Kubernetes & Infrastructure CLI MCP Servers (`CWE-88` positional flag injection).
   - *Protection:* Blocks leading `-` / `--` flags (`--upload-pack=`, `--template=`, `--kubeconfig=`, `--token=`, `--output=`, `-o...`) and embedded `--flag` tokens injected into positional resource, directory, git, or target arguments (`CWE-88`).
5. **Multi-Statement & Clause-Level SQL AST Guard (`sql_safety_guard`)**
   - *Empirical Lineage:* Enterprise Data Warehouse & Relational SQL MCP Servers (`CWE-89` comment-split & clause injection).
   - *Protection:* Strips `-- ...` and `/* ... */` SQL comments (both space-joined and compact to defeat `DR/**/OP` token splitting), rejects unclosed block comments, detects stacked `;` queries (while respecting string literals), and enforces clause-level SQL injection checks across `where_clause`, `order_by`, `filter`, `having`, `sort_by`, and `group_by` (`A4.3` / `A8.1`).
6. **Unified Zero-Config Wire Enforcement & Regression Suite (`test_mcp_cage_v30_empirical_guards.py` & `test_agentic_ai_tools_and_non_regression.py`)**
   - Wired all empirical guards into `ToxicFlowGraphAnalyzer.build_default_profile`, `MCPCageEngine` (`MCPWireGateway`), `DynamicProfileAwareProxy` (`mcp_cage_cli.py`), and Plane B native hooks (`_build_native_hook_profile`).
   - Added **Open-Source Agentic AI Framework & Extended Wire Guards**:
     - `pickle_deserialization_guard` (Scientific Computing MCP Servers, `CWE-502` with binary header allowlist).
     - `package_install_guard` (Multi-Agent Python Toolkits PEP 508 validation blocking pip command/flag/URL injection in dynamic library lists).
     - `code_sandbox_escape_guard` (In-process Python sandbox dunder `__subclasses__` escape & environment `*_API_KEY`/`*_SECRET` credential harvesting).
     - Split `(directory, filename)` path joining & Agent Skill (`SKILL.md`, `AGENTS.md`, `.claude/skills/`, `.agents/`) write protection.
     - Single-command 7-suite non-regression runner (`run_all_regression_suites.py`).

---

## [0.2.2] — 2026-11-14

### Added — Dual-Plane Reference Monitor, SSRF/DNS Guard & `CurXecute` Auditor
- **Cross-Process SQLite WAL State & Secret Vault:** `SessionTaintStateMachine` (`BEGIN IMMEDIATE` atomic transactions) and `BidirectionalSecretScrubber` across Plane A (`mcp-cage wrap`) and Plane B (`mcp-cage hook <claude|cursor|gemini|agy|codex>`).
- **SSRF, Cloud Metadata & High-Entropy DNS Exfiltration Guard (`validate_outbound_network_target`):** Blocks `169.254.169.254`, `metadata.google.internal`, loopback/RFC1918 IPs, non-HTTP schemes (`file://`, `gopher://`, `dict://`), and high-entropy/hex/base64 DNS exfiltration subdomains.
- **`CurXecute` / `MCPoison` Config Auditor (`WorkspaceMCPConfigAuditor` / `mcp-cage audit-config`):** Audits `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and `claude_desktop_config.json`.
- **Interactive Web Showcase (`docs/index.html` / `visualizer.html`):** Live Exploit Simulator, 8-Plane Matrix, and Copy-Paste Config Generator.

---

## [0.1.0] — Initial Prototype

### Added — Core IFC & JSON-RPC Wire Prototype
- Initial `SessionTaintStateMachine` Dual-Lattice IFC (`Integrity` × `Confidentiality`), `SchemaLockVerifier` (`mcp-lock.json` SHA-256 pinning), Microsoft Spotlighting boundaries (`<<<UNTRUSTED_DATA_BOUNDARY>>>`), MELON provenance attribution, and `mcp-sploit` toxic-flow graph analysis (`ToxicFlowGraphAnalyzer`).
