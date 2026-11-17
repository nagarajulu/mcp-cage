# Changelog

All notable changes to `mcp-cage` are documented in this file.
`mcp-cage` follows **Empirical Co-Design**: each release generalizes vulnerability classes observed and verified across real-world public and enterprise MCP servers into zero-config, deterministic wire-level defenses.

---

## [0.3.0] — 2026-11-17

### Added — Empirical Wire-Level Security Guards (Zero-Config in `MCPCageEngine` / `ToxicFlowGraphAnalyzer`)
Derived directly from security audits of real-world public and Big-Tech MCP servers:

1. **Runtime Endpoint & Session Re-pointing Guard (`endpoint_repoint_guard` / `make_endpoint_repoint_guard`)**
   - *Empirical Lineage:* `datalayer/jupyter-mcp-server` (`GHSA-rvjm-7hvp-f868`).
   - *Protection:* Fail-closed blocking of runtime connection-mutation tools (`connect_to_*`, `switch_server`, `set_endpoint`, `configure_connection`, etc.) unless explicitly opted in (`allow_endpoint_repoint=True`, `trusted_endpoints=...`), and blocking mid-session `*_url` + `*_token`/`*_key` parameter pairs, raw bearer tokens in LLM context, and re-pointing to `local`, `localhost`, `127.0.0.1`, `169.254.169.254`, or RFC1918 networks.
2. **Embedded POSIX Command Substitution Guard in File/Folder Paths (`path_command_substitution_guard` + hardened `is_safe_workspace_path` / `make_workspace_path_guard`)**
   - *Empirical Lineage:* `GoogleCloudPlatform/cloud-run-mcp` (`source-processor.js`, Issue `#586725173`).
   - *Protection:* Inspects all path/directory/folder parameters (`folderPath`, `filePath`, `source_dir`, `app_dir`, `working_directory`, `download_directory`, `destination`, `path`, `file_path`, etc.) for embedded POSIX command substitution (`$(...)`, backticks `` `...` ``, `${...}`, `\x00`) even when disguised inside a valid relative/workspace path segment, in addition to `Path.resolve()` workspace confinement and protected dotfile locks.
3. **REST URL Path-Segment Traversal Guard (`url_path_segment_guard`)**
   - *Empirical Lineage:* `cloudflare/mcp-server-cloudflare`.
   - *Protection:* Deterministically inspects resource identifier parameters (`*_id`, `*Id`, `*Name`, `*_name`, `scriptName`, `job_id`, `session_id`, `rag_id`, `bucket`, `repo`, etc., including nested payloads and URL-decoded/double-encoded variants) and blocks `..`, `%2e%2e`, `/`, `%2f`, `\`, `%5c`, `?`, and `#` before REST URL interpolation (`CWE-22`).
4. **CLI Positional-Argument Flag Injection Guard (`cli_flag_injection_guard`)**
   - *Empirical Lineage:* `GoogleCloudPlatform/gke-mcp` & `Flux159/mcp-server-kubernetes`.
   - *Protection:* Blocks leading `-` / `--` flags (`--upload-pack=`, `--template=`, `--kubeconfig=`, `--token=`, `--output=`, `-o...`) and embedded `--flag` tokens injected into positional resource, directory, git, or target arguments (`CWE-88`).
5. **Multi-Statement & Clause-Level SQL AST Guard (`sql_safety_guard`)**
   - *Empirical Lineage:* `Snowflake-Labs/mcp` & `benborla/mcp-server-mysql`.
   - *Protection:* Strips `-- ...` and `/* ... */` SQL comments (both space-joined and compact to defeat `DR/**/OP` token splitting), rejects unclosed block comments, detects stacked `;` queries (while respecting string literals), and enforces clause-level SQL injection checks across `where_clause`, `order_by`, `filter`, `having`, `sort_by`, and `group_by` (`A4.3` / `A8.1`).
6. **Unified Zero-Config Wire Enforcement & Regression Suite (`test_mcp_cage_v30_empirical_guards.py`)**
   - Wired all 5 empirical guards into `ToxicFlowGraphAnalyzer.build_default_profile`, `MCPCageEngine` (`MCPWireGateway`), `DynamicProfileAwareProxy` (`mcp_cage_cli.py`), and Plane B native hooks (`_build_native_hook_profile`).
   - Fixed `MUTATOR_REGEX` server-prefix over-matching on `filesystem.*` read/search tools.
   - Added comprehensive unit, E2E, and sub-millisecond latency regression tests in `test_mcp_cage_v30_empirical_guards.py`.

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
