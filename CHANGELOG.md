# Changelog

All notable changes to `mcp-cage` are documented in this file.
`mcp-cage` follows **Empirical Co-Design**: each release generalizes vulnerability classes observed and verified across real-world public and enterprise MCP servers into zero-config, deterministic wire-level defenses.

---

## [0.4.3] — 2026-11-26

### Added — 13 Competitive & First-in-Industry Capabilities: Child `SubprocessEnvJail`, Damerau-Levenshtein Slopsquatting Guard, Multi-Encoding Shingle DLP, Temporal Flow Rules & `learn-policy`, Honeytoken Canary Tripwires, HTTP/OAuth 2.1 Transport Firewall, Forensic Causal Trace Inspector (`inspect-audit`), Persistent Memory Quarantine, Scalar Return-Value Trojan Verifier, Transactional Workspace Rollback (`rollback`), Automated 0-Day Virtual Patch Compiler (`--auto-patch`), Polyglot Magic-Byte Guard & Zero-LLM Prompt-Intent Alignment Envelope
1. **Zero-Leak Child Environment Jail (`SubprocessEnvJail`) & Offline Damerau-Levenshtein Supply-Chain Slopsquatting / Unpinned `npx -y` Guard (`WorkspaceMCPConfigAuditor`)**
   - `mcp-cage wrap` now scrubs ambient credentials (`AWS_*`, `OPENAI_*`, `ANTHROPIC_*`, `GITHUB_*`, `*_KEY`, `*_TOKEN`, `*_SECRET`, `DATABASE_URL`) from child MCP server `os.environ` by default (`--allow-env` opt-in), preventing third-party MCP servers from harvesting shell environment secrets (`CWE-200` / `CWE-526`).
   - `mcp-cage audit-config` computes exact Damerau-Levenshtein edit distance ($1 \le d_{\text{DL}} \le 2$) against canonical `@modelcontextprotocol/*` and ecosystem MCP packages to detect typosquatted/slopsquatted packages (`MCP_SUPPLY_CHAIN_TYPOSQUAT`, `CWE-829`) and unpinned dynamic runners (`UNPINNED_DYNAMIC_PACKAGE_EXEC`, `CWE-1357`).
2. **Content-Addressed Rolling Shingle & Multi-Encoding De-Obfuscation DLP (`record_confidential_content_fingerprints` + `check_outbound_encoded_confidential_exfil`)**
   - Fingerprints 24-character rolling SHA-256 shingles of `CONFIDENTIAL`/`SECRET` reads into SQLite WAL (`confidential_content_fingerprints`) and inspects outbound arguments across raw, URL-decoded, Base64, Base64URL, Base32, Hex, Reversed (`[::-1]`), and ROT13 views (`CWE-200` / `LLM02`).
3. **Declarative Temporal Call-Graph Invariants (`temporal_rules`, `argument_policies`) & Automated Least-Privilege Policy Learner (`mcp-cage learn-policy`)**
   - Enforces `require_prior`, `forbid_after`, and `max_calls` session call-graph invariants plus per-argument regex/range policies in `.mcp-cage/policy.json`, and synthesizes zero-false-positive least-privilege policies directly from `--mode shadow` `audit.jsonl` ledgers.
4. **Active Cryptographic Honeytoken / Canary Decoy Tripwire System (`mcp-cage plant-canaries` / `check_honeytoken_tripwire`)**
   - Mints deterministic HMAC-tagged canary credentials (`OPENAI_CANARY`, `ANTHROPIC_CANARY`, `AWS_CANARY`) in `canary_tripwires`; if any canary (raw or Base64/Hex/reversed) touches the wire, triggers an immediate session lockdown and revokes all active leases.
5. **Streamable HTTP / SSE Transport Firewall & OAuth 2.1 Token-Binding Proxy (`MCPHttpTransportFirewall`)**
   - Blocks local HTTP/SSE DNS Rebinding (`CVE-2025-66416`, `CWE-346`) via strict `Host` and `Origin` header validation, blocks malicious OAuth 2.1 `.well-known/oauth-authorization-server` endpoint command injection and SSRF (`CVE-2025-6514`), and strips `Authorization` / `Cookie` / `Mcp-Session-Id` headers across cross-origin HTTP redirects (`CWE-918` / `CWE-863`).
6. **Offline Forensic Causal Trace & Attack-Graph Inspector (`ForensicAuditInspector` / `mcp-cage inspect-audit [--format markdown|mermaid|html|sarif]`)**
   - Verifies the SHA-256 audit hash chain and compiles zero-dependency Mermaid `flowchart TD` causal attack graphs, standalone offline HTML forensic dashboards, Markdown executive reports, and SARIF v2.1.0 runtime incident logs.
7. **Persistent Memory / Knowledge-Graph / RAG & A2A Context Poisoning Quarantine (`mcp-memory://` in `PersistentLineSpanProvenance`)**
   - Extends content-addressed SHA-256 line-span provenance to MCP Memory / RAG servers (`create_entities`, `add_observations`, `save_memory`, `search_nodes`, `open_nodes`) and A2A handoffs, stopping second-order knowledge-graph poisoning across sessions.
8. **Semantic Output Contract & Return-Value Trojan Verifier (`WirePayloadSanitizer.verify_and_sanitize_output_contract`)**
   - Defeats "Post-Pinning Server Turncoat" attacks where a pinned MCP server injects imperative prompt-override trojans inside scalar return fields (`id`, `timestamp`, `status`, `version`, `count`, `sha256`).
9. **Transactional Filesystem Snapshot & Automatic Taint-Induced Rollback Journal (`workspace_undo_journal` / `mcp-cage rollback`)**
   - Records zlib-compressed content-addressed pre-image snapshots in SQLite WAL before agent file writes/edits and deterministically rolls back tainted file mutations in `<5ms`.
10. **Automated 0-Day Discovery $\rightarrow$ Live Wire Virtual Patch Compiler (`mcp-cage audit-server --auto-patch .mcp-cage/policy.json`)**
    - Automatically compiles static AST 0-day findings from `MCPServerSourceAuditor` into live per-tool, per-parameter wire virtual patches (`argument_policies` + `virtual_patches`).
11. **Polyglot / Magic-Byte File Smuggling & Active SVG Payload Guard (`StandardArgGuards.polyglot_and_magic_byte_guard`)**
    - Blocks executable binary headers (ELF `\x7fELF`, Mach-O, Windows PE `MZ`, Java class, ZIP/JAR `PK\x03\x04`) and interpreter shebangs disguised inside `.txt`/`.md`/`.json`/`.png` files (`CWE-434` / `CWE-436`), as well as active `<script>`, `onload=`, and `<!ENTITY>` payloads inside `.svg` files (`CWE-79`).
12. **Zero-LLM Prompt-Intent vs. Tool-Action Lexical Alignment Envelope (`record_user_prompt_intent` + `check_prompt_intent_alignment`)**
    - Extracts a `<0.1ms` read-only vs. mutation/egress capability envelope from the user's prompt at `UserPromptSubmit`, tripping `[ZERO-LLM INTENT-DRIFT CIRCUIT BREAKER]` if a read-only prompt attempts unrequested high-impact destructive or external-egress actions.
13. **Cross-Server Impersonation & Fake Protocol-Frame Spoofing Guard (`WirePayloadSanitizer.CROSS_SERVER_SPOOF_RE`)**
    - Strips spoofed `[SYSTEM ERROR from <other_server>]` and fake inline `{"jsonrpc": "2.0", "method": "tools/call"}` directives from untrusted tool responses (`CWE-290` / `CWE-345`).

---

## [0.4.2] — 2026-11-22

### Added — 7-Vector MCP Server Source-to-Sink 0-Day Scanner (`audit-server`), Live Differential Boundary Prober (`probe-live`), Inbound Response & Reverse-Channel Firewall, Cross-Turn Salami-Slice Circuit Breaker & SHA-256 Hash-Chained Audit Ledger
1. **7-Vector Python AST & TypeScript MCP Server Source-to-Sink 0-Day Vulnerability Scanner (`MCPServerSourceAuditor` / `mcp-cage audit-server <path> [--format json|sarif]`)**
   - Traces untrusted MCP tool/resource parameters (`@mcp.tool()`, `@server.call_tool()`, TypeScript `server.tool(...)`) directly into 7 critical sink classes with dominance-aware sanitizer recognition (`0.0%` false positives on properly guarded code):
     1. `MCP_SINK_CMD_INJECTION` (`CWE-78`): `subprocess.*(..., shell=True)`, `os.system`, `os.popen`, `asyncio.create_subprocess_shell`, TS `child_process.exec`/`execSync`.
     2. `MCP_SINK_PATH_TRAVERSAL` (`CWE-22`): Unconfined `open()`, `Path.read_text/write_text`, `os.path.join`, TS `fs.readFile/writeFile` without `.resolve().relative_to()` or `os.path.commonpath`.
     3. `MCP_SINK_SQL_INJECTION` (`CWE-89`): Raw f-string/format/`%` SQL interpolation into `.execute()`.
     4. `MCP_SINK_UNVALIDATED_SSRF` (`CWE-918`): Unvalidated `requests.*`, `httpx.*`, `urllib.request.urlopen` without IP/IMDS filtering.
     5. `MCP_SINK_UNSAFE_DESERIALIZATION_EVAL` (`CWE-94` / `CWE-502`): `eval()`, `exec()`, `pickle.loads()`, `yaml.load()` without `SafeLoader`.
     6. `MCP_TRANSPORT_UNAUTH_BIND_REBINDING` (`CWE-346` — `CVE-2025-66416` class): Unauthenticated `0.0.0.0` transport binds without DNS-rebinding `Host`/`Origin` middleware.
     7. `MCP_OAUTH_CONFUSED_DEPUTY` (`CWE-863`): Raw `access_token` / `bearer_token` parameters accepted directly in LLM tool schemas.
   - Emits standards-compliant **SARIF v2.1.0** (`--format sarif`) and synthesizes deterministic JSON-RPC `tools/call` PoC payloads (`poc_jsonrpc`).
2. **Live Black-Box / Grey-Box MCP Server Schema Introspector & Non-Destructive Canary Boundary Prober (`LiveMCPServerProber` / `mcp-cage probe-live -- <cmd...>`)**
   - Spawns any stdio MCP server inside a temporary canary workspace, performs the JSON-RPC `initialize` $\rightarrow$ `tools/list` handshake, scores live schemas with `WireDIFCCanonicalizer`, and executes side-effect-free differential boundary probes to identify `CWE-209` stack-trace and SQL syntax error oracles.
3. **Inbound Response & Server-to-Client Reverse-Channel Firewall (`WirePayloadSanitizer.sanitize_untrusted_inbound_text` + `MCPWireGateway.process_server_to_client`)**
   - Neutralizes zero-click external Markdown image exfiltration beacons (`![...](https://...)`), active HTML `<img>`/`<iframe>`/`<script>` tags, and spoofed ChatML/XML turn-closing role delimiters (`</tool_result>`, `<|im_start|>system`, `<|endoftext|>`) inside untrusted `tools/call` and external `resources/read` responses.
   - Blocks server-initiated `roots/list` host reconnaissance when tainted, `elicitation/create` credential-phishing prompts (`api_key`, `password`, `otp`), and `sampling/createMessage` with `includeContext: "allServers"` or injected system prompts even on Turn 1.
4. **Cross-Turn Salami-Slice Chunked Exfiltration Circuit Breaker (`SessionTaintStateMachine.check_and_record_cross_turn_egress`)**
   - Tracks rolling per-domain short token concatenation across turns in SQLite WAL (`domain_egress_ledger`), defeating multi-turn 4–12 byte chunked hex/base32/base64 DNS or URL query/path exfiltration that stays below single-call length/entropy thresholds.
5. **Plane A + Plane B Wire-DIFC Parity, Imperative Line-Span Provenance & Subagent (`Task`) Taint Inheritance (`propagate_taint_to_subagent`)**
   - Unifies `PersistentLineSpanProvenance`, `is_covert_exfil_identifier`, and `check_and_record_cross_turn_egress` across both Plane A and Plane B (`handle_cli_hook`), records imperative natural-language lines written during `UNTRUSTED` turns, and propagates session taint across subagent (`Task` / `invoke_subagent` / `spawn_agent`) handoffs (`CWE-269`).
6. **Cryptographic SHA-256 / HMAC-SHA256 Hash-Chained Audit Ledger (`SessionTaintStateMachine.verify_audit_ledger` / `mcp-cage verify-audit`)**
   - Chains every `audit.jsonl` record with `seq`, `args_sha256`, `prev_hash`, and `entry_hash` (`SHA-256` or `HMAC-SHA256` via `MCP_CAGE_AUDIT_KEY`) and verifies chain integrity from genesis to head.

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
