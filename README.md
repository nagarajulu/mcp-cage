# `mcp-cage` 🛡️

**Zero-Code Wire & Native-Hook Security Firewall for Claude Code, Cursor, Codex, Gemini CLI & MCP**  
*("Gitleaks + Little Snitch for AI Coding Agents" — 100% Python 3.10+ Standard Library, Zero External Dependencies)*

[![Live Interactive Web Showcase](https://img.shields.io/badge/🌐%20Live%20Interactive%20Sandbox-nagarajulu.github.io%2Fmcp--cage-06b6d4?style=for-the-badge)](https://nagarajulu.github.io/mcp-cage/)

[![CI — mcp-cage Security Suite](https://github.com/nagarajulu/mcp-cage/actions/workflows/ci.yml/badge.svg)](https://github.com/nagarajulu/mcp-cage/actions/workflows/ci.yml)
[![Interactive Web Demo](https://img.shields.io/badge/Interactive%20Demo-Live%20Exploit%20%26%20Config%20Sandbox-3b82f6.svg)](https://nagarajulu.github.io/mcp-cage/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](pyproject.toml)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-zero%20(100%25%20stdlib)-success.svg)](pyproject.toml)

> 🚀 **Try the Live Interactive Web Sandbox in Your Browser:** [**`https://nagarajulu.github.io/mcp-cage/`**](https://nagarajulu.github.io/mcp-cage/)  
> Explore the **5 Integration Modes** (`wrap`, `hook`, `shell`, Python SDK, `mcp-sploit`), inspect the **8-Plane Security Feature Matrix**, replay **V1 Failure vs. v0.3.0 Blocked Exploits** on the live $(P \times U \Rightarrow S)$ graph, and generate copy-paste configs for **Claude Code, Cursor, Gemini CLI, Antigravity (`agy`), Codex, Claude Desktop, and LangGraph**.

---

## Why `mcp-cage`?

Modern AI coding agents (**Claude Code**, **Cursor**, **OpenAI Codex CLI**, **Google Gemini CLI**, **Google Antigravity `agy`**, and **Claude Desktop**) combine three capabilities in a single context window:

1. **Private Data Access (`[P]`)** — reading `.env`, SSH keys, source code, and production databases.
2. **Untrusted Content Ingestion (`[U]`)** — reading external GitHub issues/PRs, web pages, and third-party documentation.
3. **External Egress & State Mutation (`[S]` / `[M]`)** — executing shell commands (`curl`, `git push`), posting Slack/GitHub comments, or mutating configuration files.

When all three meet in a single session—Simon Willison's **Lethal Trifecta**—a single indirect prompt injection (`XPIA`) or poisoned MCP tool definition (`MCPTox` / `CurXecute` CVE-2025-54135) can silently exfiltrate credentials or execute arbitrary commands.

**`mcp-cage` is a deterministic, OS-process-isolated security reference monitor** that sits across **both** planes of an AI coding agent:
- **Plane A (MCP JSON-RPC 2.0 Wire Gateway):** Wraps any `stdio` MCP server (`mcp-cage wrap`) to scrub secrets on the wire, pin `tools/list` schemas (`mcp-lock.json`), block `sampling/createMessage` hijacks, and spotlight untrusted outputs.
- **Plane B (Native Agent Lifecycle Hooks):** Plugs directly into `PreToolUse` / `PostToolUse` / `BeforeTool` / `beforeShellExecution` hooks across Claude Code, Cursor, Gemini CLI, Antigravity (`agy`), and Codex CLI—sharing a single cross-process **SQLite WAL** taint & secret vault.

---

## Core Security Capabilities

### 1. Zero-Leak Bidirectional Secret Scrubbing (`BidirectionalSecretScrubber`)
- Intercepts 11+ credential classes (`OPENAI_KEY`, `ANTHROPIC_KEY`, `AWS_ACCESS_KEY`, `GITHUB_PAT`, `STRIPE_KEY`, `SLACK_TOKEN`, `PRIVATE_KEY_PEM`, `JWT_TOKEN`, `DB_CONN_URI`, JSON/YAML secrets, and `.env` assignments) **before** they enter the LLM context window.
- Replaces raw secrets on the wire with deterministic placeholders (`<MCP_REDACTED_OPENAI_KEY_1>`) backed by an atomic cross-process **SQLite WAL vault**.
- Even if Process 1 (`filesystem` MCP or native `Read`) mints a token, Process 2 (`slack` MCP or native `Bash`) immediately blocks any attempt to exfiltrate that placeholder to an unauthorized sink.

### 2. Destructive Command, SSRF (`169.254.169.254`) & High-Entropy DNS Exfiltration Firewall
- **Path & Dotfile Confinement (`CVE-2025-53110` / `CVE-2025-53773` / `CVE-2025-54135`):** Resolves canonical paths (`Path.resolve()`) to block symlink escapes and hard-denies agent writes to `.env`, `.git/hooks/`, `.vscode/settings.json`, `.cursor/mcp.json`, `CLAUDE.md`, and `~/.ssh/`.
- **Cloud Metadata & Private Network SSRF Guard (`validate_outbound_network_target`):** Deterministically blocks requests to AWS/ECS/GCP/Alibaba/IPv6 cloud metadata (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`, `metadata.google.internal`, `100.100.100.200`), loopback (`127.0.0.0/8`, `localhost`, `[::1]`), RFC 1918 private networks, and dangerous non-HTTP schemes (`file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`).
- **High-Entropy DNS Exfiltration Blocker:** Computes per-label Shannon entropy ($H > 3.9$ bits/char for labels $>28$ chars) and regex signatures to block hex/base64 secret exfiltration over DNS (`<hex32>.attacker.com`).

### 3. Lethal-Trifecta Circuit Breaker + MELON Provenance Attribution
- Tracks monotonic session **Integrity** (`TRUSTED` $\rightarrow$ `ENDORSED` $\rightarrow$ `UNTRUSTED`) and **Confidentiality** (`PUBLIC` $\rightarrow$ `INTERNAL` $\rightarrow$ `CONFIDENTIAL` $\rightarrow$ `SECRET`) across concurrent tool calls using `BEGIN IMMEDIATE` SQLite transactions.
- **MELON Provenance Attribution:** Extracts URLs, domains, and email addresses from untrusted external inputs (`UNTRUSTED_SOURCE`) and hard-denies any subsequent sink or shell call targeting those untrusted entities (`[PROVENANCE HIJACK BLOCKED]`).
- **Zero-Fatigue UX:** Distinguishes benign reads (`README.md` + teammate issues stay `ENDORSED`/`PUBLIC`), allows safe workspace-local code edits, and supports **5-minute scoped workspace edit leases** (`LEASE_MUTATOR_5M`) while keeping external egress locked.

### 4. `CurXecute` Config Linter (`audit-config`) & `MCPTox` Schema Lockfile Verification
- **On-the-Wire Tool Sanitization & Rug-Pull Detection (`SchemaLockVerifier`):** Strips `<IMPORTANT>`, `<system>`, HTML comments, and cross-server shadowing directives from `tools/list` descriptions prior to SHA-256 pinning in `mcp-lock.json`.
- **Workspace Config Auditor (`mcp-cage audit-config`):** Scans `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and `claude_desktop_config.json` for `CurXecute` relative-path RCE (`./`, `../`, `/tmp/`, `bash -c`, command chaining), hardcoded plaintext API keys in `env` blocks, and unwrapped MCP servers.

### 5. Zero-Config Empirical Wire-Level Parameter Guards (`v0.3.0`)
Automatically enforced out of the box by `MCPCageEngine` (`MCPWireGateway`), `DynamicProfileAwareProxy`, and Plane B hooks:
- **Runtime Endpoint & Session Re-pointing Guard (`endpoint_repoint_guard`):** Blocks runtime connection-mutation tools (`connect_to_*`, `switch_server`, `set_endpoint`, `configure_connection`) unless explicitly opted in, and blocks mid-session `*_url` + `*_token`/`*_key` repointing to `local`, `localhost`, `127.0.0.1`, `169.254.169.254`, RFC1918, or untrusted hosts as well as raw bearer tokens in LLM context (`GHSA-rvjm-7hvp-f868`).
- **Embedded POSIX Command Substitution Guard (`path_command_substitution_guard` + `make_workspace_path_guard`):** Inspects `folderPath`, `filePath`, `source_dir`, `app_dir`, `working_directory`, `download_directory`, `destination`, and `path` for `$(...)`, `` `...` ``, and `${...}` even when disguised inside a valid relative workspace path segment (`CWE-78`).
- **REST URL Path-Segment Traversal Guard (`url_path_segment_guard`):** Blocks `..`, `%2e%2e`, `/`, `%2f`, `\`, `?`, and `#` (including URL-decoded/double-encoded forms) across `*_id`, `*Id`, `*Name`, `scriptName`, `job_id`, `session_id`, `rag_id`, `bucket`, and `repo` before REST URL interpolation (`CWE-22`).
- **CLI Positional-Argument Flag Injection Guard (`cli_flag_injection_guard`):** Blocks leading `-` / `--` flags (`--upload-pack=`, `--template=`, `--kubeconfig=`, `--token=`, `--output=`) injected into positional resource, directory, or target arguments (`CWE-88`).
- **Multi-Statement & Clause-Level SQL AST Guard (`sql_safety_guard`):** Strips `--` and `/* ... */` comments (both space-joined and compact to defeat token splitting), detects stacked `;` queries, and enforces SQLi checks across `where_clause`, `order_by`, `filter`, `having`, `sort_by`, and `group_by` (`A4.3` / `A8.1`).

---

## Empirical Co-Design Evolution (`v0.1.0` → `v0.2.2` → `v0.3.0`)

Each `mcp-cage` release translates real-world vulnerability classes uncovered across audited public and Big-Tech MCP servers into general-purpose, zero-config architectural capabilities:

| Release | Architectural Milestone | Real-World Audited MCP Servers / Incidents Addressed | Generalized Guard Plane |
| :--- | :--- | :--- | :--- |
| **`v0.1.0`** | Dual-Lattice IFC & Wire Prototype | Invariant Labs GitHub MCP Exploit, `MCPTox`, Microsoft Spotlighting, `MELON` | `SessionTaintStateMachine`, `SchemaLockVerifier` (`mcp-lock.json`), randomized datamarking boundaries, `ToxicFlowGraphAnalyzer` (`mcp-sploit`). |
| **`v0.2.2`** | Cross-Process WAL & Dual-Plane Firewall | `CVE-2025-53110`, `CVE-2025-53773` (Copilot YOLO), `CVE-2025-54135` (`CurXecute`), AWS IMDSv1 SSRF, DNS exfiltration | Shared SQLite WAL `BidirectionalSecretScrubber`, `BEGIN IMMEDIATE` atomic taint, `validate_outbound_network_target` (IMDS/RFC1918/Shannon DNS), `WorkspaceMCPConfigAuditor`, Plane A + Plane B hooks. |
| **`v0.3.0`** | Empirical Zero-Config Wire Guards | `datalayer/jupyter-mcp-server` (`GHSA-rvjm-7hvp-f868`), `GoogleCloudPlatform/cloud-run-mcp` (`#586725173`), `cloudflare/mcp-server-cloudflare`, `GoogleCloudPlatform/gke-mcp` & `Flux159/mcp-server-kubernetes`, `Snowflake-Labs/mcp` & `benborla/mcp-server-mysql` | `endpoint_repoint_guard`, `path_command_substitution_guard` + hardened `make_workspace_path_guard`, `url_path_segment_guard`, `cli_flag_injection_guard`, comment-stripping & clause-level `sql_safety_guard`. |
| **`v0.4.0`** | Wire-DIFC, 4-Slot Canonicalizer, Line-Span WAL & Kernel Sandbox Compiler | Day-0 Non-Collision Tool-Provider Misbinding, Cross-Session Stored XPIA (`CLAUDE.md`), `OverServe` Resource Amplification ($93.88\times$), EFF Diceware Covert Identifiers, Missing OS Kernel Containment | `WireDIFCCanonicalizer` (`S_poison >= 0.45` + 4-Slot Canonicalizer), `PersistentLineSpanProvenance` (`persistent_span_taint`), `DestinationBoundFPEVault`, `CausalStateProgressGovernor`, `SchemaToKernelSandboxCompiler` (`mcp-cage compile-sandbox` Seatbelt SBPL / Landlock), `mcp-cage bench`. |

---

## Quick Start (Zero Dependencies)

```bash
git clone https://github.com/nagarajulu/mcp-cage.git
cd mcp-cage
pip install -e .

# 1. Run the Unified 6-Suite Non-Regression & 9-Plane E2E Verification Runner
python3 run_all_regression_suites.py

# 2. Compile an OS Kernel Seatbelt SBPL (macOS) or Landlock/bwrap (Linux) Sandbox Profile
mcp-cage compile-sandbox --workspace . --os auto

# 3. Audit workspace MCP configs for CurXecute RCE & hardcoded secrets
mcp-cage audit-config

# 4. Run static Toxic-Flow Graph Analysis (mcp-sploit)
mcp-sploit audit
```

---

## Universal Dual-Plane Integration Guide

`mcp-cage` unifies **Plane A (`mcp-cage wrap`)** and **Plane B (`mcp-cage hook`)** against a single shared SQLite WAL database (`.mcp-cage/taint.db`).

### 1. Claude Code (`.claude/settings.json` + `.mcp.json`)

Add Plane B hooks to `.claude/settings.json`:
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [{ "type": "command", "command": "mcp-cage hook claude UserPromptSubmit --db .mcp-cage/taint.db" }]
      }
    ],
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [{ "type": "command", "command": "mcp-cage hook claude PreToolUse --db .mcp-cage/taint.db" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [{ "type": "command", "command": "mcp-cage hook claude PostToolUse --db .mcp-cage/taint.db" }]
      }
    ]
  }
}
```

### 2. Cursor (`.cursor/hooks.json` + `.cursor/mcp.json`)

Add Plane B hooks to `.cursor/hooks.json`:
```json
{
  "version": 1,
  "hooks": {
    "beforeReadFile": [{ "command": "mcp-cage hook cursor beforeReadFile --db .mcp-cage/taint.db" }],
    "beforeShellExecution": [{ "command": "mcp-cage hook cursor beforeShellExecution --db .mcp-cage/taint.db" }],
    "beforeMCPExecution": [{ "command": "mcp-cage hook cursor beforeMCPExecution --db .mcp-cage/taint.db" }],
    "afterMCPExecution": [{ "command": "mcp-cage hook cursor afterMCPExecution --db .mcp-cage/taint.db" }]
  }
}
```

### 3. Google Gemini CLI (`.gemini/settings.json`)

```json
{
  "hooks": {
    "SessionStart": [{ "command": "mcp-cage hook gemini SessionStart --db .mcp-cage/taint.db" }],
    "BeforeTool": [{ "command": "mcp-cage hook gemini BeforeTool --db .mcp-cage/taint.db" }],
    "AfterTool": [{ "command": "mcp-cage hook gemini AfterTool --db .mcp-cage/taint.db" }]
  }
}
```

### 4. Google Antigravity CLI (`agy`)

Register a wrapped MCP server with `agy`:
```bash
agy mcp add filesystem-caged -- mcp-cage wrap \
  --server filesystem \
  --workspace . \
  --state-dir .mcp-cage \
  -- npx -y @modelcontextprotocol/server-filesystem .
```
And configure `PreToolUse` / `PostToolUse` hooks using `mcp-cage hook agy PreToolUse --db .mcp-cage/taint.db`.

### 5. OpenAI Codex CLI (`~/.codex/hooks.json`)

```json
{
  "hooks": {
    "UserPromptSubmit": [{ "command": "mcp-cage hook codex UserPromptSubmit --db .mcp-cage/taint.db" }],
    "PreToolUse": [{ "command": "mcp-cage hook codex PreToolUse --db .mcp-cage/taint.db" }],
    "PostToolUse": [{ "command": "mcp-cage hook codex PostToolUse --db .mcp-cage/taint.db" }]
  }
}
```

### 6. Claude Desktop / Any `stdio` MCP Host (`claude_desktop_config.json`)

Wrap any upstream MCP server with `mcp-cage wrap`:
```json
{
  "mcpServers": {
    "filesystem-caged": {
      "command": "mcp-cage",
      "args": [
        "wrap",
        "--server", "filesystem",
        "--workspace", "/Users/you/workspace",
        "--state-dir", "/Users/you/workspace/.mcp-cage",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/workspace"
      ]
    }
  }
}
```

---

## Research Foundations & Academic Lineage

`mcp-cage` translates foundational Operating Systems & Agentic Information-Flow Control (IFC) research into a zero-dependency runtime firewall:

| Research System / Paper | Reference | Core Concept Adapted in `mcp-cage` |
| :--- | :--- | :--- |
| **CaMeL** *(Debenedetti et al., Google DeepMind, 2025)* | [`arXiv:2503.18813`](https://arxiv.org/abs/2503.18813) | Separating data capabilities & provenance from untrusted control flow in LLM tool invocations. |
| **FIDES** *(Costa et al., Microsoft Research, 2025)* | [`arXiv:2505.23643`](https://arxiv.org/abs/2505.23643) | Dual-lattice Information-Flow Control (Integrity $\times$ Confidentiality labels) with deterministic sink gates. |
| **Progent** *(Shi et al., UC Berkeley, 2025)* | [`arXiv:2504.11703`](https://arxiv.org/abs/2504.11703) | Programmable privilege control & deterministic argument guards (`StandardArgGuards`) over tool parameters. |
| **MELON** *(Zhu et al., 2025)* | [`arXiv:2502.05174`](https://arxiv.org/abs/2502.05174) | Provenance attribution blocking target arguments (URLs, domains, emails) extracted from untrusted tool outputs. |
| **Spotlighting** *(Hines et al., Microsoft, 2024)* | [`arXiv:2403.14720`](https://arxiv.org/abs/2403.14720) | Cryptographically randomized datamarking boundaries (`<<<UNTRUSTED_DATA_BOUNDARY id=...>>>`) with anti-spoofing. |
| **MCPTox** *(Wang et al., 2025)* | [`arXiv:2508.14925`](https://arxiv.org/abs/2508.14925) | Structural sanitization of poisoned MCP tool descriptions and cross-server shadowing detection (`SchemaLockVerifier`). |
| **FLOWSEAL** *(Aerakoni, 2026)* | `arXiv:2609.14003` | Cross-process SQLite WAL ambient taint state machine & bidirectional secret vault across Plane A + Plane B. |
| **HiStar / Flume / Capsicum** *(Zeldovich et al., Krohn et al., Watson et al.)* | *OSDI '06 / SOSP '07 / USENIX '10* | Decentralized IFC labels, explicit human declassification leases, and OS-level capability confinement. |

---

## Repository Structure

| File | Description |
| :--- | :--- |
| [`mcp_cage_core.py`](mcp_cage_core.py) | Unified core engine: `SessionTaintStateMachine`, `BidirectionalSecretScrubber`, `SchemaLockVerifier`, `ToxicFlowGraphAnalyzer`, `WorkspaceMCPConfigAuditor`, SSRF/DNS Exfil Guard, `MCPWireGateway`, and Dual-Plane CLI (`mcp-cage` / `mcp-sploit`). |
| [`mcp_cage_proxy.py`](mcp_cage_proxy.py) | Full JSON-RPC 2.0 wire proxy (`MCPJsonRpcProxy` & `StdioSubprocessBridge`) covering `tools/list`, `tools/call`, `resources/read`, `prompts/get`, and `sampling/createMessage`. |
| [`mcp_cage_cli.py`](mcp_cage_cli.py) | Standalone `stdio` process wrapper (`mcp-cage wrap`) with dynamic `tools/list` classification and config generator. |
| [`demo_interactive.py`](demo_interactive.py) | 5-Act interactive terminal walkthrough demonstrating every defense end-to-end. |
| [`test_mcp_cage_v30_empirical_guards.py`](test_mcp_cage_v30_empirical_guards.py) | v0.3.0 empirical guard regression suite covering Jupyter runtime hijack, Cloud Run `app$(...)`, Cloudflare path traversal, GKE/K8s CLI flag injection, Snowflake/MySQL SQLi, and sub-millisecond latency. |
| [`test_mcp_cage_v21.py`](test_mcp_cage_v21.py) | Comprehensive V2.2 unit & integration test suite (10 test suites including SSRF/DNS exfil & `CurXecute` config auditing). |
| [`test_e2e_all_8_planes.py`](test_e2e_all_8_planes.py) | 8-Plane End-to-End security test suite (17 tests across cognitive, protocol, trifecta, parameter, memory, and subprocess planes). |
| [`CHANGELOG.md`](CHANGELOG.md) | Empirical Co-Design release lineage (`v0.1.0` → `v0.2.2` → `v0.3.0`). |
| [`docs/index.html`](docs/index.html) / [`visualizer.html`](visualizer.html) | Interactive browser-based showcase: 5 Integration Modes, 8-Plane Security Matrix, V1 vs. v0.3.0 Exploit Simulator, Config Generator & 1966–2026 Research Lineage ([live on GitHub Pages](https://nagarajulu.github.io/mcp-cage/)). |

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 [Nagarajulu Aerakoni](https://github.com/nagarajulu).
