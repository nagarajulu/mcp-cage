# `mcp-cage` 🛡️

**Zero-Code Wire & Native-Hook Security Firewall for Claude Code, Cursor, Codex, Gemini CLI & MCP**  
*("Gitleaks + Little Snitch for AI Coding Agents" — 100% Python 3.10+ Standard Library, Zero External Dependencies)*

[![Live Interactive Web Showcase](https://img.shields.io/badge/🌐%20Live%20Interactive%20Sandbox-nagarajulu.github.io%2Fmcp--cage-06b6d4?style=for-the-badge)](https://nagarajulu.github.io/mcp-cage/)

[![CI — mcp-cage Security Suite](https://github.com/nagarajulu/mcp-cage/actions/workflows/ci.yml/badge.svg)](https://github.com/nagarajulu/mcp-cage/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-cage.svg)](https://pypi.org/project/mcp-cage/)
[![Interactive Web Demo](https://img.shields.io/badge/Interactive%20Demo-Live%20Exploit%20%26%20Config%20Sandbox-3b82f6.svg)](https://nagarajulu.github.io/mcp-cage/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](pyproject.toml)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-zero%20(100%25%20stdlib)-success.svg)](pyproject.toml)

> 🚀 **Try the Live Interactive Web Sandbox in Your Browser:** [**`https://nagarajulu.github.io/mcp-cage/`**](https://nagarajulu.github.io/mcp-cage/)  
> Explore the **5 Integration Modes** (`wrap`, `hook`, `shell`, Python SDK, `mcp-sploit`), inspect the **8-Plane Security Feature Matrix**, replay **V1 Failure vs. v0.4.0 Blocked Exploits** on the live $(P \times U \Rightarrow S)$ graph, and generate copy-paste configs for **Claude Code, Cursor, Gemini CLI, Antigravity (`agy`), Codex, Claude Desktop, and LangGraph**.

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

### 4. `CurXecute` Config Linter (`audit-config`), 7-Vector Skill/Rule AST Scanner (`audit-skills`) & `MCPTox` Schema Lockfile Verification
- **On-the-Wire Tool Sanitization & Rug-Pull Detection (`SchemaLockVerifier`):** Strips `<IMPORTANT>`, `<system>`, HTML comments, and cross-server shadowing directives from `tools/list` descriptions prior to SHA-256 pinning in `mcp-lock.json`.
- **Workspace Config Auditor (`mcp-cage audit-config`):** Scans `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and `claude_desktop_config.json` for `CurXecute` relative-path RCE (`./`, `../`, `/tmp/`, `bash -c`, command chaining), hardcoded plaintext API keys in `env` blocks, and unwrapped MCP servers.
- **7-Vector Agent Skill & Rule Static + AST Auditor (`mcp-cage audit-skills` / `WorkspaceSkillAndRuleAuditor`):** Scans `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, `.claude/skills/**`, and companion `scripts/*.py` (via Python `ast.parse()`) for:
  1. `RULE_UNICODE_SMUGGLING` (Invisible Unicode Tag `U+E0000..U+E007F`, zero-width, and BiDi overrides — *"Rules File Backdoor"* / `CVE-2021-42574`)
  2. `RULE_MARKDOWN_IMAGE_BEACON` (Zero-click Markdown image exfiltration beacons `![...](https://...?...)`)
  3. `RULE_SECURITY_BYPASS_DIRECTIVE` (`<IMPORTANT>`, `--no-verify`, `chat.tools.autoApprove`, `dangerouslyDisableSandbox`)
  4. `SKILL_OBFUSCATED_OR_PIPE_EXEC` (`curl ... | sh` and Python AST `eval(base64.b64decode(...))` / `exec(...)`)
  5. `SKILL_AST_CAPABILITY_DRIFT` (Declarative-to-Executable Capability Drift: `SKILL.md` frontmatter claims read-only/formatting while companion `scripts/*.py` invoke `subprocess`/`socket`/`urllib`)
  6. `SKILL_PERSISTENCE_BACKDOOR` (Self-propagating writes to `~/.bashrc`, `~/.zshrc`, or `.git/hooks/`)
  7. `SKILL_UNTRUSTED_PACKAGE_SOURCE` (Malicious `--index-url` or unpinned `git+https://` package installs)

### 5. Zero-Config Empirical Wire-Level Parameter Guards (`v0.3.0`)
Automatically enforced out of the box by `MCPCageEngine` (`MCPWireGateway`), `DynamicProfileAwareProxy`, and Plane B hooks:
- **Runtime Endpoint & Session Re-pointing Guard (`endpoint_repoint_guard`):** Blocks runtime connection-mutation tools (`connect_to_*`, `switch_server`, `set_endpoint`, `configure_connection`) unless explicitly opted in, and blocks mid-session `*_url` + `*_token`/`*_key` repointing to `local`, `localhost`, `127.0.0.1`, `169.254.169.254`, RFC1918, or untrusted hosts as well as raw bearer tokens in LLM context (`GHSA-rvjm-7hvp-f868`).
- **Embedded POSIX Command Substitution Guard (`path_command_substitution_guard` + `make_workspace_path_guard`):** Inspects `folderPath`, `filePath`, `source_dir`, `app_dir`, `working_directory`, `download_directory`, `destination`, and `path` for `$(...)`, `` `...` ``, and `${...}` even when disguised inside a valid relative workspace path segment (`CWE-78`).
- **REST URL Path-Segment Traversal Guard (`url_path_segment_guard`):** Blocks `..`, `%2e%2e`, `/`, `%2f`, `\`, `?`, and `#` (including URL-decoded/double-encoded forms) across `*_id`, `*Id`, `*Name`, `scriptName`, `job_id`, `session_id`, `rag_id`, `bucket`, and `repo` before REST URL interpolation (`CWE-22`).
- **CLI Positional-Argument Flag Injection Guard (`cli_flag_injection_guard`):** Blocks leading `-` / `--` flags (`--upload-pack=`, `--template=`, `--kubeconfig=`, `--token=`, `--output=`) injected into positional resource, directory, or target arguments (`CWE-88`).
- **Multi-Statement & Clause-Level SQL AST Guard (`sql_safety_guard`):** Strips `--` and `/* ... */` comments (both space-joined and compact to defeat token splitting), detects stacked `;` queries, and enforces SQLi checks across `where_clause`, `order_by`, `filter`, `having`, `sort_by`, and `group_by` (`A4.3` / `A8.1`).

### 6. Wire-DIFC 4-Slot Canonicalizer, Line-Span WAL Provenance & Kernel Sandbox Compiler (`v0.4.0`)
- **Unconditional 4-Slot Wire Canonicalizer (`WireDIFCCanonicalizer`):** Neutralizes Day-0 tool-provider misbinding and comparative authority inflation (`S_poison >= 0.45`) on `tools/list`.
- **Content-Addressed Line-Span Persistent Provenance (`PersistentLineSpanProvenance`):** Tracks SHA-256 line-span taint in SQLite WAL across `CLAUDE.md`, `.cursorrules`, and `MEMORY.md` to defeat cross-session stored prompt injection without freezing clean lines.
- **Destination-Bound Format-Preserving Secret Vault (`DestinationBoundFPEVault`) & Covert Identifier Guard (`is_covert_exfil_identifier`):** Prevents confused-deputy secret oracle forwarding and detects natural-language EFF Diceware / high-entropy identifier exfiltration.
- **Causal State-Progress Entropy Governor (`CausalStateProgressGovernor`) & Kernel Sandbox Compiler (`mcp-cage compile-sandbox`):** Arrests cyclic `OverServe` polling amplification loops and compiles stratified macOS Seatbelt SBPL / Linux Landlock/`bwrap` containment profiles.

---

## Empirical Co-Design Evolution (`v0.1.0` → `v0.2.2` → `v0.3.0` → `v0.4.0`)

Each `mcp-cage` release translates real-world vulnerability classes uncovered across audited public and Big-Tech MCP servers into general-purpose, zero-config architectural capabilities:

| Release | Architectural Milestone | Real-World Audited MCP Servers / Incidents Addressed | Generalized Guard Plane |
| :--- | :--- | :--- | :--- |
| **`v0.1.0`** | Dual-Lattice IFC & Wire Prototype | Invariant Labs GitHub MCP Exploit, `MCPTox`, Microsoft Spotlighting, `MELON` | `SessionTaintStateMachine`, `SchemaLockVerifier` (`mcp-lock.json`), randomized datamarking boundaries, `ToxicFlowGraphAnalyzer` (`mcp-sploit`). |
| **`v0.2.2`** | Cross-Process WAL & Dual-Plane Firewall | `CVE-2025-53110`, `CVE-2025-53773` (Copilot YOLO), `CVE-2025-54135` (`CurXecute`), AWS IMDSv1 SSRF, DNS exfiltration | Shared SQLite WAL `BidirectionalSecretScrubber`, `BEGIN IMMEDIATE` atomic taint, `validate_outbound_network_target` (IMDS/RFC1918/Shannon DNS), `WorkspaceMCPConfigAuditor`, Plane A + Plane B hooks. |
| **`v0.3.0`** | Empirical Zero-Config Wire Guards | `datalayer/jupyter-mcp-server` (`GHSA-rvjm-7hvp-f868`), Cloud Container Deployment MCP Servers (`CWE-78`), Edge & API Gateway MCP Servers (`CWE-22` REST path-segment traversal), Kubernetes & Infrastructure CLI MCP Servers (`CWE-88` positional flag injection), Enterprise Data Warehouse & Relational SQL MCP Servers (`CWE-89` comment-split & clause injection) | `endpoint_repoint_guard`, `path_command_substitution_guard` + hardened `make_workspace_path_guard`, `url_path_segment_guard`, `cli_flag_injection_guard`, comment-stripping & clause-level `sql_safety_guard`. |
| **`v0.4.0`** | Wire-DIFC, 4-Slot Canonicalizer, Line-Span WAL & Kernel Sandbox Compiler | Day-0 Non-Collision Tool-Provider Misbinding, Cross-Session Stored XPIA (`CLAUDE.md`), `OverServe` Resource Amplification ($93.88\times$), EFF Diceware Covert Identifiers, Missing OS Kernel Containment | `WireDIFCCanonicalizer` (`S_poison >= 0.45` + 4-Slot Canonicalizer), `PersistentLineSpanProvenance` (`persistent_span_taint`), `DestinationBoundFPEVault`, `CausalStateProgressGovernor`, `SchemaToKernelSandboxCompiler` (`mcp-cage compile-sandbox` Seatbelt SBPL / Landlock), `mcp-cage bench`. |
| **`v0.4.1`** | Modular Package Architecture (`mcp_cage/`), Declarative Policy Loader & 25-Mechanism CWE Paired-Twin Matrix | 25 Empirical CWE Vulnerability Mechanisms (75+ attack payloads paired with 35+ benign twins across Plane A & Plane B), Enterprise Declarative Policy Configuration (`.mcp-cage/policy.json`) | Modular `mcp_cage.{core,lattice,vault,schema,guards,surfaces,policy,proxy,cli}` package hierarchy, `MCPCagePolicyConfig`, 10-suite non-regression & 7-Gate OPSEC runner (`run_all_regression_suites.py`). |

---

## Quick Start (Zero Dependencies)

```bash
# Install directly from PyPI (or run zero-install via `uvx mcp-cage --help`):
pip install mcp-cage

# Or install from source:
git clone https://github.com/nagarajulu/mcp-cage.git
cd mcp-cage
pip install -e .

# 1. Run the Unified 10-Suite Non-Regression, 25-Mechanism CWE Matrix & 7-Gate OPSEC Runner
python3 run_all_regression_suites.py

# 2. Compile an OS Kernel Seatbelt SBPL (macOS) or Landlock/bwrap (Linux) Sandbox Profile
mcp-cage compile-sandbox --workspace . --os auto

# 3. Audit workspace MCP configs (.mcp.json) AND Agent Skills/Rules (SKILL.md, CLAUDE.md, .cursorrules, scripts/*.py)
mcp-cage audit-config
mcp-cage audit-skills

# 4. Run static Toxic-Flow Graph Analysis (mcp-sploit)
mcp-sploit audit

# 5. Day-1 Zero-Friction Onboarding: Start in '--mode shadow' (logs alerts to .mcp-cage/audit.jsonl without blocking)
#    then switch to '--mode enforce' once verified in your workflow:
mcp-cage wrap --server filesystem --workspace . --mode shadow -- npx -y @modelcontextprotocol/server-filesystem .
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

## Foundational Security, Academic Research & Standard Taxonomies (`OWASP` / `MITRE ATLAS` / `CWE`)

`mcp-cage` translates peer-reviewed Operating Systems & Agentic Information-Flow Control (IFC) research into deterministic, sub-millisecond (`<1ms`) wire and hook primitives:

### 1. Peer-Reviewed Academic Research & Industry Advisories

| Published System / Paper / Advisory | Reference | Core Mechanism Implemented in `mcp-cage` |
| :--- | :--- | :--- |
| **CaMeL** *(Debenedetti et al., Google DeepMind, 2025)* | [`arXiv:2503.18813`](https://arxiv.org/abs/2503.18813) | Separating data capabilities & provenance from untrusted LLM control flow via out-of-process reference monitoring (`MCPWireGateway` + `handle_cli_hook`). |
| **FIDES** *(Costa et al., Microsoft Research, 2025)* | [`arXiv:2505.23643`](https://arxiv.org/abs/2505.23643) | Dual-lattice Information-Flow Control ($\mathcal{I} \times \mathcal{C}$ Integrity $\times$ Confidentiality labels) with deterministic sink gates in [`SessionTaintStateMachine`](mcp_cage/lattice.py). |
| **Progent** *(Shi et al., UC Berkeley, 2025)* | [`arXiv:2504.11703`](https://arxiv.org/abs/2504.11703) | Programmable privilege control, deterministic argument guards ([`StandardArgGuards`](mcp_cage/guards.py)), and Declarative-to-Executable AST capability drift detection (`SKILL_AST_CAPABILITY_DRIFT`). |
| **MELON** *(Zhu et al., 2025)* | [`arXiv:2502.05174`](https://arxiv.org/abs/2502.05174) | Provenance attribution extracting URLs, domains, and emails from untrusted tool outputs and blocking sink calls targeting them (`extract_untrusted_sink_entities`). |
| **Spotlighting** *(Hines et al., Microsoft, 2024)* | [`arXiv:2403.14720`](https://arxiv.org/abs/2403.14720) | Cryptographically randomized datamarking boundaries (`<<<UNTRUSTED_DATA_BOUNDARY id=...>>>`) with anti-spoofing sanitization ([`WirePayloadSanitizer`](mcp_cage/vault.py)). |
| **MCPTox** *(Wang et al., 2025)* | [`arXiv:2508.14925`](https://arxiv.org/abs/2508.14925) | Unconditional 4-Slot Schema Canonicalizer ([`WireDIFCCanonicalizer`](mcp_cage/schema.py)), authority log-odds scoring ($S_{\text{poison}} \ge 0.45$), and SHA-256 `mcp-lock.json` pinning. |
| **Trojan Source & Rules File Backdoor** *(Boucher et al., Cambridge / Pillar Security, 2025)* | `CVE-2021-42574` / `CVE-2025-53773` | Static + wire stripping of invisible Unicode Tag (`U+E0000..U+E007F`), zero-width, and BiDi override codepoints in [`WorkspaceSkillAndRuleAuditor`](mcp_cage/surfaces.py) (`mcp-cage audit-skills`). |
| **CurXecute / MCPoison & Copilot YOLO** *(2025 CVEs)* | `CVE-2025-54135` / `CVE-2025-53110` | Pre-execution config auditing ([`WorkspaceMCPConfigAuditor`](mcp_cage/surfaces.py) / `mcp-cage audit-config`) + runtime dotfile/hook write locks (`PROTECTED_DOTFILE_WRITE_PATTERNS`). |
| **HiStar / Flume / Capsicum** *(Zeldovich et al., Krohn et al., Watson et al.)* | *OSDI '06 / SOSP '07 / USENIX '10* | Decentralized IFC labels, explicit human declassification leases (`LEASE_MUTATOR_5M`), and OS-kernel sandbox compilation ([`SchemaToKernelSandboxCompiler`](mcp_cage/surfaces.py)). |

### 2. OWASP Top 10 for LLM & Agentic Applications + MITRE ATLAS Coverage Matrix

| Standard Taxonomy ID | Threat Category | `mcp-cage` Enforcement Primitive & Verification Suite |
| :--- | :--- | :--- |
| **OWASP `LLM01` / MITRE `AML.T0051`** | Direct & Indirect Prompt Injection (`XPIA`) | Dual-Lattice IFC (`SessionTaintStateMachine`), Spotlighting boundaries, Content-Addressed Line-Span WAL Provenance (`PersistentLineSpanProvenance`), and `mcp-cage audit-skills`. |
| **OWASP `LLM02` / MITRE `AML.T0048`** | Sensitive Information & Credential Disclosure | `BidirectionalSecretScrubber`, `DestinationBoundFPEVault`, Two-Axis Covert Hex DNS / EFF Diceware Identifier Detector (`is_covert_exfil_identifier`), and blind filter-oracle guards (`CWE-200`). |
| **OWASP `LLM03` / MITRE `AML.T0010`** | AI Supply Chain, MCP Config & Skill Poisoning | `SchemaLockVerifier` (`mcp-lock.json` rug-pull detection), `WireDIFCCanonicalizer`, `WorkspaceMCPConfigAuditor` (`audit-config`), `WorkspaceSkillAndRuleAuditor` (`audit-skills`), and PEP 508 `package_install_guard`. |
| **OWASP `LLM05` / `LLM06`** | Improper Output Handling & Excessive Agency | 34-Mechanism Empirical CWE Parameter Guards (`StandardArgGuards`), Meta-Tool Inner Dispatch Guard (`tool_execute`), Tenant Organization Allowlist Guard (`CWE-863`), and OS Kernel Sandbox Compiler (`compile-sandbox`). |
| **OWASP `LLM08` / `LLM10`** | Persistent Memory Poisoning & Unbounded Consumption | Line-Span WAL Provenance on `CLAUDE.md`/`.cursorrules`/`MEMORY.md` (`PersistentLineSpanProvenance`) + Causal State-Progress Entropy Governor (`CausalStateProgressGovernor` defeating `OverServe` $93.88\times$ loops). |

### 3. Complete 34-Mechanism Empirical CWE & CVE Protection Catalog

Every vulnerability mechanism below is continuously verified via paired `[ATTACK_BLOCKED]` + `[BENIGN_ALLOWED]` twins across **both** Plane A (`MCPWireGateway`) and Plane B (`handle_cli_hook`) in [`tests/cwe_catalog/test_cwe_paired_twin_matrix.py`](tests/cwe_catalog/test_cwe_paired_twin_matrix.py):

- **Path Traversal, Workspace Escape & REST Identifier Smuggling (`CWE-22`):** Sibling-prefix escape (`/workspace-evil`), split `(directory, filename)` join traversal, double-URL-encoded dot-segments (`%252e%252e`), nested `path_params`/`path` dictionary traversal, relative REST path & scheme smuggling (`../../oauth2/userinfo`), repository/artifact/node config path smuggling, and optional log-file path reads (`secops_read_web_log`).
- **OS Command, POSIX Subshell & Git Transport/Flag Injection (`CWE-78` / `CWE-88`):** Embedded POSIX command substitution (`app$(id)`, backticks, `${IFS}`) in path/command arguments (with zero false positives on free-text file `content`/`body`), positional CLI flag injection (`--kubeconfig=`, `--upload-pack=`, `--output=`, `-oProxyCommand=`), `git::ext::` / `fd::` transport RCE, `core.sshCommand`/`core.fsmonitor` config injection, and PEP 508 `pip` package list injection.
- **SQL, Cypher & NoSQL Injection (`CWE-89` / `CWE-943`):** Comment-split stacked SQLi (`DR/**/OP`), clause-level injection (`where_clause`, `order_by`, `having`), `EXPLAIN ANALYZE` destructive DML execution, analytical file-read functions (`read_text`, `read_parquet`), SQL identifier breakout, Neo4j/Memgraph Cypher property identifier injection, and MongoDB/Document-DB `$where`/`$function` JS execution & `$regex` credential oracles.
- **Code Sandbox Escape, SSTI, XXE & Unsafe Deserialization (`CWE-94` / `CWE-502` / `CWE-611` / `CWE-1336`):** Python dunder sandbox escape gadgets (`__subclasses__`, `__globals__`, `dir.__self__.__import__`, `asyncio.create_subprocess_exec`), process environment `*_API_KEY` harvesting, Jinja2/Mako Server-Side Template Injection (`{{ self.__init__.__globals__... }}`), XML External Entity (`<!ENTITY` / `<!DOCTYPE SYSTEM`) expansion, Python `pickle` payload blocking (with binary molecule magic allowlist), and PyYAML `!!python/object/apply` / `jsonpickle` `py/object` deserialization blocking.
- **SSRF, Runtime Endpoint Hijack, RBAC Bypass, MQTT & OAuth XSS (`CWE-20` / `CWE-79` / `CWE-200` / `CWE-639` / `CWE-863` / `CWE-918`):** AWS/GCP/Alibaba Cloud IMDSv1 (`169.254.169.254`), IPv6-mapped IPv4 loopback (`[::ffff:127.0.0.1]`), runtime notebook/service endpoint re-pointing (`GHSA-rvjm-7hvp-f868`), meta-tool inner dispatch (`tool_execute` / `call_tool`), `kubectl --dry-run=none` bypass, read-only GraphQL mutation smuggling, tenant organization boundary enforcement, sensitive email attachment dotfile blocking (`~/.ssh/id_rsa`, `~/.mail-mcp/`), MQTT wildcard topic injection (`#`, `+`), and reflected OAuth callback XSS (`<script>`).

---

## Repository Structure

```text
mcp-cage/
├── mcp_cage/                                                   # Modular Zero-Dependency Python Package
│   ├── __init__.py                                             # Public API exports
│   ├── core.py                                                 # Core Wire-DIFC reference monitor engine
│   ├── lattice.py                                              # Dual-Axis Taint Lattice, SQLite WAL State Machine, Line-Span Provenance
│   ├── vault.py                                                # Bidirectional Secret Scrubber, FPE Vault, Covert Entropy Detectors
│   ├── schema.py                                               # 4-Slot Canonicalizer, SchemaLockVerifier, ToxicFlowGraphAnalyzer
│   ├── guards.py                                               # 25 Empirical CWE Parameter Guards (StandardArgGuards, SSRF, Workspace Jail)
│   ├── surfaces.py                                             # Plane A (MCPWireGateway), Plane B (handle_cli_hook), Kernel Sandbox Compiler
│   ├── policy.py                                               # Declarative Enterprise Policy Loader (.mcp-cage/policy.json)
│   ├── proxy.py                                                # Full JSON-RPC 2.0 wire proxy (MCPJsonRpcProxy & StdioSubprocessBridge)
│   ├── cli_runner.py                                           # Standalone stdio process wrapper (mcp-cage wrap) & config generator
│   └── cli.py                                                  # Unified mcp-cage & mcp-sploit CLI entrypoint
│
├── tests/                                                      # Structured Verification & Regression Hierarchy
│   ├── unit/
│   │   ├── test_ifc_lattice_and_wal_vault.py                   # Core IFC lattice, WAL vault, SSRF/DNS & CurXecute config auditor suite
│   │   ├── test_empirical_guards.py                            # Empirical wire guard & sub-millisecond latency suite
│   │   ├── test_wiredifc_canonicalizer_and_sandbox.py          # 4-Slot Canonicalizer, Line-Span WAL, FPE Vault & Kernel Sandbox suite
│   │   └── test_modular_package_and_policy.py                  # Modular package exports & declarative policy (.mcp-cage/policy.json) suite
│   ├── cwe_catalog/
│   │   ├── test_cwe_paired_twin_matrix.py                      # 25-Mechanism Empirical CWE Paired-Twin Matrix (Plane A & Plane B parity)
│   │   └── test_agentic_ai_frameworks.py                       # Agentic AI frameworks, Python sandbox guards & stdlib-purity AST suite
│   ├── e2e/
│   │   ├── test_tier1_all_8_planes.py                          # Tier 1: 8-Plane E2E adversarial verification harness
│   │   └── test_tier2_real_mcp_and_canary.py                   # Tier 2: Official Node.js MCP server + live HTTP canary listener
│   └── fixtures/
│       └── mock_mcp_server.py                                  # Deterministic mock stdio MCP server for offline E2E tests
│
├── examples/
│   └── demo_interactive.py                                     # 5-Act interactive terminal walkthrough demonstrating every defense
├── docs/index.html & visualizer.html                           # Interactive browser simulator & GitHub Pages showcase
├── .githooks/pre-commit                                        # Automated 7-Gate OPSEC, Embargo, Personal-Path & Docs-Sync scanner
├── run_all_regression_suites.py                                # Unified 1-command runner executing all 10 verification suites
├── CONTRIBUTING.md                                             # Architecture guide & Paired-Twin CWE Promotion Contract
├── CHANGELOG.md                                                # Release changelog (v0.1.0 -> v0.2.2 -> v0.3.0 -> v0.4.0 -> v0.4.1)
└── SECURITY.md                                                 # Coordinated vulnerability disclosure policy
```

| Path | Description |
| :--- | :--- |
| [`mcp_cage/`](mcp_cage/__init__.py) ([`mcp_cage/core.py`](mcp_cage/core.py)) | Modular security engine package (`lattice`, `vault`, `schema`, `guards`, `surfaces`, `policy`, `proxy`, `cli`). Also accessible via the root [`mcp_cage_core.py`](mcp_cage_core.py) compatibility shim. |
| [`mcp_cage/proxy.py`](mcp_cage/proxy.py) | Full JSON-RPC 2.0 wire proxy (`MCPJsonRpcProxy` & `StdioSubprocessBridge`) covering `tools/list`, `tools/call`, `resources/read`, `prompts/get`, and `sampling/createMessage`. |
| [`mcp_cage/cli_runner.py`](mcp_cage/cli_runner.py) | Standalone `stdio` process wrapper (`mcp-cage wrap`) with dynamic `tools/list` classification and config generator. |
| [`examples/demo_interactive.py`](examples/demo_interactive.py) | 5-Act interactive terminal walkthrough demonstrating every defense end-to-end. |
| [`tests/cwe_catalog/test_cwe_paired_twin_matrix.py`](tests/cwe_catalog/test_cwe_paired_twin_matrix.py) | 25-Mechanism Empirical CWE Paired-Twin Matrix verifying 75+ `[ATTACK_BLOCKED]` payloads paired with 35+ `[BENIGN_ALLOWED]` twins across Plane A and Plane B. |
| [`tests/cwe_catalog/test_agentic_ai_frameworks.py`](tests/cwe_catalog/test_agentic_ai_frameworks.py) | Multi-agent framework guards (split `directory`+`filename`, PEP 508 package install, Python sandbox dunder escape), stdlib purity AST test, and latency budget verification. |
| [`tests/unit/test_wiredifc_canonicalizer_and_sandbox.py`](tests/unit/test_wiredifc_canonicalizer_and_sandbox.py) | Wire-DIFC regression suite covering the 4-Slot Wire Canonicalizer, Line-Span WAL Provenance, Destination-Bound FPE Vault, Diceware Covert Identifier Detector, Causal Progress Governor, and Kernel Sandbox Compiler. |
| [`tests/unit/test_empirical_guards.py`](tests/unit/test_empirical_guards.py) | Empirical wire guard regression suite covering Jupyter runtime hijack (`GHSA-rvjm-7hvp-f868`), embedded command substitution (`CWE-78`), REST path traversal (`CWE-22`), CLI flag injection (`CWE-88`), SQLi (`CWE-89`), and sub-millisecond latency. |
| [`tests/unit/test_ifc_lattice_and_wal_vault.py`](tests/unit/test_ifc_lattice_and_wal_vault.py) | Core IFC lattice, WAL vault, SSRF/DNS exfiltration & `CurXecute` config auditing unit & integration suite. |
| [`tests/unit/test_modular_package_and_policy.py`](tests/unit/test_modular_package_and_policy.py) | Modular package submodule exports & declarative enterprise policy (`.mcp-cage/policy.json`) verification suite. |
| [`tests/e2e/test_tier1_all_8_planes.py`](tests/e2e/test_tier1_all_8_planes.py) | Tier 1 End-to-End security test suite across cognitive, protocol, trifecta, parameter, memory, and subprocess planes. |
| [`tests/e2e/test_tier2_real_mcp_and_canary.py`](tests/e2e/test_tier2_real_mcp_and_canary.py) | Tier 2 multi-process `stdio` integration suite against the official Node.js `@modelcontextprotocol/server-filesystem` and a live local HTTP Canary Listener. |
| [`run_all_regression_suites.py`](run_all_regression_suites.py) | Unified single-command non-regression verification runner executing all 10 verification suites (including `.githooks/pre-commit`). |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor architecture guide and the mandatory Paired-Twin CWE Promotion Contract (`EmpiricalCWETwinSpec`). |
| [`CHANGELOG.md`](CHANGELOG.md) | Release changelog (`v0.1.0` → `v0.2.2` → `v0.3.0` → `v0.4.0` → `v0.4.1`). |
| [`docs/index.html`](docs/index.html) / [`visualizer.html`](visualizer.html) | Interactive browser-based showcase: 5 Integration Modes, 8-Plane Security Matrix, Live Exploit Simulator, Config Generator & IFC References ([live on GitHub Pages](https://nagarajulu.github.io/mcp-cage/)). |

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 [Nagarajulu Aerakoni](https://github.com/nagarajulu).
