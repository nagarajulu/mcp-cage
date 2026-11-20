"""
Core engine for `mcp-cage` (Zero-Code Wire & Native-Hook Security Firewall) & `mcp-sploit` (Toxic-Flow & Config Scanner).

v0.3.0 Empirical Co-Design Architecture (`v0.1.0` -> `v0.2.2` -> `v0.3.0`):
1. Cross-Process SQLite-Backed `BidirectionalSecretScrubber`:
   - Stores redacted secret tokens (`<MCP_REDACTED_...>`) in SQLite WAL so separate OS processes
     (`filesystem` vs `slack` vs `github`) share the same token vault without collisions or amnesia.
   - Detects 11+ secret classes (OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, PEM keys,
     DB connection URIs, JWTs, JSON/YAML secrets, and .env assignments).
2. Atomic SQLite Transactions (`BEGIN IMMEDIATE`) in `SessionTaintStateMachine`:
   - Eliminates TOCTOU lost-update race conditions during parallel LLM tool calls.
   - Enforces MELON provenance attribution (blocking sink/mutator arguments derived from untrusted entities).
   - Supports turn integrity resets (`reset_turn_integrity`), context endorsement (`endorse_session`),
     and scoped 5-minute workspace edit leases (`DeclassificationAction.LEASE_MUTATOR_5M`).
3. SSRF, Cloud Metadata (`169.254.169.254`) & High-Entropy DNS Exfiltration Guard:
   - Deterministically blocks AWS/GCP/Alibaba/IPv6 cloud metadata endpoints, loopback/RFC1918 private IPs,
     dangerous non-HTTP schemes (`file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`), and high-entropy
     or hex/base64-encoded DNS exfiltration subdomains (`<hex32>.attacker.com`).
4. `CurXecute` / `MCPoison` Workspace Config Auditor (`WorkspaceMCPConfigAuditor`):
   - Audits `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and `claude_desktop_config.json` for
     relative-path binary execution, shell wrappers, command chaining, hardcoded plaintext secrets,
     and unwrapped MCP servers.
5. v0.3.0 Empirical Wire-Level Security Guards (Generalizing Real-World MCP Audit Findings):
   - Runtime Endpoint & Session Re-pointing Guard (`endpoint_repoint_guard` — `GHSA-rvjm-7hvp-f868`).
   - Embedded POSIX Command Substitution Guard in File/Folder Paths (`path_command_substitution_guard` + `make_workspace_path_guard`).
   - REST URL Path-Segment Traversal Guard (`url_path_segment_guard`).
   - CLI Positional-Argument Flag Injection Guard (`cli_flag_injection_guard`).
   - Multi-Statement & Clause-Level SQL AST Guard (`sql_safety_guard`).
6. Universal Dual-Plane Enforcement:
   - Plane A (MCP Wire Gateway): `MCPWireGateway` (`MCPCageEngine`) & `MCPJsonRpcProxy` for stdio MCP servers.
   - Plane B (Native Agent Lifecycle Hooks): `mcp-cage hook <claude|cursor|gemini|agy|codex>` for built-in tools.
"""

from __future__ import annotations

__version__ = "0.4.0"

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple


class Integrity(IntEnum):
    UNTRUSTED = 0   # External web pages, external GitHub issues/PRs, incoming emails/Slack
    ENDORSED = 1    # Explicitly human-declassified or trusted-teammate content
    TRUSTED = 2     # Authenticated user prompt & pinned system configuration


class Confidentiality(IntEnum):
    PUBLIC = 0        # Public documentation, open web, README.md
    INTERNAL = 1      # Internal workspace source code, non-sensitive config
    CONFIDENTIAL = 2  # Customer DB rows, private repos, internal hostnames
    SECRET = 3        # Raw credentials, .env files, SSH keys, API tokens, DB URIs


class ToolRole(IntEnum):
    NEUTRAL = 0
    UNTRUSTED_SOURCE = 1     # Ingests external untrusted text (lowers session integrity)
    PRIVATE_SOURCE = 2       # Ingests confidential/secret data (raises session confidentiality)
    PRIVILEGED_MUTATOR = 3   # Mutates local/remote system state (bash, SQL write, git push)
    EXTERNAL_EGRESS_SINK = 4 # Sends data outside trust boundary (Slack, email, HTTP, public PR)
    WORKSPACE_MUTATOR = 5    # Scoped workspace source file edit (allowed when confined to safe paths)


class GateDecisionType(IntEnum):
    ALLOW = 0
    STEP_UP = 1
    DENY = 2


class EnforcementMode(StrEnum):
    SHADOW = "shadow"   # Audit-only mode: logs violations to audit.jsonl without blocking calls
    ENFORCE = "enforce" # Active firewall mode: blocks DENY and triggers STEP_UP approval


class DeclassificationAction(StrEnum):
    DENY = "deny"
    APPROVE_ONCE = "approve_once"
    LEASE_MUTATOR_5M = "lease_mutator_5m"
    ENDORSE_CONTEXT = "endorse_context"


# Dynamic taint resolver signature: (arguments, response_text, had_redacted_secrets) -> (Integrity, Confidentiality)
SourceTaintResolver = Callable[[Mapping[str, Any], str, bool], tuple[Integrity, Confidentiality]]


@dataclass(frozen=True)
class ToolSecurityProfile:
    server: str
    tool_name: str
    roles: frozenset[ToolRole]
    source_integrity: Integrity = Integrity.TRUSTED
    source_confidentiality: Confidentiality = Confidentiality.PUBLIC
    min_required_integrity: Integrity = Integrity.TRUSTED
    max_allowed_confidentiality: Confidentiality = Confidentiality.PUBLIC
    arg_guard: Callable[[Mapping[str, Any]], tuple[bool, str]] | None = None
    source_taint_resolver: SourceTaintResolver | None = None

    @property
    def fq_name(self) -> str:
        return f"{self.server}.{self.tool_name}"


@dataclass
class GateEvaluation:
    decision: GateDecisionType
    effective_decision: GateDecisionType  # In SHADOW mode, STEP_UP/DENY become ALLOW on wire but logged
    mode: EnforcementMode
    reason: str
    human_summary: str
    trifecta_triggered: bool = False
    lease_applied: str | None = None
    ambient_integrity: Integrity = Integrity.TRUSTED
    ambient_confidentiality: Confidentiality = Confidentiality.PUBLIC
    provenance_log: list[str] = field(default_factory=list)


class StateTuple(tuple):  # type: ignore[type-arg]
    """
    Backward-compatible state tuple returned by `SessionTaintStateMachine.get_state()`.
    Supports both 3-tuple unpacking `(integrity, confidentiality, provenance)` (V2.1 API)
    and 4-tuple unpacking `(integrity, confidentiality, provenance, leases)` (V3 API).
    """

    def __new__(
        cls,
        integrity: Integrity,
        confidentiality: Confidentiality,
        provenance: list[str],
        leases: dict[str, float],
    ) -> StateTuple:
        obj = super().__new__(cls, (integrity, confidentiality, provenance, leases))
        return obj


# -----------------------------------------------------------------------------
# Built-in File, Path, SSRF & High-Entropy DNS Exfiltration Guards
# -----------------------------------------------------------------------------

SENSITIVE_FILE_PATTERNS = re.compile(
    r"(?i)(^|/)\.env($|\.)|id_rsa|id_ed25519|\.pem$|\.key$|credentials|secrets?\.ya?ml|secrets?\.json|\.aws/|\.npmrc|\.pypirc|\.ssh/"
)
PUBLIC_DOC_PATTERNS = re.compile(r"(?i)(^|/)(readme|license|changelog|contributing)(\.[a-z0-9]+)?$")
PROTECTED_DOTFILE_WRITE_PATTERNS = re.compile(
    r"(?i)(^|/)(\.env($|\.)|\.git/|\.vscode/|\.cursor/|\.claude/|\.gemini/|\.codex/|\.agents/|\.opencode/|claude_desktop_config\.json|claude\.md|agents\.md|skill\.md|\.cursorrules|mcp-cage\.ya?ml|\.mcp-cage/|\.bashrc|\.zshrc|\.profile|\.ssh/|makefile|package\.json)"
)


WORKSPACE_PATH_KEYS: tuple[str, ...] = (
    "path",
    "file_path",
    "filePath",
    "filename",
    "file_name",
    "fileName",
    "target_file",
    "targetFile",
    "folderPath",
    "folder_path",
    "source_dir",
    "sourceDir",
    "app_dir",
    "appDir",
    "working_directory",
    "workingDirectory",
    "download_directory",
    "downloadDirectory",
    "destination",
    "dest",
    "directory",
    "dir",
    "cwd",
    "root_dir",
    "output_path",
    "outputPath",
    "input_path",
    "inputPath",
)
LOCAL_DIR_ONLY_KEYS: frozenset[str] = frozenset(
    {
        "folderpath",
        "folder_path",
        "source_dir",
        "sourcedir",
        "app_dir",
        "appdir",
        "working_directory",
        "workingdirectory",
        "download_directory",
        "downloaddirectory",
    }
)
POSIX_CMD_SUBST_RE = re.compile(r"\$\(|`|\$\{|\x00")


def is_safe_workspace_path(raw_path: str | Path, workspace_root: Path, *, is_write: bool = True) -> tuple[bool, str]:
    """
    Verifies that `raw_path` contains no embedded POSIX command substitution (`$(...)`, backticks),
    resolves strictly inside `workspace_root` (blocking `../`, `~`, and symlink escapes),
    and does not modify protected dotfiles or agent configuration files.
    """
    path_str = str(raw_path).strip()
    if not path_str:
        return False, "Missing file path parameter."
    if POSIX_CMD_SUBST_RE.search(path_str):
        return (
            False,
            f"Embedded POSIX command substitution / shell expansion blocked in path (CWE-78): '{path_str}'.",
        )
    if path_str.startswith("~"):
        return False, f"Home directory path expansion blocked (A4.2): '{path_str}'."

    resolved_root = workspace_root.resolve()
    p_obj = Path(path_str)
    candidate = p_obj.resolve() if p_obj.is_absolute() else (workspace_root / p_obj).resolve()
    try:
        rel = candidate.relative_to(resolved_root)
    except ValueError:
        return (
            False,
            f"Path traversal / symlink escape blocked (A4.2): '{path_str}' resolves to '{candidate}' outside workspace '{resolved_root}'.",
        )

    rel_norm = str(rel).replace("\\", "/")
    raw_norm = path_str.replace("\\", "/")
    if is_write and (
        PROTECTED_DOTFILE_WRITE_PATTERNS.search(raw_norm)
        or PROTECTED_DOTFILE_WRITE_PATTERNS.search(rel_norm)
    ):
        return (
            False,
            f"Protected config/dotfile write blocked (A3.3/A3.4): '{path_str}' cannot be modified by an agent.",
        )
    return True, "OK"


def _collect_workspace_paths(args: Mapping[str, Any]) -> list[str]:
    candidates: list[Mapping[str, Any]] = [args]
    nested = args.get("args")
    if isinstance(nested, Mapping):
        candidates.append(nested)
    nested_params = args.get("params")
    if isinstance(nested_params, Mapping):
        candidates.append(nested_params)

    found: list[str] = []
    for src in candidates:
        for key in WORKSPACE_PATH_KEYS:
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                found.append(val)
        # Support split (directory, filename) tool schemas in multi-agent Python toolkits
        dir_val = src.get("directory") or src.get("dir") or src.get("folder_path") or src.get("folderPath")
        fname_val = src.get("filename") or src.get("file_name") or src.get("fileName")
        if isinstance(dir_val, str) and dir_val.strip() and isinstance(fname_val, str) and fname_val.strip():
            found.append(str(Path(dir_val.strip()) / fname_val.strip()))
        for list_key in ("paths", "files", "folders", "directories"):
            list_val = src.get(list_key)
            if isinstance(list_val, (list, tuple)):
                for item in list_val:
                    if isinstance(item, str) and item.strip():
                        found.append(item)
    return found


def make_workspace_path_guard(
    workspace_root: Path, *, is_write: bool = True
) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
    def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
        paths = _collect_workspace_paths(args)
        if not paths:
            return is_safe_workspace_path("", workspace_root, is_write=is_write)
        for raw_path in paths:
            ok, reason = is_safe_workspace_path(raw_path, workspace_root, is_write=is_write)
            if not ok:
                return False, reason
        return True, "OK"

    return _guard


# -----------------------------------------------------------------------------
# Primitive A: SSRF, Cloud Metadata & High-Entropy DNS Exfiltration Guard
# -----------------------------------------------------------------------------

DANGEROUS_URI_SCHEMES = {"file", "gopher", "dict", "ftp", "tftp", "ldap", "ldaps", "jar", "netdoc"}

CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",  # Alibaba Cloud IMDS
    "192.0.0.192",      # Oracle Cloud IMDS
}

LOOPBACK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

URL_IN_TEXT_RE = re.compile(
    r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s\"'<>`]+)"
)
DNS_CMD_HOST_RE = re.compile(
    r"(?i)\b(?:nslookup|dig|host|ping|curl|wget|nc|ncat|netcat)\s+(?:-[a-zA-Z0-9]+\s+)*([a-z0-9_.\-]+\.[a-z]{2,63})\b"
)
HEX_EXFIL_LABEL_RE = re.compile(r"^[0-9a-fA-F]{24,}$")
BASE64_EXFIL_LABEL_RE = re.compile(r"^[A-Za-z0-9_\-]{28,}$")


def shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (in bits per character) for DNS exfiltration detection."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_high_entropy_exfil_subdomain(hostname: str) -> tuple[bool, str]:
    """
    Detects high-entropy or hex/base64-encoded DNS exfiltration subdomains
    (e.g., `4f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c.attacker.com` or high-entropy base64 labels).
    """
    clean_host = hostname.strip(".").lower()
    labels = [lbl for lbl in clean_host.split(".") if lbl]
    if len(labels) < 3:
        return False, "OK"

    # Inspect subdomain labels (excluding the registrable domain + TLD `example.com`)
    subdomain_labels = labels[:-2]
    raw_labels = hostname.strip(".").split(".")[:-2]

    for sub_low, sub_raw in zip(subdomain_labels, raw_labels):
        if HEX_EXFIL_LABEL_RE.match(sub_low):
            return (
                True,
                f"Hex-encoded DNS exfiltration subdomain blocked: label '{sub_raw}' ({len(sub_raw)} hex chars) in '{hostname}'.",
            )
        ent = shannon_entropy(sub_raw)
        if len(sub_raw) > 28 and ent > 3.9:
            return (
                True,
                f"High-entropy DNS exfiltration subdomain blocked: label '{sub_raw}' (len={len(sub_raw)}, entropy={ent:.2f} bits/char > 3.9) in '{hostname}'.",
            )
        has_digit = any(c.isdigit() for c in sub_raw)
        has_alpha = any(c.isalpha() for c in sub_raw)
        if len(sub_raw) >= 30 and has_digit and has_alpha and BASE64_EXFIL_LABEL_RE.match(sub_raw) and ent > 3.7:
            return (
                True,
                f"Encoded secret DNS exfiltration subdomain blocked: label '{sub_raw}' (len={len(sub_raw)}, entropy={ent:.2f}) in '{hostname}'.",
            )
    return False, "OK"


def _validate_single_host_or_ip(
    raw_host: str, *, allow_private_hosts: set[str] | None = None
) -> tuple[bool, str]:
    host = raw_host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return True, "OK"
    allowed = {h.strip().strip("[]").rstrip(".").lower() for h in (allow_private_hosts or set())}
    if host in allowed:
        return True, "OK"

    if host in CLOUD_METADATA_HOSTS or host.endswith(".metadata.google.internal"):
        return False, f"SSRF to cloud metadata endpoint blocked (A4.4): '{raw_host}'."

    if host in LOOPBACK_HOSTNAMES or host.endswith(".localhost") or host.endswith((".nip.io", ".sslip.io", ".localtest.me")):
        return False, f"SSRF to loopback/rebinding hostname blocked (A4.4): '{raw_host}'."

    if host.isdigit() or re.match(r"^(?:0x[0-9a-f]+|0[0-7]+)(?:\.[0-9a-fx]+)*$", host):
        return False, f"SSRF via integer/octal/hex IP literal blocked (A4.4): '{raw_host}'."

    # Check IP address (including IPv4, IPv6, IPv6-mapped IPv4, link-local, loopback, RFC1918)
    try:
        ip_obj = ipaddress.ip_address(host)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        if str(ip_obj) in CLOUD_METADATA_HOSTS or ip_obj.is_link_local:
            return False, f"SSRF to cloud metadata / link-local IP blocked (A4.4): '{raw_host}' ({ip_obj})."
        if ip_obj.is_loopback or ip_obj.is_unspecified:
            return False, f"SSRF to loopback/unspecified IP blocked (A4.4): '{raw_host}' ({ip_obj})."
        if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_multicast:
            return False, f"SSRF to RFC1918 private/internal IP blocked (A4.4): '{raw_host}' ({ip_obj})."
        return True, "OK"
    except ValueError:
        pass

    # Check DNS exfiltration entropy on hostname labels
    is_exfil, reason = _is_high_entropy_exfil_subdomain(raw_host)
    if is_exfil:
        return False, reason

    return True, "OK"


def validate_outbound_network_target(
    text_or_url: str, *, allow_private_hosts: set[str] | None = None
) -> tuple[bool, str]:
    """
    Primitive A: Validates any URL or command string against:
    1. Cloud metadata & link-local endpoints (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`,
       `metadata.google.internal`, `100.100.100.200`).
    2. Loopback & RFC 1918 private IP ranges (`127.0.0.0/8`, `localhost`, `0.0.0.0`, `[::1]`,
       `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) unless explicitly allowlisted.
    3. Dangerous non-HTTP schemes (`file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`).
    4. High-entropy DNS exfiltration subdomains (label > 28 chars with Shannon entropy > 3.9 or hex/base64 exfil).
    """
    raw = text_or_url.strip()
    if not raw:
        return True, "OK"

    # Extract all URI candidates in the string
    uri_candidates = URL_IN_TEXT_RE.findall(raw)
    if not uri_candidates and "://" in raw:
        uri_candidates = [raw]

    for candidate in uri_candidates:
        try:
            parsed = urllib.parse.urlsplit(candidate)
        except Exception:
            return False, f"Malformed outbound URL blocked: '{candidate}'."

        scheme = (parsed.scheme or "").lower()
        if scheme in DANGEROUS_URI_SCHEMES:
            return (
                False,
                f"Dangerous non-HTTP URI scheme '{scheme}://' blocked (A4.4): '{candidate}'.",
            )
        if scheme in {"http", "https", "ws", "wss"}:
            hostname = parsed.hostname or ""
            # Preserve original case for entropy calculation by extracting host from netloc
            netloc_host = parsed.netloc.split("@")[-1]
            if netloc_host.startswith("["):
                netloc_host = netloc_host.split("]")[0] + "]"
            else:
                netloc_host = netloc_host.split(":")[0]
            ok, reason = _validate_single_host_or_ip(
                netloc_host or hostname, allow_private_hosts=allow_private_hosts
            )
            if not ok:
                return False, reason

    # Also inspect raw command strings for DNS/network utilities (`nslookup <hex>.attacker.com`, `dig`, `ping`, `curl`)
    for match in DNS_CMD_HOST_RE.finditer(raw):
        host_token = match.group(1)
        ok, reason = _validate_single_host_or_ip(host_token, allow_private_hosts=allow_private_hosts)
        if not ok:
            return False, reason

    # If the string itself looks like a bare hostname with 3+ labels, check DNS exfiltration
    if " " not in raw and "://" not in raw and "/" not in raw and raw.count(".") >= 2:
        ok, reason = _validate_single_host_or_ip(raw, allow_private_hosts=allow_private_hosts)
        if not ok:
            return False, reason

    return True, "OK"


def make_ssrf_and_dns_guard(
    allow_private_hosts: set[str] | None = None,
) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
    """Returns an `arg_guard` callable that checks all string parameters for SSRF & DNS exfiltration."""

    def _scan_value(val: Any) -> tuple[bool, str]:
        if isinstance(val, str):
            return validate_outbound_network_target(val, allow_private_hosts=allow_private_hosts)
        if isinstance(val, Mapping):
            for v in val.values():
                ok, reason = _scan_value(v)
                if not ok:
                    return False, reason
        elif isinstance(val, (list, tuple)):
            for item in val:
                ok, reason = _scan_value(item)
                if not ok:
                    return False, reason
        return True, "OK"

    def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
        return _scan_value(args)

    return _guard


class WirePayloadSanitizer:
    """
    Sanitizes untrusted wire text against:
    - A1.4: Invisible Unicode Tag characters (U+E0000..U+E007F), zero-width joiners, and RTL overrides (U+202A..U+202E).
    - A2.7: Terminal ANSI CSI escape codes (`\\x1b[...`) and OSC 52 clipboard injection sequences (`\\x1b]...`).
    """

    UNICODE_SMUGGLING_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\U000e0000-\U000e007f]+")
    ANSI_ESCAPE_RE = re.compile(
        r"(?:\x1b|\\u001b)(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b\\]*(?:\x07|\\u0007|\x1b\\|\\u001b\\\\))"
    )
    SPOOFED_BOUNDARY_RE = re.compile(r"<<<\s*/?\s*UNTRUSTED_DATA_BOUNDARY[^>]*>>>")

    @classmethod
    def sanitize_text(cls, text: str) -> tuple[str, list[str]]:
        alerts: list[str] = []
        cleaned = text
        if cls.UNICODE_SMUGGLING_RE.search(cleaned):
            alerts.append("Stripped invisible Unicode Tag / bidirectional smuggling characters (A1.4).")
            cleaned = cls.UNICODE_SMUGGLING_RE.sub("", cleaned)
        if cls.ANSI_ESCAPE_RE.search(cleaned):
            alerts.append("Stripped terminal ANSI / OSC clipboard escape sequences (A2.7).")
            cleaned = cls.ANSI_ESCAPE_RE.sub("", cleaned)
        return cleaned, alerts

    @classmethod
    def spotlight_untrusted_text(cls, text: str) -> str:
        """
        Wraps untrusted tool output in a randomized Microsoft Spotlighting boundary
        (`<<<UNTRUSTED_DATA_BOUNDARY id=...>>>`) after neutralizing any spoofed boundary markers.
        """
        cleaned, _ = cls.sanitize_text(text)
        de_spoofed = cls.SPOOFED_BOUNDARY_RE.sub("[SPOOFED_BOUNDARY_STRIPPED]", cleaned)
        boundary_id = uuid.uuid4().hex[:8]
        return (
            f"<<<UNTRUSTED_DATA_BOUNDARY id={boundary_id}>>>\n"
            f"{de_spoofed}\n"
            f"<<<END_UNTRUSTED_DATA_BOUNDARY id={boundary_id}>>>"
        )


class StandardArgGuards:
    """
    Built-in deterministic parameter guards (`arg_guard`) for Planes 3, 4, and 8 and v0.3.0 empirical guards:
    - A3.3 / A3.4: Blocks writes to `.git/hooks/`, `.vscode/settings.json` (Copilot YOLO mode), `.cursor/mcp.json` (CurXecute).
    - A4.1 & CWE-78: Blocks shell metacharacters (`;`, `|`, `&&`, `$()`, backticks) and embedded POSIX command substitution in paths.
    - A4.2: Resolves symlinks (`Path.resolve()`) and blocks path traversal outside `workspace_root`.
    - A4.3 / A8.1: Multi-statement & clause-level SQL AST guard (`where_clause`, `order_by`, `filter`, comment stripping).
    - A4.4: Blocks SSRF requests to cloud metadata (`169.254.169.254`), localhost (`127.0.0.1`), RFC1918 IPs,
      dangerous URI schemes (`file://`, `gopher://`), and high-entropy DNS exfiltration subdomains.
    - GHSA-rvjm-7hvp-f868: Runtime endpoint & session re-pointing guard (`endpoint_repoint_guard`).
    - CWE-22 REST URL path-segment traversal guard (`url_path_segment_guard`).
    - CWE-88 CLI positional-argument flag injection guard (`cli_flag_injection_guard`).
    - A8.2: Enforces financial transaction / refund dollar caps.
    """

    SHELL_METACHAR_RE = re.compile(r"[;|&`$><]|\$\(")
    DESTRUCTIVE_SQL_RE = re.compile(
        r"(?i)\b(DROP|DELETE|TRUNCATE|ALTER|GRANT|REVOKE|COPY|INSERT|UPDATE|MERGE|CREATE|REPLACE\s+INTO|ATTACH\s+DATABASE|DETACH\s+DATABASE|PRAGMA|VACUUM|REINDEX|EXECUTE\s+IMMEDIATE|CALL|INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE|LOAD\s+DATA|pg_read_file|pg_ls_dir|pg_stat_file|lo_import|lo_export|dblink|xp_cmdshell)\b"
    )
    SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
    SQL_COMMENT_RE = re.compile(r"--[^\n]*|/\*[\s\S]*?\*/")
    SQL_SINGLE_QUOTED_RE = re.compile(r"'(?:[^'\\]|\\.|'')*'")
    SQL_CLAUSE_INJECTION_RE = re.compile(
        r"(?i)\b(UNION\s+(?:ALL\s+)?SELECT|SLEEP|BENCHMARK|LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b|\bOR\s+(?:1\s*=\s*1|TRUE|'[^']*'\s*=\s*'[^']*')\b"
    )
    SQL_VALUE_INJECTION_RE = re.compile(
        r"(?i)(?:;\s*(?:SELECT|DROP|DELETE|INSERT|UPDATE|COPY|ATTACH|CREATE|ALTER)\b|"
        r"'(?:\s*(?:OR|AND)\s+(?:\d+\s*=\s*\d+|TRUE|'[^']*'\s*=\s*'[^']*')|\s+UNION\b|\s*;|\s*--|\s*/\*)|"
        r"\bUNION\s+(?:ALL\s+)?SELECT\b|\bread_(?:text|csv|csv_auto|parquet|json|blob)\s*\()"
    )
    URL_PATH_TRAVERSAL_RE = re.compile(r"(?i)(?:\.\.|[/\\?#]|%2e|%2f|%5c|%3f|%23)")
    URL_PATH_STATIC_KEYS = frozenset(
        {
            "id",
            "resourcetype",
            "resource_type",
            "scriptname",
            "script_name",
            "job_id",
            "session_id",
            "rag_id",
            "account_id",
            "deviceid",
            "commandid",
            "gateway_id",
            "log_id",
            "bucket",
            "repo",
            "owner",
            "org",
            "organization",
            "organizations",
            "account_name",
            "zone",
            "worker",
            "namespace",
            "cluster",
            "instance",
            "domain",
            "service",
            "username",
            "ip_or_domain",
            "tracking_number",
            "new_tracking_number",
            "test_type",
            "ip",
            "symbol",
            "product_code",
            "productcode",
        }
    )
    SENSITIVE_QUERY_FILTER_FIELDS = frozenset(
        {
            "api_key",
            "api_secret",
            "password",
            "ldap_password",
            "access_token",
            "refresh_token",
            "client_secret",
            "secret_access_key",
            "reset_password_key",
            "iban",
            "bank_account_no",
            "auth_token",
            "private_key",
            "session_token",
            "indexing_refresh_token",
            "indexing_access_token",
        }
    )
    PICKLE_PARAM_KEYS = frozenset({"pmol", "p_mol", "p_query", "pickled_mol", "pickle_data"})
    PICKLE_ASCII_RE = re.compile(rb"(?:^|[\n(])(?:c(?:posix|nt|os|builtins|subprocess|importlib|sys|operator)\n|\(S['\"])")
    ALLOWED_BINARY_MOL_MAGIC = b"\xef\xbe\xad\xde"
    PACKAGE_INSTALL_KEYS = frozenset(
        {"libraries_used", "libraries", "packages", "pip_packages", "dependencies", "extra_packages"}
    )
    SAFE_PEP508_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*(?:\[[A-Za-z0-9,._\-]+\])?(?:(?:==|>=|<=|~=|!=|>|<)[A-Za-z0-9.*+_!\-]+)?$")
    CODE_EXEC_KEYS = frozenset({"code", "python_code", "script"})
    SANDBOX_ESCAPE_RE = re.compile(
        r"(?i)(?:__subclasses__|__bases__|__base__|__mro__|__globals__|__builtins__|__import__|__getattribute__|__self__|__class__|__code__|__closure__|__reduce__|__reduce_ex__|BuiltinImporter|ctypes\.(?:WinDLL|CDLL|windll|cdll)|pty\.spawn|asyncio\.(?:create_subprocess_(?:exec|shell)|subprocess)|[A-Z0-9_]+_(?:API_KEY|SECRET_KEY|ACCESS_TOKEN)\b)"
    )
    KUBECTL_DRY_RUN_BYPASS_RE = re.compile(
        r"(?i)(?:^|\s)kubectl(?:\.exe|\.[0-9.]+)?\b[^\n]*(?:--dry-run=(?:none|false)\b|--dry-run\s+(?:none|false)\b)"
    )
    REST_RELATIVE_PATH_TOOL_RE = re.compile(
        r"(?i)(?:^|[._])(restful|[a-z0-9_]+_execute|send_management_api_request)(?:$|[._])"
    )
    REST_RELATIVE_PATH_UNSAFE_RE = re.compile(
        r"(?i)(?:^|[\\/])\.\.(?:$|[\\/])|://|^//|[\r\n\x00\\@]|%2e%2e|%5c"
    )
    CLI_FLAG_STATIC_KEYS = frozenset(
        {
            "node",
            "pod",
            "namespace",
            "deployment",
            "container",
            "cluster",
            "context",
            "resource",
            "kind",
            "service",
            "project",
            "region",
            "zone",
            "location",
            "destination",
            "dest",
            "download_directory",
            "folderpath",
            "folder_path",
            "source_dir",
            "app_dir",
            "working_directory",
            "directory",
            "dir",
            "path",
            "file_path",
            "filepath",
            "target",
            "target_file",
            "repo",
            "repo_url",
            "remote",
            "branch",
            "ref",
            "tag",
            "commit",
            "chart",
            "release",
            "name",
            "bucket",
            "object",
            "url",
            "uri",
            "source",
            "scriptname",
            "script_name",
            "argv",
            "binary",
            "username",
            "email",
            "phone",
        }
    )
    INLINE_CMD_SUBST_RE = re.compile(r"\$\([^)\n]*\)")
    CLI_EMBEDDED_FLAG_RE = re.compile(r"\s--[a-zA-Z0-9][a-zA-Z0-9_-]*")
    ENDPOINT_REPOINT_TOOL_RE = re.compile(
        r"(?i)(?:^|[._])(connect_to_[a-z0-9_]+|switch_server|set_endpoint|configure_connection|set_connection|set_server_url|update_endpoint|change_endpoint|bind_endpoint|reconnect(?:_[a-z0-9_]+)?)(?:$|[._])"
    )
    ENDPOINT_URL_KEYS = frozenset(
        {
            "url",
            "endpoint",
            "endpoint_url",
            "server_url",
            "base_url",
            "runtime_url",
            "document_url",
            "jupyter_url",
            "connection_url",
            "target_url",
            "remote_url",
            "api_url",
            "host",
            "provider",
        }
    )
    ENDPOINT_TOKEN_KEYS = frozenset(
        {
            "token",
            "api_key",
            "auth_token",
            "bearer_token",
            "access_token",
            "jupyter_token",
            "runtime_token",
            "document_token",
            "authorization",
            "auth_header",
            "secret",
            "password",
        }
    )
    RAW_BEARER_RE = re.compile(r"(?i)^\s*bearer\s+\S+")
    PATH_KEY_SET = frozenset(k.lower() for k in WORKSPACE_PATH_KEYS) | {"paths", "files", "folders", "directories"}

    @classmethod
    def _iter_kv_pairs(cls, obj: Any) -> list[tuple[str, Any]]:
        pairs: list[tuple[str, Any]] = []
        if isinstance(obj, Mapping):
            for k, v in obj.items():
                key_str = str(k)
                pairs.append((key_str, v))
                if isinstance(v, (Mapping, list, tuple)):
                    pairs.extend(cls._iter_kv_pairs(v))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                if isinstance(item, (Mapping, list, tuple)):
                    pairs.extend(cls._iter_kv_pairs(item))
        return pairs

    @classmethod
    def _is_resource_id_key(cls, key: str) -> bool:
        low = key.lower()
        return (
            key.endswith(("_id", "_ids", "Id", "Ids", "_name", "Name", "_key", "Key"))
            or low in cls.URL_PATH_STATIC_KEYS
        )

    @classmethod
    def _is_cli_positional_key(cls, key: str) -> bool:
        low = key.lower()
        return (
            low in cls.CLI_FLAG_STATIC_KEYS
            or key.endswith(("_name", "Name", "_dir", "Dir", "_path", "Path", "_url", "Url", "_target", "_id", "Id"))
        )

    @classmethod
    def _is_path_key(cls, key: str) -> bool:
        low = key.lower()
        return (
            low in cls.PATH_KEY_SET
            or key.endswith(("_path", "Path", "_dir", "Dir", "_folder", "Folder", "_directory", "Directory"))
        )

    @classmethod
    def _is_endpoint_url_key(cls, key: str) -> bool:
        low = key.lower()
        return low in cls.ENDPOINT_URL_KEYS or low.endswith("_url") or key.endswith("Url")

    @classmethod
    def _is_endpoint_token_key(cls, key: str) -> bool:
        low = key.lower()
        return low in cls.ENDPOINT_TOKEN_KEYS or low.endswith("_token") or key.endswith("Token") or low.endswith("_key") or key.endswith("Key")

    @classmethod
    def make_workspace_file_guard(
        cls, workspace_root: Path, *, is_write: bool
    ) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
        return make_workspace_path_guard(workspace_root, is_write=is_write)

    @classmethod
    def path_command_substitution_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks embedded POSIX command substitution (`$(...)`, backticks, `${...}`) in path/command args and `$(...)` in any tool arg."""
        for k, v in cls._iter_kv_pairs(args):
            is_path_or_cmd = cls._is_path_key(k) or k.lower() in {"argv", "binary", "cmd", "command", "executable"}
            values = v if isinstance(v, (list, tuple)) else [v]
            for item in values:
                if not isinstance(item, str):
                    continue
                if is_path_or_cmd and POSIX_CMD_SUBST_RE.search(item):
                    return (
                        False,
                        f"Embedded POSIX command substitution / shell expansion blocked in parameter '{k}' (CWE-78): '{item}'.",
                    )
                if "$(" in item and cls.INLINE_CMD_SUBST_RE.search(item):
                    return (
                        False,
                        f"Embedded POSIX command substitution `$(...)` blocked in parameter '{k}' (CWE-78): '{item}'.",
                    )
        return True, "OK"

    @classmethod
    def shell_metachar_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        def _scan(val: Any, key_path: str) -> tuple[bool, str]:
            if isinstance(val, str):
                if cls.SHELL_METACHAR_RE.search(val) or '"' in val:
                    return False, f"Shell metacharacter injection blocked in parameter '{key_path}' (A4.1)."
                return True, "OK"
            if isinstance(val, Mapping):
                for k, v in val.items():
                    ok, reason = _scan(v, f"{key_path}.{k}" if key_path else str(k))
                    if not ok:
                        return False, reason
            elif isinstance(val, (list, tuple)):
                for idx, item in enumerate(val):
                    ok, reason = _scan(item, f"{key_path}[{idx}]")
                    if not ok:
                        return False, reason
            return True, "OK"

        return _scan(args, "")

    @classmethod
    def sql_safety_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """
        Multi-statement & clause-level SQL AST guard (A4.3 / A8.1).
        Strips `--` and `/* ... */` comments (both space-joined and compact) to defeat
        comment-splitting obfuscation, detects stacked `;` queries, and validates
        sub-clauses (`where_clause`, `order_by`, `filter`, `having`, `sort_by`, `group_by`).
        """
        kv_pairs = cls._iter_kv_pairs(args)

        for key, val in kv_pairs:
            if key.lower() not in {"statement", "sql", "sql_query", "query"}:
                continue
            if not isinstance(val, str) or not val.strip():
                continue
            sql = val
            sql_space = cls.SQL_COMMENT_RE.sub(" ", sql)
            sql_compact = cls.SQL_COMMENT_RE.sub("", sql)
            if "/*" in sql_space:
                return False, f"Unclosed SQL block comment blocked in '{key}' (A4.3)."
            for candidate in (sql, sql_space, sql_compact):
                match = cls.DESTRUCTIVE_SQL_RE.search(candidate)
                if match:
                    return False, f"Forbidden SQL keyword/function '{match.group(1)}' blocked (A4.3/A8.1)."
            no_literals = cls.SQL_SINGLE_QUOTED_RE.sub("''", sql_space)
            if ";" in no_literals.strip().rstrip(";"):
                return False, "Stacked multi-statement SQL query blocked (A4.3)."

        for key, clause_val in kv_pairs:
            if key.lower() not in {"where_clause", "order_by", "filter", "having", "sort_by", "group_by"}:
                continue
            if not isinstance(clause_val, str) or not clause_val.strip():
                continue
            if ";" in clause_val or cls.SQL_COMMENT_RE.search(clause_val) or "/*" in clause_val or "--" in clause_val:
                return False, f"SQL clause injection blocked in '{key}' (A4.3)."
            clause_space = cls.SQL_COMMENT_RE.sub(" ", clause_val)
            clause_compact = cls.SQL_COMMENT_RE.sub("", clause_val)
            for candidate in (clause_space, clause_compact):
                if cls.SQL_CLAUSE_INJECTION_RE.search(candidate):
                    return False, f"SQL clause injection blocked in '{key}' (A4.3)."
                match = cls.DESTRUCTIVE_SQL_RE.search(candidate)
                if match:
                    return False, f"Forbidden SQL keyword '{match.group(1)}' blocked in '{key}' (A4.3)."

        for key, val in kv_pairs:
            low_k = key.lower()
            if low_k in {"table_name", "schema_name", "time_column", "metric_column", "dimension_column"}:
                if isinstance(val, str) and val.strip() and not cls.SQL_IDENTIFIER_RE.match(val.strip()):
                    return False, f"Unsafe SQL identifier in '{key}' blocked (CWE-89): '{val[:80]}'."
                continue
            if low_k in {"statement", "sql", "sql_query", "query", "where_clause", "order_by", "filter", "having", "sort_by", "group_by"}:
                continue
            if not isinstance(val, str) or not val.strip():
                continue
            if cls.SQL_VALUE_INJECTION_RE.search(val):
                return False, f"SQL filter value injection blocked in '{key}' (A4.3/CWE-89): '{val[:80]}'."
        return True, "OK"

    @classmethod
    def url_path_segment_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks `..`, `%2e%2e`, `/`, `%2f`, `\\`, `?`, `@`, and `#` in REST resource identifier parameters (CWE-22)."""
        for container_key in ("path_params", "path"):
            path_params_val = args.get(container_key) if isinstance(args, Mapping) else None
            if isinstance(path_params_val, Mapping):
                for p_key, p_val in path_params_val.items():
                    if not isinstance(p_val, str) or not p_val:
                        continue
                    decoded_fixed = iterative_fixed_point_unquote(p_val, max_depth=5)
                    for candidate in (p_val, decoded_fixed):
                        if cls.URL_PATH_TRAVERSAL_RE.search(candidate) or "@" in candidate:
                            return (
                                False,
                                f"URL path/host-segment traversal or delimiter blocked in '{container_key}.{p_key}' (CWE-22/CWE-918): '{p_val}'.",
                            )

        for key, val in cls._iter_kv_pairs(args):
            low_key = key.lower()
            is_id = cls._is_resource_id_key(key)
            is_rel_repo_path = low_key in {"artifact_path", "file_path", "relative_path", "fullname", "target"}
            if not is_id and not is_rel_repo_path:
                continue
            values = val if isinstance(val, (list, tuple)) else [val]
            for item in values:
                if not isinstance(item, str) or not item:
                    continue
                if low_key == "target" and item.lower().startswith(("http://", "https://")):
                    continue
                decoded_fixed = iterative_fixed_point_unquote(item, max_depth=5)
                for candidate in (item, decoded_fixed):
                    if is_id and cls.URL_PATH_TRAVERSAL_RE.search(candidate):
                        return (
                            False,
                            f"URL path-segment traversal / delimiter blocked in '{key}' (CWE-22): '{item}'.",
                        )
                    if is_rel_repo_path and cls.REST_RELATIVE_PATH_UNSAFE_RE.search(candidate):
                        return (
                            False,
                            f"Relative path traversal / smuggling blocked in '{key}' (CWE-22): '{item}'.",
                        )
                    if low_key in {"artifact_path", "relative_path", "fullname"} and ("?" in candidate or "#" in candidate):
                        return (
                            False,
                            f"URL query/fragment delimiter blocked in '{key}' (CWE-22): '{item}'.",
                        )
        return True, "OK"

    @classmethod
    def pickle_deserialization_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks Python pickle payloads in serialized molecule/object parameters (CWE-502)."""
        for key, val in cls._iter_kv_pairs(args):
            if key.lower() not in cls.PICKLE_PARAM_KEYS:
                continue
            if not isinstance(val, str) or not val.strip():
                continue
            try:
                raw = base64.b64decode(val.strip(), validate=False)
            except Exception:
                continue
            if not raw:
                continue
            if raw.startswith(cls.ALLOWED_BINARY_MOL_MAGIC):
                continue
            if (len(raw) >= 2 and raw[0] == 0x80 and 2 <= raw[1] <= 5) or cls.PICKLE_ASCII_RE.search(raw):
                return (
                    False,
                    f"Unsafe Python pickle deserialization payload blocked in '{key}' (CWE-502).",
                )
        return True, "OK"

    @classmethod
    def package_install_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """
        Blocks command injection, pip CLI flag injection (`--index-url`, `--extra-index-url`, `-f`),
        and untrusted URL/path specs in dynamic library installation parameters.
        """
        for key, val in cls._iter_kv_pairs(args):
            if key.lower() not in cls.PACKAGE_INSTALL_KEYS:
                continue
            items: list[Any]
            if isinstance(val, str):
                items = [p.strip() for p in val.split(",") if p.strip()]
            elif isinstance(val, (list, tuple)):
                items = list(val)
            else:
                continue
            for item in items:
                if not isinstance(item, str):
                    continue
                pkg = item.strip()
                if not pkg or not cls.SAFE_PEP508_PKG_RE.match(pkg):
                    return (
                        False,
                        f"Unsafe package specification / pip command injection blocked in '{key}' (CWE-78/CWE-88): '{item}'.",
                    )
        return True, "OK"

    @classmethod
    def code_sandbox_escape_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """
        Blocks Python dunder sandbox-escape chains (`__subclasses__`, `__globals__`, `BuiltinImporter`,
        `ctypes.WinDLL`) and credential environment harvesting in agent code-interpreter tools.
        """
        for key, val in cls._iter_kv_pairs(args):
            if key.lower() == "command" and isinstance(val, str) and cls.KUBECTL_DRY_RUN_BYPASS_RE.search(val):
                return (
                    False,
                    "Disabling kubectl dry-run (`--dry-run=none` / `--dry-run=false`) in command blocked (CWE-863).",
                )
            if key.lower() not in cls.CODE_EXEC_KEYS:
                continue
            if not isinstance(val, str) or not val.strip():
                continue
            match = cls.SANDBOX_ESCAPE_RE.search(val)
            if match:
                return (
                    False,
                    f"Python sandbox-escape gadget / process-secret harvesting ('{match.group(0)}') blocked in '{key}' (CWE-94).",
                )
        return True, "OK"

    @classmethod
    def rest_relative_path_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks `..` dot-segments, schemes (`://`), `//`, `@`, and control chars in relative REST API paths."""
        for key in ("path", "action"):
            val = args.get(key)
            if not isinstance(val, str) or not val:
                continue
            decoded_fixed = iterative_fixed_point_unquote(val, max_depth=5)
            for candidate in (val, decoded_fixed):
                if cls.REST_RELATIVE_PATH_UNSAFE_RE.search(candidate):
                    return (
                        False,
                        f"Relative REST path traversal / scheme smuggling blocked in '{key}' (CWE-22): '{val}'.",
                    )
        return True, "OK"

    @classmethod
    def cli_flag_injection_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks leading `-` / `--` flags injected into positional resource/directory/target arguments (CWE-88)."""
        for key, val in cls._iter_kv_pairs(args):
            if not cls._is_cli_positional_key(key):
                continue
            values = val if isinstance(val, (list, tuple)) else [val]
            for item in values:
                if not isinstance(item, str):
                    continue
                stripped = item.strip()
                if stripped.startswith("-") or cls.CLI_EMBEDDED_FLAG_RE.search(stripped):
                    return (
                        False,
                        f"CLI argument/flag injection blocked in '{key}' (CWE-88): '{item}'.",
                    )
        return True, "OK"

    CYPHER_IDENTIFIER_KEYS = frozenset(
        {"node_identifier_property", "nodeidentifierproperty", "relationship_property", "relationshipproperty"}
    )
    CYPHER_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    XSS_INJECTION_RE = re.compile(r"(?i)(?:<\s*(?:script|img|svg|iframe|object|embed|body)\b|on(?:error|load|click|mouseover)\s*=|javascript:)")

    @classmethod
    def cypher_identifier_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks Cypher injection in unquoted node/relationship property identifier parameters (CWE-943)."""
        for key, val in cls._iter_kv_pairs(args):
            if key.lower() not in cls.CYPHER_IDENTIFIER_KEYS:
                continue
            if isinstance(val, str) and val and not cls.CYPHER_IDENTIFIER_RE.match(val):
                return (
                    False,
                    f"Cypher identifier injection blocked in '{key}' (CWE-943): '{val[:80]}'.",
                )
        return True, "OK"

    @classmethod
    def oauth_xss_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks reflected HTML/XSS payloads in OAuth error/callback parameters (CWE-79)."""
        for key, val in cls._iter_kv_pairs(args):
            if key.lower() not in {"error_description", "error_desc", "error"}:
                continue
            if isinstance(val, str) and val and cls.XSS_INJECTION_RE.search(val):
                return (
                    False,
                    f"Reflected HTML/XSS payload blocked in OAuth parameter '{key}' (CWE-79): '{val[:80]}'.",
                )
        return True, "OK"

    @classmethod
    def make_endpoint_repoint_guard(
        cls,
        *,
        tool_name: str = "",
        allow_repoint: bool = False,
        trusted_hosts: set[str] | list[str] | tuple[str, ...] | None = None,
    ) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
        """
        Runtime Endpoint & Session Re-pointing Guard (inspired by `GHSA-rvjm-7hvp-f868`).
        Blocks runtime connection-mutation tools (`connect_to_*`, `switch_server`, `set_endpoint`,
        `configure_connection`) unless explicitly opted in, and blocks mid-session `*_url` +
        `*_token`/`*_key` repointing to local/private/untrusted hosts or raw bearer token exposure.
        """
        is_repoint_tool = bool(tool_name and cls.ENDPOINT_REPOINT_TOOL_RE.search(tool_name))
        normalized_trusted = {h.strip().lower() for h in (trusted_hosts or ()) if h and h.strip()}

        def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
            if is_repoint_tool and not allow_repoint:
                return (
                    False,
                    f"Runtime endpoint/session re-pointing tool '{tool_name}' blocked (GHSA-rvjm-7hvp-f868): explicit capability opt-in required.",
                )

            pairs = cls._iter_kv_pairs(args)
            url_entries: list[tuple[str, str]] = []
            token_entries: list[tuple[str, str]] = []

            for k, v in pairs:
                if not isinstance(v, str) or not v.strip():
                    continue
                val_s = v.strip()
                if cls._is_endpoint_url_key(k):
                    url_entries.append((k, val_s))
                elif "://" in val_s and k.lower() not in {"content", "body", "text", "replacement", "diff", "markdown", "html"}:
                    ok_net, net_reason = validate_outbound_network_target(
                        val_s, allow_private_hosts=normalized_trusted or None
                    )
                    if not ok_net:
                        return False, f"Split-turn SSRF / dangerous URI blocked in '{k}' (CWE-918): {net_reason}"
                if cls._is_endpoint_token_key(k) or cls.RAW_BEARER_RE.search(val_s):
                    token_entries.append((k, val_s))

            # Raw bearer token or secret credential passed in connection-mutation context
            # or paired mid-session with an endpoint URL (`*_url` + `*_token`/`*_key`).
            has_raw_token = any(
                not t_val.startswith("<MCP_REDACTED_")
                for _, t_val in token_entries
            )
            if has_raw_token and (is_repoint_tool or url_entries):
                tok_keys = ", ".join(k for k, _ in token_entries)
                return (
                    False,
                    f"Raw bearer token / credential in LLM context blocked for runtime endpoint parameters ({tok_keys}) (GHSA-rvjm-7hvp-f868).",
                )

            # Validate any endpoint/provider URL target when repointing
            for u_key, u_val in url_entries:
                low_u = u_val.lower()
                if low_u in {"local", "localhost", "127.0.0.1", "::1", "0.0.0.0"}:
                    if low_u not in normalized_trusted:
                        return (
                            False,
                            f"Runtime endpoint re-pointing to '{u_val}' in '{u_key}' blocked (GHSA-rvjm-7hvp-f868).",
                        )
                    continue

                if "://" in u_val or u_key.lower() in {"host", "endpoint"}:
                    ok_net, net_reason = validate_outbound_network_target(
                        u_val, allow_private_hosts=normalized_trusted or None
                    )
                    if not ok_net:
                        return False, f"Runtime endpoint re-pointing blocked in '{u_key}' (GHSA-rvjm-7hvp-f868): {net_reason}"

                    if is_repoint_tool or token_entries or (u_key.lower() == "host" and not allow_repoint):
                        parsed = urllib.parse.urlsplit(u_val if "://" in u_val else f"https://{u_val}")
                        target_host = (parsed.hostname or "").lower()
                        if target_host and target_host not in normalized_trusted:
                            return (
                                False,
                                f"Untrusted runtime endpoint host '{target_host}' in '{u_key}' blocked (GHSA-rvjm-7hvp-f868).",
                            )

            return True, "OK"

        return _guard

    SENSITIVE_ATTACHMENT_RE = re.compile(
        r"(?i)(?:^|[\\/])(?:\.[a-z0-9_-]+-mcp|\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.env(?:\.[^\\/]*)?|id_rsa|id_ed25519|etc[\\/]shadow|etc[\\/]passwd)(?:$|[\\/]|$)"
    )

    @classmethod
    def make_attachment_path_guard(
        cls, workspace_root: Path | None = None
    ) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
        """Blocks sensitive host credentials/dotfiles and out-of-workspace escapes in email `attachments`."""

        def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
            att_val = args.get("attachments")
            if not isinstance(att_val, (list, tuple)) or not att_val:
                return True, "OK"
            for item in att_val:
                raw_path = None
                if isinstance(item, str):
                    raw_path = item
                elif isinstance(item, Mapping):
                    for k in ("path", "filePath", "file_path"):
                        if isinstance(item.get(k), str):
                            raw_path = item[k]
                            break
                if not raw_path or not raw_path.strip():
                    continue
                if "\x00" in raw_path or cls.SENSITIVE_ATTACHMENT_RE.search(raw_path):
                    return (
                        False,
                        f"Sensitive host credential/dotfile attachment blocked (CWE-22/CWE-200): '{raw_path}'.",
                    )
                if workspace_root is not None:
                    ok, reason = is_safe_workspace_path(raw_path, workspace_root, is_write=False)
                    if not ok:
                        return False, reason
            return True, "OK"

        return _guard

    @classmethod
    def endpoint_repoint_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Default fail-closed runtime endpoint & session re-pointing argument guard (GHSA-rvjm-7hvp-f868)."""
        return cls.make_endpoint_repoint_guard()(args)

    MQTT_ID_SEGMENT_KEYS = frozenset({"client_id", "clientid", "server_id", "serverid"})
    MQTT_SERVER_NAME_KEYS = frozenset({"server_name", "servername"})

    @classmethod
    def mqtt_topic_wildcard_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Blocks MQTT wildcard (`+`, `#`), topic separator (`/`), and control-char injection in MQTT MCP IDs (CWE-20)."""
        for key, val in cls._iter_kv_pairs(args):
            if not isinstance(val, str):
                continue
            low_key = key.lower()
            has_ctrl = any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in val)
            if low_key in cls.MQTT_ID_SEGMENT_KEYS:
                if not val or has_ctrl or any(ch in val for ch in ("+", "#", "/")):
                    return (
                        False,
                        f"MQTT wildcard/topic-separator injection blocked in '{key}' (CWE-20): '{val}'.",
                    )
            elif low_key in cls.MQTT_SERVER_NAME_KEYS:
                if (
                    not val
                    or has_ctrl
                    or "+" in val
                    or "#" in val
                    or val.startswith("/")
                    or val.endswith("/")
                    or "//" in val
                ):
                    return (
                        False,
                        f"MQTT wildcard/malformed topic path blocked in '{key}' (CWE-20): '{val}'.",
                    )
        return True, "OK"

    @classmethod
    def make_org_allowlist_guard(
        cls, allowed_orgs: set[str] | list[str] | tuple[str, ...]
    ) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
        normalized = {o.strip().lower() for o in allowed_orgs if o and o.strip()}

        def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
            if not normalized:
                return True, "OK"
            org = ""
            for k, v in args.items():
                k_low = str(k).lower()
                if k_low in {"org", "org_name", "organization", "tenant_id"} or k_low.endswith("_org_name"):
                    org = str(v or "").strip().lower()
                    if org:
                        break
            if not org:
                return (
                    False,
                    "Fail-closed tenant boundary policy: unscoped ID-only tool call missing organization parameter blocked (CWE-863).",
                )
            if org not in normalized:
                return (
                    False,
                    f"Organization '{org}' is not in mcp-cage tenant allowlist {sorted(normalized)} (CWE-863).",
                )
            return True, "OK"

        return _guard

    @classmethod
    def ssrf_url_guard(cls, args: Mapping[str, Any]) -> tuple[bool, str]:
        return make_ssrf_and_dns_guard()(args)

    @classmethod
    def make_financial_cap_guard(cls, max_amount_usd: float) -> Callable[[Mapping[str, Any]], tuple[bool, str]]:
        def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
            amt = float(args.get("amount", args.get("amount_usd", 0.0)))
            if amt > max_amount_usd:
                return (
                    False,
                    f"Autonomous financial transaction (${amt:.2f}) exceeds safety cap (${max_amount_usd:.2f}) (A8.2).",
                )
            return True, "OK"

        return _guard


def filesystem_read_taint_resolver(
    args: Mapping[str, Any], response_text: str, had_redacted_secrets: bool
) -> tuple[Integrity, Confidentiality]:
    """
    Distinguishes reading `README.md` (PUBLIC) vs `src/app.py` (INTERNAL) vs `.env` (SECRET).
    """
    path_str = str(args.get("path") or args.get("file_path") or "")
    if had_redacted_secrets or SENSITIVE_FILE_PATTERNS.search(path_str):
        return Integrity.TRUSTED, Confidentiality.SECRET
    if PUBLIC_DOC_PATTERNS.search(path_str):
        return Integrity.TRUSTED, Confidentiality.PUBLIC
    return Integrity.TRUSTED, Confidentiality.INTERNAL


def github_issue_taint_resolver(
    args: Mapping[str, Any], response_text: str, had_redacted_secrets: bool
) -> tuple[Integrity, Confidentiality]:
    """
    Distinguishes issues authored by trusted repo owners/members vs untrusted external internet users.
    """
    author_role = str(args.get("author_association", "NONE")).upper()
    conf = Confidentiality.SECRET if had_redacted_secrets else Confidentiality.PUBLIC
    if author_role in {"OWNER", "MEMBER", "COLLABORATOR"}:
        return Integrity.ENDORSED, conf
    return Integrity.UNTRUSTED, conf


# -----------------------------------------------------------------------------
# Primitive 1: Atomic, Cross-Process `SessionTaintStateMachine` with MELON & Leases
# -----------------------------------------------------------------------------

UNTRUSTED_ENTITY_URL_RE = re.compile(r"https?://[^\s\"'<>`)]+")
UNTRUSTED_ENTITY_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")


class SessionTaintStateMachine:
    """
    Cross-process, monotonic ambient context taint tracker backed by SQLite WAL.
    Features:
    - Uses `BEGIN IMMEDIATE` transactions + atomic SQL `MIN`/`MAX` to prevent parallel lost-update races.
    - Tracks untrusted URLs/domains/emails (MELON provenance attribution) to block target hijacking.
    - Automatically runs `make_ssrf_and_dns_guard()` on all `EXTERNAL_EGRESS_SINK` tool calls.
    - Supports dynamic argument/content taint resolvers, scoped 5-minute workspace leases,
      context endorsement (`endorse_session`), and turn integrity resets (`reset_turn_integrity`).
    """

    def __init__(
        self,
        db_path: Path,
        session_id: str,
        mode: EnforcementMode = EnforcementMode.ENFORCE,
        audit_log_path: Path | None = None,
    ) -> None:
        self.db_path = db_path
        self.session_id = session_id
        self.mode = mode
        self.audit_log_path = audit_log_path or (db_path.parent / "audit.jsonl")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=15000;")
        return conn

    def _init_db(self) -> None:
        for attempt in range(10):
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS session_taint (
                        session_id TEXT PRIMARY KEY,
                        integrity INTEGER NOT NULL,
                        confidentiality INTEGER NOT NULL,
                        provenance_json TEXT NOT NULL,
                        leases_json TEXT NOT NULL DEFAULT '{}',
                        untrusted_entities_json TEXT NOT NULL DEFAULT '[]',
                        updated_at REAL NOT NULL
                    )
                    """
                )
                # Ensure column exists if table was created by an older schema
                cols = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info(session_taint);").fetchall()
                }
                if "untrusted_entities_json" not in cols:
                    conn.execute(
                        "ALTER TABLE session_taint ADD COLUMN untrusted_entities_json TEXT NOT NULL DEFAULT '[]';"
                    )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO session_taint
                    (session_id, integrity, confidentiality, provenance_json, leases_json, untrusted_entities_json, updated_at)
                    VALUES (?, ?, ?, '[]', '{}', '[]', ?)
                    """,
                    (self.session_id, int(Integrity.TRUSTED), int(Confidentiality.PUBLIC), time.time()),
                )
                conn.execute("COMMIT;")
                return
            except sqlite3.OperationalError:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                if attempt == 9:
                    raise
                time.sleep(0.05 * (attempt + 1))
            finally:
                conn.close()

    def get_state(self) -> StateTuple:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT integrity, confidentiality, provenance_json, leases_json FROM session_taint WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            if not row:
                return StateTuple(Integrity.TRUSTED, Confidentiality.PUBLIC, [], {})
            return StateTuple(
                Integrity(row[0]),
                Confidentiality(row[1]),
                json.loads(row[2]),
                json.loads(row[3]),
            )
        finally:
            conn.close()

    def get_untrusted_entities(self) -> list[str]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT untrusted_entities_json FROM session_taint WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            return json.loads(row[0]) if row and row[0] else []
        finally:
            conn.close()

    @staticmethod
    def _extract_untrusted_entities(text: str) -> list[str]:
        entities: list[str] = []
        for url in UNTRUSTED_ENTITY_URL_RE.findall(text):
            cleaned_url = url.rstrip(".,;)")
            entities.append(cleaned_url)
            try:
                host = urllib.parse.urlsplit(cleaned_url).hostname
                if host:
                    entities.append(host.lower())
            except Exception:
                pass
        for email in UNTRUSTED_ENTITY_EMAIL_RE.findall(text):
            entities.append(email.lower())
        return entities

    def on_tool_response(
        self,
        profile: ToolSecurityProfile,
        arguments: Mapping[str, Any] | str | None = None,
        response_text: str = "",
        had_redacted_secrets: bool = False,
    ) -> tuple[Integrity, Confidentiality]:
        """
        Atomically updates session ambient integrity, confidentiality, and untrusted entity provenance
        inside a `BEGIN IMMEDIATE` transaction.
        """
        if isinstance(arguments, Mapping):
            arg_map: Mapping[str, Any] = arguments
            arg_summary = ", ".join(f"{k}={repr(v)[:30]}" for k, v in arg_map.items())
        elif isinstance(arguments, str):
            arg_map = {"raw": arguments}
            arg_summary = arguments[:60]
        else:
            arg_map = {}
            arg_summary = ""

        if profile.source_taint_resolver is not None:
            src_int, src_conf = profile.source_taint_resolver(arg_map, response_text, had_redacted_secrets)
        else:
            src_int = profile.source_integrity
            src_conf = (
                Confidentiality.SECRET
                if had_redacted_secrets
                else profile.source_confidentiality
            )

        extracted_entities = (
            self._extract_untrusted_entities(response_text)
            if (src_int == Integrity.UNTRUSTED or ToolRole.UNTRUSTED_SOURCE in profile.roles) and response_text
            else []
        )

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT integrity, confidentiality, provenance_json, untrusted_entities_json FROM session_taint WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            cur_int = Integrity(row[0]) if row else Integrity.TRUSTED
            cur_conf = Confidentiality(row[1]) if row else Confidentiality.PUBLIC
            prov: list[str] = json.loads(row[2]) if row else []
            untrusted_entities: list[str] = json.loads(row[3]) if row and row[3] else []

            new_int = Integrity(min(cur_int, src_int))
            new_conf = Confidentiality(max(cur_conf, src_conf))

            if new_int < cur_int or new_conf > cur_conf or src_int < Integrity.TRUSTED or src_conf > Confidentiality.PUBLIC:
                entry = (
                    f"{profile.fq_name}({arg_summary}) -> "
                    f"Int:{src_int.name}, Conf:{src_conf.name}"
                )
                prov.append(entry)

            for ent in extracted_entities:
                if ent not in untrusted_entities:
                    untrusted_entities.append(ent)

            conn.execute(
                """
                UPDATE session_taint
                SET integrity = MIN(integrity, ?),
                    confidentiality = MAX(confidentiality, ?),
                    provenance_json = ?,
                    untrusted_entities_json = ?,
                    updated_at = ?
                WHERE session_id = ?
                """,
                (
                    int(src_int),
                    int(src_conf),
                    json.dumps(prov[-50:]),
                    json.dumps(untrusted_entities[-100:]),
                    time.time(),
                    self.session_id,
                ),
            )
            conn.execute("COMMIT;")
            return new_int, new_conf
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def endorse_session(self, note: str = "") -> tuple[Integrity, Confidentiality]:
        """Upgrades session integrity from `UNTRUSTED` to `ENDORSED`."""
        self.apply_declassification(DeclassificationAction.ENDORSE_CONTEXT, note=note)
        cur_int, cur_conf, _, _ = self.get_state()
        return cur_int, cur_conf

    def reset_turn_integrity(self, note: str = "") -> tuple[Integrity, Confidentiality]:
        """
        Resets session integrity back to `Integrity.TRUSTED` at the start of a new authenticated
        user prompt turn while preserving `Confidentiality` (secrets read earlier in the session
        remain protected).
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT confidentiality, provenance_json FROM session_taint WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            cur_conf = Confidentiality(row[0]) if row else Confidentiality.PUBLIC
            prov: list[str] = json.loads(row[1]) if row else []
            prov.append(f"[TURN RESET] Restored Integrity:TRUSTED ({note or 'new user prompt'})")
            conn.execute(
                """
                UPDATE session_taint
                SET integrity = ?, provenance_json = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (int(Integrity.TRUSTED), json.dumps(prov[-50:]), time.time(), self.session_id),
            )
            conn.execute("COMMIT;")
            return Integrity.TRUSTED, cur_conf
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def apply_declassification(
        self,
        action: DeclassificationAction,
        target_key: str = "PRIVILEGED_MUTATOR",
        lease_seconds: float = 300.0,
        note: str = "",
    ) -> None:
        """
        Records a human step-up decision in SQLite:
        - `LEASE_MUTATOR_5M`: Grants a 5-minute lease for local workspace mutations without popups.
        - `ENDORSE_CONTEXT`: Elevates ambient integrity from UNTRUSTED -> ENDORSED (keeps SECRET confidentiality intact).
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT integrity, confidentiality, provenance_json, leases_json FROM session_taint WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            if not row:
                conn.execute("COMMIT;")
                return
            cur_int, cur_conf, prov_raw, leases_raw = row
            prov: list[str] = json.loads(prov_raw)
            leases: dict[str, float] = json.loads(leases_raw)

            if action == DeclassificationAction.LEASE_MUTATOR_5M:
                leases[target_key] = time.time() + lease_seconds
                prov.append(f"[HUMAN STEP-UP] Granted {int(lease_seconds)}s lease for `{target_key}`")
            elif action == DeclassificationAction.ENDORSE_CONTEXT:
                if cur_int == int(Integrity.UNTRUSTED):
                    cur_int = int(Integrity.ENDORSED)
                suffix = f" ({note})" if note else ""
                prov.append(f"[HUMAN STEP-UP] Endorsed current untrusted context -> Integrity:ENDORSED{suffix}")

            conn.execute(
                """
                UPDATE session_taint
                SET integrity = ?, provenance_json = ?, leases_json = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (cur_int, json.dumps(prov[-50:]), json.dumps(leases), time.time(), self.session_id),
            )
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def _get_state_and_entities(self) -> tuple[StateTuple, list[str]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT integrity, confidentiality, provenance_json, leases_json, untrusted_entities_json FROM session_taint WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            if not row:
                return StateTuple(Integrity.TRUSTED, Confidentiality.PUBLIC, [], {}), []
            return (
                StateTuple(
                    Integrity(row[0]),
                    Confidentiality(row[1]),
                    json.loads(row[2]),
                    json.loads(row[3]),
                ),
                json.loads(row[4]) if row[4] else [],
            )
        finally:
            conn.close()

    def on_tool_call(
        self,
        profile: ToolSecurityProfile,
        arguments: Mapping[str, Any],
    ) -> GateEvaluation:
        (ambient_int, ambient_conf, prov, leases), untrusted_entities = self._get_state_and_entities()
        now = time.time()

        # 1. Deterministic Argument Guard (Hard DENY — never bypassed by leases)
        if profile.arg_guard is not None:
            ok, reason = profile.arg_guard(arguments)
            if not ok:
                human_msg = (
                    f"Blocked `{profile.fq_name}` because its arguments violated a deterministic safety rule: {reason}"
                )
                return self._finalize(
                    GateEvaluation(
                        decision=GateDecisionType.DENY,
                        effective_decision=GateDecisionType.ALLOW if self.mode == EnforcementMode.SHADOW else GateDecisionType.DENY,
                        mode=self.mode,
                        reason=f"Argument policy violation on {profile.fq_name}: {reason}",
                        human_summary=human_msg,
                        ambient_integrity=ambient_int,
                        ambient_confidentiality=ambient_conf,
                        provenance_log=prov,
                    ),
                    profile,
                    arguments,
                )

        # 1B. Automatic Outbound SSRF, Cloud Metadata (`169.254.169.254`) & High-Entropy DNS Exfil Guard (Primitive A)
        if ToolRole.EXTERNAL_EGRESS_SINK in profile.roles:
            ssrf_ok, ssrf_reason = make_ssrf_and_dns_guard()(arguments)
            if not ssrf_ok:
                human_msg = (
                    f"Blocked `{profile.fq_name}` due to outbound network / SSRF / DNS exfiltration violation: {ssrf_reason}"
                )
                return self._finalize(
                    GateEvaluation(
                        decision=GateDecisionType.DENY,
                        effective_decision=GateDecisionType.ALLOW if self.mode == EnforcementMode.SHADOW else GateDecisionType.DENY,
                        mode=self.mode,
                        reason=f"[SSRF / DNS EXFILTRATION BLOCKED] {ssrf_reason}",
                        human_summary=human_msg,
                        ambient_integrity=ambient_int,
                        ambient_confidentiality=ambient_conf,
                        provenance_log=prov,
                    ),
                    profile,
                    arguments,
                )

        # 1C. MELON Provenance Attribution Check: Block sink/mutator arguments containing untrusted entities
        is_sink_or_mutator = bool(
            profile.roles & {ToolRole.PRIVILEGED_MUTATOR, ToolRole.EXTERNAL_EGRESS_SINK, ToolRole.WORKSPACE_MUTATOR}
        )
        if is_sink_or_mutator and untrusted_entities:
            serialized_args = json.dumps(arguments, ensure_ascii=False).lower()
            for ent in untrusted_entities:
                if ent.lower() in serialized_args:
                    reason = (
                        f"[PROVENANCE HIJACK BLOCKED] Target argument originated inside untrusted external data: '{ent}'"
                    )
                    return self._finalize(
                        GateEvaluation(
                            decision=GateDecisionType.DENY,
                            effective_decision=GateDecisionType.ALLOW if self.mode == EnforcementMode.SHADOW else GateDecisionType.DENY,
                            mode=self.mode,
                            reason=reason,
                            human_summary=f"Blocked `{profile.fq_name}` because parameter matched untrusted external entity `{ent}`.",
                            ambient_integrity=ambient_int,
                            ambient_confidentiality=ambient_conf,
                            provenance_log=prov,
                        ),
                        profile,
                        arguments,
                    )

        # 2. Check Scoped Lease for Non-Egress Workspace Mutators
        is_mutator_only = (
            bool(profile.roles & {ToolRole.PRIVILEGED_MUTATOR, ToolRole.WORKSPACE_MUTATOR})
            and ToolRole.EXTERNAL_EGRESS_SINK not in profile.roles
        )
        active_lease = None
        if is_mutator_only:
            for key in (profile.fq_name, "PRIVILEGED_MUTATOR"):
                if leases.get(key, 0.0) > now:
                    active_lease = key
                    break

        if active_lease is not None:
            return self._finalize(
                GateEvaluation(
                    decision=GateDecisionType.ALLOW,
                    effective_decision=GateDecisionType.ALLOW,
                    mode=self.mode,
                    reason=f"Permitted under active human step-up lease '{active_lease}'.",
                    human_summary=f"Allowed `{profile.fq_name}` under your active 5-minute workspace edit lease.",
                    lease_applied=active_lease,
                    ambient_integrity=ambient_int,
                    ambient_confidentiality=ambient_conf,
                    provenance_log=prov,
                ),
                profile,
                arguments,
            )

        # 3. Evaluate Ambient Taint & Lethal Trifecta
        reasons: list[str] = []
        causal_parts: list[str] = []

        if is_sink_or_mutator and ambient_int < profile.min_required_integrity:
            reasons.append(
                f"Session integrity is {ambient_int.name} (requires >= {profile.min_required_integrity.name})."
            )
            causal_parts.append("ingested untrusted external content")

        if ToolRole.EXTERNAL_EGRESS_SINK in profile.roles and ambient_conf > profile.max_allowed_confidentiality:
            reasons.append(
                f"Session holds {ambient_conf.name} data (sink egress ceiling: {profile.max_allowed_confidentiality.name})."
            )
            causal_parts.append(f"read {ambient_conf.name.lower()} private data")

        trifecta = (
            ambient_int == Integrity.UNTRUSTED
            and ambient_conf >= Confidentiality.CONFIDENTIAL
            and is_sink_or_mutator
        )

        if reasons:
            prefix = "[LETHAL TRIFECTA CIRCUIT BREAKER] " if trifecta else "[TAINT POLICY TRIGGER] "
            action_desc = (
                f"send data outside your machine via `{profile.fq_name}`"
                if ToolRole.EXTERNAL_EGRESS_SINK in profile.roles
                else f"modify system state via `{profile.fq_name}`"
            )
            human_msg = (
                f"Paused `{profile.fq_name}`: This session {' AND '.join(causal_parts)}, "
                f"and the agent is now attempting to {action_desc}."
            )
            return self._finalize(
                GateEvaluation(
                    decision=GateDecisionType.STEP_UP,
                    effective_decision=GateDecisionType.ALLOW if self.mode == EnforcementMode.SHADOW else GateDecisionType.STEP_UP,
                    mode=self.mode,
                    reason=prefix + " | ".join(reasons),
                    human_summary=human_msg,
                    trifecta_triggered=trifecta,
                    ambient_integrity=ambient_int,
                    ambient_confidentiality=ambient_conf,
                    provenance_log=prov,
                ),
                profile,
                arguments,
            )

        return self._finalize(
            GateEvaluation(
                decision=GateDecisionType.ALLOW,
                effective_decision=GateDecisionType.ALLOW,
                mode=self.mode,
                reason="Permitted within current session taint bounds.",
                human_summary=f"Allowed `{profile.fq_name}` (Session taint within safe bounds).",
                ambient_integrity=ambient_int,
                ambient_confidentiality=ambient_conf,
                provenance_log=prov,
            ),
            profile,
            arguments,
        )

    def _finalize(
        self,
        evaluation: GateEvaluation,
        profile: ToolSecurityProfile,
        arguments: Mapping[str, Any],
    ) -> GateEvaluation:
        """Appends tamper-evident structured record to `audit.jsonl`."""
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": self.session_id,
            "mode": evaluation.mode.value,
            "tool": profile.fq_name,
            "policy_decision": evaluation.decision.name,
            "wire_decision": evaluation.effective_decision.name,
            "trifecta": evaluation.trifecta_triggered,
            "ambient_integrity": evaluation.ambient_integrity.name,
            "ambient_confidentiality": evaluation.ambient_confidentiality.name,
            "human_summary": evaluation.human_summary,
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return evaluation


# -----------------------------------------------------------------------------
# Primitive 2: Cross-Process SQLite-Backed `BidirectionalSecretScrubber`
# -----------------------------------------------------------------------------

class BidirectionalSecretScrubber:
    """
    Cross-process SQLite-backed secret scrubber.
    When Process 1 (`filesystem`) mints `<MCP_REDACTED_OPENAI_KEY_1>`, the token-to-secret
    mapping is persisted in SQLite WAL so Process 2 (`slack`) immediately recognizes and
    blocks exfiltration of that token, while authorized tools (matched by exact placeholder
    OR secret `kind`) can rehydrate it on the wire.
    """

    SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("PRIVATE_KEY_PEM", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
        ("OPENAI_KEY", re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}")),
        ("STRIPE_KEY", re.compile(r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}")),
        ("GITHUB_PAT", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}")),
        ("AWS_ACCESS_KEY", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
        ("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
        ("JWT_TOKEN", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
        ("DB_CONN_URI", re.compile(r"(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis)://[^:\s]+:([^@\s]+)@[^\s\"']+")),
        ("JSON_YAML_SECRET", re.compile(r"(?i)([\"']?(?:client_secret|api_key|access_token|db_password|secret_key)[\"']?\s*:\s*[\"'])([^\"'\s]{8,})([\"'])")),
        ("ENV_ASSIGNMENT", re.compile(r"(?m)^([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY)[A-Z0-9_]*\s*=\s*)(['\"]?[^\s'\"#]+['\"]?)")),
    ]

    TOKEN_SCAN_REGEX = re.compile(r"<MCP_REDACTED_([A-Z0-9_]+)_(\d+)>")

    def __init__(
        self,
        db_path: Path | None = None,
        allowed_rehydration_tools: dict[str, set[str]] | None = None,
    ) -> None:
        self.db_path = db_path
        self._mem_vault: dict[str, tuple[str, str]] = {}
        self.allowed_rehydration_tools = allowed_rehydration_tools or {}
        if self.db_path is not None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _connect(self) -> sqlite3.Connection:
        assert self.db_path is not None
        conn = sqlite3.connect(str(self.db_path), timeout=15.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=15000;")
        return conn

    def _init_db(self) -> None:
        for attempt in range(10):
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS secret_vault (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind TEXT NOT NULL,
                        raw_secret TEXT NOT NULL UNIQUE,
                        placeholder TEXT
                    )
                    """
                )
                conn.execute("COMMIT;")
                return
            except sqlite3.OperationalError:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                if attempt == 9:
                    raise
                time.sleep(0.05 * (attempt + 1))
            finally:
                conn.close()

    def _mint_placeholder(self, kind: str, raw_secret: str) -> str:
        if self.db_path is None:
            for tok, (k, sec) in self._mem_vault.items():
                if sec == raw_secret:
                    return tok
            seq_id = len(self._mem_vault) + 1
            placeholder = f"<MCP_REDACTED_{kind}_{seq_id}>"
            self._mem_vault[placeholder] = (kind, raw_secret)
            return placeholder

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT placeholder FROM secret_vault WHERE raw_secret = ?",
                (raw_secret,),
            ).fetchone()
            if row and row[0]:
                conn.execute("COMMIT;")
                return str(row[0])

            cursor = conn.execute(
                "INSERT INTO secret_vault (kind, raw_secret) VALUES (?, ?)",
                (kind, raw_secret),
            )
            seq_id = cursor.lastrowid
            placeholder = f"<MCP_REDACTED_{kind}_{seq_id}>"
            conn.execute(
                "UPDATE secret_vault SET placeholder = ? WHERE id = ?",
                (placeholder, seq_id),
            )
            conn.execute("COMMIT;")
            return placeholder
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def lookup_placeholder(self, placeholder: str) -> str | None:
        if self.db_path is None:
            entry = self._mem_vault.get(placeholder)
            return entry[1] if entry else None

        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT raw_secret FROM secret_vault WHERE placeholder = ?",
                (placeholder,),
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            conn.close()

    def scrub_text(self, text: str) -> tuple[str, list[str]]:
        minted: list[str] = []
        scrubbed = text
        for kind, pattern in self.SECRET_PATTERNS:
            if kind == "ENV_ASSIGNMENT":
                def _env_repl(match: re.Match[str]) -> str:
                    prefix, secret_val = match.group(1), match.group(2)
                    if "<MCP_REDACTED_" in secret_val:
                        return match.group(0)
                    tok = self._mint_placeholder("ENV_SECRET", secret_val)
                    minted.append(tok)
                    return f"{prefix}{tok}"
                scrubbed = pattern.sub(_env_repl, scrubbed)
            elif kind == "JSON_YAML_SECRET":
                def _json_repl(match: re.Match[str]) -> str:
                    prefix, secret_val, suffix = match.group(1), match.group(2), match.group(3)
                    if "<MCP_REDACTED_" in secret_val:
                        return match.group(0)
                    tok = self._mint_placeholder("CONFIG_SECRET", secret_val)
                    minted.append(tok)
                    return f"{prefix}{tok}{suffix}"
                scrubbed = pattern.sub(_json_repl, scrubbed)
            elif kind == "DB_CONN_URI":
                def _uri_repl(match: re.Match[str]) -> str:
                    full_uri = match.group(0)
                    password = match.group(1)
                    if "<MCP_REDACTED_" in password:
                        return full_uri
                    tok = self._mint_placeholder("DB_PASSWORD", password)
                    minted.append(tok)
                    return full_uri.replace(f":{password}@", f":{tok}@", 1)
                scrubbed = pattern.sub(_uri_repl, scrubbed)
            else:
                def _std_repl(match: re.Match[str], k: str = kind) -> str:
                    tok = self._mint_placeholder(k, match.group(0))
                    minted.append(tok)
                    return tok
                scrubbed = pattern.sub(_std_repl, scrubbed)
        return scrubbed, minted

    def inspect_and_rehydrate_args(self, fq_tool_name: str, obj: Any) -> Any:
        """
        Scans incoming tool arguments across ANY process using the shared SQLite vault.
        Supports authorization lookup by either exact token (`<MCP_REDACTED_OPENAI_KEY_1>`)
        or secret kind (`OPENAI_KEY`).
        """
        if isinstance(obj, str):
            result = obj
            for match_obj in self.TOKEN_SCAN_REGEX.finditer(result):
                full_token = match_obj.group(0)
                kind = match_obj.group(1)
                raw_secret = self.lookup_placeholder(full_token)
                allowed = (
                    self.allowed_rehydration_tools.get(full_token, set())
                    | self.allowed_rehydration_tools.get(kind, set())
                )
                if fq_tool_name not in allowed:
                    raise PermissionError(
                        f"[SECRET EXFILTRATION BLOCKED] LLM attempted to pass redacted secret {full_token} "
                        f"to unauthorized sink '{fq_tool_name}'."
                    )
                if raw_secret is not None:
                    result = result.replace(full_token, raw_secret)
            return result
        if isinstance(obj, list):
            return [self.inspect_and_rehydrate_args(fq_tool_name, x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.inspect_and_rehydrate_args(fq_tool_name, v) for k, v in obj.items()}
        return obj


# -----------------------------------------------------------------------------
# Primitive 3: Structural `SchemaLockVerifier` & `ToxicFlowGraphAnalyzer`
# -----------------------------------------------------------------------------

class SchemaLockVerifier:
    """
    Pins sanitized MCP tool definitions in `mcp-lock.json`, strips structural prompt-injection
    patterns (`<IMPORTANT>`, HTML comments, hidden file-inclusion directives), and detects
    cross-server tool shadowing (`MCPTox` / Invariant Labs attack).
    """

    INJECTION_MARKERS = re.compile(
        r"(?i)(<\s*(?:important|system|instruction)[^>]*>[\s\S]*?<\s*/\s*(?:important|system|instruction)\s*>|"
        r"<!--[\s\S]*?-->|"
        r"ignore\s+(?:all\s+)?previous\s+instructions|"
        r"system\s*prompt\s*:|"
        r"do\s+not\s+(?:mention|tell|inform)\s+[^.\n]+|"
        r"(?:before|prior\s+to|whenever)\s+(?:calling|running|invoking|returning)[^.\n]*(?:read|fetch|send|include)\s+[^.\n]+\.?)"
    )

    SHADOWING_VERBS_RE = re.compile(
        r"(?i)\b(?:whenever|before|after|when)\s+(?:calling|invoking|using|running)\s+([a-z0-9_.\-]+)"
    )

    def __init__(self, lockfile_path: Path, known_servers: set[str] | None = None) -> None:
        self.lockfile_path = lockfile_path
        self.known_servers = {s.lower() for s in (known_servers or set())}
        self.locks: dict[str, str] = {}
        if self.lockfile_path.exists():
            self.locks = json.loads(self.lockfile_path.read_text())

    @staticmethod
    def compute_tool_hash(server: str, tool_def: dict[str, Any]) -> str:
        canonical = json.dumps(
            {
                "server": server,
                "name": tool_def.get("name"),
                "description": tool_def.get("description"),
                "inputSchema": tool_def.get("inputSchema"),
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_and_sanitize_tools_list(
        self, server: str, tools: list[dict[str, Any]], *, auto_pin_new: bool = False
    ) -> tuple[list[dict[str, Any]], list[str]]:
        sanitized: list[dict[str, Any]] = []
        alerts: list[str] = []
        updated = False

        for tool in tools:
            fq_name = f"{server}.{tool.get('name')}"
            clean_tool = dict(tool)
            desc = clean_tool.get("description") or ""

            # 1. Detect cross-server shadowing references before stripping
            other_servers = self.known_servers - {server.lower()}
            if any(re.search(rf"(?i)\b{re.escape(other)}\b", desc) for other in other_servers) or self.SHADOWING_VERBS_RE.search(desc):
                alerts.append(
                    f"[CROSS-SERVER SHADOWING] Tool `{fq_name}` attempted to hook or shadow another server/tool."
                )

            # 2. Strip structural prompt-injection markers & score Day-0 authority/provider misbinding
            schema_props = list(((clean_tool.get("inputSchema") or {}).get("properties") or {}).keys())
            p_score, p_flagged = WireDIFCCanonicalizer.score_tool_poisoning(desc, schema_props)
            if self.INJECTION_MARKERS.search(desc):
                alerts.append(f"Stripped tool-poisoning injection from `{fq_name}` description.")
            elif p_flagged:
                alerts.append(
                    f"[PROVIDER MISBINDING / AUTHORITY INFLATION] Tool `{fq_name}` scored S_poison={p_score:.2f} >= 0.45."
                )
            clean_tool["description"] = self.INJECTION_MARKERS.sub("[STRIPPED_BY_MCP_CAGE]", desc).strip()

            # 3. Compute SHA-256 over the sanitized tool definition and verify/pin in `mcp-lock.json`
            digest = self.compute_tool_hash(server, clean_tool)
            if fq_name in self.locks:
                if self.locks[fq_name] != digest:
                    raise RuntimeError(
                        f"[MCP RUG-PULL DETECTED] Tool definition for '{fq_name}' mutated after pinning! "
                        f"Expected SHA-256 {self.locks[fq_name][:12]}..., got {digest[:12]}..."
                    )
            elif auto_pin_new:
                self.locks[fq_name] = digest
                updated = True
            else:
                raise RuntimeError(f"[UNPINNED MCP TOOL] '{fq_name}' is not in {self.lockfile_path}.")

            sanitized.append(clean_tool)

        if updated:
            self.lockfile_path.parent.mkdir(parents=True, exist_ok=True)
            self.lockfile_path.write_text(json.dumps(self.locks, indent=2, sort_keys=True))

        return sanitized, alerts


@dataclass(frozen=True)
class ToxicFlowFinding:
    severity: str
    pattern_type: str
    untrusted_source: str
    private_source: str | None
    sink: str
    exploit_narrative: str


class ToxicFlowGraphAnalyzer:
    """
    Static analyzer (`mcp-sploit`) that maps Lethal Trifecta paths across configured MCP servers.
    Uses word-boundary regex tokens + official MCP 2025 tool `annotations`
    (`readOnlyHint`, `destructiveHint`, `openWorldHint`) + dual-role classification for
    `fetch`/`web`/`browser`/`http`/`curl` (which act as both `UNTRUSTED_SOURCE` and `EXTERNAL_EGRESS_SINK`).
    """

    UNTRUSTED_REGEX = re.compile(
        r"(?i)(?:^|[._])(get_issue|list_issues|get_pr|pull_request|fetch_url|fetch_url_content|fetchurlcontent|fetch|fetch_html|fetch_txt|fetch_json|fetch_markdown|fetch_youtube_transcript|web_search|web|webfetch|web_fetch|web_fetch_and_analyze|get_page|visit_webpage|read_webpage|scrape_website|scrape_element_from_website|browse|browser|browser_[a-z0-9_]+|navigate|http|curl|get_request|post_request|patch_request|put_request|delete_request|read_email|read_channel|receive_message|scrape|kubectl_logs|get_metadata|[a-z0-9_]+_add_item|add_by_url|download_[a-z0-9_]+)(?:$|[._])"
    )
    PRIVATE_REGEX = re.compile(
        r"(?i)(?:^|[._])(read_file|read_text_file|read_multiple_files|file_read_tool|directory_read_tool|query|select_sql|get_secret|read_env|customer_db|get_file_contents|get_config|run_[a-z0-9_]+_query|query_semantic_view|container_file_read|[a-z0-9_]+_get_worker|get_crawl_result|fhir_read|fhir_search|search_health_records_[a-z0-9_]+|search_values_[a-z0-9_]+|get_application|get_app_project|get_pod_logs|get_application_logs|get_workload_logs|get_application_events|get_resource_events|get_resources|get_resource_actions|run_[a-z0-9]+_search|get_record|get_object_fields|list_[a-z0-9]*objects)(?:$|[._])"
    )
    MUTATOR_REGEX = re.compile(
        r"(?i)(?:^|[._])(bash|exec|py_eval|py_exec_file|execute_code|execute_[a-z0-9_]+_code|code_interpreter|python_interpreter|browser_exec|powershell|start_process|run_command|run_shell_command|write_file|file_writer_tool|edit_file|delete_file|execute_sql|drop_table|git_push|merge_pr|set_config_value|connect_to_jupyter|install_helm_chart|upgrade_helm_chart|kubectl|kubectl_generic|append_content|put_content|patch_content|save_as_pdf|deploy_local_folder|deploy_file_contents|deploy_container_image|cluster_toolkit_download|get_node_sos_report|delete_workspace_safely|force_unlock_workspace|delete_project|action_run|cancel_crawl|kill_browser_session|container_file_write|container_file_delete|container_exec|fhir_create|fhir_update|create_application|update_application|delete_application|sync_application|run_resource_action|create_record|update_record|delete_record|bulk_create_records|bulk_update_records|bulk_delete_records|[a-z0-9_]+_execute|restful|send_management_api_request|install_[a-z0-9_]+_instance)(?:$|[._])"
    )
    EGRESS_REGEX = re.compile(
        r"(?i)(?:^|[._])(send_email|[a-z0-9_]+_send_email|post_message|publish_message|create_issue_comment|create_pull_request|webhook|http_post|fetch_url|fetch_url_content|fetchurlcontent|fetch|fetch_html|fetch_txt|fetch_json|fetch_markdown|fetch_youtube_transcript|web|webfetch|web_fetch|web_fetch_and_analyze|visit_webpage|read_webpage|scrape_website|scrape_element_from_website|browser|browser_[a-z0-9_]+|navigate|http|curl|get_request|post_request|patch_request|put_request|delete_request|import_asset|import_generated_asset_[a-z0-9_]+|connect_to_jupyter|[a-z0-9_]+_add_item|add_by_url|download_[a-z0-9_]+|[a-z0-9_]+_test_connection|create[-_]contact[-_]import|install_[a-z0-9_]+_instance)(?:$|[._])"
    )

    SQL_TOOL_RE = re.compile(
        r"(?i)(?:^|[._]|_)(?:sql|mysql|postgres|postgresql|sqlite|snowflake|bigquery|[a-z0-9]*db|clickhouse|health_records_ch|by_type_ch|trend_data_ch|values_ch|semantic_view|run_query|run_[a-z0-9_]+_query|execute_query|execute_[a-z0-9_]+_query|db_query|db_query_explain|db_table_profile|db_table_stats|db_index_usage|ai_analytics_detect_anomalies|query_table|read_records|select_rows|execute_statement|run_statement|get_tables|get_table_schema)(?:$|[._])"
    )
    NON_SQL_SEARCH_RE = re.compile(r"(?i)(?:web_search|search_web|search_files|grep_search|code_search)")
    WORKSPACE_FILE_TOOL_RE = re.compile(
        r"(?i)(?:read_file|read_text_file|read_multiple_files|file_read_tool|directory_read_tool|write_file|file_writer_tool|edit_file|delete_file|append_file|move_file|copy_file|put_content|patch_content|append_content|deploy_local_folder|container_file_|sos_report|cluster_toolkit|local_folder)"
    )

    @classmethod
    def classify_tool(
        cls,
        server: str,
        tool_or_def: Mapping[str, Any] | str,
        description: str = "",
    ) -> set[ToolRole]:
        if isinstance(tool_or_def, Mapping):
            tool_name = str(tool_or_def.get("name", ""))
            annotations = tool_or_def.get("annotations") or {}
        else:
            tool_name = str(tool_or_def)
            annotations = {}

        fq = f"{server}.{tool_name}"
        roles: set[ToolRole] = set()

        # 1. Word-boundary tool identifier matching
        if cls.UNTRUSTED_REGEX.search(fq):
            roles.add(ToolRole.UNTRUSTED_SOURCE)
        if cls.PRIVATE_REGEX.search(fq):
            roles.add(ToolRole.PRIVATE_SOURCE)
        if cls.MUTATOR_REGEX.search(fq):
            roles.add(ToolRole.PRIVILEGED_MUTATOR)
        if cls.EGRESS_REGEX.search(fq):
            roles.add(ToolRole.EXTERNAL_EGRESS_SINK)
        if StandardArgGuards.ENDPOINT_REPOINT_TOOL_RE.search(fq):
            roles.add(ToolRole.PRIVILEGED_MUTATOR)
            roles.add(ToolRole.EXTERNAL_EGRESS_SINK)

        # 2. Official MCP 2025 Tool Annotations support
        if annotations.get("destructiveHint") is True:
            roles.add(ToolRole.PRIVILEGED_MUTATOR)
        if annotations.get("openWorldHint") is True and annotations.get("readOnlyHint") is True:
            roles.add(ToolRole.UNTRUSTED_SOURCE)
        elif annotations.get("openWorldHint") is True and annotations.get("readOnlyHint") is False:
            roles.add(ToolRole.EXTERNAL_EGRESS_SINK)

        return roles or {ToolRole.NEUTRAL}

    @classmethod
    def build_default_profile(
        cls,
        server: str,
        tool_name: str,
        description: str = "",
        workspace_root: Path | None = None,
        allowed_orgs: set[str] | list[str] | tuple[str, ...] | None = None,
        allow_endpoint_repoint: bool = False,
        trusted_endpoints: set[str] | list[str] | tuple[str, ...] | None = None,
    ) -> ToolSecurityProfile:
        roles = frozenset(cls.classify_tool(server, tool_name, description))
        is_egress = ToolRole.EXTERNAL_EGRESS_SINK in roles
        is_mutator = ToolRole.PRIVILEGED_MUTATOR in roles
        low_tool = tool_name.lower()

        # Universal zero-config v0.3.0 wire-level parameter guards
        guards: list[Callable[[Mapping[str, Any]], tuple[bool, str]]] = [
            StandardArgGuards.make_endpoint_repoint_guard(
                tool_name=tool_name,
                allow_repoint=allow_endpoint_repoint,
                trusted_hosts=trusted_endpoints,
            ),
            StandardArgGuards.path_command_substitution_guard,
            StandardArgGuards.cli_flag_injection_guard,
            StandardArgGuards.url_path_segment_guard,
            StandardArgGuards.pickle_deserialization_guard,
            StandardArgGuards.package_install_guard,
            StandardArgGuards.code_sandbox_escape_guard,
            StandardArgGuards.make_attachment_path_guard(workspace_root),
            StandardArgGuards.mqtt_topic_wildcard_guard,
            StandardArgGuards.cypher_identifier_guard,
            StandardArgGuards.oauth_xss_guard,
        ]
        if StandardArgGuards.REST_RELATIVE_PATH_TOOL_RE.search(low_tool):
            guards.append(StandardArgGuards.rest_relative_path_guard)
        if low_tool in {"get_node", "get_node_config", "set_node_config", "get_item", "get_item_config"}:
            def _named_resource_segment_guard(args: Mapping[str, Any]) -> tuple[bool, str]:
                raw_name = args.get("name")
                if isinstance(raw_name, str) and raw_name:
                    d1 = urllib.parse.unquote(raw_name)
                    d2 = urllib.parse.unquote(d1)
                    for candidate in (raw_name, d1, d2):
                        if StandardArgGuards.URL_PATH_TRAVERSAL_RE.search(candidate):
                            return (
                                False,
                                f"URL path-segment traversal / delimiter blocked in 'name' (CWE-22): '{raw_name}'.",
                            )
                return True, "OK"

            guards.append(_named_resource_segment_guard)
        if low_tool in {"search_documents", "list_documents", "search_link"} or low_tool.startswith("search_doc"):
            def _sensitive_filter_oracle_guard(args: Mapping[str, Any]) -> tuple[bool, str]:
                raw_filters = args.get("filters")
                if raw_filters is None:
                    return True, "OK"

                def _iter_filter_fields(obj: Any) -> list[str]:
                    found: list[str] = []
                    if isinstance(obj, Mapping):
                        for k, v in obj.items():
                            found.append(str(k))
                            if isinstance(v, (Mapping, list, tuple)):
                                found.extend(_iter_filter_fields(v))
                    elif isinstance(obj, (list, tuple)):
                        if obj and isinstance(obj[0], str) and obj[0].lower() not in {"and", "or"}:
                            found.append(obj[1] if len(obj) >= 4 and isinstance(obj[1], str) else obj[0])
                        else:
                            for item in obj:
                                if isinstance(item, (Mapping, list, tuple)):
                                    found.extend(_iter_filter_fields(item))
                    return found

                for field_ref in _iter_filter_fields(raw_filters):
                    norm = field_ref.replace("`", "").strip().lower().split(".")[-1]
                    if norm in StandardArgGuards.SENSITIVE_QUERY_FILTER_FIELDS:
                        return (
                            False,
                            f"Blind filter oracle on restricted sensitive field '{field_ref}' blocked (CWE-639/CWE-200).",
                        )
                return True, "OK"

            guards.append(_sensitive_filter_oracle_guard)
        if is_egress:
            guards.append(make_ssrf_and_dns_guard(allow_private_hosts=set(trusted_endpoints) if trusted_endpoints else None))

        if cls.SQL_TOOL_RE.search(low_tool) and not cls.NON_SQL_SEARCH_RE.search(low_tool):
            guards.append(StandardArgGuards.sql_safety_guard)
        else:
            def _sql_presence_guard(args: Mapping[str, Any]) -> tuple[bool, str]:
                keys_low = {k.lower() for k, _ in StandardArgGuards._iter_kv_pairs(args)}
                has_explicit_sql = bool(keys_low & {"statement", "sql", "sql_query", "where_clause", "order_by"})
                has_table_filter = bool(keys_low & {"filter", "having", "sort_by"}) and bool(
                    keys_low & {"table", "table_name", "schema", "database", "collection"}
                )
                if has_explicit_sql or has_table_filter:
                    return StandardArgGuards.sql_safety_guard(args)
                return True, "OK"

            guards.append(_sql_presence_guard)

        if any(tok in low_tool for tok in ("deploy_local_folder", "cluster_toolkit", "sos_report", "container_exec")):
            guards.append(StandardArgGuards.shell_metachar_guard)

        if allowed_orgs and any(
            tok in low_tool
            for tok in (
                "workspace",
                "project",
                "action_run",
                "plan_",
                "state_version",
                "run_details",
                "run_comments",
                "team",
            )
        ):
            guards.append(StandardArgGuards.make_org_allowlist_guard(allowed_orgs))

        if workspace_root is not None:
            is_write_tool = any(
                w in low_tool for w in ("write", "edit", "delete", "append", "patch", "put", "move", "copy", "sos_report", "toolkit", "deploy")
            )
            ws_guard = StandardArgGuards.make_workspace_file_guard(workspace_root, is_write=is_write_tool)
            if cls.WORKSPACE_FILE_TOOL_RE.search(low_tool) or ToolRole.WORKSPACE_MUTATOR in roles:
                guards.append(ws_guard)
            else:
                has_optional_local_file_tool = (
                    bool(re.search(r"(?:^|_)(?:[a-z0-9]+team|secops)_", low_tool))
                    or any(tok in low_tool for tok in ("read_web_log", "hash_file", "yara_rules", "document_convert", "pdf_extract"))
                )

                def _local_dir_presence_guard(args: Mapping[str, Any]) -> tuple[bool, str]:
                    keys_low = {k.lower() for k, _ in StandardArgGuards._iter_kv_pairs(args)}
                    trigger_keys = (
                        LOCAL_DIR_ONLY_KEYS | {"path", "file_path", "filepath", "paths"}
                        if has_optional_local_file_tool
                        else LOCAL_DIR_ONLY_KEYS
                    )
                    if keys_low & trigger_keys:
                        return ws_guard(args)
                    return True, "OK"

                guards.append(_local_dir_presence_guard)

        def _combined_guard(args: Mapping[str, Any]) -> tuple[bool, str]:
            for g in guards:
                ok, reason = g(args)
                if not ok:
                    return False, reason
            return True, "OK"

        return ToolSecurityProfile(
            server=server,
            tool_name=tool_name,
            roles=roles,
            source_integrity=(
                Integrity.UNTRUSTED if ToolRole.UNTRUSTED_SOURCE in roles else Integrity.TRUSTED
            ),
            source_confidentiality=(
                Confidentiality.CONFIDENTIAL if ToolRole.PRIVATE_SOURCE in roles else Confidentiality.PUBLIC
            ),
            min_required_integrity=(
                Integrity.TRUSTED if (is_egress or is_mutator) else Integrity.UNTRUSTED
            ),
            max_allowed_confidentiality=(
                Confidentiality.PUBLIC if is_egress else Confidentiality.SECRET
            ),
            arg_guard=_combined_guard if guards else None,
        )

    @classmethod
    def audit_mcp_tools(
        cls, server_tools: dict[str, list[dict[str, Any]]]
    ) -> tuple[dict[str, list[str]], list[ToxicFlowFinding]]:
        classified: dict[str, list[str]] = {
            "UNTRUSTED_SOURCES": [],
            "PRIVATE_SOURCES": [],
            "MUTATOR_SINKS": [],
            "EGRESS_SINKS": [],
        }

        for server, tools in server_tools.items():
            for t in tools:
                fq = f"{server}.{t['name']}"
                roles = cls.classify_tool(server, t)
                if ToolRole.UNTRUSTED_SOURCE in roles:
                    classified["UNTRUSTED_SOURCES"].append(fq)
                if ToolRole.PRIVATE_SOURCE in roles:
                    classified["PRIVATE_SOURCES"].append(fq)
                if ToolRole.PRIVILEGED_MUTATOR in roles:
                    classified["MUTATOR_SINKS"].append(fq)
                if ToolRole.EXTERNAL_EGRESS_SINK in roles:
                    classified["EGRESS_SINKS"].append(fq)

        findings: list[ToxicFlowFinding] = []
        for u in classified["UNTRUSTED_SOURCES"]:
            for p in classified["PRIVATE_SOURCES"]:
                for s in classified["EGRESS_SINKS"]:
                    if len({u, p, s}) >= 2:
                        findings.append(
                            ToxicFlowFinding(
                                severity="CRITICAL",
                                pattern_type="LETHAL_TRIFECTA_EXFIL",
                                untrusted_source=u,
                                private_source=p,
                                sink=s,
                                exploit_narrative=(
                                    f"[{p}] (Private) + [{u}] (Untrusted) ==> [{s}] (External Sink)"
                                ),
                            )
                        )

        for u in classified["UNTRUSTED_SOURCES"]:
            for m in classified["MUTATOR_SINKS"]:
                if u != m:
                    findings.append(
                        ToxicFlowFinding(
                            severity="HIGH",
                            pattern_type="INDIRECT_INJECTION_MUTATION",
                            untrusted_source=u,
                            private_source=None,
                            sink=m,
                            exploit_narrative=(
                                f"[{u}] (Untrusted) ==> [{m}] (Privileged State Mutation)"
                            ),
                        )
                    )

        return classified, findings


# -----------------------------------------------------------------------------
# Primitive B: `CurXecute` / `MCPoison` Workspace Config Auditor (`audit-config`)
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class ConfigAuditFinding:
    severity: str          # "CRITICAL", "HIGH", "MEDIUM"
    rule_id: str           # "CURXECUTE_RCE_COMMAND", "PLAINTEXT_ENV_SECRET", "UNWRAPPED_MCP_SERVER"
    server_name: str
    source_path: str
    message: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "rule_id": self.rule_id,
            "server_name": self.server_name,
            "source_path": self.source_path,
            "message": self.message,
            "remediation": self.remediation,
        }


class WorkspaceMCPConfigAuditor:
    """
    Primitive B: Audits `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and
    `claude_desktop_config.json` files for:
    1. `CRITICAL` (`CurXecute` / `MCPoison` RCE — CVE-2025-54135):
       - Relative or workspace/tmp binary paths (`./`, `../`, `/tmp/`, `/var/tmp/`)
       - Shell wrappers or inline eval (`sh -c`, `bash -c`, `cmd /c`, `powershell`, `eval`, `curl`, `wget`)
       - Command chaining / subshell injection (`;`, `&&`, `||`, `|`, backticks, `$()`)
    2. `HIGH` (Plaintext Credential Leak):
       - Hardcoded API keys/secrets inside `env` blocks or `args` matching `BidirectionalSecretScrubber.SECRET_PATTERNS`
         instead of `${ENV_VAR}` references.
    3. `MEDIUM` (Unwrapped MCP Server):
       - MCP servers not wrapped by `mcp-cage wrap`.
    """

    RELATIVE_OR_TMP_EXEC_RE = re.compile(
        r"(?i)(?:^|\s)(?:\./|\.\./|~\b|/tmp/|/var/tmp/|\.git/|\.cursor/|\.vscode/)"
    )
    SHELL_WRAPPER_RE = re.compile(
        r"(?i)(?:^|[/\\])(sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh|eval|curl|wget|nc|ncat|netcat)$"
    )
    INLINE_EXEC_FLAG_RE = re.compile(
        r"(?i)(?:\b(?:sh|bash|zsh)\s+-c\b|\bcmd(?:\.exe)?\s+/c\b|\b(?:powershell|pwsh)\b.*-(?:e|enc|encodedcommand|c|command)\b|\b(?:eval|curl|wget)\b|\bpython3?\s+-c\b|\bnode\s+-e\b)"
    )
    CHAINING_METACHAR_RE = re.compile(r"[;|&`>]|&&|\|\||\$\(")
    ENV_INTERPOLATION_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^%[^%]+%$")
    SENSITIVE_ENV_NAME_RE = re.compile(r"(?i)(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|AUTH|CREDENTIALS)")

    @classmethod
    def audit_config_dict(
        cls, config: Mapping[str, Any], source_path: str = "<config>"
    ) -> list[ConfigAuditFinding]:
        findings: list[ConfigAuditFinding] = []
        servers = config.get("mcpServers") or config.get("servers") or {}
        if not isinstance(servers, Mapping):
            return findings

        for srv_name, srv_cfg in servers.items():
            if not isinstance(srv_cfg, Mapping):
                continue
            command = str(srv_cfg.get("command") or "").strip()
            raw_args = srv_cfg.get("args") or []
            args = [str(a) for a in raw_args] if isinstance(raw_args, (list, tuple)) else [str(raw_args)]
            env_block = srv_cfg.get("env") or {}
            full_cmd_str = " ".join([command, *args]).strip()

            # 1. CRITICAL: CurXecute / MCPoison RCE checks
            rce_reasons: list[str] = []
            if cls.RELATIVE_OR_TMP_EXEC_RE.search(command) or any(
                cls.RELATIVE_OR_TMP_EXEC_RE.search(a) and idx == 0 for idx, a in enumerate(args)
            ):
                rce_reasons.append(
                    f"relative or temporary binary path in command `{full_cmd_str}`"
                )
            elif any(cls.RELATIVE_OR_TMP_EXEC_RE.search(a) and (a.endswith(".sh") or a.endswith(".py") or a.endswith(".js") or "/tmp/" in a) for a in args):
                rce_reasons.append(
                    f"workspace-relative or `/tmp/` script execution in `{full_cmd_str}`"
                )

            if cls.SHELL_WRAPPER_RE.search(command) or cls.INLINE_EXEC_FLAG_RE.search(full_cmd_str):
                rce_reasons.append(
                    f"dangerous shell/network wrapper execution (`{full_cmd_str}`)"
                )

            if cls.CHAINING_METACHAR_RE.search(full_cmd_str):
                rce_reasons.append(
                    f"shell command chaining or subshell injection metacharacters in `{full_cmd_str}`"
                )

            if rce_reasons:
                findings.append(
                    ConfigAuditFinding(
                        severity="CRITICAL",
                        rule_id="CURXECUTE_RCE_COMMAND",
                        server_name=str(srv_name),
                        source_path=source_path,
                        message=(
                            f"[CurXecute / MCPoison RCE Risk] Server '{srv_name}' uses "
                            + "; ".join(rce_reasons)
                            + "."
                        ),
                        remediation=(
                            "Replace shell wrappers and workspace-relative scripts with pinned package "
                            "entrypoints wrapped via `mcp-cage wrap --server <name> -- <cmd>`."
                        ),
                    )
                )

            # 2. HIGH: Plaintext Credential Leak inside `env` block or `args`
            if isinstance(env_block, Mapping):
                for env_k, env_v in env_block.items():
                    val_str = str(env_v).strip()
                    if not val_str or cls.ENV_INTERPOLATION_RE.match(val_str):
                        continue
                    matched_kind = None
                    for kind, pat in BidirectionalSecretScrubber.SECRET_PATTERNS:
                        if kind in ("ENV_ASSIGNMENT", "JSON_YAML_SECRET"):
                            continue
                        if pat.search(val_str):
                            matched_kind = kind
                            break
                    if matched_kind is None and cls.SENSITIVE_ENV_NAME_RE.search(str(env_k)) and len(val_str) >= 12:
                        matched_kind = "HARDCODED_SECRET_VALUE"

                    if matched_kind is not None:
                        findings.append(
                            ConfigAuditFinding(
                                severity="HIGH",
                                rule_id="PLAINTEXT_ENV_SECRET",
                                server_name=str(srv_name),
                                source_path=source_path,
                                message=(
                                    f"[Plaintext Secret in Config] Server '{srv_name}' hardcodes `{env_k}` "
                                    f"(matched `{matched_kind}`) in plaintext instead of an environment reference."
                                ),
                                remediation=f"Replace hardcoded secret in `{env_k}` with `${{{env_k}}}` and load from OS keychain.",
                            )
                        )

            # 3. MEDIUM: Unwrapped MCP Server
            is_wrapped = (
                "mcp-cage" in command
                or "mcp_cage" in command
                or any("mcp-cage" in a or "mcp_cage" in a for a in args)
            ) and "wrap" in args
            if not is_wrapped and command:
                findings.append(
                    ConfigAuditFinding(
                        severity="MEDIUM",
                        rule_id="UNWRAPPED_MCP_SERVER",
                        server_name=str(srv_name),
                        source_path=source_path,
                        message=(
                            f"[Unwrapped MCP Server] Server '{srv_name}' (`{command}`) runs without `mcp-cage wrap` wire protection."
                        ),
                        remediation=(
                            f"Wrap '{srv_name}' with: `mcp-cage wrap --server {srv_name} -- {full_cmd_str}`"
                        ),
                    )
                )

        return findings

    @classmethod
    def audit_config_file(cls, path: Path) -> list[ConfigAuditFinding]:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.audit_config_dict(data, source_path=str(path))

    @classmethod
    def discover_and_audit(cls, root: Path, explicit_paths: list[Path] | None = None) -> dict[str, Any]:
        candidate_paths: list[Path] = []
        if explicit_paths:
            candidate_paths.extend(explicit_paths)
        else:
            for rel in (
                ".mcp.json",
                ".cursor/mcp.json",
                ".vscode/mcp.json",
                "claude_desktop_config.json",
            ):
                p = root / rel
                if p.exists():
                    candidate_paths.append(p)

        all_findings: list[ConfigAuditFinding] = []
        audited_files: list[str] = []
        for p in candidate_paths:
            if p.exists() and p.is_file():
                audited_files.append(str(p))
                all_findings.extend(cls.audit_config_file(p))

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "audited_files": audited_files,
            "summary": counts,
            "findings": [f.to_dict() for f in all_findings],
        }


# -----------------------------------------------------------------------------
# Plane A: `MCPWireGateway` (Async & Sync JSON-RPC 2.0 Proxy with Spotlighting)
# -----------------------------------------------------------------------------

@dataclass
class InFlightRequest:
    req_id: int | str
    method: str
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)


class MCPWireGateway:
    """
    Plane A JSON-RPC 2.0 Wire Gateway (`MCPWireGateway`) supporting:
    - `in_flight_requests` correlation across `tools/list`, `tools/call`, and `resources/read`
    - Microsoft Spotlighting (`<<<UNTRUSTED_DATA_BOUNDARY id=...>>>`) on untrusted tool outputs
    - Secret scrubbing on `tools/call` results, `resources/read` contents, AND `error.message`
    - `sampling/createMessage` server-to-client hijack blocking when session is tainted
    - Async `run_stdio_proxy` for subprocess stdio pipelines
    """

    def __init__(
        self,
        server_name: str = "default",
        state_machine: SessionTaintStateMachine | None = None,
        scrubber: BidirectionalSecretScrubber | None = None,
        verifier: SchemaLockVerifier | None = None,
        workspace_root: Path | None = None,
        tool_profiles: dict[str, ToolSecurityProfile] | None = None,
        allowed_orgs: set[str] | list[str] | tuple[str, ...] | None = None,
        allow_endpoint_repoint: bool = False,
        trusted_endpoints: set[str] | list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self.server_name = server_name
        self.workspace_root = (workspace_root or Path.cwd()).resolve()
        default_state_dir = self.workspace_root / ".mcp-cage"
        legacy_db = default_state_dir / "taint_state.db"
        default_db = legacy_db if (legacy_db.exists() and not (default_state_dir / "taint.db").exists()) else (default_state_dir / "taint.db")
        if state_machine is None or scrubber is None or verifier is None:
            default_state_dir.mkdir(parents=True, exist_ok=True)
        self.state_machine = state_machine or SessionTaintStateMachine(
            db_path=default_db,
            audit_log_path=default_state_dir / "audit.jsonl",
        )
        self.scrubber = scrubber or BidirectionalSecretScrubber(db_path=default_db)
        self.verifier = verifier or SchemaLockVerifier(lockfile_path=default_state_dir / "mcp-lock.json")
        self.tool_profiles: dict[str, ToolSecurityProfile] = dict(tool_profiles or {})
        self.allowed_orgs = allowed_orgs
        self.allow_endpoint_repoint = allow_endpoint_repoint
        self.trusted_endpoints = trusted_endpoints
        self.in_flight_requests: dict[int | str, InFlightRequest] = {}
        self.auto_pin_new: bool = True
        self.progress_governor = CausalStateProgressGovernor()
        self.span_provenance = PersistentLineSpanProvenance(self.state_machine.db_path)

    def _get_or_build_profile(self, tool_name: str) -> ToolSecurityProfile:
        if tool_name in self.tool_profiles:
            return self.tool_profiles[tool_name]
        prof = ToxicFlowGraphAnalyzer.build_default_profile(
            self.server_name,
            tool_name,
            workspace_root=self.workspace_root,
            allowed_orgs=self.allowed_orgs,
            allow_endpoint_repoint=self.allow_endpoint_repoint,
            trusted_endpoints=self.trusted_endpoints,
        )
        self.tool_profiles[tool_name] = prof
        return prof

    def process_client_to_server(
        self, msg: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        method = str(msg.get("method") or "")
        req_id = msg.get("id")
        params = dict(msg.get("params") or {})

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            arguments = dict(params.get("arguments") or {})
            profile = self._get_or_build_profile(tool_name)

            try:
                rehydrated_args = self.scrubber.inspect_and_rehydrate_args(profile.fq_name, arguments)
            except PermissionError as exc:
                return None, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"isError": True, "content": [{"type": "text", "text": str(exc)}]},
                }

            eval_res = self.state_machine.on_tool_call(profile, arguments)
            if eval_res.effective_decision != GateDecisionType.ALLOW:
                return None, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": f"[MCP-CAGE {eval_res.decision.name}] {eval_res.reason}"}],
                    },
                }

            # v0.4.0 Wire-DIFC Active Guards:
            # (a) Causal State-Progress Entropy Governor (blocks OverServe cyclic polling loops under untrusted integrity)
            cur_int, cur_conf = eval_res.ambient_integrity, eval_res.ambient_confidentiality
            prog_ok, prog_reason = self.progress_governor.record_step_and_check(tool_name, arguments, cur_int.name)
            if not prog_ok:
                return None, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": f"[MCP-CAGE HARD_DENY] {prog_reason}"}],
                    },
                }

            # (b) Two-Axis Covert Hex DNS & Natural-Language EFF Diceware-in-Identifier Guard
            if cur_int < Integrity.TRUSTED and cur_conf >= Confidentiality.SECRET:
                for arg_k, arg_v in arguments.items():
                    if isinstance(arg_v, str):
                        cov_flagged, cov_reason = is_covert_exfil_identifier(str(arg_k), arg_v)
                        if cov_flagged:
                            return None, {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "isError": True,
                                    "content": [{"type": "text", "text": f"[MCP-CAGE HARD_DENY] {cov_reason}"}],
                                },
                            }

            # (c) Content-Addressed Line-Span Persistent Provenance Recording on Untrusted File Writes
            if cur_int < Integrity.TRUSTED and tool_name in {"write_file", "edit_file", "append_file"}:
                w_path = str(arguments.get("path") or arguments.get("file_path") or "")
                w_content = str(arguments.get("content") or arguments.get("replacement") or "")
                if w_path and w_content:
                    self.span_provenance.record_file_write_spans(w_path, w_content, cur_int.name)

            # Meta-tool inner dispatch guard: evaluate wrapped `tool_name`/`tool` + `arguments`/`args`
            inner_tool = arguments.get("tool_name") or arguments.get("tool")
            inner_args = arguments.get("arguments") if "arguments" in arguments else arguments.get("args")
            if tool_name in {"tool_execute", "call_tool"} and isinstance(inner_tool, str) and inner_tool.strip():
                inner_profile = self._get_or_build_profile(inner_tool.strip())
                inner_eval = self.state_machine.on_tool_call(
                    inner_profile,
                    inner_args if isinstance(inner_args, Mapping) else {},
                )
                if inner_eval.effective_decision != GateDecisionType.ALLOW:
                    return None, {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"[MCP-CAGE {inner_eval.decision.name}] Meta-dispatch blocked: {inner_eval.reason}"}],
                        },
                    }

            forwarded = dict(msg)
            forwarded["params"] = {**params, "arguments": rehydrated_args}
            if req_id is not None:
                self.in_flight_requests[req_id] = InFlightRequest(
                    req_id=req_id,
                    method=method,
                    tool_name=tool_name,
                    arguments=arguments,
                    params=params,
                )
            return forwarded, None

        if req_id is not None and method:
            self.in_flight_requests[req_id] = InFlightRequest(
                req_id=req_id,
                method=method,
                params=params,
            )
        return msg, None

    def process_server_to_client(
        self, msg: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """
        Processes a message from the upstream MCP server -> client.
        Returns `(message_to_client, error_response_to_server)`.
        """
        if "method" in msg:
            method = str(msg.get("method") or "")
            if method == "sampling/createMessage":
                cur_int, cur_conf, _, _ = self.state_machine.get_state()
                if cur_int < Integrity.TRUSTED or cur_conf >= Confidentiality.CONFIDENTIAL:
                    return None, {
                        "jsonrpc": "2.0",
                        "id": msg.get("id"),
                        "error": {
                            "code": -32001,
                            "message": (
                                f"[MCP SAMPLING FIREWALL] [MCP-CAGE BLOCKED SAMPLING HIJACK] "
                                f"Server '{self.server_name}' denied sampling while session is ({cur_int.name}, {cur_conf.name})."
                            ),
                        },
                    }
            elif method == "notifications/tools/list_changed":
                self.auto_pin_new = False
            return msg, None

        req_id = msg.get("id")
        in_flight = self.in_flight_requests.pop(req_id, None) if req_id is not None else None

        # Scrub any secrets leaked inside JSON-RPC `error` payloads
        if "error" in msg and isinstance(msg["error"], Mapping):
            err_copy = dict(msg["error"])
            if "message" in err_copy and isinstance(err_copy["message"], str):
                scrubbed_msg, _ = self.scrubber.scrub_text(err_copy["message"])
                err_copy["message"] = scrubbed_msg
            return {**msg, "error": err_copy}, None

        if in_flight is None or "result" not in msg:
            return msg, None

        result = dict(msg["result"])

        if in_flight.method == "tools/list":
            tools = result.get("tools") or []
            sanitized_tools, _ = self.verifier.verify_and_sanitize_tools_list(
                self.server_name, tools, auto_pin_new=self.auto_pin_new
            )
            self.auto_pin_new = False
            for t in sanitized_tools:
                t_name = str(t.get("name") or "")
                if t_name and t_name not in self.tool_profiles:
                    self.tool_profiles[t_name] = ToxicFlowGraphAnalyzer.build_default_profile(
                        self.server_name,
                        t_name,
                        str(t.get("description") or ""),
                        workspace_root=self.workspace_root,
                        allowed_orgs=self.allowed_orgs,
                        allow_endpoint_repoint=self.allow_endpoint_repoint,
                        trusted_endpoints=self.trusted_endpoints,
                    )
            return {**msg, "result": {**result, "tools": sanitized_tools}}, None

        if in_flight.method == "tools/call":
            profile = self._get_or_build_profile(in_flight.tool_name)
            raw_str = json.dumps(result, ensure_ascii=False)
            sanitized_str, _ = WirePayloadSanitizer.sanitize_text(raw_str)
            scrubbed_str, minted = self.scrubber.scrub_text(sanitized_str)
            scrubbed_result = json.loads(scrubbed_str)

            # Apply Spotlighting boundary to text content blocks from UNTRUSTED_SOURCE tools
            if ToolRole.UNTRUSTED_SOURCE in profile.roles and isinstance(scrubbed_result.get("content"), list):
                new_content = []
                for item in scrubbed_result["content"]:
                    if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                        item = {**item, "text": WirePayloadSanitizer.spotlight_untrusted_text(item["text"])}
                    new_content.append(item)
                scrubbed_result["content"] = new_content

            self.state_machine.on_tool_response(
                profile=profile,
                arguments=in_flight.arguments,
                response_text=sanitized_str,
                had_redacted_secrets=bool(minted),
            )
            # Enforce v0.4.0 Content-Addressed Line-Span Persistent Provenance on file reads
            r_path = str(in_flight.arguments.get("path") or in_flight.arguments.get("file_path") or "")
            if r_path:
                recovered_ents = self.span_provenance.check_file_read_spans(r_path, sanitized_str)
                if recovered_ents:
                    untrusted_span_profile = ToolSecurityProfile(
                        server=self.server_name,
                        tool_name=f"{in_flight.tool_name}:tainted_span",
                        roles=frozenset({ToolRole.UNTRUSTED_SOURCE}),
                        source_integrity=Integrity.UNTRUSTED,
                    )
                    self.state_machine.on_tool_response(
                        profile=untrusted_span_profile,
                        arguments={"path": r_path},
                        response_text=" ".join(f"https://{e}" for e in sorted(recovered_ents)),
                        had_redacted_secrets=False,
                    )
            return {**msg, "result": scrubbed_result}, None

        if in_flight.method == "resources/read":
            uri = str(in_flight.params.get("uri") or "")
            raw_str = json.dumps(result, ensure_ascii=False)
            sanitized_str, _ = WirePayloadSanitizer.sanitize_text(raw_str)
            scrubbed_str, minted = self.scrubber.scrub_text(sanitized_str)
            scrubbed_result = json.loads(scrubbed_str)

            res_profile = ToolSecurityProfile(
                server=self.server_name,
                tool_name="resources/read",
                roles=frozenset({ToolRole.PRIVATE_SOURCE}),
                source_taint_resolver=filesystem_read_taint_resolver,
            )
            self.state_machine.on_tool_response(
                profile=res_profile,
                arguments={"path": uri},
                response_text=sanitized_str,
                had_redacted_secrets=bool(minted),
            )
            return {**msg, "result": scrubbed_result}, None

        if in_flight.method == "prompts/get":
            raw_str = json.dumps(result, ensure_ascii=False)
            sanitized_str, _ = WirePayloadSanitizer.sanitize_text(raw_str)
            cleaned_str = SchemaLockVerifier.INJECTION_MARKERS.sub("[STRIPPED_BY_MCP_CAGE]", sanitized_str)
            return {**msg, "result": json.loads(cleaned_str)}, None

        return msg, None

    async def run_stdio_proxy(
        self,
        cmd: list[str],
        client_reader: asyncio.StreamReader,
        client_writer: Any,
    ) -> None:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdin is not None and proc.stdout is not None

        while True:
            line = await client_reader.readline()
            if not line:
                break
            req = json.loads(line.decode("utf-8"))
            fwd, imm = self.process_client_to_server(req)
            if imm is not None:
                client_writer.write((json.dumps(imm) + "\n").encode("utf-8"))
                continue
            if fwd is not None:
                proc.stdin.write((json.dumps(fwd) + "\n").encode("utf-8"))
                await proc.stdin.drain()
                srv_line = await proc.stdout.readline()
                if not srv_line:
                    break
                srv_msg = json.loads(srv_line.decode("utf-8"))
                out_client, err_srv = self.process_server_to_client(srv_msg)
                if err_srv is not None:
                    proc.stdin.write((json.dumps(err_srv) + "\n").encode("utf-8"))
                    await proc.stdin.drain()
                if out_client is not None:
                    client_writer.write((json.dumps(out_client) + "\n").encode("utf-8"))

        proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            proc.terminate()


# -----------------------------------------------------------------------------
# Plane B: Universal Native Lifecycle Hook Handler (`claude`, `cursor`, `gemini`, `agy`, `codex`)
# -----------------------------------------------------------------------------

def _build_native_hook_profile(
    tool_name: str, tool_input: Mapping[str, Any], workspace_root: Path
) -> ToolSecurityProfile:
    low = tool_name.lower()

    # 1. File Read tools
    if low in {"read", "read_file", "view_file", "beforereadfile"}:
        return ToolSecurityProfile(
            server="native",
            tool_name=tool_name,
            roles=frozenset({ToolRole.PRIVATE_SOURCE}),
            source_taint_resolver=filesystem_read_taint_resolver,
            arg_guard=make_workspace_path_guard(workspace_root, is_write=False),
        )

    # 2. File Write / Edit tools
    if low in {"write", "edit", "multi_edit", "write_file", "edit_file", "replace_file_content"}:
        return ToolSecurityProfile(
            server="native",
            tool_name=tool_name,
            roles=frozenset({ToolRole.WORKSPACE_MUTATOR}),
            min_required_integrity=Integrity.UNTRUSTED,
            arg_guard=make_workspace_path_guard(workspace_root, is_write=True),
        )

    # 3. Web Fetch / Search tools (Both Untrusted Source & External Egress Sink)
    if low in {"webfetch", "websearch", "fetch", "fetch_url", "read_url_content", "search_web"}:
        return ToolSecurityProfile(
            server="native",
            tool_name=tool_name,
            roles=frozenset({ToolRole.UNTRUSTED_SOURCE, ToolRole.EXTERNAL_EGRESS_SINK}),
            source_integrity=Integrity.UNTRUSTED,
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.PUBLIC,
            arg_guard=make_ssrf_and_dns_guard(),
        )

    # 4. Shell / Command execution tools (`Bash`, `run_command`, `run_shell_command`)
    if low in {"bash", "run_command", "run_shell_command", "beforeshellexecution"}:
        cmd_str = str(
            tool_input.get("command")
            or tool_input.get("CommandLine")
            or tool_input.get("cmd")
            or ""
        )
        has_network_egress = bool(
            re.search(
                r"(?i)\b(curl|wget|nc|ncat|netcat|socat|scp|ssh|rsync|nslookup|dig|ping|openssl\s+s_client|gh\s+(?:pr|api|issue|gist)|git\s+push|python3?\s+-c|node\s+-e|ruby\s+-e|perl\s+-e)\b|/dev/tcp/",
                cmd_str,
            )
        )
        roles = (
            frozenset({ToolRole.PRIVILEGED_MUTATOR, ToolRole.EXTERNAL_EGRESS_SINK})
            if has_network_egress
            else frozenset({ToolRole.PRIVILEGED_MUTATOR})
        )
        ssrf_g = make_ssrf_and_dns_guard()

        def _shell_cmd_guard(args: Mapping[str, Any]) -> tuple[bool, str]:
            c_str = str(args.get("command") or args.get("CommandLine") or args.get("cmd") or "")
            if has_network_egress:
                ok_net, reason_net = ssrf_g(args)
                if not ok_net:
                    return False, reason_net
            if re.search(r"(?i)(?:>|>>|\btee\b|\bcp\b|\bmv\b)[^\n]*(?:\.git/hooks|\.env\b|\.claude/|\.cursor/|\.vscode/|\.mcp-cage/)", c_str):
                return False, f"Protected config/dotfile shell modification blocked (A3.3/A3.4): '{c_str[:80]}'."
            return True, "OK"

        return ToolSecurityProfile(
            server="native",
            tool_name=tool_name,
            roles=roles,
            min_required_integrity=Integrity.ENDORSED,
            max_allowed_confidentiality=Confidentiality.PUBLIC if has_network_egress else Confidentiality.SECRET,
            arg_guard=_shell_cmd_guard,
        )

    return ToxicFlowGraphAnalyzer.build_default_profile(
        "native", tool_name, workspace_root=workspace_root
    )


def handle_cli_hook(
    agent: str,
    event: str,
    payload: Mapping[str, Any],
    *,
    db_path: Path,
    workspace_root: Path,
    mode: EnforcementMode = EnforcementMode.ENFORCE,
) -> dict[str, Any]:
    """
    Universal Plane B lifecycle hook handler for:
    - Claude Code (`claude`): `PreToolUse`, `PostToolUse`, `UserPromptSubmit`
    - Cursor (`cursor`): `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution`, `afterMCPExecution`
    - Gemini CLI (`gemini`): `BeforeTool`, `AfterTool`, `SessionStart`
    - Google Antigravity (`agy`): `PreToolUse`, `PostToolUse`, `UserPromptSubmit`
    - OpenAI Codex CLI (`codex`): `PreToolUse`, `PostToolUse`, `UserPromptSubmit`
    """
    agent_low = agent.lower()
    event_low = event.lower()
    session_id = str(payload.get("session_id") or payload.get("conversation_id") or "default")
    sm = SessionTaintStateMachine(db_path=db_path, session_id=session_id, mode=mode)
    scrubber = BidirectionalSecretScrubber(db_path=db_path)

    # 1. User Prompt Turn Reset events
    if event_low in {"userpromptsubmit", "beforesubmitprompt", "sessionstart"}:
        sm.reset_turn_integrity(f"{agent}:{event}")
        return {"continue": True, "decision": "allow", "permission": "allow"}

    # Normalize tool_name and tool_input across agent hook schemas
    tool_name = str(payload.get("tool_name") or event)
    tool_input: dict[str, Any] = dict(payload.get("tool_input") or {})
    if not tool_input:
        for k in ("file_path", "path", "command", "CommandLine", "url"):
            if k in payload:
                tool_input["path" if k == "file_path" else k] = payload[k]

    profile = _build_native_hook_profile(tool_name, tool_input, workspace_root)

    # 2. Cursor `beforeReadFile` pre-taints session if reading sensitive `.env` / credentials
    if event_low == "beforereadfile":
        eval_res = sm.on_tool_call(profile, tool_input)
        if eval_res.effective_decision == GateDecisionType.DENY:
            return {"permission": "deny", "user_message": eval_res.human_summary}
        sm.on_tool_response(profile, tool_input, response_text="", had_redacted_secrets=False)
        return {"permission": "allow"}

    # 3. Post-Tool Response hooks (`PostToolUse`, `AfterTool`, `afterMCPExecution`)
    if event_low in {"posttooluse", "aftertool", "aftermcpexecution"}:
        raw_resp = str(payload.get("tool_response") or payload.get("output") or "")
        sanitized_resp, _ = WirePayloadSanitizer.sanitize_text(raw_resp)
        scrubbed_resp, minted = scrubber.scrub_text(sanitized_resp)
        sm.on_tool_response(
            profile=profile,
            arguments=tool_input,
            response_text=sanitized_resp,
            had_redacted_secrets=bool(minted),
        )
        spotlighted = (
            WirePayloadSanitizer.spotlight_untrusted_text(scrubbed_resp)
            if ToolRole.UNTRUSTED_SOURCE in profile.roles
            else scrubbed_resp
        )
        return {
            "continue": True,
            "decision": "allow",
            "spotlighted_output": spotlighted,
        }

    # 4. Pre-Tool Execution Gate (`PreToolUse`, `BeforeTool`, `beforeShellExecution`, `beforeMCPExecution`)
    try:
        scrubber.inspect_and_rehydrate_args(profile.fq_name, tool_input)
    except PermissionError as exc:
        eff_dec = GateDecisionType.ALLOW if sm.mode == EnforcementMode.SHADOW else GateDecisionType.DENY
        eval_res = GateEvaluation(
            decision=GateDecisionType.DENY,
            effective_decision=eff_dec,
            mode=sm.mode,
            reason=str(exc),
            human_summary=str(exc),
        )
    else:
        eval_res = sm.on_tool_call(profile, tool_input)

    eff = eval_res.effective_decision

    if agent_low == "agy":
        agy_map = {
            GateDecisionType.ALLOW: "allow",
            GateDecisionType.STEP_UP: "force_ask",
            GateDecisionType.DENY: "deny",
        }
        return {"decision": agy_map[eff], "reason": eval_res.reason}

    if agent_low == "cursor":
        cur_map = {
            GateDecisionType.ALLOW: "allow",
            GateDecisionType.STEP_UP: "ask",
            GateDecisionType.DENY: "deny",
        }
        return {"permission": cur_map[eff], "user_message": eval_res.human_summary}

    if agent_low == "gemini":
        gem_map = {
            GateDecisionType.ALLOW: "allow",
            GateDecisionType.STEP_UP: "ask",
            GateDecisionType.DENY: "deny",
        }
        return {"decision": gem_map[eff], "reason": eval_res.reason}

    # Default Claude Code / Codex format
    claude_map = {
        GateDecisionType.ALLOW: "allow",
        GateDecisionType.STEP_UP: "ask",
        GateDecisionType.DENY: "deny",
    }
    return {
        "decision": claude_map[eff],
        "reason": eval_res.reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": claude_map[eff],
            "permissionDecisionReason": eval_res.human_summary,
        },
    }


# -----------------------------------------------------------------------------
# Unified CLI Entrypoint (`mcp-cage` & `mcp-sploit`)
# -----------------------------------------------------------------------------

DEFAULT_AUDIT_CATALOG: dict[str, list[dict[str, Any]]] = {
    "filesystem": [
        {"name": "read_file", "description": "Read file from workspace."},
        {"name": "write_file", "description": "Write file to workspace.", "annotations": {"destructiveHint": True}},
    ],
    "github": [
        {"name": "get_issue", "description": "Read GitHub issue.", "annotations": {"readOnlyHint": True, "openWorldHint": True}},
        {"name": "create_issue_comment", "description": "Post comment on issue.", "annotations": {"readOnlyHint": False, "openWorldHint": True}},
    ],
    "fetch": [
        {"name": "fetch_url", "description": "Fetch a URL over HTTP/HTTPS."},
    ],
    "slack": [
        {"name": "post_message", "description": "Send message to Slack channel."},
    ],
}


# ============================================================================
# 1. INFORMATION-THEORETIC, FIXED-POINT AST & TWO-AXIS COVERT IDENTIFIER GUARDS
# ============================================================================

ENGLISH_BIGRAMS: frozenset[str] = frozenset({
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or",
    "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha",
    "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne",
    "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
})

AUTHORITY_LEXICON: frozenset[str] = frozenset({
    "critical", "directive", "always", "first", "instead", "override", "supersede",
    "official", "primary", "recommended", "high-priority", "enterprise-verified",
    "preferred", "authoritative", "replace", "legacy", "mandatory", "priority",
})

SENSITIVE_BAIT_LEXICON: frozenset[str] = frozenset({
    "id_rsa", ".ssh", "context_dump", ".env", "credentials", "shadow",
})

CANONICAL_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def bigram_transition_plausibility(s: str) -> float:
    """Fraction of alphabetical bigrams belonging to high-frequency English bigrams."""
    clean = re.sub(r"[^a-zA-Z]", "", s.lower())
    if len(clean) < 4:
        return 0.5
    total = len(clean) - 1
    hits = sum(1 for i in range(total) if clean[i : i + 2] in ENGLISH_BIGRAMS)
    return hits / total


def iterative_fixed_point_unquote(s: str, max_depth: int = 5) -> str:
    """Applies URL percent-decoding until a fixed point s^(k) == s^(k-1) is reached."""
    curr = s
    for _ in range(max_depth):
        nxt = urllib.parse.unquote(curr)
        if nxt == curr:
            break
        curr = nxt
    return curr


def extract_untrusted_sink_entities(text: str) -> Set[str]:
    """Extracts untrusted domains, IPv4 literals, URLs, and emails from untrusted ingress [U]."""
    entities: Set[str] = set()
    for m in re.finditer(
        r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|169\.254\.169\.254)",
        text,
    ):
        entities.add(m.group(1).lower())
    for m in re.finditer(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", text):
        entities.add(m.group(1).lower())
        entities.add(m.group(1).split("@")[1].lower())
    for m in re.finditer(
        r"\b((?:[a-z0-9-]+\.)+(?:evil|attacker|exfil|webhook|burp|oast|leak)[a-z0-9.-]*)\b",
        text.lower(),
    ):
        entities.add(m.group(1).strip())
    return entities


def is_covert_exfil_identifier(param_name: str, val: str, h0_threshold: float = 3.35) -> Tuple[bool, str]:
    """
    Two-Axis Information-Theoretic & Schema-Grammar Divergence Detector:
    - Axis 1: Subdomain / Identifier Shannon Entropy >= H_0 (default 3.35 bits/char).
    - Axis 2: Typed-Identifier Semantic Surprise — detects natural-language EFF Diceware
      word sequences stuffed into UUID/hex/ID fields.
    """
    if not isinstance(val, str) or len(val) < 16:
        return False, "OK"

    m_dig = re.search(r"\bdig\s+([a-zA-Z0-9_-]{20,})\.", val)
    if m_dig:
        sub_label = m_dig.group(1)
        h_val = shannon_entropy(sub_label)
        if h_val >= h0_threshold:
            return True, f"[COVERT DNS ENTROPY BLOCKED] Subdomain entropy H={h_val:.2f} >= {h0_threshold}"

    p_low = param_name.lower()
    if any(k in p_low for k in ("uuid", "hex", "id", "token", "hash")):
        non_hex_alpha = re.findall(r"[g-zG-Z]", val)
        hyphen_words = [w for w in val.split("-") if w.isalpha() and len(w) >= 3]
        if len(non_hex_alpha) >= 3 and len(hyphen_words) >= 4 and bigram_transition_plausibility(val) >= 0.22:
            return True, f"[DICEWARE-IN-IDENTIFIER BLOCKED] Natural-language word sequence in '{param_name}'"
        if CANONICAL_UUID_RE.fullmatch(val.strip()):
            return False, "OK"
        if " " not in val and len(val) >= 24:
            h_val = shannon_entropy(val)
            if h_val >= h0_threshold:
                return True, f"[COVERT IDENTIFIER ENTROPY BLOCKED] Param '{param_name}' H={h_val:.2f} >= {h0_threshold}"

    return False, "OK"


# ============================================================================
# 2. UNCONDITIONAL 4-SLOT WIRE CANONICALIZER & AUTHORITY LOG-ODDS SCORER
# ============================================================================

class WireDIFCCanonicalizer:
    """
    Defeats Day-0 Non-Collision Tool-Provider Misbinding and
    Cross-Framework Tool Poisoning via unconditional 4-slot schema canonicalization.
    """

    @staticmethod
    def score_tool_poisoning(desc: str, schema_keys: List[str]) -> Tuple[float, bool]:
        tokens = re.findall(r"[a-zA-Z0-9_.-]+", desc.lower())
        if not tokens:
            return 0.0, False
        auth_hits = sum(1 for t in tokens if t in AUTHORITY_LEXICON)
        supersede_hits = len(
            re.findall(r"\b(instead of|supersede|replace|first|all file queries|legacy)\b", desc.lower())
        )
        bait_hits = sum(
            1 for b in SENSITIVE_BAIT_LEXICON if b in desc.lower() or b in " ".join(schema_keys).lower()
        )
        score = (2.5 * auth_hits / max(len(tokens), 8)) + (1.8 * supersede_hits) + (3.0 * bait_hits)
        return round(score, 4), (score >= 0.45)

    @classmethod
    def canonicalize_tool_4slot(
        cls,
        server_id: str,
        tool_name: str,
        raw_desc: str,
        schema_keys: List[str],
        trust_tier: str = "EXTERNAL",
    ) -> Tuple[str, float, bool]:
        score, flagged = cls.score_tool_poisoning(raw_desc, schema_keys)
        first_clause = raw_desc.split(".")[0].strip()
        strip_words = AUTHORITY_LEXICON | {
            "supersede", "instead", "first", "always", "superior", "canonical",
            "trusted", "default", "bypass", "faster", "more", "reliable", "better",
        }
        neutral_words = [
            w for w in re.findall(r"[a-zA-Z0-9_-]+", first_clause)
            if w.lower() not in strip_words
        ][:12]
        neutral_summary = " ".join(neutral_words) if neutral_words else f"Invoke {tool_name}"
        is_ro = any(
            k in tool_name.lower()
            for k in ("read", "get", "list", "search", "query", "status", "diff", "log", "describe")
        )
        side_effect = "READ_ONLY" if is_ro else "STATE_OR_NET_MUTATION"
        canonical_desc = (
            f"[Provider: {server_id} | Trust: {trust_tier}] "
            f"Action: {neutral_summary}. "
            f"Params: ({', '.join(schema_keys)}). "
            f"Class: {side_effect}."
        )
        return canonical_desc, score, flagged


# ============================================================================
# 3. CONTENT-ADDRESSED LINE-SPAN PERSISTENT PROVENANCE IN SQLITE WAL
# ============================================================================

class PersistentLineSpanProvenance:
    """
    Defeats Cross-Session Stored Prompt Injection across CLAUDE.md,
    .cursorrules, MEMORY.md, and source files without whole-file taint freeze.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = str(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS persistent_span_taint (
                    file_path TEXT,
                    line_hash TEXT,
                    origin_integrity TEXT,
                    entities_json TEXT,
                    updated_at REAL,
                    PRIMARY KEY (file_path, line_hash)
                );
                """
            )
        finally:
            conn.close()

    @staticmethod
    def _hash_line(line: str) -> str:
        return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()

    def record_file_write_spans(self, file_path: str, content: str, origin_integrity: str = "UNTRUSTED") -> int:
        if origin_integrity == "TRUSTED" or not content:
            return 0
        conn = self._connect()
        inserted = 0
        now = time.time()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            for line in content.splitlines():
                ents = extract_untrusted_sink_entities(line)
                if ents:
                    lhash = self._hash_line(line)
                    conn.execute(
                        "INSERT OR REPLACE INTO persistent_span_taint VALUES (?, ?, ?, ?, ?);",
                        (file_path, lhash, origin_integrity, json.dumps(sorted(ents)), now),
                    )
                    inserted += 1
            conn.execute("COMMIT;")
        finally:
            conn.close()
        return inserted

    def check_file_read_spans(self, file_path: str, content: str) -> Set[str]:
        if not content:
            return set()
        conn = self._connect()
        matched_entities: Set[str] = set()
        try:
            cur = conn.execute(
                "SELECT line_hash, entities_json FROM persistent_span_taint WHERE file_path = ?;",
                (file_path,),
            )
            span_map = {row[0]: set(json.loads(row[1])) for row in cur.fetchall()}
            if not span_map:
                return set()
            for line in content.splitlines():
                lhash = self._hash_line(line)
                if lhash in span_map:
                    matched_entities |= span_map[lhash]
        finally:
            conn.close()
        return matched_entities


# ============================================================================
# 4. DESTINATION-BOUND FORMAT-PRESERVING SECRET TOKENIZATION VAULT
# ============================================================================

class DestinationBoundFPEVault:
    """
    Mints format-preserving synthetic tokens T(s_i) before secrets enter the LLM
    context window (I(s_i; W_LLM) = 0) and enforces destination-bound
    capability ACLs on outbound re-hydration.
    """

    def __init__(self, vault_key: bytes | None = None) -> None:
        self._key = vault_key or os.urandom(32)
        self._raw_to_meta: Dict[str, Tuple[str, str]] = {}  # raw_secret -> (synth_token, auth_server)
        self._synth_to_meta: Dict[str, Tuple[str, str]] = {}  # synth_token -> (raw_secret, auth_server)

    def mint_token(self, raw_secret: str, authorized_server: str) -> str:
        if raw_secret in self._raw_to_meta:
            return self._raw_to_meta[raw_secret][0]
        prefix = raw_secret[:7] if len(raw_secret) >= 12 else raw_secret[:3]
        digest = hmac.new(self._key, raw_secret.encode("utf-8"), hashlib.sha256).hexdigest()
        synth = f"{prefix}SYNTH_{digest[:16]}"
        self._raw_to_meta[raw_secret] = (synth, authorized_server)
        self._synth_to_meta[synth] = (raw_secret, authorized_server)
        return synth

    def verify_or_rehydrate_outbound(
        self,
        target_server: str,
        session_integrity: str,
        args_payload: str,
    ) -> Tuple[bool, str, str]:
        """
        Enforces destination-bound capability verification:
          AllowRehydrate(T(s_i), S_target, I_k) <=> (S_target == AuthServer(s_i)) and (I_k == "TRUSTED")
        Returns (allowed, reason, rehydrated_payload).
        """
        out_payload = args_payload
        for synth, (raw_sec, auth_srv) in self._synth_to_meta.items():
            if synth in out_payload:
                if target_server != auth_srv or session_integrity != "TRUSTED":
                    return (
                        False,
                        f"[CONFUSED-DEPUTY SECRET ORACLE BLOCKED] Synthetic token '{synth}' cannot be re-hydrated for server='{target_server}' under integrity='{session_integrity}' (authorized='{auth_srv}').",
                        args_payload,
                    )
                out_payload = out_payload.replace(synth, raw_sec)
        for raw_sec in self._raw_to_meta:
            if raw_sec in args_payload:
                return False, "[RAW SECRET EGRESS BLOCKED] Unscrubbed secret detected on outbound wire.", args_payload
        return True, "OK", out_payload


# ============================================================================
# 5. CAUSAL STATE-PROGRESS ENTROPY GOVERNOR (DEFEATING OVERSERVE 93.88x)
# ============================================================================

@dataclass
class CausalStateProgressGovernor:
    """
    Tracks causal state-progress entropy:
      Z_k = sum_{j=1}^k exp(-eta * Delta S_j) * I(Delta S_j < epsilon_prog)
    Trips circuit breaker when Z_k >= Theta_circuit on cyclic zero-progress polling
    loops while allowing arbitrary-length multi-file refactoring workflows.
    """
    eta: float = 3.0
    epsilon_prog: float = 0.20
    theta_circuit: float = 4.0
    zero_progress_score: float = 0.0
    prior_signatures: Set[str] = field(default_factory=set)

    def reset_on_human_turn(self) -> None:
        self.zero_progress_score = 0.0
        self.prior_signatures.clear()

    def record_step_and_check(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        session_integrity: str,
    ) -> Tuple[bool, str]:
        if session_integrity == "TRUSTED":
            return True, "OK"
        sig = f"{tool_name}:{args.get('path', '')}:{args.get('job_id', '')}:{args.get('url', '')}"
        if "_state_delta" in args:
            delta_s = float(args["_state_delta"])
        else:
            delta_s = 0.0 if sig in self.prior_signatures else 0.85
        self.prior_signatures.add(sig)
        if delta_s < self.epsilon_prog:
            self.zero_progress_score += math.exp(-self.eta * delta_s)
        if self.zero_progress_score >= self.theta_circuit:
            return (
                False,
                f"[OVERSERVE RESOURCE AMPLIFICATION CIRCUIT BREAKER] Causal zero-progress score Z_k={self.zero_progress_score:.2f} >= {self.theta_circuit}",
            )
        return True, "OK"


# ============================================================================
# 6. AUTOMATED SCHEMA-TO-KERNEL SANDBOX COMPILER (`mcp-cage compile-sandbox`)
# ============================================================================

class SchemaToKernelSandboxCompiler:
    """
    Compiles MCP server capability schemas / lockfiles into stratified OS kernel
    containment profiles:
      Pi_kernel = Pi_runtime_RO + Pi_secret_DENY + Pi_workspace_RW + Pi_net_EGRESS
    Supports macOS Seatbelt (`/usr/bin/sandbox-exec` SBPL) and Linux Bubblewrap/Landlock.
    """

    @staticmethod
    def compile_macos_seatbelt_sbpl(
        workspace_dir: Path | str,
        extra_secret_dirs: List[Path | str] | None = None,
        allow_network: bool = False,
    ) -> str:
        ws = os.path.realpath(str(workspace_dir))
        home = os.path.realpath(str(Path.home()))
        secret_paths = [
            os.path.join(home, ".ssh"),
            os.path.join(home, ".aws"),
            os.path.join(home, ".kube"),
            os.path.join(home, ".gnupg"),
            os.path.join(home, ".config", "gcloud"),
        ]
        if extra_secret_dirs:
            secret_paths.extend(os.path.realpath(str(d)) for d in extra_secret_dirs)

        deny_rules = "\n".join(
            f'(deny file-read* file-write* (subpath "{sp}"))' for sp in secret_paths
        )
        net_rule = "(allow network*)" if allow_network else "(deny network-outbound)"
        return (
            "(version 1)\n"
            "(allow default)\n"
            f"{deny_rules}\n"
            f'(deny file-read* file-write* (subpath "{ws}/.mcp-cage"))\n'
            f'(deny file-write* (subpath "{ws}/.git/hooks"))\n'
            f'(deny file-write* (literal "{ws}/.env"))\n'
            f'(deny file-write* (literal "{ws}/.mcp.json"))\n'
            f'(deny file-write* (literal "{ws}/.cursor/mcp.json"))\n'
            f"{net_rule}\n"
        )

    @staticmethod
    def compile_linux_bwrap_args(
        workspace_dir: Path | str,
        allow_network: bool = False,
    ) -> List[str]:
        ws = os.path.realpath(str(workspace_dir))
        args = [
            "bwrap",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/etc", "/etc",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--bind", ws, ws,
            "--tmpfs", f"{ws}/.mcp-cage",
            "--ro-bind-try", f"{ws}/.git/hooks", f"{ws}/.git/hooks",
            "--ro-bind-try", f"{ws}/.env", f"{ws}/.env",
            "--die-with-parent",
        ]
        if not allow_network:
            args.append("--unshare-net")
        return args


# ============================================================================
# 7. CLI PERSONA RUNNERS (`compile-sandbox` and `bench`)
# ============================================================================

def run_compile_sandbox_cli(
    workspace: str,
    target_os: str = "auto",
    allow_network: bool = False,
    output_path: Optional[str] = None,
) -> int:
    if target_os == "auto":
        target_os = "macos" if sys.platform == "darwin" else "linux"
    if target_os == "macos":
        profile = SchemaToKernelSandboxCompiler.compile_macos_seatbelt_sbpl(
            workspace_dir=workspace,
            allow_network=allow_network,
        )
    else:
        bwrap_cmd = SchemaToKernelSandboxCompiler.compile_linux_bwrap_args(
            workspace_dir=workspace,
            allow_network=allow_network,
        )
        profile = " ".join(bwrap_cmd) + " -- <MCP_SERVER_CMD>\n"

    if output_path:
        Path(output_path).write_text(profile)
        print(json.dumps({"status": "ok", "target_os": target_os, "output_path": output_path}, indent=2))
    else:
        print(profile)
    return 0


def run_secbench_cli(suite_dir: Optional[str] = None) -> int:
    """Runs the reproducible MCP-SecBench and bundled non-regression evaluation suites."""
    base_dir = Path(suite_dir) if suite_dir else Path(__file__).resolve().parent
    v2_script = base_dir / "run_mcp_secbench_v2.py"
    v3_script = base_dir / "run_mcp_secbench_v3_ecological.py"
    if v2_script.exists() and v3_script.exists():
        r2 = subprocess.run([sys.executable, str(v2_script)], cwd=str(base_dir))
        r3 = subprocess.run([sys.executable, str(v3_script)], cwd=str(base_dir))
        return 0 if (r2.returncode == 0 and r3.returncode == 0) else 1
    runner = Path(__file__).resolve().parent / "run_all_regression_suites.py"
    if runner.exists():
        res = subprocess.run([sys.executable, str(runner)], cwd=str(runner.parent))
        return res.returncode
    print("Benchmark scripts not found at:", base_dir)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-cage",
        description="Zero-Code Wire & Native-Hook Security Firewall for Claude Code, Cursor, Codex, Gemini CLI & MCP",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # 1. `status`
    p_status = sub.add_parser("status", help="Inspect current session taint & provenance state")
    p_status.add_argument("--db", default=".mcp-cage/taint.db", help="Path to SQLite state DB")
    p_status.add_argument("--session", default="default", help="Session ID")

    # 2. `reset`
    p_reset = sub.add_parser("reset", help="Reset turn integrity to TRUSTED or clear session")
    p_reset.add_argument("--db", default=".mcp-cage/taint.db", help="Path to SQLite state DB")
    p_reset.add_argument("--session", default="default", help="Session ID")

    # 3. `audit` (`mcp-sploit` toxic-flow graph analyzer)
    p_audit = sub.add_parser("audit", help="Run mcp-sploit Lethal Trifecta toxic-flow graph audit")
    p_audit.add_argument("--catalog", help="Optional JSON file mapping server->tools")

    # 4. `audit-config` (Primitive B: CurXecute / MCPoison config linter)
    p_cfg = sub.add_parser(
        "audit-config",
        help="Audit .mcp.json / .cursor/mcp.json / .vscode/mcp.json / claude_desktop_config.json for CurXecute RCE & secrets",
    )
    p_cfg.add_argument("paths", nargs="*", help="Config files to audit (auto-discovers workspace configs if omitted)")
    p_cfg.add_argument("--workspace", default=".", help="Workspace root directory")

    # 5. `hook` (Plane B native lifecycle hook handler)
    p_hook = sub.add_parser("hook", help="Handle native agent lifecycle hook from stdin JSON")
    p_hook.add_argument("agent", choices=["claude", "cursor", "gemini", "agy", "codex"])
    p_hook.add_argument("event", help="Hook event name (e.g. PreToolUse, PostToolUse, BeforeTool, beforeReadFile)")
    p_hook.add_argument("--db", default=".mcp-cage/taint.db", help="Path to SQLite state DB")
    p_hook.add_argument("--workspace", default=".", help="Workspace root directory")
    p_hook.add_argument(
        "--mode",
        choices=["enforce", "shadow"],
        default=os.environ.get("MCP_CAGE_MODE", "enforce"),
        help="Firewall enforcement mode (enforce or shadow)",
    )

    # 6. `wrap` (Plane A stdio MCP wrapper)
    p_wrap = sub.add_parser("wrap", help="Wrap an upstream stdio MCP server with mcp-cage wire enforcement")
    p_wrap.add_argument("--server", required=True, help="Logical server name (e.g., filesystem, github, slack)")
    p_wrap.add_argument("--workspace", default=".", help="Workspace root directory")
    p_wrap.add_argument("--state-dir", default=".mcp-cage", help="Directory for shared SQLite state, vault & audit.jsonl")
    p_wrap.add_argument("--session-id", default="default", help="Session identifier")
    p_wrap.add_argument("--mode", choices=["enforce", "shadow"], default="enforce")
    p_wrap.add_argument(
        "--step-up-policy",
        choices=["deny", "approve_once", "lease_mutator_5m", "endorse_context"],
        default="deny",
    )
    p_wrap.add_argument("upstream_cmd", nargs=argparse.REMAINDER, help="Command and args after '--'")

    p_cs = sub.add_parser("compile-sandbox", help="Compile MCP schema/lockfile into OS kernel Seatbelt/Landlock sandbox profile")
    p_cs.add_argument("--workspace", default=".", help="Workspace root directory")
    p_cs.add_argument("--os", choices=["auto", "macos", "linux"], default="auto", help="Target OS kernel")
    p_cs.add_argument("--allow-network", action="store_true", help="Permit outbound network sockets in kernel profile")
    p_cs.add_argument("--output", default=None, help="Optional file path to save compiled kernel sandbox profile")

    p_bench = sub.add_parser("bench", help="Execute the reproducible MCP-SecBench & non-regression evaluation suite")
    p_bench.add_argument("--suite-dir", default=None, help="Optional custom directory for benchmark scripts")

    p_gen = sub.add_parser("generate-config", help="Generate Claude Desktop & agy CLI config examples")
    p_gen.add_argument("--workspace", default=".", help="Workspace root path")
    p_gen.add_argument("--output-dir", default=".", help="Directory to write example config files")

    args = parser.parse_args(argv)

    if args.subcommand == "status":
        sm = SessionTaintStateMachine(Path(args.db), session_id=args.session)
        cur_int, cur_conf, prov, leases = sm.get_state()
        print(
            json.dumps(
                {
                    "session_id": args.session,
                    "integrity": cur_int.name,
                    "confidentiality": cur_conf.name,
                    "provenance": prov,
                    "leases": leases,
                    "untrusted_entities": sm.get_untrusted_entities(),
                },
                indent=2,
            )
        )
        return 0

    if args.subcommand == "reset":
        sm = SessionTaintStateMachine(Path(args.db), session_id=args.session)
        new_int, cur_conf = sm.reset_turn_integrity("CLI reset")
        print(json.dumps({"session_id": args.session, "integrity": new_int.name, "confidentiality": cur_conf.name}))
        return 0

    if args.subcommand == "audit":
        catalog = (
            json.loads(Path(args.catalog).read_text())
            if args.catalog
            else DEFAULT_AUDIT_CATALOG
        )
        classified, findings = ToxicFlowGraphAnalyzer.audit_mcp_tools(catalog)
        print(
            json.dumps(
                {
                    "classified": classified,
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
            )
        )
        return 0

    if args.subcommand == "audit-config":
        explicit = [Path(p) for p in args.paths] if args.paths else None
        report = WorkspaceMCPConfigAuditor.discover_and_audit(Path(args.workspace), explicit)
        print(json.dumps(report, indent=2))
        return 1 if report["summary"]["CRITICAL"] > 0 else 0

    if args.subcommand == "hook":
        raw_in = sys.stdin.read().strip()
        payload = json.loads(raw_in) if raw_in else {}
        hook_mode = EnforcementMode.SHADOW if args.mode == "shadow" else EnforcementMode.ENFORCE
        resp = handle_cli_hook(
            args.agent,
            args.event,
            payload,
            db_path=Path(args.db),
            workspace_root=Path(args.workspace),
            mode=hook_mode,
        )
        print(json.dumps(resp))
        return 0

    if args.subcommand == "wrap":
        from mcp_cage_cli import run_stdio_wrapper

        return run_stdio_wrapper(args)

    if args.subcommand == "generate-config":
        from mcp_cage_cli import generate_configs

        return generate_configs(args)

    if args.subcommand == "compile-sandbox":
        return run_compile_sandbox_cli(
            workspace=args.workspace,
            target_os=args.os,
            allow_network=args.allow_network,
            output_path=args.output,
        )

    if args.subcommand == "bench":
        return run_secbench_cli(suite_dir=args.suite_dir)

    return 1


MCPCageEngine = MCPWireGateway
endpoint_repoint_guard = StandardArgGuards.endpoint_repoint_guard
make_endpoint_repoint_guard = StandardArgGuards.make_endpoint_repoint_guard
path_command_substitution_guard = StandardArgGuards.path_command_substitution_guard
url_path_segment_guard = StandardArgGuards.url_path_segment_guard
cli_flag_injection_guard = StandardArgGuards.cli_flag_injection_guard
sql_safety_guard = StandardArgGuards.sql_safety_guard
mqtt_topic_wildcard_guard = StandardArgGuards.mqtt_topic_wildcard_guard


if __name__ == "__main__":
    raise SystemExit(main())
