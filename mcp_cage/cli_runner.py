#!/usr/bin/env python3
"""
Standalone Wire-Level CLI Wrapper for `mcp-cage` (`mcp_cage_cli.py`).

Wraps ANY real stdio MCP server (e.g. `npx -y @modelcontextprotocol/server-filesystem`,
GitHub MCP, Slack MCP, Postgres MCP) in a zero-code JSON-RPC 2.0 security proxy
suitable for Claude Desktop (`claude_desktop_config.json`), Antigravity CLI (`agy mcp add`),
Cursor (`.cursor/mcp.json`), or automated E2E test suites.

Usage:
  python3 mcp_cage_cli.py wrap \
      --server filesystem \
      --workspace /path/to/workspace \
      --state-dir /path/to/.mcp-cage \
      -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_cage.core import (
    BidirectionalSecretScrubber,
    Confidentiality,
    DeclassificationAction,
    EnforcementMode,
    Integrity,
    SchemaLockVerifier,
    SessionTaintStateMachine,
    StandardArgGuards,
    ToolRole,
    ToolSecurityProfile,
    ToxicFlowGraphAnalyzer,
    WorkspaceMCPConfigAuditor,
    filesystem_read_taint_resolver,
    github_issue_taint_resolver,
)
from mcp_cage.proxy import MCPJsonRpcProxy


def _multi_file_read_guard(workspace_root: Path):
    single_guard = StandardArgGuards.make_workspace_file_guard(workspace_root, is_write=False)

    def _guard(args: Mapping[str, Any]) -> tuple[bool, str]:
        if "path" in args:
            return single_guard(args)
        paths = args.get("paths") or []
        for p in paths:
            ok, msg = single_guard({"path": p})
            if not ok:
                return False, msg
        return True, "OK"

    return _guard


def build_default_profiles(server_name: str, workspace_root: Path) -> dict[str, ToolSecurityProfile]:
    """
    Builds comprehensive default `ToolSecurityProfile` mappings for standard MCP tools
    (including official `@modelcontextprotocol/server-filesystem`, GitHub, Slack, HTTP,
    PostgreSQL, Stripe/Refund, and Memory MCP tools).
    """
    read_guard = _multi_file_read_guard(workspace_root)
    write_guard = StandardArgGuards.make_workspace_file_guard(workspace_root, is_write=True)

    read_profile = lambda name: ToolSecurityProfile(
        server=server_name,
        tool_name=name,
        roles=frozenset({ToolRole.PRIVATE_SOURCE}),
        source_integrity=Integrity.TRUSTED,
        source_confidentiality=Confidentiality.INTERNAL,
        min_required_integrity=Integrity.UNTRUSTED,
        max_allowed_confidentiality=Confidentiality.SECRET,
        arg_guard=read_guard,
        source_taint_resolver=filesystem_read_taint_resolver,
    )

    write_profile = lambda name: ToolSecurityProfile(
        server=server_name,
        tool_name=name,
        roles=frozenset({ToolRole.PRIVILEGED_MUTATOR}),
        min_required_integrity=Integrity.TRUSTED,
        max_allowed_confidentiality=Confidentiality.SECRET,
        arg_guard=write_guard,
    )

    return {
        # Official @modelcontextprotocol/server-filesystem tools
        "read_file": read_profile("read_file"),
        "read_text_file": read_profile("read_text_file"),
        "read_media_file": read_profile("read_media_file"),
        "read_multiple_files": read_profile("read_multiple_files"),
        "write_file": write_profile("write_file"),
        "edit_file": write_profile("edit_file"),
        "append_file": write_profile("append_file"),
        "move_file": ToolSecurityProfile(
            server=server_name,
            tool_name="move_file",
            roles=frozenset({ToolRole.PRIVILEGED_MUTATOR}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.SECRET,
            arg_guard=lambda a: write_guard({"path": a.get("destination", "")}),
        ),
        # Git / Shell tools
        "exec_git_diff": ToolSecurityProfile(
            server=server_name,
            tool_name="exec_git_diff",
            roles=frozenset({ToolRole.PRIVATE_SOURCE}),
            min_required_integrity=Integrity.UNTRUSTED,
            max_allowed_confidentiality=Confidentiality.SECRET,
            arg_guard=StandardArgGuards.shell_metachar_guard,
        ),
        # GitHub / Issue Tracker tools
        "get_issue": ToolSecurityProfile(
            server=server_name,
            tool_name="get_issue",
            roles=frozenset({ToolRole.UNTRUSTED_SOURCE}),
            source_integrity=Integrity.UNTRUSTED,
            source_confidentiality=Confidentiality.PUBLIC,
            min_required_integrity=Integrity.UNTRUSTED,
            max_allowed_confidentiality=Confidentiality.SECRET,
            source_taint_resolver=github_issue_taint_resolver,
        ),
        "create_issue_comment": ToolSecurityProfile(
            server=server_name,
            tool_name="create_issue_comment",
            roles=frozenset({ToolRole.EXTERNAL_EGRESS_SINK}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.PUBLIC,
        ),
        # Slack / Messaging / Outbound HTTP Egress tools
        "post_message": ToolSecurityProfile(
            server=server_name,
            tool_name="post_message",
            roles=frozenset({ToolRole.EXTERNAL_EGRESS_SINK}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.PUBLIC,
        ),
        "send_canary_report": ToolSecurityProfile(
            server=server_name,
            tool_name="send_canary_report",
            roles=frozenset({ToolRole.EXTERNAL_EGRESS_SINK}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.PUBLIC,
        ),
        "fetch_url": ToolSecurityProfile(
            server=server_name,
            tool_name="fetch_url",
            roles=frozenset({ToolRole.UNTRUSTED_SOURCE, ToolRole.EXTERNAL_EGRESS_SINK}),
            source_integrity=Integrity.UNTRUSTED,
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.PUBLIC,
            arg_guard=StandardArgGuards.ssrf_url_guard,
        ),
        # Database / Financial / Memory Mutators
        "run_sql": ToolSecurityProfile(
            server=server_name,
            tool_name="run_sql",
            roles=frozenset({ToolRole.PRIVILEGED_MUTATOR}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.SECRET,
            arg_guard=StandardArgGuards.sql_safety_guard,
        ),
        "issue_refund": ToolSecurityProfile(
            server=server_name,
            tool_name="issue_refund",
            roles=frozenset({ToolRole.PRIVILEGED_MUTATOR}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.SECRET,
            arg_guard=StandardArgGuards.make_financial_cap_guard(max_amount_usd=100.0),
        ),
        "save_memory": ToolSecurityProfile(
            server=server_name,
            tool_name="save_memory",
            roles=frozenset({ToolRole.PRIVILEGED_MUTATOR}),
            min_required_integrity=Integrity.TRUSTED,
            max_allowed_confidentiality=Confidentiality.PUBLIC,
        ),
    }


class DynamicProfileAwareProxy(MCPJsonRpcProxy):
    """
    Extends `MCPJsonRpcProxy` so any previously unseen tool returned in `tools/list`
    or called dynamically is automatically classified by `ToxicFlowGraphAnalyzer.build_default_profile`
    with full v0.3.0 empirical wire-level guards.
    """

    def __init__(self, *args: Any, workspace_root: Path | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.workspace_root = (workspace_root or Path.cwd()).resolve()

    def _default_profile(self, tool_name: str) -> ToolSecurityProfile:
        return ToxicFlowGraphAnalyzer.build_default_profile(
            self.server_name,
            tool_name,
            workspace_root=self.workspace_root,
        )

    def handle_server_to_client(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        req_id = msg.get("id")
        req_meta = self._pending_requests.get(req_id) if req_id is not None else None
        is_tools_list = bool(req_meta and req_meta.get("method") == "tools/list" and "result" in msg)

        out = super().handle_server_to_client(msg)
        if is_tools_list and out and "result" in out:
            for t in out["result"].get("tools", []):
                t_name = t.get("name", "")
                if t_name and t_name not in self.tool_profiles:
                    self.tool_profiles[t_name] = ToxicFlowGraphAnalyzer.build_default_profile(
                        self.server_name,
                        t_name,
                        str(t.get("description") or ""),
                        workspace_root=self.workspace_root,
                    )
        return out


def run_stdio_wrapper(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace).resolve()
    state_dir = Path(args.state_dir).resolve()
    state_dir.mkdir(parents=True, exist_ok=True)

    legacy_db = state_dir / "taint_state.db"
    db_path = legacy_db if (legacy_db.exists() and not (state_dir / "taint.db").exists()) else (state_dir / "taint.db")
    lock_path = state_dir / "mcp-lock.json"
    audit_path = state_dir / "audit.jsonl"

    mode = EnforcementMode.SHADOW if args.mode == "shadow" else EnforcementMode.ENFORCE
    step_up_map = {
        "deny": DeclassificationAction.DENY,
        "approve_once": DeclassificationAction.APPROVE_ONCE,
        "lease_mutator_5m": DeclassificationAction.LEASE_MUTATOR_5M,
        "endorse_context": DeclassificationAction.ENDORSE_CONTEXT,
    }
    default_step_up = step_up_map[args.step_up_policy]

    state_machine = SessionTaintStateMachine(
        db_path=db_path,
        session_id=args.session_id,
        mode=mode,
        audit_log_path=audit_path,
    )
    scrubber = BidirectionalSecretScrubber(db_path=db_path)
    lock_verifier = SchemaLockVerifier(lockfile_path=lock_path)
    profiles = build_default_profiles(args.server, workspace_root)

    proxy = DynamicProfileAwareProxy(
        server_name=args.server,
        state_machine=state_machine,
        scrubber=scrubber,
        lock_verifier=lock_verifier,
        tool_profiles=profiles,
        step_up_callback=lambda _t, _a, _e: default_step_up,
        auto_pin_on_first_list=True,
        workspace_root=workspace_root,
    )

    upstream_cmd = list(args.upstream_cmd)
    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]
    if not upstream_cmd:
        sys.stderr.write("Error: Missing upstream MCP server command after '--'.\n")
        return 2

    # v0.4.3 Zero-Leak Child Process Environment Jail (`SubprocessEnvJail`)
    raw_allow_env = getattr(args, "allow_env", "") or ""
    allowed_env_keys = [k.strip() for k in raw_allow_env.split(",") if k.strip()]
    scrubbed_child_env, _ = WorkspaceMCPConfigAuditor.build_scrubbed_child_env(
        os.environ, allowed_env_keys=allowed_env_keys
    )

    proc = subprocess.Popen(
        upstream_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
        start_new_session=True,
        env=scrubbed_child_env,
    )

    def _cleanup_child(*_a: Any) -> None:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()

    signal.signal(signal.SIGTERM, lambda *_: (_cleanup_child(), sys.exit(0)))

    stdout_lock = threading.Lock()

    def write_to_host(payload: dict[str, Any]) -> None:
        with stdout_lock:
            sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def read_upstream_loop() -> None:
        assert proc.stdout is not None
        while True:
            raw_line = proc.stdout.readline()
            if not raw_line:
                break
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            sanitized = proxy.handle_server_to_client(msg)
            if sanitized is not None:
                write_to_host(sanitized)

    reader_thread = threading.Thread(target=read_upstream_loop, daemon=True)
    reader_thread.start()

    try:
        while True:
            raw_line = sys.stdin.readline()
            if not raw_line:
                break
            line = raw_line.strip()
            if not line:
                continue
            try:
                client_msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            forwarded, immediate_resp = proxy.handle_client_to_server(client_msg)
            if immediate_resp is not None:
                write_to_host(immediate_resp)
                continue
            if forwarded is not None and proc.stdin is not None:
                proc.stdin.write(json.dumps(forwarded, ensure_ascii=False) + "\n")
                proc.stdin.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if proc.stdin:
            try:
                proc.stdin.close()
            except Exception:
                pass
        _cleanup_child()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        if proc.stdout:
            try:
                proc.stdout.close()
            except Exception:
                pass

    return 0


def generate_configs(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cli_path = str(Path(__file__).resolve())
    workspace_path = str(Path(args.workspace).resolve())
    state_dir = str((out_dir / ".mcp-cage-state").resolve())

    claude_cfg = {
        "mcpServers": {
            "filesystem-caged": {
                "command": sys.executable,
                "args": [
                    cli_path,
                    "wrap",
                    "--server",
                    "filesystem",
                    "--workspace",
                    workspace_path,
                    "--state-dir",
                    state_dir,
                    "--",
                    "npx",
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    workspace_path,
                ],
            }
        }
    }
    claude_file = out_dir / "claude_desktop_config.mcp-cage.example.json"
    claude_file.write_text(json.dumps(claude_cfg, indent=2) + "\n")

    agy_cmd = (
        f"agy mcp add filesystem-caged -- {sys.executable} {cli_path} wrap "
        f"--server filesystem --workspace {workspace_path} --state-dir {state_dir} "
        f"-- npx -y @modelcontextprotocol/server-filesystem {workspace_path}"
    )
    print(f"Wrote Claude Desktop config snippet to: {claude_file}")
    print(f"Antigravity CLI (`agy`) registration command:\n  {agy_cmd}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser( prog="mcp-cage", description="Wire-Level MCP Security Firewall CLI" )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    wrap_p = subparsers.add_parser("wrap", help="Wrap an upstream stdio MCP server with mcp-cage enforcement")
    wrap_p.add_argument("--server", required=True, help="Logical server name (e.g., filesystem, github, slack)")
    wrap_p.add_argument("--workspace", default=".", help="Workspace root directory for path/symlink confinement")
    wrap_p.add_argument("--state-dir", default=".mcp-cage", help="Directory for shared SQLite state, vault & audit.jsonl")
    wrap_p.add_argument("--session-id", default="default", help="Session identifier across concurrent MCP servers")
    wrap_p.add_argument("--mode", choices=["enforce", "shadow"], default="enforce", help="Firewall mode")
    wrap_p.add_argument(
        "--step-up-policy",
        choices=["deny", "approve_once", "lease_mutator_5m", "endorse_context"],
        default="deny",
        help="Default headless step-up policy when interactive UI is not attached",
    )
    wrap_p.add_argument("upstream_cmd", nargs=argparse.REMAINDER, help="Command and args after '--'")

    gen_p = subparsers.add_parser("generate-config", help="Generate Claude Desktop & agy CLI config examples")
    gen_p.add_argument("--workspace", default=".", help="Workspace root path")
    gen_p.add_argument("--output-dir", default=".", help="Directory to write example config files")

    cs_p = subparsers.add_parser("compile-sandbox", help="Compile MCP schema into macOS Seatbelt SBPL or Linux bwrap/Landlock profile")
    cs_p.add_argument("--workspace", default=".", help="Workspace root path")
    cs_p.add_argument("--os", choices=["auto", "macos", "linux"], default="auto", help="Target OS kernel")
    cs_p.add_argument("--allow-network", action="store_true", help="Allow outbound network sockets in kernel profile")
    cs_p.add_argument("--output", default=None, help="Output file path for kernel profile")

    bench_p = subparsers.add_parser("bench", help="Execute 800-scenario MCP-SecBench & Live Ecological evaluation suite")
    bench_p.add_argument("--suite-dir", default=None, help="Optional suite directory")

    parsed = parser.parse_args()
    if parsed.subcommand == "wrap":
        return run_stdio_wrapper(parsed)
    if parsed.subcommand == "generate-config":
        return generate_configs(parsed)
    if parsed.subcommand == "compile-sandbox":
        from mcp_cage_core import run_compile_sandbox_cli

        return run_compile_sandbox_cli(
            workspace=parsed.workspace,
            target_os=parsed.os,
            allow_network=parsed.allow_network,
            output_path=parsed.output,
        )
    if parsed.subcommand == "bench":
        from mcp_cage_core import run_secbench_cli

        return run_secbench_cli(suite_dir=parsed.suite_dir)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
