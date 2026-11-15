"""
Real JSON-RPC 2.0 Wire Interceptor (`mcp_cage_proxy.py`).

Addresses Critic Audit Part 2:
- Implements full JSON-RPC 2.0 packet processing across ALL MCP attack surfaces:
  1. `tools/list` -> `mcp-lock.json` SHA-256 verification + description injection scrubbing.
  2. `tools/call` -> Argument policy gate + Cross-process secret rehydration check +
     Lethal Trifecta circuit breaker + Timeout-safe soft-error fallback + Response secret scrubbing.
  3. `resources/read` -> Secret scrubbing + dynamic URI tainting (`file:///.env` vs `file:///README.md`).
  4. `prompts/get` -> Strips prompt-injection markers from server-supplied prompt templates.
  5. `sampling/createMessage` -> Blocks server-initiated Host LLM sampling hijacks when session is tainted.
  6. `notifications/tools/list_changed` -> Intercepts mid-session dynamic rug-pull notifications.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from mcp_cage_core import (
    BidirectionalSecretScrubber,
    Confidentiality,
    DeclassificationAction,
    EnforcementMode,
    GateDecisionType,
    GateEvaluation,
    Integrity,
    SchemaLockVerifier,
    SessionTaintStateMachine,
    ToolRole,
    ToolSecurityProfile,
    WirePayloadSanitizer,
    filesystem_read_taint_resolver,
)


class MCPJsonRpcProxy:
    """
    Bidirectional JSON-RPC 2.0 Wire Interceptor between an MCP Host (Cursor/Claude)
    and an upstream MCP Server process.
    """

    def __init__(
        self,
        server_name: str,
        state_machine: SessionTaintStateMachine,
        scrubber: BidirectionalSecretScrubber,
        lock_verifier: SchemaLockVerifier,
        tool_profiles: dict[str, ToolSecurityProfile],
        step_up_callback: Callable[[str, dict[str, Any], GateEvaluation], DeclassificationAction] | None = None,
        auto_pin_on_first_list: bool = True,
    ) -> None:
        self.server_name = server_name
        self.state_machine = state_machine
        self.scrubber = scrubber
        self.lock_verifier = lock_verifier
        self.tool_profiles = tool_profiles
        self.step_up_callback = step_up_callback
        self.auto_pin_on_first_list = auto_pin_on_first_list
        # Tracks in-flight client->server requests by JSON-RPC `id`
        self._pending_requests: dict[int | str, dict[str, Any]] = {}

    def _default_profile(self, tool_name: str) -> ToolSecurityProfile:
        return ToolSecurityProfile(
            server=self.server_name,
            tool_name=tool_name,
            roles=frozenset({ToolRole.NEUTRAL}),
        )

    def handle_client_to_server(
        self, msg: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """
        Inspects a JSON-RPC message traveling from MCP Host -> Upstream MCP Server.
        Returns `(forwarded_request_to_server, immediate_response_to_client)`.
        If blocked or soft-paused, returns `(None, synthetic_jsonrpc_response)` so the
        MCP Host never hangs or times out!
        """
        method = msg.get("method", "")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            arguments = dict(params.get("arguments") or {})
            profile = self.tool_profiles.get(tool_name, self._default_profile(tool_name))

            # 1. Cross-process secret rehydration & exfiltration guard
            try:
                rehydrated_args = self.scrubber.inspect_and_rehydrate_args(profile.fq_name, arguments)
            except PermissionError as exc:
                return None, self._soft_block_response(req_id, str(exc))

            # 2. Session Taint & Lethal Trifecta Gate
            eval_res = self.state_machine.on_tool_call(profile, arguments)

            if eval_res.effective_decision == GateDecisionType.DENY:
                return None, self._soft_block_response(req_id, eval_res.human_summary)

            if eval_res.effective_decision == GateDecisionType.STEP_UP:
                action = (
                    self.step_up_callback(profile.fq_name, arguments, eval_res)
                    if self.step_up_callback is not None
                    else DeclassificationAction.DENY
                )
                if action == DeclassificationAction.DENY:
                    return None, self._soft_block_response(
                        req_id,
                        f"[MCP-CAGE STEP-UP DENIED] {eval_res.human_summary}",
                    )
                if action in (DeclassificationAction.LEASE_MUTATOR_5M, DeclassificationAction.ENDORSE_CONTEXT):
                    self.state_machine.apply_declassification(action)

            # Forward request with rehydrated arguments (if authorized)
            forwarded = dict(msg)
            forwarded["params"] = {**params, "arguments": rehydrated_args}
            if req_id is not None:
                self._pending_requests[req_id] = {
                    "method": "tools/call",
                    "tool_name": tool_name,
                    "arguments": arguments,
                }
            return forwarded, None

        if method in ("tools/list", "resources/read", "prompts/get"):
            if req_id is not None:
                self._pending_requests[req_id] = {"method": method, "params": params}
            return msg, None

        return msg, None

    def handle_server_to_client(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """
        Inspects a JSON-RPC message traveling from Upstream MCP Server -> MCP Host.
        Covers `tools/list`, `tools/call` responses, `resources/read` responses,
        `prompts/get` responses, `sampling/createMessage` server-to-client requests,
        and `notifications/tools/list_changed`.
        """
        # 1. Server-initiated request or notification (e.g. `sampling/createMessage` or `notifications/tools/list_changed`)
        if "method" in msg:
            method = msg["method"]
            if method == "sampling/createMessage":
                cur_int, cur_conf, _, _ = self.state_machine.get_state()
                if cur_int == Integrity.UNTRUSTED or cur_conf >= Confidentiality.CONFIDENTIAL:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg.get("id"),
                        "error": {
                            "code": -32001,
                            "message": (
                                f"[MCP-CAGE BLOCKED SAMPLING HIJACK] Upstream server '{self.server_name}' "
                                f"attempted `sampling/createMessage` while session is ({cur_int.name}, {cur_conf.name})."
                            ),
                        },
                    }
            elif method == "notifications/tools/list_changed":
                # Force next tools/list to verify against existing lockfile (blocks dynamic rug-pulls)
                self.auto_pin_on_first_list = False
            return msg

        # 2. Response to a client request
        req_id = msg.get("id")
        req_meta = self._pending_requests.pop(req_id, None) if req_id is not None else None
        if not req_meta or "result" not in msg:
            return msg

        req_method = req_meta["method"]
        result = msg["result"]

        # Case A: `tools/list` response -> verify SHA-256 lockfile & strip poisoned descriptions
        if req_method == "tools/list":
            tools = result.get("tools", [])
            sanitized_tools, _ = self.lock_verifier.verify_and_sanitize_tools_list(
                self.server_name, tools, auto_pin_new=self.auto_pin_on_first_list
            )
            self.auto_pin_on_first_list = False
            return {**msg, "result": {**result, "tools": sanitized_tools}}

        # Case B: `tools/call` response -> sanitize Unicode/ANSI, scrub secrets & update session taint
        if req_method == "tools/call":
            tool_name = req_meta["tool_name"]
            arguments = req_meta["arguments"]
            profile = self.tool_profiles.get(tool_name, self._default_profile(tool_name))

            raw_json_str = json.dumps(result, ensure_ascii=False)
            sanitized_str, _ = WirePayloadSanitizer.sanitize_text(raw_json_str)
            scrubbed_json_str, minted_tokens = self.scrubber.scrub_text(sanitized_str)
            scrubbed_result = json.loads(scrubbed_json_str)

            self.state_machine.on_tool_response(
                profile=profile,
                arguments=arguments,
                response_text=sanitized_str,
                had_redacted_secrets=bool(minted_tokens),
            )
            return {**msg, "result": scrubbed_result}

        # Case C: `resources/read` response -> sanitize Unicode/ANSI, scrub secrets & taint based on URI + content
        if req_method == "resources/read":
            uri = str((req_meta.get("params") or {}).get("uri", ""))
            raw_json_str = json.dumps(result, ensure_ascii=False)
            sanitized_str, _ = WirePayloadSanitizer.sanitize_text(raw_json_str)
            scrubbed_json_str, minted_tokens = self.scrubber.scrub_text(sanitized_str)
            scrubbed_result = json.loads(scrubbed_json_str)

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
                had_redacted_secrets=bool(minted_tokens),
            )
            return {**msg, "result": scrubbed_result}

        # Case D: `prompts/get` response -> strip Unicode/ANSI & prompt-injection markers from server templates
        if req_method == "prompts/get":
            raw_json_str = json.dumps(result, ensure_ascii=False)
            sanitized_str, _ = WirePayloadSanitizer.sanitize_text(raw_json_str)
            cleaned_str = SchemaLockVerifier.INJECTION_MARKERS.sub("[STRIPPED_BY_MCP_CAGE]", sanitized_str)
            return {**msg, "result": json.loads(cleaned_str)}

        return msg

    @staticmethod
    def _soft_block_response(req_id: Any, human_message: str) -> dict[str, Any]:
        """
        Returns a structured MCP tool result with `isError: True` instead of hanging
        the stdio pipe or crashing the MCP connection when a call is blocked.
        """
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": human_message,
                    }
                ],
            },
        }


class StdioSubprocessBridge:
    """
    Spawns a real child MCP server subprocess (`command` + `args`) and routes all
    newline-delimited JSON-RPC 2.0 traffic through `MCPJsonRpcProxy`.
    """

    def __init__(self, command: list[str], proxy: MCPJsonRpcProxy) -> None:
        self.command = command
        self.proxy = proxy
        self._proc: subprocess.Popen[str] | None = None

    def __enter__(self) -> StdioSubprocessBridge:
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._proc is not None:
            if self._proc.stdin:
                self._proc.stdin.close()
            if self._proc.stdout:
                self._proc.stdout.close()
            if self._proc.stderr:
                self._proc.stderr.close()
            self._proc.terminate()
            self._proc.wait(timeout=3)

    def send_request(self, client_msg: dict[str, Any]) -> dict[str, Any]:
        """
        Sends a client JSON-RPC request through `MCPJsonRpcProxy` -> child `stdin` ->
        child `stdout` -> `MCPJsonRpcProxy` -> returns sanitized response to client.
        """
        forwarded, immediate_client_resp = self.proxy.handle_client_to_server(client_msg)
        if immediate_client_resp is not None:
            return immediate_client_resp

        assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(forwarded) + "\n")
        self._proc.stdin.flush()

        raw_line = self._proc.stdout.readline()
        if not raw_line:
            raise RuntimeError("Upstream MCP server closed stdout unexpectedly.")
        server_msg = json.loads(raw_line)
        sanitized = self.proxy.handle_server_to_client(server_msg)
        assert sanitized is not None
        return sanitized
