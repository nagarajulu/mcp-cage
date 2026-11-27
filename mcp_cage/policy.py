"""
`mcp_cage.policy` — Declarative Enterprise Policy Configuration Loader
(`.mcp-cage/policy.json` / `mcp-cage.json`).

Allows enterprise AppSec teams to customize enforcement mode (`enforce` vs `shadow`),
tenant organization allowlists (`allowed_orgs`), trusted endpoint hosts
(`trusted_endpoints`), runtime endpoint re-pointing opt-in (`allow_endpoint_repoint`),
and custom tool role overrides (`custom_tool_roles`) without editing Python source.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from mcp_cage.core import (
    BidirectionalSecretScrubber,
    EnforcementMode,
    GateDecisionType,
    GateEvaluation,
    MCPCageEngine,
    SchemaLockVerifier,
    SessionTaintStateMachine,
    ToolRole,
    ToolSecurityProfile,
    ToxicFlowGraphAnalyzer,
)


@dataclass(frozen=True)
class MCPCagePolicyConfig:
    """
    Declarative policy schema loadable from `.mcp-cage/policy.json` or `mcp-cage.json`.
    Supports v0.4.3 `temporal_rules`, `argument_policies`, `virtual_patches`, and `server_env_allowlist`.
    """

    mode: EnforcementMode = EnforcementMode.ENFORCE
    allowed_orgs: frozenset[str] = field(default_factory=frozenset)
    trusted_endpoints: frozenset[str] = field(default_factory=frozenset)
    allow_endpoint_repoint: bool = False
    financial_cap_usd: float = 50.0
    custom_tool_roles: dict[str, frozenset[ToolRole]] = field(default_factory=dict)
    temporal_rules: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    argument_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    virtual_patches: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    server_env_allowlist: dict[str, frozenset[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MCPCagePolicyConfig:
        raw_mode = str(data.get("mode", "enforce")).strip().lower()
        mode = EnforcementMode.SHADOW if raw_mode == "shadow" else EnforcementMode.ENFORCE

        raw_orgs = data.get("allowed_orgs") or ()
        allowed_orgs = frozenset(str(o).strip() for o in raw_orgs if str(o).strip())

        raw_endpoints = data.get("trusted_endpoints") or ()
        trusted_endpoints = frozenset(str(h).strip().lower() for h in raw_endpoints if str(h).strip())

        allow_repoint = bool(data.get("allow_endpoint_repoint", False))
        fin_cap = float(data.get("financial_cap_usd", 50.0))

        custom_roles: dict[str, frozenset[ToolRole]] = {}
        raw_roles = data.get("custom_tool_roles") or {}
        if isinstance(raw_roles, Mapping):
            for fq_tool, role_names in raw_roles.items():
                parsed_roles: set[ToolRole] = set()
                if isinstance(role_names, (list, tuple, set)):
                    for r_name in role_names:
                        r_str = str(r_name).strip().upper()
                        if hasattr(ToolRole, r_str):
                            parsed_roles.add(ToolRole[r_str])
                if parsed_roles:
                    custom_roles[str(fq_tool).strip()] = frozenset(parsed_roles)

        raw_temporal = data.get("temporal_rules") or ()
        temporal_rules = tuple(dict(r) for r in raw_temporal if isinstance(r, Mapping))

        raw_arg_pol = data.get("argument_policies") or {}
        argument_policies: dict[str, dict[str, Any]] = {}
        if isinstance(raw_arg_pol, Mapping):
            for t_name, p_map in raw_arg_pol.items():
                if isinstance(p_map, Mapping):
                    argument_policies[str(t_name).strip()] = dict(p_map)

        raw_vpatches = data.get("virtual_patches") or ()
        virtual_patches = tuple(dict(p) for p in raw_vpatches if isinstance(p, Mapping))

        raw_env_allow = data.get("server_env_allowlist") or {}
        server_env_allowlist: dict[str, frozenset[str]] = {}
        if isinstance(raw_env_allow, Mapping):
            for s_name, env_list in raw_env_allow.items():
                if isinstance(env_list, (list, tuple, set)):
                    server_env_allowlist[str(s_name).strip()] = frozenset(str(x).strip() for x in env_list if str(x).strip())

        return cls(
            mode=mode,
            allowed_orgs=allowed_orgs,
            trusted_endpoints=trusted_endpoints,
            allow_endpoint_repoint=allow_repoint,
            financial_cap_usd=fin_cap,
            custom_tool_roles=custom_roles,
            temporal_rules=temporal_rules,
            argument_policies=argument_policies,
            virtual_patches=virtual_patches,
            server_env_allowlist=server_env_allowlist,
        )

    def evaluate_argument_policy(self, tool_name: str, fq_name: str, args: Mapping[str, Any]) -> tuple[bool, str]:
        """
        Evaluates declarative per-tool `argument_policies` (including compiled 0-day `virtual_patches`):
        `regex`, `not_regex`, `allowed_values`, `max_length`, `min_value`, `max_value`.
        """
        pol = self.argument_policies.get(fq_name) or self.argument_policies.get(tool_name)
        if not pol:
            return True, "OK"
        for param_name, rules in pol.items():
            if not isinstance(rules, Mapping) or param_name not in args:
                continue
            val = args[param_name]
            val_str = str(val)
            cwe_tag = str(rules.get("virtual_patch_cwe") or "POLICY")
            if "not_regex" in rules and re.search(str(rules["not_regex"]), val_str):
                return (
                    False,
                    f"[DECLARATIVE POLICY / VIRTUAL PATCH BLOCKED ({cwe_tag})] Tool `{tool_name}` argument `{param_name}` matched forbidden pattern `{rules['not_regex']}`.",
                )
            if "regex" in rules and not re.search(str(rules["regex"]), val_str):
                return (
                    False,
                    f"[DECLARATIVE ARGUMENT POLICY BLOCKED] Tool `{tool_name}` argument `{param_name}` failed required pattern `{rules['regex']}`.",
                )
            if "allowed_values" in rules and val not in set(rules["allowed_values"]):
                return (
                    False,
                    f"[DECLARATIVE ARGUMENT POLICY BLOCKED] Tool `{tool_name}` argument `{param_name}`='{val}' not in allowed values {rules['allowed_values']}.",
                )
            if "max_length" in rules and len(val_str) > int(rules["max_length"]):
                return (
                    False,
                    f"[DECLARATIVE ARGUMENT POLICY BLOCKED] Tool `{tool_name}` argument `{param_name}` length {len(val_str)} exceeds max_length {rules['max_length']}.",
                )
            if ("min_value" in rules or "max_value" in rules) and isinstance(val, (int, float)):
                if "min_value" in rules and float(val) < float(rules["min_value"]):
                    return False, f"[DECLARATIVE ARGUMENT POLICY BLOCKED] `{param_name}`={val} < min_value {rules['min_value']}."
                if "max_value" in rules and float(val) > float(rules["max_value"]):
                    return False, f"[DECLARATIVE ARGUMENT POLICY BLOCKED] `{param_name}`={val} > max_value {rules['max_value']}."
        return True, "OK"

    def evaluate_temporal_rules(self, tool_name: str, fq_name: str, call_history: list[str]) -> tuple[bool, str]:
        """
        Evaluates declarative temporal call-graph invariants (`require_prior`, `forbid_after`, `max_calls`)
        against the session's prior tool call history.
        """
        if not self.temporal_rules:
            return True, "OK"
        for rule in self.temporal_rules:
            rtype = str(rule.get("type") or "").strip().lower()
            rid = str(rule.get("id") or rtype)
            target = str(rule.get("target_tool") or rule.get("forbidden_tool") or "").strip()
            if target not in {tool_name, fq_name}:
                continue

            if rtype == "require_prior":
                req_prior = str(rule.get("required_prior_tool") or "").strip()
                if req_prior and not any(req_prior in h for h in call_history):
                    return (
                        False,
                        f"[TEMPORAL CALL-GRAPH INVARIANT BLOCKED ({rid})] Tool `{fq_name}` requires prior execution of `{req_prior}` in this session.",
                    )
            elif rtype == "forbid_after":
                trig = str(rule.get("trigger_tool") or "").strip()
                if trig and any(trig in h for h in call_history):
                    return (
                        False,
                        f"[TEMPORAL CALL-GRAPH INVARIANT BLOCKED ({rid})] Tool `{fq_name}` is forbidden after `{trig}` was invoked in this session.",
                    )
            elif rtype == "max_calls":
                limit = int(rule.get("max_calls") or 1)
                prior_count = sum(1 for h in call_history if target in h)
                if prior_count >= limit:
                    return (
                        False,
                        f"[TEMPORAL RATE-LIMIT INVARIANT BLOCKED ({rid})] Tool `{fq_name}` exceeded session call limit ({prior_count}/{limit}).",
                    )
        return True, "OK"

    @classmethod
    def load_file(cls, path: Path) -> MCPCagePolicyConfig:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError(f"Expected JSON object in policy file {path}")
        return cls.from_dict(data)

    @classmethod
    def discover(cls, workspace_root: Path) -> MCPCagePolicyConfig:
        """
        Discovers `.mcp-cage/policy.json` or `mcp-cage.json` in `workspace_root`,
        falling back to fail-closed zero-config defaults if absent.
        """
        for rel in (Path(".mcp-cage") / "policy.json", Path("mcp-cage.json")):
            candidate = Path(workspace_root) / rel
            if candidate.is_file():
                return cls.load_file(candidate)
        return cls()

    def build_engine(
        self,
        *,
        server_name: str,
        workspace_root: Path,
        state_dir: Path | None = None,
        session_id: str = "default",
    ) -> MCPCageEngine:
        resolved_state = Path(state_dir) if state_dir is not None else (Path(workspace_root) / ".mcp-cage")
        resolved_state.mkdir(parents=True, exist_ok=True)
        db_path = resolved_state / "taint.db"
        lock_path = resolved_state / "mcp-lock.json"

        sm = SessionTaintStateMachine(
            db_path=db_path,
            session_id=session_id,
            mode=self.mode,
        )
        scrubber = BidirectionalSecretScrubber(db_path=db_path)
        verifier = SchemaLockVerifier(lock_path)
        engine = MCPCageEngine(
            server_name=server_name,
            state_machine=sm,
            scrubber=scrubber,
            verifier=verifier,
            workspace_root=Path(workspace_root).resolve(),
            allowed_orgs=set(self.allowed_orgs) if self.allowed_orgs else None,
            allow_endpoint_repoint=self.allow_endpoint_repoint,
            trusted_endpoints=set(self.trusted_endpoints) if self.trusted_endpoints else None,
        )
        engine.policy_config = self  # type: ignore[attr-defined]
        return engine
