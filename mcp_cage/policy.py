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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from mcp_cage.core import (
    BidirectionalSecretScrubber,
    EnforcementMode,
    MCPCageEngine,
    SchemaLockVerifier,
    SessionTaintStateMachine,
    ToolRole,
)


@dataclass(frozen=True)
class MCPCagePolicyConfig:
    """
    Declarative policy schema loadable from `.mcp-cage/policy.json` or `mcp-cage.json`.
    """

    mode: EnforcementMode = EnforcementMode.ENFORCE
    allowed_orgs: frozenset[str] = field(default_factory=frozenset)
    trusted_endpoints: frozenset[str] = field(default_factory=frozenset)
    allow_endpoint_repoint: bool = False
    financial_cap_usd: float = 50.0
    custom_tool_roles: dict[str, frozenset[ToolRole]] = field(default_factory=dict)

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

        return cls(
            mode=mode,
            allowed_orgs=allowed_orgs,
            trusted_endpoints=trusted_endpoints,
            allow_endpoint_repoint=allow_repoint,
            financial_cap_usd=fin_cap,
            custom_tool_roles=custom_roles,
        )

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
        return MCPCageEngine(
            server_name=server_name,
            state_machine=sm,
            scrubber=scrubber,
            verifier=verifier,
            workspace_root=Path(workspace_root).resolve(),
            allowed_orgs=set(self.allowed_orgs) if self.allowed_orgs else None,
            allow_endpoint_repoint=self.allow_endpoint_repoint,
            trusted_endpoints=set(self.trusted_endpoints) if self.trusted_endpoints else None,
        )
