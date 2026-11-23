"""
`mcp_cage.surfaces` — Runtime Enforcement Surfaces:
  - Plane A: `MCPWireGateway` / `MCPCageEngine` (JSON-RPC stdio/HTTP proxy reference monitor)
  - Plane B: `handle_cli_hook` (PreToolUse / PostToolUse / UserPromptSubmit coding-agent hook)
  - Plane C: `WorkspaceMCPConfigAuditor` (`CurXecute` / `MCPoison` config scanner)
  - Plane D: `SchemaToKernelSandboxCompiler` (macOS Seatbelt `.sb` & Linux `bubblewrap` compiler)
"""

from __future__ import annotations

from mcp_cage.core import (
    ConfigAuditFinding,
    InFlightRequest,
    LiveMCPServerProber,
    MCPCageEngine,
    MCPServerSourceAuditor,
    MCPWireGateway,
    SchemaToKernelSandboxCompiler,
    ServerSourceAuditFinding,
    SkillAuditFinding,
    WorkspaceMCPConfigAuditor,
    WorkspaceSkillAndRuleAuditor,
    handle_cli_hook,
)

__all__ = [
    "ConfigAuditFinding",
    "InFlightRequest",
    "LiveMCPServerProber",
    "MCPCageEngine",
    "MCPServerSourceAuditor",
    "MCPWireGateway",
    "SchemaToKernelSandboxCompiler",
    "ServerSourceAuditFinding",
    "SkillAuditFinding",
    "WorkspaceMCPConfigAuditor",
    "WorkspaceSkillAndRuleAuditor",
    "handle_cli_hook",
]
