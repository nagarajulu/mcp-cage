"""
`mcp_cage.lattice` — Dual-Axis Taint Lattice, SQLite WAL State Machine,
Line-Span Provenance Tracker, and Causal Progress Governor.
"""

from __future__ import annotations

from mcp_cage_core import (
    CausalStateProgressGovernor,
    Confidentiality,
    DeclassificationAction,
    EnforcementMode,
    GateDecisionType,
    GateEvaluation,
    Integrity,
    PersistentLineSpanProvenance,
    SENSITIVE_FILE_PATTERNS,
    PUBLIC_DOC_PATTERNS,
    SessionTaintStateMachine,
    SourceTaintResolver,
    StateTuple,
    ToolRole,
    ToolSecurityProfile,
    UNTRUSTED_ENTITY_EMAIL_RE,
    UNTRUSTED_ENTITY_URL_RE,
    extract_untrusted_sink_entities,
    filesystem_read_taint_resolver,
    github_issue_taint_resolver,
)

__all__ = [
    "CausalStateProgressGovernor",
    "Confidentiality",
    "DeclassificationAction",
    "EnforcementMode",
    "GateDecisionType",
    "GateEvaluation",
    "Integrity",
    "PUBLIC_DOC_PATTERNS",
    "PersistentLineSpanProvenance",
    "SENSITIVE_FILE_PATTERNS",
    "SessionTaintStateMachine",
    "SourceTaintResolver",
    "StateTuple",
    "ToolRole",
    "ToolSecurityProfile",
    "UNTRUSTED_ENTITY_EMAIL_RE",
    "UNTRUSTED_ENTITY_URL_RE",
    "extract_untrusted_sink_entities",
    "filesystem_read_taint_resolver",
    "github_issue_taint_resolver",
]
