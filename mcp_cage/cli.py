"""
`mcp_cage.cli` — Unified CLI Entrypoint for `mcp-cage` and `mcp-sploit`.
"""

from __future__ import annotations

from mcp_cage_core import (
    main,
    run_compile_sandbox_cli,
    run_secbench_cli,
)

__all__ = [
    "main",
    "run_compile_sandbox_cli",
    "run_secbench_cli",
]

if __name__ == "__main__":
    raise SystemExit(main())
