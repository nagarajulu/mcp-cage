"""Backward-compatible import alias for `mcp_cage.core` (prefer `from mcp_cage import ...`)."""

from __future__ import annotations

from mcp_cage.core import *  # noqa: F401, F403
from mcp_cage.core import __version__, main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
