"""CLI entrypoint for `python3 -m mcp_cage`."""

from __future__ import annotations

import sys

from mcp_cage.cli import main

if __name__ == "__main__":
    sys.exit(main())
