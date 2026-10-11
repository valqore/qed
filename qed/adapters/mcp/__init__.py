"""MCP proxy adapter (SPEC §12.1).

``qed mcp -- <command>`` speaks MCP to the agent on one side and MCP to the
upstream server on the other, and asks the kernel about every ``tools/call`` in
between. It runs in shadow by default: every call is decided and recorded, no
call is stopped. Enforcing changes one thing and nothing else -- ``mode`` in
``qed.yaml``.

``intent`` is importable on its own and imports almost nothing, so the
classification can be unit tested and audited without the MCP SDK present.
"""

from __future__ import annotations
