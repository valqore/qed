"""MCP proxy adapter (SPEC §12.1).

``gate mcp -- <command>`` speaks MCP to the agent on one side and MCP to the
upstream server on the other, and asks the kernel about every ``tools/call`` in
between. Week 2 runs it in shadow: every call is decided and recorded, no call
is stopped. Enforcement is week 10, and the only thing that changes then is
``mode`` in ``gate.yaml``.

``intent`` is importable on its own and imports almost nothing, so the
classification can be unit tested and audited without the MCP SDK present.
"""

from __future__ import annotations
