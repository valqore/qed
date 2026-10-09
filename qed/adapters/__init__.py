"""Adapters (SPEC §12).

An adapter sits where the agent already is -- in front of an MCP server, inside
a coding agent's hook, on the HTTP egress path -- turns whatever the agent is
about to do into an :class:`~qed.core.schemas.ActionProposal`, asks the kernel,
and does what the verdict says.

Nothing in here decides anything. ``qed.runtime.check_proposal`` is the single
decision path (SPEC §5); an adapter that reached its own conclusion would be a
second policy engine nobody linted.
"""

from __future__ import annotations
