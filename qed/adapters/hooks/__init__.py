"""Coding-agent hooks (SPEC §12.2).

An adapter that runs *inside* the agent's own process tree, invoked by the
agent before it uses a tool. It is the weakest of the three adapter classes
and the easiest to install, which is exactly the trade ADR-001 describes: a
hook is `enforcement: advisory` always, because the agent or the developer can
delete the line of settings that calls it.

That is not a reason to skip it. A hook is the only adapter that sees a `Bash`
command or a file write, and most of what a coding agent does is one of those.
"""

from __future__ import annotations

from qed.adapters.hooks.claude_code import (
    ADAPTER_NAME,
    Decision_,
    HookInput,
    HookOptions,
    HookOutcome,
    build_hook_proposal,
    parse_hook_input,
    run_hook,
)

__all__ = [
    "ADAPTER_NAME",
    "Decision_",
    "HookInput",
    "HookOptions",
    "HookOutcome",
    "build_hook_proposal",
    "parse_hook_input",
    "run_hook",
]
