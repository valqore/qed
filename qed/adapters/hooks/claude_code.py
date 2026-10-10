"""The Claude Code `PreToolUse` hook (SPEC §12.2).

Claude Code runs this before it uses a tool, hands it the call as JSON on
stdin, and reads the answer back. One invocation, one proposal, one verdict,
one record.

Three decisions here depart from SPEC §12.2, which was written against the
older exit-code-only hook contract. ADR-0008 records them; the short versions:

**ALLOW emits nothing at all.** The hook contract has a
``permissionDecision: "allow"``, and using it would be wrong. ``allow``
*bypasses* the permission rules the operator configured — so a governance
layer that answered ``allow`` to everything it did not block would be quietly
granting permissions nobody asked it to grant, and would switch off the user's
own allow-list in the process. Exit 0 with no output means "no decision, carry
on with the normal permission flow", which is the only honest thing for a gate
that was asked *whether to stop something*, not whether to permit it.

**REQUIRE_APPROVAL becomes ``ask``, not a block.** SPEC §12.2 degrades it to
exit 2 with a pending message because "the hook cannot wait". It cannot — but
the newer contract has ``ask``, which routes the call to the person already
sitting at the terminal. Turning "a human must agree" into "refused" when
there is a human right there was a limitation of the old contract, not a
policy.

**A crash is a refusal, never a stack trace.** The hook contract treats any
non-zero exit that is not 2 as *non-blocking*: the tool call proceeds and the
transcript shows a small notice. So an unhandled exception in here does not
fail closed, it fails silently open — the docs warn that a mistyped path
"silently disables the gate". Every path out of :func:`main` is therefore a
deliberate exit, and the fail-open path writes an ``ungated_window`` record so
the gap is in the chain rather than only in somebody's scrollback.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

from qed.adapters.common import AdapterInfo, build_proposal
from qed.adapters.mcp.intent import ToolIntent, classify
from qed.core.schemas import (
    ActionKind,
    ActionProposal,
    Assurance,
    Decision,
    Enforcement,
    Environment,
    EvidenceType,
    Mandate,
    Mode,
)
from qed.runtime import CheckOutcome, Session, check_proposal
from qed.version import VERSION

__all__ = [
    "ADAPTER_NAME",
    "EXIT_ALLOW",
    "EXIT_BLOCK",
    "Decision_",
    "HookInput",
    "HookOptions",
    "HookOutcome",
    "build_hook_proposal",
    "main",
    "parse_hook_input",
    "run_hook",
]

logger = logging.getLogger("qed.adapters.hooks.claude_code")

ADAPTER_NAME: Final = f"claude-code-hook/{VERSION}"

#: Exit 0 leaves the normal permission flow alone. Exit 2 is the only exit the
#: hook contract treats as blocking; every other non-zero code is a
#: *non-blocking* notice, which is why nothing here exits 1 on purpose.
EXIT_ALLOW: Final = 0
EXIT_BLOCK: Final = 2

#: What this adapter may answer. `allow` is deliberately absent -- see the
#: module docstring.
Decision_ = Literal["deny", "ask", "none"]

FailMode = Literal["closed", "open"]

#: SPEC §12.2's mapping, plus the rest. A tool nobody listed is recorded as
#: `custom` under its own name rather than ignored: an unmapped tool that
#: silently left no record would be the one an investigation needed.
_KINDS: Final[dict[str, tuple[ActionKind, str]]] = {
    "Bash": (ActionKind.shell, "shell.bash"),
    "Edit": (ActionKind.custom, "fs.write"),
    "Write": (ActionKind.custom, "fs.write"),
    "NotebookEdit": (ActionKind.custom, "fs.write"),
    "Skill": (ActionKind.skill, "skill"),
    "Read": (ActionKind.custom, "fs.read"),
    "Glob": (ActionKind.custom, "fs.read"),
    "Grep": (ActionKind.custom, "fs.read"),
    "WebFetch": (ActionKind.http, "web.fetch"),
    "WebSearch": (ActionKind.http, "web.search"),
    "Task": (ActionKind.custom, "agent.spawn"),
}

#: Which `tool_input` field names the thing being acted on, per tool. Used for
#: `action.target`, which is what a policy rule globs against.
_TARGET_FIELDS: Final = (
    "file_path",
    "path",
    "notebook_path",
    "url",
    "pattern",
    "command",
    "skill",
    "subagent_type",
)


@dataclass(frozen=True)
class HookInput:
    """What Claude Code puts on stdin, as far as this adapter reads it.

    Unknown fields are kept in ``extra``. The contract has grown `prompt_id`,
    `scratchpad_dir`, `permission_mode`, `effort` and more since SPEC §12.2 was
    written, and an adapter that refused a payload because it had learned a new
    field would break on an upgrade of the thing it is governing.
    """

    tool_name: str
    tool_input: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    cwd: str = ""
    tool_use_id: str = ""
    permission_mode: str = ""
    #: Present only when the hook fires inside a subagent, which is what makes
    #: a real `agent_chain` possible rather than an asserted one.
    agent_id: str = ""
    agent_type: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HookOptions:
    environment: Environment = "dev"
    #: Who the session acts for. Required for the same reason the other
    #: adapters require it: without a principal every verdict is a synthetic
    #: AG-IDN-007 identity BLOCK reached before any rule runs.
    human_hash: str | None = None
    mandate: Mandate | None = None
    token_jti: str = "claude-code-hook"
    adapter_id: str = "adp_hook_local"
    identity_note: str | None = None
    #: SPEC §12.2: open in dev, closed in prod. Applies to a *kernel* failure,
    #: not to a tool the policy refused.
    fail_mode: FailMode = "open"
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # The same guard the MCP proxy and the HTTP proxy carry, for the same
        # reason: `evaluate` short-circuits to a synthetic AG-IDN-007 BLOCK
        # when a proposal has neither a human principal nor a mandate, before
        # any rule in the bundle runs. An adapter left without identity would
        # fill the chain with identical identity BLOCKs in which no policy was
        # ever evaluated, and in shadow mode nothing would look wrong.
        #
        # On the dataclass rather than only in `main`, so that every caller
        # gets it -- a test, or the SDK, or whatever builds options next.
        if self.human_hash is None and self.mandate is None:
            raise ValueError(
                "the hook needs either a human principal or a mandate: without one every "
                "verdict is a synthetic AG-IDN-007 identity BLOCK and no policy rule is "
                "ever evaluated"
            )

    @property
    def adapter(self) -> AdapterInfo:
        return AdapterInfo(ADAPTER_NAME, self.adapter_id)


@dataclass(frozen=True)
class HookOutcome:
    """What to print and what to exit with."""

    decision: Decision_
    reason: str = ""
    exit_code: int = EXIT_ALLOW

    def payload(self) -> dict[str, Any] | None:
        """The structured answer, or None when there is nothing to say.

        ``none`` prints nothing. See the module docstring: a gate that was
        asked whether to stop something does not answer by granting
        permission.
        """
        if self.decision == "none":
            return None
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.decision,
                "permissionDecisionReason": self.reason,
            }
        }


# --------------------------------------------------------------------------
# Reading stdin
# --------------------------------------------------------------------------


def parse_hook_input(raw: str) -> HookInput:
    """Parse the hook payload. Raises ValueError on anything unusable."""
    try:
        loaded = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"the hook payload is not JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("the hook payload is not a JSON object")

    tool_name = loaded.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("the hook payload has no `tool_name`")
    tool_input = loaded.get("tool_input")

    known = {
        "tool_name",
        "tool_input",
        "session_id",
        "cwd",
        "tool_use_id",
        "permission_mode",
        "agent_id",
        "agent_type",
    }
    return HookInput(
        tool_name=tool_name,
        tool_input=tool_input if isinstance(tool_input, dict) else {},
        session_id=str(loaded.get("session_id") or ""),
        cwd=str(loaded.get("cwd") or ""),
        tool_use_id=str(loaded.get("tool_use_id") or ""),
        permission_mode=str(loaded.get("permission_mode") or ""),
        agent_id=str(loaded.get("agent_id") or ""),
        agent_type=str(loaded.get("agent_type") or ""),
        extra={key: value for key, value in loaded.items() if key not in known},
    )


# --------------------------------------------------------------------------
# Building the proposal
# --------------------------------------------------------------------------


def _kind_and_name(tool_name: str) -> tuple[ActionKind, str]:
    """SPEC §12.2's mapping, with MCP tools recognised by their prefix."""
    if tool_name.startswith("mcp__"):
        # `mcp__<server>__<tool>` -> `<server>.<tool>`, which is the same
        # `action.name` the MCP proxy writes for the same call. A rule written
        # for one adapter then matches the other, which is the point.
        parts = tool_name.split("__")
        if len(parts) >= 3:
            return ActionKind.mcp_tool, f"{parts[1]}.{'__'.join(parts[2:])}"
        return ActionKind.mcp_tool, tool_name
    mapped = _KINDS.get(tool_name)
    if mapped is not None:
        return mapped
    return ActionKind.custom, f"tool.{tool_name}"


def _target(payload: HookInput, name: str) -> str:
    """What the call acts on, for `action.target`.

    A path is made relative to the session's `cwd` when it sits underneath it,
    because an absolute path carries the developer's home directory into the
    chain and a rule written against `src/*` should match on two machines.
    """
    for field_name in _TARGET_FIELDS:
        value = payload.tool_input.get(field_name)
        if isinstance(value, str) and value.strip():
            if field_name in {"file_path", "path", "notebook_path"}:
                return f"file:{_relative(value, payload.cwd)}"
            if field_name == "url":
                return value
            if field_name == "command":
                # The command is the parameters, not the target. The target is
                # the machine it runs on, which is the honest answer for a
                # shell: a rule that wants the command matches
                # `params_redacted.command`.
                return f"host:{platform.node() or 'localhost'}"
            return f"{name.split('.')[0]}:{value}"
    if payload.tool_name.startswith("mcp__"):
        # The server, which is at least stable and globbable. Falling through
        # to the session id would give every MCP call through one server a
        # different target, and a rule written against `mcp:postgres*` would
        # match none of them. The MCP proxy derives a real target from a
        # template (SPEC §12.1); a hook has no template to read, so it says
        # what it actually knows.
        return f"mcp:{name.split('.')[0]}"
    return f"session:{payload.session_id or 'unknown'}"


def _relative(value: str, cwd: str) -> str:
    if not cwd:
        return value
    try:
        return Path(value).resolve().relative_to(Path(cwd).resolve()).as_posix()
    except (ValueError, OSError):
        return value


def _agent_chain(payload: HookInput) -> list[str]:
    """Outermost first (SPEC §3.1).

    Claude Code sends `agent_id` and `agent_type` only when the hook fires
    inside a subagent, so a chain of two means a subagent really is acting and
    not that the adapter guessed.
    """
    host = platform.node() or "unknown"
    chain = [f"claude-code@{host}"]
    if payload.agent_type:
        chain.append(f"sub:{payload.agent_type}")
    elif payload.agent_id:
        chain.append(f"sub:{payload.agent_id}")
    return chain


def build_hook_proposal(
    payload: HookInput, options: HookOptions, mode: Mode
) -> tuple[ActionProposal, ToolIntent]:
    """One `PreToolUse` call as a proposal. Pure apart from the id and clock."""
    kind, name = _kind_and_name(payload.tool_name)
    target = _target(payload, name)
    hints = classify(name, payload.tool_input)

    proposal = build_proposal(
        kind=kind,
        name=name,
        target=target,
        params=payload.tool_input,
        adapter=options.adapter,
        environment=options.environment,
        # Always advisory (SPEC §12.2, ADR-001). The developer can delete the
        # settings entry that calls this, so the chain must not claim the call
        # could not have happened without it.
        enforcement=Enforcement.advisory,
        mode=mode,
        token_jti=options.token_jti,
        human_hash=options.human_hash,
        agent_chain=_agent_chain(payload),
        mandate_id=None if options.mandate is None else options.mandate.id,
        client_fingerprint=options.identity_note,
        summary=_summary(payload, name, target, hints),
        writes=hints.writes,
        deletes=hints.deletes,
        scope=hints.scope,
        tags=list(options.tags),
    )
    return proposal, hints


def _summary(payload: HookInput, name: str, target: str, hints: ToolIntent) -> str:
    """One line for an approver, who will not have the transcript."""
    verb = {"read": "read", "create": "create on", "update": "change", "delete": "delete on"}.get(
        hints.change_type, "use"
    )
    command = payload.tool_input.get("command")
    if isinstance(command, str) and command.strip():
        shortened = command.strip().splitlines()[0][:120]
        return f"{payload.tool_name} wants to run: {shortened}"
    return f"{payload.tool_name} wants to {verb} {target} (via {name})"


# --------------------------------------------------------------------------
# Deciding
# --------------------------------------------------------------------------


def run_hook(
    session: Session,
    payload: HookInput,
    options: HookOptions,
    *,
    now: datetime | None = None,
) -> HookOutcome:
    """Decide one hook invocation. Writes to the chain; does not touch stdio."""
    proposal, _ = build_hook_proposal(payload, options, session.config.mode)
    outcome: CheckOutcome = check_proposal(session, proposal, mandate=options.mandate, now=now)

    decision = outcome.effective_decision
    if decision is Decision.BLOCK:
        return HookOutcome(decision="deny", reason=_block_reason(outcome), exit_code=EXIT_BLOCK)
    if decision is Decision.REQUIRE_APPROVAL:
        # `ask`, not a refusal. There is a person at this terminal; handing
        # them the question is what the rule asked for (ADR-0008).
        return HookOutcome(decision="ask", reason=_approval_reason(outcome))
    return HookOutcome(decision="none")


def _block_reason(outcome: CheckOutcome) -> str:
    hits = [hit for hit in outcome.verdict.hits if hit.verdict is Decision.BLOCK]
    ids = ", ".join(hit.rule_id for hit in hits) or "default verdict"
    first = hits[0] if hits else None
    text = f"[qed BLOCK] {ids}: {first.message if first else 'blocked by policy'}"
    if first is not None and first.fix:
        text += f" Fix: {first.fix}"
    return text


def _approval_reason(outcome: CheckOutcome) -> str:
    hits = [hit for hit in outcome.verdict.hits if hit.verdict is Decision.REQUIRE_APPROVAL]
    ids = ", ".join(hit.rule_id for hit in hits) or "default verdict"
    first = hits[0] if hits else None
    text = f"[qed APPROVAL] {ids}: {first.message if first else 'a person must agree'}"
    if first is not None and first.fix:
        text += f" Fix: {first.fix}"
    approval = outcome.verdict.approval_id
    if approval:
        text += f" Approval {approval} is open; `qed approvals` lists it."
    return text


def _record_ungated(
    session: Session, payload: HookInput, options: HookOptions, exc: Exception
) -> None:
    """A call that proceeded without a decision (SPEC §10, ADR-003).

    The gap is a record, not silence. Without this, `fail_mode: open` would be
    indistinguishable from a quiet afternoon.
    """
    try:
        session.writer.append(
            type_=EvidenceType.ungated_window,
            assurance=Assurance.adapter,
            payload={
                "adapter": ADAPTER_NAME,
                "adapter_id": options.adapter_id,
                "tool": payload.tool_name,
                "session_id": payload.session_id,
                "calls": 1,
                "reason": f"{type(exc).__name__}: {exc}",
                "fail_mode": options.fail_mode,
            },
            mode=session.config.mode,
            enforcement=Enforcement.advisory,
        )
    except Exception as inner:  # pragma: no cover - disk level failure
        logger.error("could not record the ungated window: %s", inner)


# --------------------------------------------------------------------------
# The process
# --------------------------------------------------------------------------


def main(
    argv: list[str] | None = None,
    *,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
) -> int:
    """Run as `qed hook claude-code`. Returns the exit code; prints the answer.

    Every path out of here is a deliberate exit. The hook contract treats a
    non-zero code that is not 2 as non-blocking, so an unhandled exception
    would leave the tool call to proceed with the gate silently off -- the
    failure the hook documentation warns about, and the exact shape of
    degradation this product exists to stop.
    """
    from qed.config import DEFAULT_DIR
    from qed.core.evidence.hashing import principal_hash
    from qed.infra.keys.file import MissingSigningKey
    from qed.runtime import PolicyErrors, open_session

    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    source = stdin if stdin is not None else sys.stdin

    args = _parse_argv(argv if argv is not None else sys.argv[1:])
    fail_mode: FailMode = "closed" if args.get("fail_mode") == "closed" else "open"

    try:
        raw = source.read()
    except Exception as exc:  # pragma: no cover - stdin closed under us
        return _bail(err, out, fail_mode, f"could not read the hook payload: {exc}")

    try:
        payload = parse_hook_input(raw)
    except ValueError as exc:
        # Malformed input is not a policy decision, and it is not this hook's
        # place to block a call it could not even read. Said on stderr, where
        # the contract puts a non-blocking notice.
        print(f"qed: {exc}", file=err)
        return _bail(err, out, fail_mode, str(exc))

    human = args.get("human")
    if not human and not args.get("mandate"):
        print(
            "qed: this hook has no --human or --mandate, so every verdict would be a "
            "synthetic AG-IDN-007 identity BLOCK before any rule ran. Re-run "
            "`qed install claude-code --human you@example.com`.",
            file=err,
        )
        return _bail(err, out, fail_mode, "the hook is not configured with an identity")

    mandate = None
    if args.get("mandate"):
        try:
            mandate = Mandate.model_validate_json(Path(args["mandate"]).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _bail(err, out, fail_mode, f"cannot read the mandate: {exc}")

    issuer = args.get("issuer", "local")
    options = HookOptions(
        environment=_environment(args.get("env", "dev")),
        human_hash=None if not human else principal_hash(human, issuer=issuer),
        mandate=mandate,
        adapter_id=args.get("adapter_id", "adp_hook_local"),
        identity_note=None if not human else f"adapter-asserted:--human:{issuer}",
        fail_mode=fail_mode,
    )

    directory = Path(args.get("dir") or os.environ.get("QED_DIR") or DEFAULT_DIR)
    session = None
    try:
        session = open_session(
            directory=directory,
            config_path=Path(args["config"]) if args.get("config") else None,
        )
        outcome = run_hook(session, payload, options)
    except (MissingSigningKey, PolicyErrors) as exc:
        return _bail(err, out, fail_mode, f"qed is not set up: {exc}")
    except Exception as exc:
        if session is not None:
            _record_ungated(session, payload, options, exc)
        logger.error("the hook could not decide: %s", exc)
        return _bail(err, out, fail_mode, f"the policy kernel could not decide: {exc}")
    finally:
        if session is not None:
            session.close()

    body = outcome.payload()
    if body is not None:
        print(json.dumps(body), file=out)
    if outcome.decision == "deny":
        # Printed on stderr as well: the contract prefers the JSON reason, and
        # a reader tailing the hook's own output should see why too.
        print(outcome.reason, file=err)
    return outcome.exit_code


def _bail(err: Any, out: Any, fail_mode: FailMode, detail: str) -> int:
    """What to do when QED itself could not answer.

    ``closed`` denies, with the reason. ``open`` gets out of the way -- and
    says so on stderr, which the contract shows as a notice rather than
    swallowing.
    """
    if fail_mode == "closed":
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"[qed ERROR] {detail} (fail_mode closed)",
                    }
                }
            ),
            file=out,
        )
        return EXIT_BLOCK
    print(f"qed: not decided, and fail_mode is open: {detail}", file=err)
    return EXIT_ALLOW


def _environment(value: str) -> Environment:
    return value if value in {"dev", "staging", "prod"} else "dev"  # type: ignore[return-value]


def _parse_argv(argv: list[str]) -> dict[str, str]:
    """``--key value`` and ``--key=value``, and nothing else.

    Hand-rolled rather than Typer because this runs on every tool call a
    coding agent makes: importing Typer and building a command tree to read
    four flags is latency the agent's user feels.
    """
    parsed: dict[str, str] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if not token.startswith("--"):
            index += 1
            continue
        key, sep, inline = token[2:].partition("=")
        key = key.replace("-", "_")
        if sep:
            parsed[key] = inline
            index += 1
            continue
        if index + 1 < len(argv) and not argv[index + 1].startswith("--"):
            parsed[key] = argv[index + 1]
            index += 2
            continue
        parsed[key] = "true"
        index += 1
    return parsed
