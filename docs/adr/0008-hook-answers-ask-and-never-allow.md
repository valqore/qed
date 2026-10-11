# ADR-0008 — The hook answers `ask`, never `allow`, and never exits 1

**Status:** accepted · week 6 (2026-10-08)
**Deviates from:** SPEC §12.2 (`REQUIRE_APPROVAL` → exit 2 with a pending message)
**Relates to:** ADR-001 (adapter classes), ADR-003 (fail modes)

## Context

SPEC §12.2 was written against the exit-code-only hook contract: exit 0 to
allow, exit 2 to block with a reason on stderr. The contract has since grown a
structured form — stdout JSON carrying
`hookSpecificOutput.permissionDecision`, which may be `allow`, `deny`, `ask`
or `defer`, with a `permissionDecisionReason` beside it.

That changes two of the spec's answers and confirms a third hazard the spec
did not mention.

## Decision 1 — ALLOW emits nothing, not `allow`

**`permissionDecision: "allow"` bypasses the operator's own permission
rules.** A governance layer that answered `allow` to every call it did not
block would therefore be *granting* permissions nobody asked it to grant, and
switching off the user's configured allow-list as a side effect. Someone who
had carefully denied `Bash(rm *)` in their settings would find QED waving it
through, because QED had no rule about it.

So an ALLOW verdict prints nothing and exits 0, which the contract reads as
"no decision, carry on with the normal permission flow". QED was asked whether
to **stop** something. Answering "yes, and also I permit everything else" is a
different question.

`tests/adapters/test_claude_code_hook.py::TestAllowIsNeverEmitted` asserts the
string never reaches stdout.

## Decision 2 — REQUIRE_APPROVAL becomes `ask`

SPEC §12.2 degrades it: *"`REQUIRE_APPROVAL` → exit 2 with pending message
(hook cannot wait)"*. The hook still cannot wait — but `ask` hands the call to
the person sitting at the terminal, which is what the rule asked for. Turning
"a human must agree" into "refused" was a limitation of the old contract, not
a policy anyone chose.

The approval is still opened and recorded, so the same action can be approved
out of band with `qed approve` and the window applies to the retry. The `ask`
reason names the approval id for exactly that.

This makes the interactive case strictly better and leaves the unattended case
unchanged: with no person present, `ask` is declined and the call does not run.

## Decision 3 — no exit code that silently disables the gate

The contract treats **any non-zero exit that is not 2** as non-blocking: the
tool call proceeds and the transcript shows a small notice. The hook
documentation says a mistyped script path *"silently disables the gate"*.

So an unhandled exception in the adapter does not fail closed. It fails
silently open, which is the precise failure this product exists to prevent and
the commonest way a gate stops being one: nothing is refused, nothing is
recorded, and the only evidence is a traceback in somebody's scrollback.

Three consequences, all tested:

- every path out of `main()` is a deliberate `return`, never a traceback;
- a `fail_mode: open` gap writes an `ungated_window` record, so the gap is in
  the chain rather than only in somebody's scrollback;
- `qed install` resolves the executable to an absolute path, because a bare
  `qed` depends on the agent's `PATH` at the moment the hook fires, and a
  command that cannot be found is one of those silent notices.

## Consequences

- The hook is still `enforcement: advisory` always (SPEC §12.2, ADR-001).
  Whoever can edit the settings can delete the entry, so nothing here claims
  the call could not have happened.
- `qed install` prints how to harden it: deploy the same entry through managed
  settings and set `allowManagedHooksOnly`. SPEC §12.2's note names
  `allowManagedPermissionRulesOnly`, which is the *permissions* equivalent and
  does not lock hooks.
- An installation that wants enforcement rather than hardening needs the agent
  to be unable to reach the target without QED: `qed proxy` and the credential
  broker, per ADR-001's class C.
- `defer` is unused. It exists for a hook that wants a later hook to decide,
  and QED is the decision.
