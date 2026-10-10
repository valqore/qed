# ADR-0014 — qed governs its own admin operations, off by default, with a loud break-glass

**Status:** accepted · week 10 (2026-10-10)
**Implements:** SPEC §17 (admin operations through the approval service with SoD)
**Relates to:** ADR-0010 (rotation destroys the old key), ADR-0012 (pack bundles)

## Context

Every rule in the baseline pack constrains an agent. The operator has been the
one actor no rule touches — and the operator is who rotates the signing key,
replaces the control catalogues, and edits the policy an agent is judged by.

"Who governs the thing doing the governing" is the first question an auditor
asks about a governance product, and until this the answer was "nobody".

SPEC §17 fixes the intent: *admin operations go through the approval service
with SoD and produce `admin_action` evidence*. It leaves open how, when, and
what happens when the approver is asleep.

## Decision 1 — Reuse the approval machinery, do not build a second one

An admin operation opens an ordinary
:class:`~qed.core.approval.model.ApprovalRequest`, is decided by the existing
`qed approve`, and goes through the existing
`check_separation_of_duties`. The only new state is a synthetic
`proposal_id` of the form `adm:<operation>:<ulid>`.

Two approval systems would be two places for the SoD check to live, and the one
that mattered would be the one nobody tested. This is also why the admin path
is **not** routed through the policy engine as a proposal: that would need a
delegation token for an operator at a terminal — so `qed keys rotate` on a
laptop would require an IdP — and `AG-IDN-009` would BLOCK it, since it exists
precisely to stop anything targeting qed's own configuration. The agent path and
the operator path are different paths that meet at the same approval.

## Decision 2 — Off by default

Self-governance needs a second person. The common case is one operator on a
laptop, and on by default would mean `qed keys rotate` fails on first use —
which teaches people that the feature is an obstacle to be removed rather than
a control to be configured.

What keeps that honest is that `qed doctor` reports it **either way**. An
instance with no gate says so, in yellow, with the sentence an auditor would
write: *the operator is the one actor no rule constrains.* A silence there would
have read as "fine".

And the `admin_action` record carries `self_governed: false` rather than
omitting the field, so an auditor can tell a rotation that was unapproved **by
configuration** from one that evaded a gate. A field that appears only when
something is wrong is a field nobody can distinguish from one this build never
wrote.

## Decision 3 — Break-glass exists, and costs a permanent record

The reason to rotate a signing key is that it may have leaked. That is exactly
when the approver is asleep.

A gate with no break-glass does not stop the rotation; it moves it outside the
tool. The operator edits `qed.yaml`, sets `self_governed: false`, rotates, and
sets it back — and *nothing records any of it*. Pushing people outside the
product to do the risky thing is worse than letting them do it inside, where it
leaves a trace.

So `--break-glass "<reason>"` proceeds. It costs: the reason is required, the
`admin_action` carries `break_glass: true` and the reason verbatim, the command
prints a red warning on stderr, and the record is permanent because
`admin_action` is in `NEVER_PURGE`.

Two ordering details, both deliberate. Break-glass is checked **after** the
governed check, so passing the flag on an ungoverned instance does not write a
false emergency into an immutable chain. And it is checked **before** the
approval lookups, so an operator in an incident is not told to go and find an
approval id first.

## Decision 4 — An approval is bound to one operation and spent once

The operation is inside the synthetic `proposal_id`, which is inside the request
the approver saw and decided on — so it cannot be changed afterwards without
the approval becoming a different approval. An approval granted for importing a
catalogue cannot be spent on rotating a key: *"approve the catalogue import"* is
a smaller ask than *"approve rotating the signing key"*, and spending one on the
other reads as an administrative slip and works as a privilege escalation.

Single use is read **out of the chain**, not from a column. The `admin_action`
carrying an `approval_id` *is* the receipt that it was used. A flag in a table
could disagree with the chain after a restore from backup, and `admin_action` is
in `NEVER_PURGE` so the receipt cannot age out from under the check. The scan
looks at `admin_action` records only — a real instance has a handful, and
somebody is standing at a terminal waiting for a key rotation, so this is a
human-latency path.

The `requested: true` flag is what separates "somebody asked to rotate the key"
from "the key was rotated". Both belong in the chain: a request that was never
approved is a thing an auditor should be able to see.

## Decision 5 — The requester is self-asserted on the CLI, and we say so

`qed approve --by you@example.com` has always taken the approver's word for it,
because the CLI runs on the operator's own machine. Self-governance inherits
that, and this ADR states the consequence rather than leaving it to be
discovered:

**On the CLI, self-governance buys that two separate invocations naming two
separate subjects are required.** That is a real obstacle to a careless action
and no obstacle at all to a determined operator who lies about who they are.
The identity is proven only on the API path, where a delegation token says who
is asking.

Claiming cryptographic separation of duties here would be the same kind of
overclaim as a compliance mapping nobody checked — a "separation of duties"
control reported in an export while nothing enforces it, and
`check_separation_of_duties`' docstring already says that reporting a control
that does not exist is worse than not having it. `THREAT_MODEL.md` carries this
where an auditor will read it.

## Consequences

- `keys_rotate` and `packs_import` are gated. `policy_reload` is in the
  operation enum with no command behind it: SPEC §17 names it, and a config
  naming an operation the enum did not know would be the quiet failure the
  validator exists to prevent.
- `admin.self_governed: true` with no `admin.approvers` is **refused at load**.
  A gate nobody can open is not a gate; it is an outage waiting for the first
  rotation.
- A misspelt operation name is refused at load too, for the same reason: a
  security setting an operator believes is on is worse than one that is off.
- Found while testing this: **any invalid `qed.yaml` printed a pydantic
  traceback.** `mode: nonsense` produced forty lines of frames with the answer
  in the middle. `ConfigError` now carries the file path and the field path, and
  the CLI's group handler prints it as a sentence. That was pre-existing and had
  nothing to do with self-governance; it was found because a validation test
  asserted on output that did not exist.
