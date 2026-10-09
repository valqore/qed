# ADR-0007 — `GET /v1/status` for the UI badge, and it does not verify

**Status:** accepted · week 4 (2026-10-08)
**Adds to:** SPEC §13's route table
**Required by:** SPEC §19 ("chain status badge (`seq`, last checkpoint age, verify ok)")

## Context

SPEC §19 says every UI page carries a chain status badge showing the sequence
number, the age of the last checkpoint, and whether verification passes. SPEC
§13's route table has no endpoint that answers any of the three, and §13 is
otherwise exhaustive — every other route the UI needs is in it.

Three existing endpoints were considered first:

| Endpoint | Why not |
|---|---|
| `GET /readyz` | Deliberately open, with no credential. It answers "can this instance decide", which is a different question, and widening it would put chain internals on an unauthenticated route. |
| `GET /v1/evidence/verify?from&to` | Re-reads and re-verifies the range. That is the right cost for an auditor's one-off and the wrong cost for something a page polls every few seconds. |
| `GET /v1/evidence?...` | Streams records. The badge needs three numbers, not the chain. |

The CLI already has the answer: `qed status` prints `chain_status(session)`.
It was simply never reachable over HTTP.

## Decision

**One route beyond SPEC §13's table: `GET /v1/status`.** It returns
`chain_status(session)` — the same function `qed status` prints, so the page
and the CLI cannot come to different conclusions about one instance — plus
`last_checkpoint_age_seconds`, which the badge needs and the CLI did not.

It authenticates like the other routes a browser reaches: an adapter signature
or a verified OIDC bearer, via `authenticate_caller`. It is not open.

**It does not verify the chain, and says so in the response.**
`verified` is always `null`, beside a `verify_with` field naming the real
procedure. Two reasons, and the second is the one that decided it:

1. Re-verifying on every poll is expensive, and a badge is polled.
2. **A verdict this instance delivers about its own chain is worth almost
   nothing.** The entire design is that an auditor exports the chain and runs
   `qed-verify` against it with the public key, trusting nothing in this
   process. A green tick served by the thing being audited would invite
   exactly the reading the architecture exists to prevent — and SPEC §19's own
   wording, "verify ok", is a trap worth refusing rather than implementing.

So the field is present and explicitly empty. A page that wants to show
something can show "not verified here", which is true, rather than a tick that
means less than it looks.

## Consequences

- SPEC §13's route table is no longer the complete list of `/v1` routes. This
  ADR is the amendment; a reader of §13 needs to know to look here.
- `SqliteStore.last_checkpoint()` now returns a `Checkpoint` named tuple
  carrying `evidence_seq`, because dating a checkpoint needs the seq of its own
  record. The old positional reads still work. `seq_to + 1` was the alternative
  and was rejected: it is true for a writer that checkpoints immediately, and
  an arithmetic guess about where a record lives stays correct until the day it
  does not.
- If a future `verified` field is ever wanted, it must come from a verifier
  that is not this process — a sidecar with only the public key, or a published
  checkpoint receipt (SPEC §10.5). Filling it in from inside would be the thing
  this ADR refused.
