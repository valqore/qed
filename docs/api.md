# HTTP API

`qed serve` runs the API from SPEC §13. Base path `/v1`. Everything is JSON;
errors are RFC 9457 `application/problem+json`.

Week 2 implements the subset SPEC §22 asks for. Routes that do not exist are
absent rather than stubbed, for the reason SPEC §14 gives about the CLI: an
endpoint that answers "not implemented" ends up in somebody's script.

| Method & path | Purpose |
|---|---|
| `POST /v1/proposals` | Submit an `ActionProposal`, get a verdict |
| `GET /v1/proposals/{id}` | The proposal and its verdict, as recorded |
| `POST /v1/proposals/{id}/result` | Report what happened when the action ran |
| `GET /v1/evidence` | Export the chain as `jsonl`, `csv` or `oscal` |
| `GET /v1/evidence/by-ref/{ref}` | Resolve an `evidence_ref` to its record |
| `GET /healthz` | Liveness. 200 while the process can serve |
| `GET /readyz` | Readiness. 503 with reasons when it cannot |

Arriving later: `/v1/token` (week 3), `/v1/approvals` (week 4), `/v1/events`
and `/v1/metrics` (weeks 4 and 7), `/v1/policies` and `/v1/admin` (week 10).

## One decision path

The router does not decide anything. It validates the body and calls
`qed.runtime.check_proposal`, which is the same function `qed check` calls.
SPEC §22's week 2 exit criterion is that both return the same verdict for the
same input, and `tests/api/test_proposals.py` asserts it by running both and
comparing the verdict field by field — not by trusting that they still share a
code path.

## Readiness

`/readyz` is false, with reasons, when any of these is true:

- **No evidence signing key.** SPEC §17. An unsigned decision is not evidence,
  so serving verdicts here would produce records nobody can verify.
- **The policy bundle has errors.** Deciding against a bundle with a broken
  regex would apply rules nobody wrote.
- **No usable adapter authentication.** SPEC §17 requires unknown adapters to
  be rejected, and an instance that cannot tell adapters apart cannot do that.

`/healthz` stays 200 through all three. They answer different questions, and an
orchestrator restarts a container whose *liveness* probe fails — restarting will
not conjure up a signing key, so a missing key must not fail there.

## Authentication

Adapters authenticate with a shared-secret MAC. Humans and admins arrive on an
OIDC bearer in week 3; this is adapter identity, and an adapter is a process in
a CI job or on a laptop with no browser to redirect.

### Registering an adapter

```yaml
# qed.yaml
adapters:
  - adapter_id: adp_laptop_ali
    secret_env: QED_SECRET_LAPTOP_ALI    # the name, never the value
    kind: mcp
```

The secret lives in the environment variable named here, so `qed.yaml` stays
safe to commit and the secret stays out of the process table. It must be at
least 32 characters: a shorter shared secret is a password somebody typed.

`qed adapters add` with per-adapter rotation is week 5 (SPEC §12.6).

### Signing a request

```
X-QED-Adapter-Id : adp_laptop_ali
X-QED-Timestamp  : 2026-10-07T12:00:00.000Z     RFC 3339, UTC, milliseconds
X-QED-Nonce      : 01JB...                       optional
X-QED-Signature  : base64url(HMAC-SHA256(secret, canonical))     unpadded
```

The canonical string is exactly five fields joined by `\n`, with nothing else:

```
METHOD \n path \n timestamp \n nonce \n sha256-hex(body)
```

- `METHOD` upper-cased. `path` without the query string.
- `nonce` is the empty string when not sent, and is still part of the MAC.
- The body digest is over the exact bytes sent. For a GET, that is `sha256("")`.

Covering the method, the path and the body means a captured signature cannot be
replayed against another endpoint or with different content. Covering the
timestamp bounds how long one stays usable: requests more than
`api.max_clock_skew_seconds` (default 300) from the server's clock are refused.

A worked example lives in `tests/api/conftest.py`, which signs through the same
`qed.api.auth` functions the server verifies with.

### Two limits in week 2

**No nonce replay cache.** Inside the skew window the same signed request can be
sent twice. It does not get two decisions — `proposal.id` is single-use, so the
second attempt is a `409` (SPEC §17, replay). The nonce is already in the MAC so
that adding the store in week 3 needs no protocol change.

**No rate limits.** SPEC §13's 100 proposals/s per adapter is week 10.

### `--dev`

`qed serve --dev` skips signature verification entirely, marks every record
`dev: true`, and records the reporting adapter as `dev-unauthenticated` so a dev
chain is honest about never having checked who was calling. It prints a warning
to stderr on start. Bind it to loopback and do not point real agents at it.

## `POST /v1/proposals`

Body: an `ActionProposal` (SPEC §3.1), or an envelope carrying context the
caller already holds:

```json
{
  "proposal": { "...": "ActionProposal" },
  "budget":   { "...": "BudgetState, optional" },
  "mandate":  { "...": "Mandate, optional" }
}
```

The envelope is the same shape `qed check --budget --mandate` takes. Budgets
become server-side state in week 3; until then whoever holds the token is the
only one who knows how much of it is left.

Response:

```json
{
  "verdict": { "decision": "REQUIRE_APPROVAL", "...": "" },
  "enforced": false,
  "effective_decision": "ALLOW",
  "evidence_ref": "3",
  "evidence_seq": [2, 3],
  "approval": null
}
```

- `enforced` is false in shadow mode, and `effective_decision` is then ALLOW
  whatever `verdict.decision` says (ADR-003). **Adapters must act on
  `effective_decision`, not on `verdict.decision`.**
- `200` normally; `202` when REQUIRE_APPROVAL is actually being enforced;
  `409` on a replayed `proposal.id`; `413` over 64 KB; `422` on a schema failure.
- `approval` is `null` rather than an empty object: there is no approval, not an
  approval with nothing in it. The approval service is week 4.

Error responses never echo the rejected input. A refused body can carry the very
secret `AG-DAT-001` exists to stop, and an error response is not masked on the
way out the way an evidence payload is; only field paths and messages come back.

## `POST /v1/proposals/{id}/result`

```json
{ "status": "ok", "http_status": 200, "error": null, "cost_actual": {"tokens": 120} }
```

`status` is one of `ok`, `error`, `skipped`, `timeout`, `deferred`.

The record's `assurance` follows the proposal's `enforcement` (SPEC §13,
ADR-007.1): `enforcing` gives `adapter`, `advisory` gives `self`. An advisory
adapter is one the agent could have gone around, so its report is the agent's
testimony and the chain says so. See `docs/assurance-classes.md`.

## `GET /v1/evidence`

| Parameter | Meaning |
|---|---|
| `from`, `to` | Sequence range, inclusive |
| `format` | `jsonl` (default), `csv`, `oscal` |
| `type` | Repeatable record-type filter |

Two response headers matter:

- `X-QED-Verifiable: true｜false`
- `X-QED-Not-Verifiable-Reason` when false

A filtered export is **not** verifiable. `qed-verify` checks that sequence
numbers are contiguous and that each record links to the previous hash, which a
`?type=verdict` export cannot satisfy. Rather than hand back something that will
fail verification later with no explanation, the response says so up front.

`format=oscal` refuses a `type` filter outright: an assessment-results document
states what was observed over a period, and one assembled from a subset would
omit observations without saying so. That document goes to an auditor. See
`docs/oscal.md`.

Up to 50,000 records per request; page with `from` and `to`. Streaming arrives
with the Postgres path in week 6.

## `evidence_ref`

SPEC §10.3 defines `evidence_ref` as an outbox id for the Postgres path, where a
decision is answered before the chain row exists. The SQLite path appends inside
the decision, so there is no outbox and the ref *is* the sequence number.
`GET /v1/evidence/by-ref/{ref}` exists now so that adapters are written against
it and need no change in week 6.

## One connection, one thread

Every handler is `async def`, so it runs on the event loop thread. The SQLite
connection belongs to the thread that opened it, and `check_proposal` contains no
`await`, so two concurrent requests cannot interleave inside it and `seq` stays
contiguous. A `def` handler would be run in a threadpool by Starlette and would
touch that connection from the wrong thread.

This constraint is load-bearing until the Postgres pool and chain leader arrive
in week 6. `tests/api/test_proposals.py` submits concurrently and asserts the
sequence has no gaps, which is what would catch its removal.
