# Threat model

**Status:** week 10, for the first auditor session. SPEC §17 names this file and
lists nine MUSTs; the last two were built in week 10 and this document says
which, where, and how far.

This is written for somebody who has to decide whether the evidence qed produces
is worth anything. So it leads with the limits rather than the controls: the
section you want is [What qed does not
protect against](#what-qed-does-not-protect-against), and it is deliberately
longer than the STRIDE table.

One claim runs through everything below, and it is the only one worth testing:
**an auditor can verify what happened without trusting the instance that
recorded it.** `qed-verify` is a separate package with one dependency
(`cryptography`), written against the format rather than against the
implementation. Where a control depends on trusting the instance, this document
says so.

---

## What is being protected

Three things, in this order.

1. **The chain's integrity.** A record that was written cannot be changed or
   removed without that being detectable by somebody holding only the public
   keys.
2. **The decision's honesty.** A verdict says what the policy actually
   concluded, and the record says how much of it was *enforced* rather than
   merely observed.
3. **The confidentiality of what passes through.** Credentials never reach the
   chain, logs or events; action parameters reach it only as the adapter
   already redacted them.

Note what is *not* on that list: preventing the action. qed prevents an action
only where an adapter holds the credential it needs (`assurance: adapter`). On
every other path it decides and records, and the agent could proceed anyway.
That is the first limitation below and it is not a gap to be closed later — it
is the shape of the product.

---

## Trust boundaries

```
  agent ──① adapter ──② API ──③ kernel ──④ store
                         │                   │
   operator ──⑤ CLI ─────┘                   │
                                             │
  third party ──⑥ pack bundle                │
  anchor log  ──⑦ (outbound only)            │
                                             │
  auditor ──⑧ export + qed-verify ───────────┘
```

| | Boundary | What crosses it | Trusted? |
|---|---|---|---|
| ① | agent → adapter | tool calls, parameters | **No.** The agent is the subject of the policy. |
| ② | adapter → API | signed `ActionProposal` | Authenticated per adapter (HMAC over a canonical string). The *contents* are not trusted. |
| ③ | API → kernel | parsed proposal | Validated; unknown fields rejected. |
| ④ | kernel → store | signed records | Trusted within the instance. An operator with database access can write here, which is what anchoring addresses. |
| ⑤ | operator → CLI | admin operations | **Self-asserted identity.** See limitation 2. |
| ⑥ | third party → pack bundle | control catalogues | **No.** Signature required by default (ADR-0012). |
| ⑦ | instance → anchor log | six values, outbound only | The log is not trusted with anything: it receives hashes (ADR-0013). |
| ⑧ | store → auditor | JSONL export | Verified independently; the instance is not trusted. |

---

## STRIDE

### Spoofing

| Threat | Control | Where |
|---|---|---|
| An unknown adapter submits proposals | Adapter authentication is mandatory; unknown adapter ids are refused | `qed/api/auth.py`; a sweep in `tests/api/test_auth.py` walks every `/v1` route and asserts an unsigned request cannot get a 2xx |
| A replayed signed request | Timestamp window (`api.max_clock_skew_seconds`, 300s) plus nonce | `qed/api/auth.py` |
| An agent claims a human principal it does not have | Delegation token; `AG-IDN-001` blocks a proposal with no token | `qed/core/delegation/` |
| A token from another issuer or audience | Issuer allow-list, `alg` fixed per issuer, audience checked | `qed/core/delegation/claims.py` |
| An approver approves as somebody else | **Not prevented on the CLI.** See limitation 2 | — |

### Tampering

| Threat | Control | Where |
|---|---|---|
| A record is edited in the database | `payload_hash` → `hash` → next record's `prev_hash`; any edit breaks linkage | `qed-verify` reports the first broken link |
| A record is deleted | `seq` is contiguous; a gap is reported | `qed-verify` |
| The whole chain is rewritten by the operator | **Only detectable with an anchor.** Checkpoint roots published outside the instance (S3 object-lock, git tag, transparency log) | `qed/infra/publishers/`, `qed/remote/anchor.py`. `qed doctor` says "anchors: none" in yellow when there are none, because without one this row is not covered |
| A forged history signed with a leaked key | Rotation **destroys** the old private key; `key_rotated` is signed by the retiring key | ADR-0010 |
| A chain from another instance is substituted | `genesis` binds `instance_id`; the writer refuses a mismatch | `InstanceMismatch` |
| A control catalogue is swapped to change what an export claims | Pack bundles are signed; an import is an `admin_action` carrying the bundle hash and key id | ADR-0012 |
| An imported catalogue is rolled back to remove a mapping | A bundle older than the installed one is refused | `check_not_older` |

### Repudiation

| Threat | Control | Where |
|---|---|---|
| "The agent never proposed that" | Every proposal is a record, before the verdict | `proposal` + `verdict` records |
| "Nobody approved that" | `approval_decided` carries the approver's hash | SPEC §9.3 |
| "The policy said something else at the time" | `policy_loaded` records the bundle hash; every verdict references it | `_record_bundle_once` |
| "The control labels meant something else" | An unsigned catalogue sets `unsigned: true` on every later `policy_loaded` | ADR-0012 |
| "The operator rotated the key quietly" | `keys_rotate` writes an `admin_action` saying whether it was approved, by whom, or that break-glass was used | ADR-0014 |
| Retention erased the evidence | `admin_action` records every purge and is itself in `NEVER_PURGE`; structural records are never purged | `qed/core/evidence/retention.py` |

### Information disclosure

| Threat | Control | Where |
|---|---|---|
| A credential reaches the chain | Broker credentials are in memory only; never in records or events | `qed/core/broker/` |
| A secret reaches the chain via parameters | Adapters redact before sending; `params_hash` still covers the originals; `AG-DAT-001` blocks secret material outright | `qed/adapters/common.py` |
| Masking removes too much, or too little | Profiles, with `STRUCTURAL_TYPES` never masked — a `key_rotated` payload holds a public key, a `checkpoint` holds its root | `qed/core/evidence/masking.py` |
| An anchor log learns the operator's infrastructure | The anchor sends six values and no payload; a checkpoint payload carries the previous receipts, which name buckets | ADR-0013 |
| An approval queue accumulates secrets | An approver sees the already-redacted parameters, never the raw call | SPEC §9.2 |
| An error message leaks a DSN | The Postgres DSN is never echoed, including in `qed doctor` | `qed/infra/storage/postgres.py` |

### Denial of service

| Threat | Control | Where |
|---|---|---|
| A caller floods the API | Per-adapter and per-principal token buckets, 429 with `Retry-After`; a refusal writes nothing to the chain | `qed/core/ratelimit.py` |
| An oversized proposal | 64 KB proposal, 16 KB `params_redacted` | `qed/adapters/common.py` |
| A catastrophic regex in a rule | `regex` module with a 100 ms timeout | `qed/core/policy/predicates.py` |
| A malformed input crashes a parser | Fuzzed: a malformed input yields the refusal its caller handles | `tests/test_fuzz_parsers.py` |
| An unreachable database hangs every command | `connect_timeout` (10s) | `qed/infra/storage/postgres.py` |
| An unreachable anchor stalls the chain | A publisher returns a failed receipt; it never raises | `qed/infra/publishers/__init__.py` |
| A third party's catalogue stops the kernel deciding | An import that would orphan a rule's control reference is refused before anything is written | ADR-0012 |

### Elevation of privilege

| Threat | Control | Where |
|---|---|---|
| An agent edits the policy it is judged by | `AG-IDN-009` blocks any action targeting qed's own keys, policy or evidence | `identity-extended.yaml` |
| An agent approves its own action | `check_separation_of_duties`: the approver may not be the principal (`AG-SOD-001`), must be a person and must be in the named group (`AG-SOD-002`) | `qed/core/approval/model.py` |
| An agent escalates through a delegation chain | `AG-IDN-002` requires approval beyond two hops; budget is charged along the chain | SPEC §6 |
| An operator changes a key or catalogue unobserved | Self-governance: an approval with SoD, or a recorded break-glass | ADR-0014 |
| An approval for one thing is spent on another | An admin approval is bound to its operation and spent once | ADR-0014 |
| An agent reaches the metadata service or a credential endpoint | `AG-DAT-013`, `AG-SKL-006` | baseline pack |

---

## What qed does not protect against

This is the section to read twice.

### 1. On most paths, qed does not stop anything

An adapter *enforces* only when it holds the credential the action needs — the
MCP proxy with a brokered credential, the HTTP proxy for a host it fronts. Those
records carry `assurance: adapter`.

Everywhere else — the Claude Code hook, the Python SDK, an advisory proxy — the
agent holds its own credentials and qed is **advisory**. It decides and records,
and a determined agent (or a developer who removes the hook) can act anyway.
`docs/assurance-classes.md` is the page an auditor should read next: it maps
`enforcement: advisory` to `assurance: self` so the distinction is in every
record rather than in a footnote. `qed doctor` prints *"every adapter is
ADVISORY"* when no upstreams are configured.

What the evidence then supports is *"this is what the agent proposed and what
policy concluded"*, not *"this is what the agent was able to do"*.

A fail-open adapter that cannot reach the kernel writes an `ungated_window`
record, so a gap in coverage is visible rather than silent.

### 2. On the CLI, identity is self-asserted

`qed approve --by you@example.com` takes your word for it, and so does
self-governance's `--by`. The CLI runs on the operator's own machine; there is
no token to check.

So self-governance on the CLI buys **two separate invocations naming two
separate subjects**. That is a real obstacle to a careless action and no
obstacle at all to one operator who lies about who they are. Identity is proven
only on the API path, where a delegation token says who is asking — which means
the web approval page with OIDC, not the terminal.

Claiming cryptographic separation of duties here would be the same kind of
overclaim as a compliance mapping nobody checked.

### 3. An operator with database access can rewrite the chain, and only an anchor catches it

Everything in the Tampering table detects edits *by somebody who cannot
recompute the signatures*. An operator holding the signing key can rewrite
every record and every hash, and the export will verify.

The only defence is a checkpoint root published where the instance cannot
change it (`evidence.checkpoint.publishers`). An instance with none configured
has no answer to this threat, which is why `qed doctor` says so in yellow
rather than reporting "anchors: none" as a neutral fact.

### 4. Break-glass bypasses self-governance by design

`--break-glass "<reason>"` rotates a key with no approval. It exists because
the reason to rotate is that the key may have leaked, which is exactly when the
approver is asleep — and because a gate with no bypass gets bypassed outside the
tool, where nothing records it.

It costs a permanent `admin_action` with the reason, and `admin_action` is in
`NEVER_PURGE`. An auditor should expect to find break-glass uses and ask about
each one.

### 5. Rate limits are per process

Four replicas with `per_adapter_rps: 100` admit 400/s between them.
`GET /v1/status` reports `scope: "this process only"`. A shared limiter would
need Redis or a database write per proposal; the honest number is the one
reported.

### 6. The clock is not verified against anything

qed does not query NTP — it is offline by design. It warns when the newest
record's timestamp is more than 5 seconds in the future, which catches a
clock that went backwards. It cannot detect a clock that is *consistently*
wrong, so timestamps are only as good as the host's clock.

Record *order* does not depend on this: `seq` and `prev_hash` fix it.

### 7. A signed pack bundle is only as trustworthy as its publisher

Signature verification proves a bundle came from the key you supplied. It says
nothing about whether the control titles in it are accurate. qed's own
catalogues were written against the standards' published material (ADR-0011);
an imported one carries whatever its publisher wrote.

### 8. Shadow mode is the shipped default

A rule in `mode: shadow`, or an instance in `mode: shadow`, records and does not
stop. The verdict records carry `enforced: false` and the OSCAL export marks
shadow findings, so an auditor reading one should not read it as a control that
worked — but the default means a fresh install enforces nothing.

### 9. The kernel judges what the adapter tells it

A verdict is about the `ActionProposal`, and the proposal is what the adapter
chose to send. An adapter that summarises an action inaccurately — by accident
or otherwise — gets an accurate verdict about an inaccurate description.

`params_hash` covers the *original* parameters even when
`params_redacted` is trimmed, so a later dispute can prove what the adapter had
in hand. But nothing in the kernel can tell whether
`name: "postgres.execute_sql"` with a harmless-looking statement was really a
harmless statement. The adapters in this repository are the ones to read for
that; a third-party adapter is a trust decision of its own, which is why
adapters authenticate individually and the records say which one spoke.

### 10. Coverage is a property of the rules, not of qed

An action no rule matches gets the bundle default — `AG-DEF-001`, and `ALLOW`
unless the deployment changed it. The baseline pack is 46 rules; nobody should
read that as "everything dangerous is covered".

`qed packs list` reports which controls the installed rules claim and, more
usefully, which they do not. The honest reading of an export is "these rules
examined these actions", and the gap between that and "the agent did nothing
bad" is exactly the size of the gap in the rules.

### 11. Not yet built

- `mode: mitm` for the HTTP proxy: a `CONNECT` tunnel is decided on the host
  name and SNI only, so the path and body are not seen.
- The Codex hook (its API is unconfirmed).
- The `remote.packs` URL feed; air-gap import only.
- The transparency log itself (the client is here; the log is not in this
  repository).

---

## SPEC §17's nine MUSTs

| MUST | State |
|---|---|
| Refuse to start without an evidence signing key (`readyz=false`) | Built. `qed/api/app.py` |
| Admin operations through approval with SoD and `admin_action` | Built week 10 for `keys_rotate` and `packs_import`, the two that exist. Off by default; see limitation 2 (ADR-0014) |
| Broker credentials in memory only; redacted everywhere | Built |
| Adapter authentication mandatory; unknown adapters rejected | Built |
| Duplicate `proposal.id` → 409, no evidence written | Built |
| Clock: warn if drift > 5s; `seq` guarantees order | Built week 10, measured locally rather than against NTP; see limitation 6 |
| Input limits and regex timeouts | Built, and fuzzed week 10 |
| Supply chain: SBOM, cosign, provenance | In `release.yml`; signing is **gated off** until the SPEC §24.1 name reservations are done |
| Dependencies pinned; `pip-audit` in CI | Built week 10: its own job, on push and daily |

---

## Reporting a vulnerability

`SECURITY.md`. Please do not open a public issue for anything in the Tampering
or Elevation of privilege tables.
