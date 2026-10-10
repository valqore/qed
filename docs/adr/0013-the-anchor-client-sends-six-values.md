# ADR-0013 — The anchor client sends six values, and the operator names the log

**Status:** accepted · week 9 (2026-10-10)
**Implements:** SPEC §10.4 (checkpoint publishers), §16 (`remote.anchor`), invariant §1.7
**Relates to:** ADR-0012 (pack bundles), the publisher seam in `qed/infra/publishers/`

## Context

A checkpoint is a Merkle root over a range of the chain, signed and appended
like any other record. On its own it proves only that the instance was
internally consistent *at the moment an auditor read it*: an operator who
rewrote the chain could recompute every root and every signature, and nothing
in the export would say so. Publishing the root outside the instance's control
is what closes that.

Three publishers already existed — a file, an S3 bucket with object-lock, a
signed git tag — and all three copy the **whole checkpoint record**, because
all three copy it into infrastructure the operator owns.

`qed.remote.anchor` is the first publisher that sends anything to a third
party. That changes what may be sent.

## Decision 1 — Six values, not the record

Invariant §1.7 promises that every `qed.remote.*` feature "carries no customer
data (hashes/signatures only)". The checkpoint record is not that.

SPEC §10.4 requires that "the **next** checkpoint's payload includes the
previous checkpoint's receipts", and a receipt's `target` is where it was
published: `s3://acme-internal-qed-anchors/…`, or
`git@github.com:acme-finance/qed-anchors.git`. Posting the record to an anchor
service would hand it a running inventory of the operator's bucket names and
git remotes — infrastructure nobody consented to publish, arriving as a side
effect of a privacy-conscious feature.

So the body is exactly:

```json
{"log_id": "...", "seq": 7, "hash": "...", "merkle_root": "...",
 "key_id": "...", "sig": "..."}
```

Every one of those is a value the auditor already holds in their export, so the
log learns nothing new and the auditor can check the log's entry against their
own copy. `from_seq`, `to_seq` and `published_to` stay home. A test renders the
body and fails if the bucket name or the git remote appears in it.

**The consequence, stated plainly: the log cannot verify that the signature
covers a meaningful payload**, because it never sees the payload. It does not
need to. A transparency log's job is "this value existed at this time", and the
value is a hash whose preimage the auditor holds. The log is a witness, not a
verifier. Any future inclusion-proof work in `qed-verify` (SPEC §24.3) checks
the hash, which is what is logged.

## Decision 2 — `log_id` is required, with no default

A log has to scope entries somehow, and qed has nothing honest to offer.

`instance_id` is a customer-chosen string: `acme-prod-qed` names a company and
an environment. It is also not on the checkpoint record at all, which is itself
a good sign about what a record carries. Hashing it was the first design and is
cleverness in the wrong place — a hash the operator cannot predict, in somebody
else's log, chosen by us on their behalf.

Deriving one from the signing key is worse: `qed keys rotate` would silently
move an instance's entries to a different scope, splitting its own history in
the log at exactly the moment an auditor most wants continuity.

So the operator writes the name their entries carry in a third party's log. It
is their decision, and a default would have made it for them quietly.

## Decision 3 — https only, and the token comes from the environment

The root is the evidence that the chain was not rewritten. Over plain http an
observer sees every root and a middlebox can replace them, so `from_config`
refuses a non-https URL rather than warning.

A `token:` or `secret:` key in the publisher's config block is refused with a
pointer to `token_env`, per SPEC §16's "secrets never in `qed.yaml`". The token
goes in an `Authorization: Bearer` header and never in the body; a test asserts
the body does not contain it. The environment is read at **publish** time, not
at construction, because config loads at startup and a secret may arrive later —
and an empty `token_env` returns a failed receipt without sending anything,
since a request that was going to be rejected is one fewer entry in somebody's
access log.

## Decision 4 — Only the log's attestation is kept, and only by name

A receipt lands in the chain, which is immutable. A log that answered with a
kilobyte of banner text would put a kilobyte in the chain for good.

So the proof keeps the status code plus `log_index`, `log_id`,
`inclusion_proof`, `signed_timestamp` and `tree_size` — the fields a
transparency log's attestation actually consists of — and drops everything
else. An error body is truncated to 200 characters for the same reason. qed
does not interpret the attestation; storing it as given is the point.

## Decision 5 — Configured as a publisher, not under `remote:`

SPEC §16 sketches `remote: {anchor: {enabled: false, url: …}}`, and SPEC §10.4
lists `qed.remote.anchor` among the checkpoint publishers. Those are two
configuration paths to one feature.

The publisher list is the one that exists, that the maintenance pass reads, and
that already expresses "two anchors, and one of them working is useful". A
second spelling under `remote:` would be a second source of truth for which
anchors are live, and the failure mode is an operator setting one and reading
the other.

So: `evidence.checkpoint.publishers: [{type: qed-anchor, url: …, log_id: …}]`,
and `remote` stays in `UNIMPLEMENTED_SECTIONS` — which is the accurate thing
for `qed doctor` to report, since no key under it is read.

## Consequences

- An anchor failure is a receipt with `ok=False`, like every other publisher: a
  log that has gone away costs one checkpoint's latency and never the chain's
  progress. The default timeout is 5 s because this runs inside the maintenance
  tick that also drains the outbox.
- `httpx` is imported inside `publish`, so an instance with no anchor
  configured pays nothing for it — the same discipline the S3 publisher follows
  with boto3. A test asserts the import is not at module scope.
- The log **server** is not in this repository and will not be: SPEC §24.2 puts
  the transparency log in `qed-cloud`, on the proprietary side. What is here is
  the client and a stub server in `tests/evidence/test_anchor_client.py`, which
  is what SPEC §22 week 9 asked for.
- The client is tested against a real HTTP server in a thread rather than a
  mocked `httpx`, because the thing worth asserting is what crosses the wire,
  and a mock only tells you what the code meant to send.
