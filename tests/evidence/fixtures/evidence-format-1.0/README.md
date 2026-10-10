# Evidence format 1.0 — conformance fixture

A real evidence chain, produced by `qed` on **10 October 2026**, committed here
and never regenerated. `docs/evidence-format.md` is the specification; this is
the acceptance test for it.

Two audiences:

- **Anyone writing a second verifier.** Point it at `chain.jsonl` and `public/`.
  If it agrees with the numbers below and rejects every mutation in the table,
  it reads 1.0.
- **This repository, forever.** `tests/evidence/test_frozen_format.py` loads
  these bytes on every CI run and checks that today's producer still hashes them
  the same way. That is the promise in SPEC §25.6 made executable: a record
  written today verifies under every later verifier.

## Do not regenerate it

`generate_1_0.py` in the parent directory is the script that produced it, kept
so the records are explicable rather than taken on trust. Running it again
replaces a 2026-10-10 artefact with one made by whatever the code is now, and
every cross-version check in the suite silently becomes a check that today's
code agrees with itself. The test pins this directory's digest for that reason;
a failure there is a signal, not a chore.

A new format version gets a **new directory**, and 1.0 goes on being verified
beside it.

## What is in it

```console
$ qed-verify chain.jsonl --keys public --instance-id qed-conformance-1.0
records   : 14 (seq 0..13)
keys      : ed25519:464e88767c380dcd, ed25519:e4b402f9126abfa9
checkpoint: 2
purged    : 1 payload(s) removed under retention
result    : OK -- chain is contiguous, unmodified and signed
```

| seq | type | why it is here |
|---|---|---|
| 0 | `genesis` | `prev_hash` binds the chain to `qed-conformance-1.0` |
| 1 | `policy_loaded` | the rules in force, with their bundle hash |
| 2 | `proposal` | **payload purged** — five days old, two-day retention on `proposal` |
| 3 | `verdict` | ALLOW: `examples/proposals/github-read.json` |
| 4 | `proposal` | `examples/proposals/prod-db-drop.json` |
| 5 | `approval_requested` | the rule named the groups that may decide |
| 6 | `verdict` | REQUIRE_APPROVAL |
| 7 | `approval_decided` | approved by a different human, in a named group |
| 8 | `proposal` | `examples/proposals/open-ingress.json` |
| 9 | `verdict` | BLOCK |
| 10 | `key_rotated` | **signed by the retiring key** — the rotation rule |
| 11 | `checkpoint` | Merkle root over 0–10 |
| 12 | `admin_action` | the retention purge recording itself |
| 13 | `checkpoint` | Merkle root over 11–12, so every record is under exactly one root |

Three decisions, three outcomes — ALLOW, REQUIRE_APPROVAL with a real
separation-of-duties check, and BLOCK — because a fixture in which everything is
allowed would not exercise the approval records at all.

The timestamps are spread over five days and the public keys are committed in
`public/`. There is no private key here: the chain cannot be extended, which is
the correct state for a published artefact.

**Nine of the eighteen record types are in it**, listed above. The other nine —
`executed`, `execution_result`, `budget_update`, `budget_exhausted`,
`mandate_issued`, `mandate_revoked`, `approval_expired`, `ungated_window`,
`correction` — are absent, and nothing here should be read as covering them. For
a verifier it makes no difference: `type` is one string among the six hash
inputs, so a record of any type hashes and verifies identically, and a
conforming verifier must not reject a type it does not recognise
(`docs/evidence-format.md`, conformance). For a reader wanting to see what a
budget exhaustion looks like, the place to look is `examples/` and the golden
suites, not here.

## What a conforming verifier must reject

Each row is a single mutation of `chain.jsonl`. `qed-verify` reports the code in
the third column; `tests/evidence/test_frozen_format.py::TestTheFrozenChainIsTamperEvident`
applies every one of them to these exact bytes, so the table is tested rather
than asserted.

| # | Mutation | Expected code |
|---|---|---|
| 1 | Edit any present `payload` | `payload_tampered` |
| 2 | Delete a record from the middle | `sequence_gap` |
| 3 | Swap two adjacent records | `broken_link` |
| 4 | Edit a `prev_hash` | `broken_link` |
| 5 | Edit a `ts` | `hash_mismatch` |
| 6 | Replace a `sig` with another record's | `bad_signature` |
| 7 | Drop record 0 | `not_from_genesis` |
| 8 | Claim a different `instance_id` | `genesis_mismatch` |
| 9 | Withhold one of the two public keys | `unknown_key` |
| 10 | Edit the `merkle_root` in a `checkpoint` | `checkpoint_mismatch` |
| 11 | Re-sign the `key_rotated` record with the new key | `rotation_discontinuity` |
| 12 | An empty file | `empty` |

Mutation 9 is the one most often got wrong, and it is the one that matters
most: a verifier that *skips* a record whose key it was not given will report a
forged chain as clean. The code must be a failure.

Mutation 11 cannot be performed on these bytes — re-signing a record needs the
private key, and there is deliberately none here. It is covered against a
freshly written chain in `tests/evidence/test_chain.py` instead, and listed in
this table because a verifier has to handle it.
