# Evidence format 1.0

**Status: Frozen, 10 October 2026** (SPEC §22 week 12, ADR-0015).

`schema_version: "1.0"`. This document is the specification of what a conforming
verifier checks. It is normative: where this page and any implementation
disagree, this page and the frozen fixture in
`tests/evidence/fixtures/evidence-format-1.0/` are right and the implementation
has a bug.

## What freezing commits to

Three promises, in the order they matter to somebody deciding whether to put
their audit trail in this format.

**A record written under 1.0 verifies under every later verifier, forever.** Not
"for the 1.x line" and not "while we support it". The frozen fixture is a real
export produced on 10 October 2026 — fourteen records including a rotation, two
checkpoints and a purged payload — committed to the repository and verified by
CI on every change. It is never regenerated: the test that loads it pins its
digest, so refreshing it is a visible edit in two places rather than a quiet
one. The day the producer and the verifier change together in a way that stops
reading those bytes, CI fails. See `tests/evidence/test_frozen_format.py`.

**Any change to the hash input or the record fields is a new
`schema_version`, with an ADR.** Not a patch release, not a "clarification". A
new version needs its own frozen fixture before CI will go green, which is
enforced rather than remembered: `schema_version` is a `Literal` in
`qed/core/schemas.py`, and bumping it fails
`test_every_schema_version_the_code_can_write_has_a_fixture` until the records
exist.

**`qed-verify` keeps every version it has ever been able to read.** It is a
separate package whose only dependency is `cryptography`, and it reimplements
canonicalisation and the record hash from this page rather than importing them
from the producer — a shared helper would mean a bug in the producer verifies
cleanly.

An auditor needs three things and nothing else: the records, the public keys,
and `qed-verify`. No access to the instance, no cooperation from the operator,
no trust in either.

## What is *not* frozen

Freezing the wrong amount is how a format becomes unimprovable, so the boundary
is written down.

| Free to change | Why it is outside the freeze |
|---|---|
| The **contents** of a payload | `payload_hash` covers whatever bytes were there. A verifier checks that the payload hashes to the recorded digest; it has no opinion about the fields inside it. New fields in a `verdict` payload are additive and break nothing. |
| The **masking pattern set** | Masking runs before hashing, so a new pattern changes what *future* records contain. It cannot change a record already written, and a verifier never re-derives the mask. |
| The **baseline rule pack**, control catalogues, `policy_hash` | Policy is data the chain records, not part of how it is read. |
| `engine_version` in a verdict | Deliberately in the record so an auditor can ask which build decided; deliberately not in the hash input. |
| Export *containers* — CSV, OSCAL | Renderings of the same records. JSONL is the one a verifier reads. |

| Frozen | Why it is inside |
|---|---|
| The six hash inputs and their order | Changing any of them changes every hash. |
| `0x1F` as the separator, and the two domain prefixes | A chain is bound to them. |
| The field names and types in the table below | A verifier reads them by name. |
| Base64url-without-padding for `sig`, lowercase hex for digests | Spelling is part of the bytes. |
| RFC 3339 UTC with exactly three fractional digits and `Z` | The timestamp is hashed as its string. |
| RFC 8785 canonicalisation, with integers limited to ±(2⁵³−1) | `payload_hash` depends on it. |
| The reserved `_`-prefixed payload keys | SPEC §10.2; a caller payload using one is rejected. |
| The Merkle construction, duplicate-last-node included | A root is not recomputable without it. |
| `key_rotated` is signed by the **old** key | The one rule that makes rotation one chain. |

## A record

```json
{
  "schema_version": "1.0",
  "seq": 3,
  "ts": "2026-10-07T09:14:22.431Z",
  "type": "verdict",
  "assurance": "kernel",
  "mode": "shadow",
  "enforcement": "enforcing",
  "dev": false,
  "payload_hash": "9f2c…",
  "payload": { "...": "...", "_assurance": "kernel", "_key_id": "ed25519:7f05…" },
  "prev_hash": "41ab…",
  "hash": "c7d0…",
  "key_id": "ed25519:7f05ae6076e7f9cd",
  "sig": "MEUCIQ…"
}
```

| Field | Rule |
|---|---|
| `seq` | starts at 0, strictly +1, no gaps, no reuse |
| `ts` | RFC 3339 UTC, exactly three fractional digits, always `Z` |
| `type` | one of the closed set in SPEC §3.5 |
| `assurance` | `kernel` / `broker` / `adapter` / `self` — who vouches (ADR-007) |
| `payload` | redacted; may become `null` after retention |
| `payload_hash` | `sha256(JCS(payload))`, never purged |
| `key_id` | `ed25519:` + first 16 hex of `sha256(raw public key)` |
| `sig` | base64url **without padding**, over the 32 raw bytes of `hash` |

## Canonicalisation

RFC 8785 (JCS). Object keys sort by UTF-16 code unit. Numbers follow ECMAScript
`Number::toString`. Integers outside ±(2⁵³−1) are rejected rather than rounded:
a number that cannot round-trip has no business in a hash.

## The hash

```
H    = SHA256( schema_version ‖ 0x1F ‖ seq ‖ 0x1F ‖ ts ‖ 0x1F ‖ type ‖ 0x1F ‖ payload_hash ‖ 0x1F ‖ prev_hash )
hash = hex(H)
sig  = base64url_nopad( Ed25519_sign(H) )
```

0x1F joining is unambiguous only because no field can contain 0x1F:
`schema_version` is a literal, `type` is a closed enum, `seq` is an integer, the
two hashes are hex, and `ts` is machine-formatted.
`tests/evidence/test_hashing.py` pins that.

The hash covers `payload_hash`, **not** the payload. That is what lets a purged
record verify forever.

Genesis: `seq = 0`,
`prev_hash = sha256("evidence-chain/1:genesis:" + instance_id)`. The chain is
therefore bound to one instance identity, and two instances cannot splice their
chains together.

Principals: `principal_hash = sha256("evidence-chain/1:principal:" + issuer +
":" + subject)`.

Those two prefixes, and the `chain_format` value `evidence-chain/1` in the
genesis payload, are the whole of the format's fixed vocabulary. They carry no
product name on purpose — a brand inside a hash input would make renaming the
product break every existing chain, and the product *was* renamed, from `gate`
to QED, on 8 October 2026 without touching a single record. See ADR-0006;
`tests/evidence/test_format_constants.py` pins the bytes.

## Reserved payload keys

SPEC §10.2 requires `assurance`, `mode`, `enforcement`, `dev` and `key_id` to be
inside the payload so `payload_hash` covers them, and mirrored as columns for
querying. They are written as `_assurance`, `_mode`, `_enforcement`, `_dev`,
`_key_id`. A caller payload using one of those names is **rejected**, not
overwritten — see `docs/adr/0005-record-encoding.md`.

## Masking

Masking runs **before** hashing (`qed/core/evidence/masking.py`). A secret
therefore never reaches `payload_hash` in the clear and no later purge is needed
to remove it.

The pattern set is outside the freeze, and the reason is worth being precise
about, because the previous version of this page said the opposite. Masking
changes what a record *contains* before it is hashed, so adding a pattern
changes future records and cannot change one already written. A verifier never
re-derives the mask — it hashes the payload as it finds it. So the pattern set
is a producer-side policy, and improving it is not a format change.

## Checkpoints

Every 1,000 records or 3,600 seconds, whichever comes first. The payload carries
`from_seq`, `to_seq`, `merkle_root` and `records`. The tree is binary over the
record `hash` values as raw bytes; when a level is odd the last node is
duplicated.

A checkpoint cannot cover itself — its hash depends on the root it carries — so
each range begins at the *previous checkpoint's own record*. Every record in the
chain, checkpoints included, ends up under exactly one root.

Publication receipts are not written back into the record they describe (that
would be a hash cycle). They land in the `checkpoints` table and appear in the
*next* checkpoint's payload.

## Key rotation

`key_rotated` carries `old_key_id`, `new_key_id` and `new_public_pem`, and is
signed by the **old** key. That single rule is what makes rotation one
verifiable chain instead of two unrelated ones. `qed-verify` reports
`rotation_discontinuity` if a rotation record is signed by the new key.

## Retention and personal data

`payload` may be removed per type after its retention period;
`payload_hash`, `hash`, `prev_hash` and `sig` never are. Principals appear only
as salted hashes; the hash-to-identity mapping lives in the erasable
`principals` table, outside the chain (ADR-005).

Some payloads are structural and may never be purged, whatever the policy says:
a `checkpoint`'s root, a `key_rotated`'s public key, `genesis`, `policy_loaded`
and the `admin_action` records of the purges themselves. That is a correctness
constraint, not a preference — see `qed/core/evidence/retention.py`.

## What `qed-verify` reports

| Code | Meaning |
|---|---|
| `not_from_genesis` | the export does not start at `seq` 0 |
| `genesis_mismatch` | record 0 does not belong to the claimed instance |
| `sequence_gap` | a record is missing or reordered |
| `broken_link` | `prev_hash` does not match the previous `hash` |
| `hash_mismatch` | `hash` does not match the record's own fields |
| `payload_tampered` | `payload_hash` does not match the payload |
| `unknown_key` | no public key was supplied for this `key_id` |
| `bad_signature` | the signature does not verify |
| `rotation_discontinuity` | a rotation record was signed by the wrong key |
| `checkpoint_mismatch` | the Merkle root does not match the range |
| `checkpoint_range_missing` | the range is not fully present in the export |
| `empty` | nothing to verify — reported as a failure, not a pass |

## Conformance

An independent implementation may call itself a conforming 1.0 verifier when it
does all of the following. The list is deliberately short; everything in it is
checkable against the fixture.

It MUST, given a JSONL export and a set of Ed25519 public keys:

1. Reject an export that does not begin at `seq` 0, and one with a gap or a
   repeat in `seq`.
2. Check `prev_hash` of record *n* against `hash` of record *n−1*, and, when the
   instance id is supplied, record 0's `prev_hash` against
   `sha256("evidence-chain/1:genesis:" + instance_id)`.
3. Recompute `hash` from the six inputs above, using `payload_hash` and never
   the payload, so a purged record still verifies.
4. Recompute `payload_hash` by RFC 8785 canonicalisation whenever the payload is
   present, and skip that check — not fail it — when the payload is `null`.
5. Verify `sig` as Ed25519 over the 32 raw bytes of `hash`, under the key named
   by `key_id`, decoding base64url without padding.
6. Report an unsupplied `key_id` as a failure. **Not a skip.** A record nobody
   can vouch for is the one an attacker would add.
7. Verify each `key_rotated` record under the **old** key, and treat one signed
   by the new key as a failure.
8. Recompute each `checkpoint`'s Merkle root over the range it claims,
   duplicating the last node on an odd level, and fail when the range is not
   fully present.
9. Report an empty input as a failure rather than a pass.
10. Reach a verdict without contacting the instance that produced the records,
    or any other network service.

It MUST NOT:

- treat an unknown `type` as a failure. The type set is closed for a producer
  and open for a reader: a verifier that refuses an unfamiliar type cannot read
  a chain written by a newer producer, and the type is only a hash input.
- accept a record whose `payload_hash` is absent, even when the payload is.
- round a number it cannot represent exactly. Reject it.

**The acceptance test is the fixture.** A conforming implementation verifies
`tests/evidence/fixtures/evidence-format-1.0/chain.jsonl` against the public
keys beside it with the instance id in its `manifest.json`, and reports
fourteen records, two checkpoints, one purged payload and two keys. The
fixture's `README.md` lists the mutations it should reject and the code each
one should produce.

```console
$ cd tests/evidence/fixtures/evidence-format-1.0
$ qed-verify chain.jsonl --keys public --instance-id qed-conformance-1.0
records   : 14 (seq 0..13)
keys      : ed25519:464e88767c380dcd, ed25519:e4b402f9126abfa9
checkpoint: 2
purged    : 1 payload(s) removed under retention
result    : OK -- chain is contiguous, unmodified and signed
```
