# Evidence format 1.0 (draft)

`schema_version: "1.0"`. This document describes what `qed-verify` checks. It
is **draft** until SPEC §22 week 12 freezes it; until then a change here is a
`schema_version` bump plus an ADR (SPEC §25.6).

An auditor needs three things and nothing else: the records, the public keys,
and `qed-verify`. No access to the instance, no cooperation from the operator,
no trust in either.

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
product name on purpose — the name is still open (SPEC §24.1) and a brand inside
a hash input would make renaming the product break every existing chain. See
ADR-0006; `tests/evidence/test_format_constants.py` pins the bytes.

## Reserved payload keys

SPEC §10.2 requires `assurance`, `mode`, `enforcement`, `dev` and `key_id` to be
inside the payload so `payload_hash` covers them, and mirrored as columns for
querying. They are written as `_assurance`, `_mode`, `_enforcement`, `_dev`,
`_key_id`. A caller payload using one of those names is **rejected**, not
overwritten — see `docs/adr/0005-record-encoding.md`.

## Masking

Masking runs **before** hashing (`qed/core/evidence/masking.py`). A secret
therefore never reaches `payload_hash` in the clear and no later purge is needed
to remove it. Because masking happens before the hash, the pattern set is part
of the format: changing it changes record hashes for future records.

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
