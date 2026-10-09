# ADR-0010 — Rotation destroys the old private key, and the writer enforces continuity

**Status:** accepted · week 7 (2026-10-09)
**Implements:** SPEC §10.5 (`qed keys rotate`), §10.7 (verification)
**Relates to:** ADR-0005 (record encoding), ADR-0009 (the outbox and one leader)

## Context

SPEC §10.5 fixes the shape of rotation: a new key becomes active, and a
`key_rotated{old_key_id, new_key_id, new_public_pem}` record is appended,
**signed by the old key**, for continuity. `qed-verify` already enforced that
rule; nothing produced the record.

Three questions the spec leaves open, and each has a wrong answer that is
quieter than the right one.

## Decision 1 — The old private key is destroyed

Rotation exists because a key might have leaked. A rotation that leaves the old
key on disk — in `retired/`, or behind a `--keep-old` flag — has reduced
nothing, and the flag would be used, because losing a key feels worse than
keeping one.

The threat is not editing an existing record. `hash` covers `payload_hash`, and
the next record's `prev_hash` covers `hash`, so an edit breaks linkage and
`qed-verify` says so. The threat is **fabrication**: with the retired private
key an attacker can produce a whole alternative history — genesis onwards,
internally consistent, correctly signed — that verifies under a key an auditor
still trusts for the period before the rotation. The only defence is that the
key no longer exists.

So `finish_rotation` overwrites `evidence-key.pem` with `os.replace`, which is
atomic on POSIX and Windows. There is no copy and no flag.

The **public** key is kept, and must be: without it the chain before the
rotation cannot be verified at all. This is why `qed keys export-public` now
prints every key rather than the active one — the previous behaviour made
"send the auditor your public key" produce a file that verifies half the chain
and reports `unknown_key` for the rest.

## Decision 2 — The record is appended before the key is activated

Three steps, in this order:

1. generate the new key and write it to `evidence-key.pem.incoming`;
2. append `key_rotated`, signed by the retiring key;
3. `os.replace` the pending key over the active one.

**(3) before (2)** would leave the chain on the old key with the next record
signed by the new one and nothing in between saying so — a discontinuity
indistinguishable from a forged chain, produced by the correct command.

**(1) after (2)** would mean a crash between them left a chain whose last
record announces a key that was never written down. Unrecoverable: the chain
cannot continue (nothing can sign as the announced key) and cannot be rewound
(the record is immutable).

Staged first, the two interruption points are both recoverable and both
visible. `pending_rotation()` reports a leftover `.incoming` file, and the
writer's own check (below) reports a chain whose expected key is not active.

## Decision 3 — The writer enforces continuity, not only the verifier

`ChainWriter.__init__` now reads the chain's last record and refuses
(`KeyDiscontinuity`) unless the active key is either the one that signed it, or
the `new_key_id` of a `key_rotated` record sitting at the tip.

The verifier had this rule already, which is the right place for an auditor and
the wrong moment for an operator: by then the records exist, are immutable, and
are unverifiable. The causes are ordinary — a key file restored from a backup
taken before a rotation, two deployments pointed at one database with different
secrets, a rotation interrupted between steps 2 and 3 — and in every case the
instance would go on appending records that look forged.

One read of one record at startup turns a permanent, silent defect into a
refusal with a sentence.

## Consequences

- **Rotation is direct, never deferred.** `ChainWriter.append_direct` exists
  for the two record types whose meaning depends on their position: a
  checkpoint covers a range ending just before it, and a `key_rotated`
  introduces the key that signs everything after it. Queued behind other
  records, either would describe a position it no longer occupied — and a
  `key_rotated` chained *after* records the new key had already signed is
  exactly what `qed-verify` reads as a discontinuity.
- **On the HA path, rotation takes the chain lock or refuses.** A running
  `qed serve` holds that lock for its lifetime, so `qed keys rotate` there
  reports `RotationRefused` and says to stop the server or rotate through the
  instance, rather than racing the leader. SPEC §13's
  `POST /admin/keys:rotate` is where that goes (week 10 adds the approval it
  needs — SPEC §17: qed governs its own admin operations).
- **Anything queued is drained before the record is appended.** Those records
  were signed by the old key, and chaining them after the record that retired
  it would invert the one ordering rotation depends on.
- **The CLI prints these as sentences.** `QedGroup.invoke` catches
  `InstanceMismatch` and `KeyDiscontinuity` for every command. On the group
  rather than in `main()`, because `main` is not the only way in — the test
  runner and anything embedding `qed.cli.app` invoke the group directly.

## Alternatives rejected

**Keep the old private key, encrypted.** Still a key, still a fabrication
route, and now with a passphrase somebody has to store next to it.

**Re-sign history under the new key.** Would make every prior `hash` wrong and
every `prev_hash` a lie. The chain is append-only; that is the entire claim.

**Let the verifier be the only place continuity is checked.** It is the
authoritative place and it is far too late. Both, then.
