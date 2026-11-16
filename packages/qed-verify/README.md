# qed-verify

An independent verifier for [Valqore QED](https://github.com/valqore/qed)
evidence chains. It answers one question — *were these records written in this
order, by the holder of these keys, unaltered since* — without trusting the
instance that produced them.

```console
pip install qed-verify
```

One dependency, `cryptography`, on purpose: an auditor must be able to install
this on a machine that is not allowed to reach the internet twice. It imports
nothing from `qed`, and it is published as its own distribution so that
installing the verifier does not install the thing it verifies.

## Running it

A QED operator produces the export with `qed export` and hands over the public
keys:

```console
qed-verify chain.jsonl --keys keys/ --instance-id acme-prod   --anchor ./qed-checkpoint-0000001234-ab12cd34ef567890.json --require-complete
```

Exit codes: `0` verified, `1` one or more problems, `2` usage error.
`--json` emits the machine-readable report, `--range FROM:TO` verifies a slice,
and `--require-complete` is what a pipeline should use — it fails unless every
check *ran*, not merely every check that ran passed.

Two of the inputs have to come from outside the export, and neither is
optional for a verification that means anything: `--instance-id` and
`--anchor`. The sections below are what each one buys.

## What it checks

1. `seq` starts at 0 and is contiguous.
2. `prev_hash` of record *n* equals `hash` of record *n-1*, and record 0's
   `prev_hash` matches the genesis binding for `--instance-id`.
3. `hash` recomputes from the record's own fields — from `payload_hash` rather
   than the payload, so a record purged under retention still verifies.
4. `payload_hash` recomputes from the payload, when the payload is present.
5. The signature verifies under the key named by `key_id`.
6. Each `key_rotated` record is signed by the **old** key, which is what makes
   rotation one continuous chain instead of two.
7. Each `checkpoint` record's Merkle root recomputes over the range it claims.
8. Each `--anchor` matches the export: the record it names is present and
   byte-identical, and the records in its range recompute to its published
   Merkle root.

## `--instance-id` is the one that matters

Check 2 is the only check that ties these records to a *particular* instance,
and the only one that can be skipped. Everything else is self-referential: a
chain generated on a laptop five minutes ago, signed with a key generated at
the same time, satisfies checks 1 and 3–7 exactly as well as a real one. So
when no instance id is given the report names the check that did not run
instead of reporting an unqualified pass.

The instance id has to reach the verifier **from outside the file under
review** — a contract, an engagement letter, the operator's published instance
identity. It is also in the genesis payload, so reading it out of the export
and passing it back proves nothing: a forger chose both. The same applies to
the public keys.

## `--anchor` is the only one that can see a chain that stops early

Checks 1 and 3–7 are satisfied by **any prefix of a chain**. Drop the last
thousand records and what remains is contiguous, correctly linked, correctly
signed and internally consistent. That is not a gap in this implementation; it
is a property of hash chains. The record that would say more records followed
is the record that was removed, so nothing inside an export can establish that
it is the whole export.

An anchor can. QED publishes each checkpoint record to somewhere the instance
cannot afterwards revise — an object-locked S3 key, a GCS bucket with a locked
retention policy, a signed git tag. Fetch that copy from the target it was
published to and pass it here:

* a record the anchor names that the export does not contain is
  `anchor_not_in_export`, and names the seq the export ends at;
* a record present but different is `anchor_mismatch`;
* a range that recomputes to a different root is `anchor_root_mismatch`,
  reported alongside the mismatch rather than instead of it: one says the
  export was rewritten, the other says where.

`--anchor` takes a file or a directory of them, so a bucket synced to disk
works without naming each object.

Two things to hold onto. An anchor **the instance hands you is not an anchor**
— it is a second file it could have written to match, exactly as with the
instance id. And an anchor **covers the records it names and nothing later**:
with the newest one at seq 1234 and an export running to 1600, the report says
those 366 records are present on the export's own word, and stays short of
`complete`.

## Why it reimplements the format

Canonicalisation and the record hash are written again here from the
specification rather than shared with the producer. A shared helper would mean
a bug in the producer verifies cleanly, which is the one failure this package
exists to rule out.

- Format and checks: [SPEC §10.7](https://github.com/valqore/qed)
- Evidence record format: `schema_version` is tracked independently of this
  package's version, and every version ever written stays verifiable.

Apache-2.0.
