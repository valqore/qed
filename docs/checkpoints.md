# Checkpoints and anchors

A checkpoint is a Merkle root over a stretch of the chain, signed and appended
like any other record (SPEC §10.4).

On its own it proves one thing: that the instance was internally consistent at
the moment somebody read it. An operator who rewrote the chain could recompute
every root and every signature, and nothing in the export would say so.

**Publishing is what closes that.** The root goes somewhere the instance does
not control, timestamped by something other than the instance. An auditor then
has two numbers to compare, and a rewritten chain fails the comparison.

```yaml
evidence:
  checkpoint:
    every_records: 1000
    every_seconds: 3600
    publishers:
      - { type: s3-object-lock, bucket: acme-qed-anchors }
      - { type: file, path: /mnt/anchors }
```

`qed doctor` says, in a line, whether any of this is configured — because a
Merkle root that lives only in the chain it summarises is the default, and the
default is the weak case.

## When one is written

```yaml
evidence:
  checkpoint:
    every_records: 1000      # SPEC 10.4's thresholds, whichever comes first
    every_seconds: 3600
```

Both are read (one of them was not, once -- see the changelog). `qed
checkpoint --force` writes one below either threshold, and the age is measured
from the **oldest uncovered record**, not the newest: a record that has been
sitting unanchored for an hour is what the threshold is about, whatever arrived
since.

Every 1,000 records or 3,600 seconds, **whichever comes first**. The age is
measured from the *oldest record not yet covered*, which is the thing the
threshold is about: a record that has been sitting unanchored for an hour,
whatever arrived since.

The background loop asks every 30 seconds. `qed checkpoint --force` runs a pass
now, which is also how a one-off instance that never runs `qed serve` gets
anchors at all.

Two properties follow from a checkpoint being an ordinary record:

* **A checkpoint cannot cover itself.** Its hash depends on the root it
  carries. So each range starts at the previous checkpoint *record*, which is
  what makes "every record in the chain, checkpoints included, is covered by
  exactly one Merkle root" true.
* **A forced checkpoint immediately after another covers exactly one record:
  the previous checkpoint.** Expected, and the thresholds stop it happening on
  their own.

## The publishers

### `file`

```yaml
- { type: file, path: /mnt/anchors, read_only: true }
```

One file per checkpoint, named so the set sorts: `qed-checkpoint-0000001234-<root
prefix>.json`. The contents are the canonical JSON of the whole record — not
just the root, because a bare Merkle root proves nothing about who computed it.

It refuses to overwrite an existing anchor, writes through a temporary name so
a reader never sees half a file, and drops the write bits afterwards.

**A directory on the same disk as the chain anchors nothing.** It becomes an
anchor when the path is somewhere the instance does not control: a volume that
is read-only after write, a share with its own retention, a path a backup job
copies off the host. The publisher cannot tell which you configured.

### `s3-object-lock`

```yaml
- { type: s3-object-lock, bucket: acme-qed-anchors, prefix: checkpoints/, mode: COMPLIANCE, retain_days: 2555 }
```

Needs `valqore-qed[s3]`. This is the anchor that actually anchors: in
compliance mode, **nobody can delete or overwrite the object until the
retain-until date** — not the uploader, not an administrator, not the account
root.

Three things worth knowing before you rely on it:

* **Object-lock has to be enabled when the bucket is created.** It cannot be
  turned on later. A bucket without it accepts every upload and provides no
  lock, so the publisher asks and says so in the receipt rather than implying a
  protection that is not there.
* **`mode: governance` is a conscious downgrade.** A principal with
  `s3:BypassGovernanceRetention` can delete the object — the same set of people
  who could rewrite the chain, so the anchor adds nothing against the threat it
  exists for. It is allowed, and logged as a warning.
* **`retain_days` defaults to seven years**, matching the usual evidence
  obligation. An anchor that expires before anybody asks about it is not an
  anchor.

Credentials come from the environment, the way every AWS tool takes them, and
never from `qed.yaml`.

#### Somewhere other than AWS

```yaml
- { type: s3-object-lock, bucket: qed-anchors, endpoint_url: "https://minio.internal:9000", region: us-east-1 }
```

`endpoint_url` points this at an S3-compatible store you run — MinIO, Ceph, a
gateway — which for a self-hosted kernel is usually the right deployment: the
anchor has to be outside **this instance's** control, not outside the building.
The store has to support object-lock for the lock to mean anything; the receipt
says which you got.

Setting an endpoint switches the client to **path-style addressing**, and that
is not a preference: boto3's default builds a virtual-host URL (`bucket.host`)
which resolves for `s3.amazonaws.com` and for nothing else without a wildcard
DNS record, and the failure reads like the bucket being down.

#### What is actually tested

`tests/evidence/test_s3_object_lock_live.py` runs this publisher over HTTP
against a server that enforces retention — LocalStack in CI, and anything else
you point `QED_TEST_S3_ENDPOINT` at — and asserts the refusals rather than the
requests: that the locked version cannot be deleted, that it cannot be deleted
with `BypassGovernanceRetention` either, that a plain delete only hides it
behind a delete marker, that an overwrite adds a version beside it, and that
`governance` mode really is bypassable where `COMPLIANCE` is not. Before that
file the only test used a fake client, which could show that the publisher
*asks* for a lock and nothing about whether a lock resulted.

One assertion is AWS-only and marked as such (`QED_TEST_S3_AWS=1`): real S3
refuses `ObjectLockMode` on a bucket that has no object-lock configuration,
where LocalStack accepts it and stores no lock. Those two divergent behaviours
are the same argument — ask the bucket, do not infer a lock from a success.

### `git-tag`

```yaml
- { type: git-tag, repository: /srv/anchors, remote: origin, push: true, sign: false }
```

An annotated tag per checkpoint, carrying the record as its message, pushed to
a remote somebody else can read. With `sign: true` it is GPG-signed, which also
names who created it.

`git` rather than a library, because `git` is what the operator's remote,
credentials, SSH agent and signing key are already configured for.

**Pushing is what makes it an anchor.** `push: false` produces a local tag that
is as rewritable as the chain beside it, and the receipt says so.

### `qed-anchor`

```yaml
evidence:
  checkpoint:
    publishers:
      - type: qed-anchor
        url: https://anchor.example            # https only
        log_id: acme-prod                      # required, see below
        token_env: QED_ANCHOR_TOKEN            # optional
        timeout_seconds: 5
```

The only publisher that sends anything to a **third party**, and for that reason
the only one that does not copy the whole record. It POSTs six values to
`<url>/v1/anchors`:

```json
{"log_id": "acme-prod", "seq": 7, "hash": "...", "merkle_root": "...",
 "key_id": "...", "sig": "..."}
```

**Why not the record.** A checkpoint payload carries the *previous* checkpoint's
receipts, and a receipt's `target` is an `s3://bucket/key` or a git remote.
Posting the record would hand an anchor service a running inventory of your
bucket names — infrastructure nobody agreed to publish, arriving as a side
effect of a privacy feature. Invariant §1.7 says these features carry hashes
and signatures only, so they carry hashes and signatures only.

Every value in that body is one your auditor already holds in their export, so
the log learns nothing new and the auditor can compare the log's entry against
their own copy. The honest consequence: **the log cannot check that the
signature covers a meaningful payload**, because it never sees the payload. It
does not need to — a transparency log witnesses that a value existed at a time,
and the value is a hash whose preimage is in the export.

**`log_id` is required.** It is the name your entries carry in somebody else's
log, and that is your decision. `instance_id` would have named your company and
environment (and is not even on the record); deriving one from the signing key
would move your entries to a new scope at the next `qed keys rotate`, splitting
your own history in the log.

`https` is enforced, not warned about: the root is the evidence that the chain
was not rewritten, and in clear anything on the path can substitute it. A
`token:` in the config file is refused with a pointer to `token_env` (SPEC §16).
The token goes in an `Authorization: Bearer` header, never in the body, and the
environment is read at publish time — so a secret that arrives after startup
still works, and an empty one returns a failed receipt without sending
anything.

The receipt keeps the status code and whichever of `log_index`, `log_id`,
`inclusion_proof`, `signed_timestamp` and `tree_size` the log returned, and
nothing else. A receipt lands in the chain, which is immutable; a log answering
with a kilobyte of banner text would put a kilobyte there for good.

**The log itself is not in this repository.** SPEC §24.2 puts the transparency
log in `qed-cloud`. What ships here is the client; the stub it is tested
against is in `tests/evidence/test_anchor_client.py`. ADR-0013 has the
reasoning.

## Receipts

A receipt is what the target gave back: an ETag, a version id, a retain-until
date, a commit sha, a sha256. It is the half that makes the anchor checkable
rather than merely claimed.

**Receipts go in the *next* checkpoint, never this one.** A receipt describes a
record that has already been hashed and signed; writing it back into that
record would change the hash the receipt is about. So each checkpoint's payload
carries the previous one's receipts under `previous_receipts`, and the first
carries none. In between they live in the `checkpoints` table — which is how
they get from one to the other, and why the chain is where they end up: a table
can be restored from a backup, and the chain cannot.

**A failed publication never stops the chain, and never disappears.** Every
publisher returns a receipt with `ok=False` rather than raising, and that
failure lands in the table, in the next checkpoint's payload, and in
`qed doctor`. A bucket that is down must not make `qed` stop deciding; a bucket
that has been down for a month must not be a surprise.

## What an auditor does with it

```bash
qed export --dir /var/lib/qed > chain.jsonl
qed-verify chain.jsonl --keys /var/lib/qed/public --instance-id <id> --require-complete
```

The instance id and the public keys both have to reach you from outside the
export — the engagement letter, the contract, the operator's published identity.
Both are *in* the material you were given, which is exactly why neither can be
taken from it: a chain forged wholesale carries whatever id and key the forger
chose, and verifies perfectly against them. `--require-complete` makes the
verifier exit non-zero rather than report a pass with the binding skipped.

`qed-verify` checks the roots against the records in the export. That catches
tampering *within* what it was given. The anchor catches the other case:

```bash
# the checkpoint record as the chain has it
jq -c 'select(.type == "checkpoint")' chain.jsonl

# the same record, as it was published
aws s3 cp s3://acme-qed-anchors/checkpoints/qed-checkpoint-0000001234-ab12cd34ef567890.json -
```

Byte-identical, or one of them is not the record that was signed.

## Maintenance order

A pass does three things, in this order, and the order is the point:

1. **checkpoint** — fix a Merkle root over everything since the last one;
2. **publish** that root;
3. **purge** payloads the retention policy has expired (`docs/deployment.md`).

Purging first would leave a window in which the payloads were gone and nothing
outside the instance had attested to the hashes they produced.

All three require being the chain's only writer: the leader on the PostgreSQL
path, the single process on SQLite. A follower never checkpoints — that would
make it a second writer, which is the one thing the advisory lock exists to
prevent (ADR-0009).
