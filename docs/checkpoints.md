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
qed-verify chain.jsonl --keys /var/lib/qed/public
```

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
