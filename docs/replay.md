# Replaying a decision

`qed verify` answers *is this record authentic*. `qed replay` answers the other
question an auditor asks:

> Does this verdict follow from the policy it says it was decided under?

These come apart, and the gap is the point. Every check the verifier makes is
self-referential — hashes over the record's own fields, signatures over those
hashes — so a chain that an operator **rewrote and re-signed** passes
verification completely. Deciding the proposal again is what notices.

```bash
qed replay 01JB0000000000000000000000 --dir .qed --config qed.yaml
```

```
reproduced
  proposal : 01JB0000000000000000000000
  policy   : 7618895d28d35b79... (matches)
  engine   : 1.0.0

assumed (not in any record): budget
```

## Three answers, three exit codes

| Exit | Meaning |
|---|---|
| `0` | **Reproduced.** The record follows from its policy, with nothing left over. |
| `2` | **Differs**, and no assumed input accounts for it. |
| `1` | **The question could not be answered**: no such proposal, a chain that does not verify, or a policy whose hash is not the one the decision was made under. |

The third is separate on purpose. A pipeline that could not tell it from `2`
would read a missing file as a forged record.

## What the chain can give it

**Exact.** The proposal and the verdict are recorded in full. And
`check_proposal` stamps the proposal record, the verdict record and the
engine's `now` from one value — so the clock is the record's own timestamp, not
an approximation of it. Replaying a chain from last year uses last year's time.

**Not in evidence at all.** The `policy_loaded` record carries a bundle's
**hash**, not its rules. The policy therefore cannot be reconstructed from
evidence, and a hash mismatch makes `replay` *refuse*:

```
cannot replay
  proposal         : 01JB0000000000000000000000
  decided under    : 7618895d28d35b796500bd76b86b0d5f5dc4fd5101b462182a3211cc7bc7d7d8
  replayed against : 2f91c0ae44bb1d0896f4b1b8c4b7e8a0d5c1e2f3a4b5c6d7e8f901a2b3c4d5e6

The chain records a policy's hash, not its rules, so the bundle that made
this decision cannot be reconstructed from evidence. Point `--policy` at the
bundle that was in force. Re-deciding under today's policy would answer a
different question.
```

Re-deciding under today's rules is a legitimate thing to want — it is how you
ask "would we still allow this?" — but it is not a replay, and presenting its
answer as one would be the most misleading thing this command could do. Keep
the bundles you decide under, and point `--policy` at the right one.

## What it has to assume, and what that excuses

Two inputs are in no record:

- the **budget ledger** state for the token. `replay` reads the ledger as it is
  now, which is what the kernel does when a caller passes no budget — a much
  better guess than an empty state, and still a guess, because the ledger has
  moved since. `--budget state.json` settles it.
- the **mandate**. `mandate_issued` keeps a mandate's id and validity window,
  not the signed document the engine is handed. `--mandate m.json` settles it.

Every difference is then classified against the rules that actually read those
values. A rule reading `derived.budget.*` coming out differently when the
budget was assumed is a statement about the replay; the same difference in a
rule that reads only the proposal is a statement about the record. The first is
reported as **inconclusive**, the second as **DIFFERS**:

```
inconclusive
  ...
  hits: recorded [...], replayed [...] (explained by the assumed budget)

Every difference is explained by an input this replay had to assume, so this
is neither a pass nor a failure. Supply the real one to settle it.
```

`blast_radius` is never excused. It is computed from the proposal, which the
chain records in full, so nothing can account for it differing.

An input is also only named when it could have mattered: a bundle with no rule
reading it gets no caveat about it, because a caveat printed on every run is
one nobody reads.

### The history counters are recovered, not assumed

`derived.history.calls_24h` and `derived.history.blocks_24h` are collected
from the chain, and the way they are collected is what keeps them replayable.
The window is **aligned**: it covers `[end - 24h, end)` with `end` floored to
`history.refresh_seconds`, so it is a pure function of the decision's own
timestamp, and `replay` counts the same two numbers back out of the records.

A cadence built as a cache with a TTL would have been easier to write and
would have made every replay of a history-dependent rule inconclusive
forever, because nothing records which stale value a decision happened to see.

Two things put the counters back among the assumptions, and `replay` says so
when they do:

- a `verdict` record inside the window whose payload retention has stripped.
  The decision is then unknowable, so `blocks_24h` is a lower bound rather
  than a number.
- `history.refresh_seconds` having changed since the decision, which moves
  the boundary. That value lives in the config and not in the chain, so
  `--refresh-seconds` is how you say what it was.

One narrower limit, worth knowing before comparing a counter to the chain by
hand: `blocks_24h` counts from migration 0006, which added the `decision`
column it reads, so verdicts written before that migration are not counted.

## Approvals are an overlay, not a decision

`check_proposal` runs the engine and *then* consults the approval store. An
open window turns a `REQUIRE_APPROVAL` into `ALLOW` with `via_approval` set; a
recent denial turns it into `BLOCK`. So the recorded `decision` is not always
the engine's verdict, and comparing them directly would report a mismatch for
every correctly approved action in every chain that has ever been used.

`replay` recovers the engine's own decision first and reports the overlay
separately:

```
  approval : recorded as ALLOW through an open approval window (apr_01...)
```

That is itself a checkable claim. An `ALLOW` the policy says needed an
approval, carrying no approval, is exactly the record somebody would forge —
and nothing excuses it.

## What it does not replace

An anchor. `replay` means that forging one verdict now requires forging a
consistent policy to go with it, rather than editing a number — but an operator
who can rewrite the chain can also rewrite the `policy_loaded` record and ship
a bundle to match, and then the replay agrees. A rewrite that simply *deletes*
records leaves nothing to replay at all.

A checkpoint root published where the instance cannot change it is still the
only thing that fixes history in place. See
[Checkpoints and anchors](checkpoints.md).

## For an auditor with an export

You do not need the instance. An export, the public keys and the bundle are
enough:

```bash
qed replay <proposal_id> \
  --from chain.jsonl \
  --instance-id acme-prod-1 \
  --policy ./archived-bundle \
  --dir ./handover
```

`--dir` is the directory holding the instance's `public/` keys -- the same
convention `qed verify` uses, since that is where signatures are checked from.

`--instance-id` is required to bind a chain read from a file, for the reason
`qed verify` requires it: binding a foreign export to the local instance id by
default would turn a real check into a coincidence.

`--json` emits the whole report, including the classified differences, for a
pipeline that reads it rather than a person.
