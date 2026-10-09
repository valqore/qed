# Performance

Measured, not estimated. `tests/perf/` runs these on every CI push and the
numbers below are from it.

## The one commitment

SPEC §18 commits to **p95 decision latency under 50 ms**. That is met with
about a 5x margin:

| | p50 | p95 | p99 |
|---|---|---|---|
| SQLite | 3.8 ms | **4.5 ms** | 6.7 ms |
| PostgreSQL | 9.5 ms | **10.6 ms** | 11.2 ms |

What is measured is `check_proposal` — a validated proposal in, a chained
verdict out — and not an HTTP round trip. That is what the target is about:
transport latency belongs to whoever runs the network, and including it would
make the number depend on the client. `/metrics` measures exactly the same span
in production, so a dashboard and this page are talking about one thing.

PostgreSQL is slower per decision and is expected to be. A decision reads
history, the budget and the dedupe window, and on PostgreSQL each is a network
round trip rather than a local page read. The reason to use it is more than one
replica, not speed.

### The budget depends on the disk

On a GitHub Actions **Windows** runner the same test reports:

| | p50 | p95 | p99 |
|---|---|---|---|
| SQLite, GitHub Windows runner | 20.2 ms | **105.5 ms** | 265 ms |

Four times the budget, with nothing changed but the hardware. The cause is not
subtle: SQLite's `BEGIN IMMEDIATE` is one `fsync` per append, a decision is two
appends, and on that runner's virtual disk an `fsync` costs about 10 ms.
Everything else — hashing, signing, evaluating 46 rules — is under a
millisecond.

So **the 50 ms budget is a claim about storage, not about Python**, and it is
worth stating plainly rather than hiding behind a green CI badge:

* on any machine with a real SSD, p95 is ~5 ms and there is a 10x margin;
* on slow or heavily shared storage it can exceed 50 ms, and the fix is the
  disk or the PostgreSQL path, not the kernel;
* `qed_decision_latency_seconds` in `/metrics` is how you find out which you
  have. It measures the same span this page does.

This is why the timing tests are marked `perf` and excluded from the matrix
cells (`pytest -m "not slow and not perf"`). A number that four parallel jobs
on one shared runner produce is a measurement of the runner.

## Throughput, and a number the spec gets wrong

SPEC §22's week-7 row asks for "1k rps proposals". **A single Python replica
does not reach that**, and will not:

| | one replica, one thread |
|---|---|
| SQLite decisions | ~250/s |
| PostgreSQL decisions | ~105/s |
| SQLite chain appends | ~1,270/s |

1,000 decisions a second is four to ten replicas, which is exactly what the
PostgreSQL path exists for (ADR-0009). Measured on one machine with one local
PostgreSQL, four replicas reach ~290/s — the scaling is real and the ceiling
there is the single database and a single Python process per replica, not the
design.

This is written down rather than quietly reinterpreted because the honest
version is more useful: **p95 is the number that constrains an agent waiting
for an answer, and it is met with room to spare. Throughput is a capacity
question answered by replica count.** SPEC §26 lists a Go hot path as the
fallback "if p95 target fails under load"; p95 is 4.5 ms against a 50 ms
budget, so that fallback is not needed for the reason it was written down.

What four concurrent replicas *do* have to prove is that the chain survives
them, and `tests/perf/test_throughput.py` asserts it: four sessions enqueueing
at once, one leader chaining, and `qed-verify` reads the result as contiguous,
unmodified and signed. A throughput figure from a run that silently forked the
chain would be worse than no figure.

## Where the time goes

One chain append — hash, sign, insert — with no policy evaluation and no store
reads:

| | p50 | p95 |
|---|---|---|
| SQLite | 0.8 ms | 1.1 ms |
| PostgreSQL, direct | 4.4 ms | 5.2 ms |
| PostgreSQL, deferred (outbox) | **1.6 ms** | 1.9 ms |

A decision is two records — proposal and verdict — so roughly twice the append
plus the policy evaluation and the reads.

That last row is ADR-0009's claim with a number on it. On the HA path the
decider writes to the outbox and the leader assigns `seq`, `prev_hash` and the
signature later; the append is **2.8x cheaper** because it skips reading the
chain tip and computing the link, which on PostgreSQL is round trips rather
than page reads. Decision latency really is independent of chain latency, and
this is the measurement that says so.

## What is not optimised, on purpose

* **Ed25519 signing is per record.** Batching signatures would make a record's
  signature depend on its neighbours, so a single record could no longer be
  verified on its own — and `qed-verify` checking one record at a time is the
  whole shape of the thing.
* **Masking runs on every payload** before hashing. It is regex work with a
  100 ms timeout, and it is the reason a payload can be written down at all.
* **The policy bundle is evaluated in full.** 46 rules against one proposal,
  no short-circuit on the first BLOCK, because the verdict carries every rule
  that fired and an auditor reading "blocked by AG-BLR-003" should also see
  AG-BLR-005 if it matched.

## Running it

```bash
pytest tests/perf -m perf -s                      # SQLite only
QED_TEST_POSTGRES_DSN=postgresql://... \
  pytest tests/perf -m perf -s                    # both backends
```

`-s` because the distributions are printed. `pytest -m "not perf"` skips them,
which is what the main matrix cells do — a timing assertion on four parallel
jobs on one runner measures the runner. CI runs them once, in the `postgres`
job, which is the only one with a database and so covers both backends in one
pass.

The thresholds are deliberately loose: a floor of 80 decisions/s against a
measured 250, and p95 against 50 ms with a measured 4.5. A test that fails at
45 ms would be a test somebody disables, which protects nothing; one that fires
at 50 ms when the real number is 4.5 ms only fires on a genuine regression.
