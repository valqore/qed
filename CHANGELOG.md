# Changelog

All notable changes to this project. Format: [Keep a Changelog]. Versioning:
semver, with `schema_version` of `ActionProposal` / `EvidenceRecord` tracked
independently (SPEC §25.6).

## [Unreleased]

Four fixes from validating `v0.6.0` end to end -- installing the built wheels
into a clean venv, driving the installed scripts, and starting the HA stack.
Three of the four were invisible to a green 2,200-test suite, and all of them
are in `docs/validation.md`.

### Fixed - the arm64 image had never worked

`/usr/lib/x86_64-linux-gnu` was hardcoded in the Dockerfile, so on arm64 every
shared library landed where that architecture's loader does not look and the
image died before it could say anything useful: `python3.12: error while
loading shared libraries: libpython3.12.so.1.0`. Nothing caught it because the
container test only ever built for the host while the release workflow builds
both.

The triplet now comes from `sysconfig.get_config_var("MULTIARCH")` -- the
interpreter being copied is the right thing to ask -- and the libraries stage
as a filesystem tree so each lands at its real path. Three guards: the script
asserts `libpython3.12.so.1.0` by name, a test refuses a hardcoded triplet, and
`tests/deploy/test_container.py` now builds and starts the **other**
architecture under emulation.

### Fixed - a replica could die on startup in the HA path

`record_bundle` was a SELECT then an INSERT. Two replicas starting together
both saw no row, both inserted, and the loser died on `UniqueViolation:
policy_bundles_pkey` **before its API came up** -- so a simultaneous start or a
rolling restart could leave a replica refusing to serve, in the one deployment
shape the PostgreSQL backend exists for.

One statement with `ON CONFLICT DO NOTHING` now, with `rowcount` deciding who
was first. The loser returns False rather than raising: another replica getting
there first is the normal case for every replica after the first.

### Fixed - AG-BLR-007 missed `terraform.destroy`

The rule is CRITICAL, BLOCK, no approvers -- teardown goes through a change
window with a named owner. It matched `terraform destroy` only inside
`action.params_redacted.command`, which is what the shell adapter sends. An IaC
adapter sends `action.name: terraform.destroy`, and that returned **ALLOW,
blast radius 40, no rule matched**.

Widened to the tool names (terraform, tf, pulumi, cdk, cdktf + destroy, and
helm uninstall/delete), scoped to the tool rather than a bare `destroy` which
would have taken `auth.destroy_session`. Six golden cases, three that must fire
and three that must not. The policy hash changes, which `policy_loaded`
records.

### Added - `examples/policy-cases.yaml`

Seven runnable cases for the shipped pack, so `qed policy test
examples/policy-cases.yaml` works out of the box. The format was documented and
no example shipped, which meant somebody who installed the wheel got 46 rules
and no way to watch them decide anything. Writing it is what found the
AG-BLR-007 gap.

### Fixed - a smoke test that failed on a good build

`docker run ... --help | head -3` under `set -o pipefail`: `head` closes the
pipe, the producer dies of SIGPIPE, and the step fails on an image that is
fine.

## [0.6.0] — 2026-10-09

Weeks 2–7 of the SPEC §22 build order. Everything below accumulated under
`[Unreleased]` across six weeks and had never been cut: `v0.1.0` was the last
tag, so the versions the exit criteria name (`v0.2.0` … `v0.6.0`) do not exist
as releases. This is all of them, under the version week 7 asked for, rather
than five tags invented after the fact for commits that were never shipped.

### Added - key rotation (SPEC 10.5, week 7)

`qed keys rotate`. The rule it implements has been in `qed-verify` since week 1
-- a `key_rotated` record must be signed by the *retiring* key -- and nothing
produced the record, so the only way to change keys was `qed keys init
--overwrite`, which breaks the chain. ADR-0010 records three decisions:

- **The old private key is destroyed.** Rotation exists because a key might
  have leaked, and one left on disk reduces nothing. The threat is not editing
  an existing record -- `hash` covers `payload_hash` and the next `prev_hash`
  covers `hash` -- it is fabricating a whole alternative history that verifies
  under a key an auditor still trusts for the period before the rotation.
- **The record is appended before the key is activated.** Activating first
  would leave the chain on the old key with the next record signed by the new
  one and nothing in between saying so: a discontinuity indistinguishable from
  a forged chain, produced by the correct command.
- **The writer enforces continuity too**, not only the verifier.
  `ChainWriter.__init__` raises `KeyDiscontinuity` unless the active key signed
  the last record or a `key_rotated` at the tip introduced it. The verifier is
  the authoritative place and the wrong moment: by then the records exist, are
  immutable, and are unverifiable.

`qed keys export-public` now prints **every** key with an `active`/`retired`
marker. The old behaviour made "send the auditor your public key" produce a
file that verifies half the chain and reports `unknown_key` for the rest.

### Added - retention and purge (SPEC 10.6, week 7)

Week 7's exit criterion is "purge-then-verify passes", and it does: `hash`
recomputes from `payload_hash`, so a record whose payload is gone still
verifies its linkage and its signature.

The interesting part is what retention refuses to touch. **Five record types
are structural and can never be purged**, whatever the config says: a
`checkpoint`'s payload holds its Merkle root, a `key_rotated`'s holds the
incoming public key, `genesis` and `policy_loaded` hold the chain's identity
and the rules in force, and `admin_action` is the record of the purges
themselves. Erasing the record of what was erased is the one thing retention
must not do.

That exemption is why the plan is an explicit set of sequence numbers rather
than `seq <= N`: retention is per type, so the expired set is not contiguous,
and a range would take an exempt checkpoint in the middle of it.

- `apply_retention` appends an `admin_action{action: "retention_purge"}`. A
  NULL payload with nothing saying why is indistinguishable from data loss.
- The policy reports ages **as the config wrote them**. `24h` reported back as
  `1d` is a small lie in a document an auditor reads.
- `0d` is refused rather than obeyed: it reads like "no retention", means
  "purge everything now", and is almost certainly a typo for `forever`.

### Added - checkpoint anchors (SPEC 10.4, week 7)

A checkpoint on its own proves the instance was internally consistent when
somebody read it; an operator who rewrote the chain could recompute every root.
Publishing puts the root somewhere the instance does not control.

- **file** -- one canonical record per file, named so the set sorts, refusing
  to overwrite an anchor. Says plainly that a directory on the same disk as the
  chain anchors nothing.
- **s3-object-lock** -- the one that actually anchors: compliance mode means
  nobody can delete the object until the retain-until date, not even the
  account root. It *asks* whether the bucket has object-lock, because one
  without it accepts the upload and provides no lock, and reports `ok` with a
  caveat rather than implying a protection that is not there. `governance` mode
  logs a warning: a principal with `s3:BypassGovernanceRetention` is the same
  set of people who could rewrite the chain.
- **git-tag** -- an annotated tag carrying the record, pushed to a remote
  somebody else can read. `push: false` is a local tag as rewritable as the
  chain beside it, and the receipt says so.

**Receipts go in the next checkpoint, never this one.** A receipt describes a
record that has already been hashed and signed, so writing it back would change
the hash the receipt is about. `previous_receipts` was a `[]` placeholder from
week 1 and now carries them.

**A failed publication never stops the chain and never disappears.** It lands
in the `checkpoints` table, in the next checkpoint's payload, and in
`qed doctor`.

### Added - the maintenance pass (SPEC 10.4, 10.6)

`qed/infra/maintenance.py`: checkpoint, publish, purge, in that order -- the
order matters, because purging before the root is anchored would leave a window
in which the payloads were gone and nothing outside the instance had attested
to the hashes they produced.

Run from the background loop every 30 seconds and from `qed checkpoint`.
Nothing was doing any of it: `writer.checkpoint()` was reachable only from the
CLI, so an instance nobody ran that command against had a chain with no
anchors, and SPEC 10.4's "every 1,000 records or 3,600 s" was a threshold with
no clock behind it.

### Added - Prometheus `/metrics` (SPEC 18)

The nine metrics SPEC 18 names, hand-rolled rather than via
`prometheus_client` -- the set is fixed and small, and a client library
registers process and GC collectors in a global registry at import, so
`/metrics` on a policy kernel would start reporting the interpreter's
internals. The tests **parse** the output, because a nearly-valid metrics
endpoint is worse than an absent one: Prometheus drops the whole scrape on a
parse error and reports it in its own logs rather than yours.

Open, like the probes: a scraper is not an adapter and has no signing secret,
and a bearer token in every Prometheus config is the arrangement that ends with
monitoring switched off. Labels are bounded by construction -- a metric
labelled with a proposal's own strings is a cardinality explosion an agent can
trigger on purpose.

### Added - OCSF events for a SIEM (SPEC 18)

A `verdict` and an `approval_decided` map to **Authorization (3003)**;
everything else to **API Activity (6003)**. Severity comes from what the
decision *did*, not from the rule's severity: a CRITICAL rule that fired in
shadow mode stopped nothing, and paging on it would train people to ignore the
channel.

Shipped by a bounded queue and one background thread, because a SIEM must never
be able to slow down or fail a decision. At 10,000 events the **oldest** are
dropped and counted -- dropping the newest would mean a burst hid itself -- and
failures are counted rather than retried forever, because a webhook down for an
hour has lost an hour of events and the operator needs to know.

`observability` has been in `UNIMPLEMENTED_SECTIONS` since week 1, which means
a config naming it was silently dropped. It is out of that list now.

### Added - the perf suite (SPEC 18, 22 week 7)

**p95 is 4.5 ms on SQLite and 10.6 ms on PostgreSQL**, against a 50 ms target.

SPEC 22 also asks for "1k rps proposals", and a single Python replica does not
reach it: ~250 decisions/s on SQLite, ~105/s on PostgreSQL. That is written
down in `docs/performance.md` rather than quietly reinterpreted -- 1,000/s is
four to ten replicas, which is what the PostgreSQL path exists for, and four
replicas on one machine reach ~290/s so the scaling is real.

ADR-0009's claim now has a number: one append on PostgreSQL is 4.4 ms direct
and **1.6 ms deferred**, so the outbox is 2.8x cheaper and "decision latency is
independent of chain latency" is a measurement rather than an argument.

### Fixed - strict masking was eating two values the chain exists to carry

Found by reasoning about two features built in the same week. The `strict`
profile masks any hex run of 32+ characters and any base64 run of 40+, which
ate a `key_rotated`'s `new_public_pem` and a checkpoint receipt's `sha256`.

Masking runs **before** `payload_hash`, so neither is a verification failure:
the record still verifies against its own hash, `qed-verify` reports OK, and
the chain is internally consistent while having quietly lost the thing it was
written to say. Same shape as the bug where masking rewrote sha256 digests and
broke a checkpoint's Merkle root.

The fix is by record type: `qed.core.schemas.STRUCTURAL_TYPES` is the five
types whose payloads the kernel writes, and `build_record` does not mask them
at all -- no agent wrote them, so there is nothing in them to redact. It is
deliberately the same set retention may not purge, and `NEVER_PURGE` is now an
alias for it.

### Fixed - the background loop could not touch SQLite

Broadening the loop to run maintenance exposed it. `asyncio.to_thread` uses a
pool and a `sqlite3` connection may only be used by the thread that created it
-- the API's was created by the event loop at startup -- so every maintenance
tick on the default backend died with `ProgrammingError: SQLite objects created
in a thread can only be used in that same thread`, in a log nobody reads. The
drain never hit it because the drain only ever ran on PostgreSQL.

The loop now runs on **one dedicated thread with its own session**, and
`start()` requires the factory that opens it: sharing the caller's session
works on PostgreSQL and fails on SQLite after the first read, so refusing up
front is the difference between a mistake that is impossible and one that is
merely unlikely.

### Added - `evidence.signing_key`

The config field existed since week 1 and was never read. It now names the
private key wherever it is, which is what a container needs: the chain is on a
writable volume or in a database, the key arrives from a read-only secret
mount, and nesting one inside the other to satisfy a fixed filename works until
a kubelet orders the mounts differently.

### Changed - `qed checkpoint` runs a whole maintenance pass

It checkpoints, publishes the root and applies retention, reporting each. The
three are together because they have to happen in that order.

### Changed - `qed doctor` reports the chain's housekeeping

Retention (and what it *would* purge on the next pass), the configured anchors
and the last publication, an interrupted rotation, and the SIEM target reduced
to scheme, host and port -- that output ends up in support tickets, and a
webhook URL often carries a token.

`QedGroup.invoke` turns `InstanceMismatch` and `KeyDiscontinuity` into one red
sentence for every command, on the group rather than in `main()`, because
`main` is not the only way in: the test runner and anything embedding
`qed.cli.app` invoke the group directly.

### Added - the outbox and one chain leader (SPEC 10.3, 15, 104; week 6)

PostgreSQL made it possible to share a chain between replicas. This makes it
safe.

The chain is the obstacle. Every record carries `seq` and `prev_hash`, so
appending means reading the tip, computing the next link and writing -- and two
replicas doing that concurrently read the same tip. Either the primary key on
`hash` refuses the loser, and a decision that was already delivered has no
evidence, or both commit and the chain forks. **A forked chain still verifies
record by record.** It just stops being a chain, and nothing says so until
somebody walks it.

Holding the lock across each decision would fix that and lose the reason for
having replicas: decision latency would become chain latency plus contention,
against SPEC 18's p95 < 50 ms. So the two guarantees are separated. "No
decision without a record" is satisfied by **durability**, not by chaining.

- **`ChainWriter` gained a `write_mode`.** In `deferred` mode `append()` masks
  the payload, writes it to `evidence_outbox` and returns an `Appended`
  carrying a reference instead of a record. Masking happens at enqueue time
  because the outbox is durable storage like any other.
- **The backend chooses the mode**, not a flag. Postgres exists in this design
  for more than one replica, and more than one direct writer forks the chain; a
  flag would be a way to configure the fork back into existence.
- **`qed/infra/chain_drain.py`** assigns `seq`, `prev_hash`, `hash` and the
  signature in batches of at most 100, one transaction per batch, reading the
  tip inside that transaction. A row it cannot parse rolls the batch back and
  is reported; it is never deleted. Dropping it would turn a parsing bug into a
  missing record, which is the one outcome the chain must never produce
  quietly.
- **`qed/api/leader.py`** is the loop around that drain, started from the app's
  lifespan on the deferred path only. It re-asks `pg_try_advisory_lock` every
  two seconds rather than remembering leadership: the lock can be lost without
  this process being told -- a connection reset, a failover, an administrator
  running `pg_advisory_unlock_all` -- and a replica appending on a stale belief
  is precisely the fork the lock exists to prevent. It never *blocks* on the
  lock either; a follower that blocked would hold a connection waiting for a
  leader to die, then wake up holding it with no idea how long it had waited.
- **Genesis and checkpoints stay direct**, even in deferred mode. Record 0 has
  nothing to be ordered against, and a chain whose first record was queued
  behind others would be a chain with no beginning.
- **`runtime.settle()`** drains on the way out of a one-shot command. `qed
  check` enqueues and exits, so without this a CLI-only Postgres deployment
  would have a chain that never advanced.

Verified against a real PostgreSQL 17 and then against two real containers.
`tests/evidence/test_ha_outbox.py` runs two connections and asserts the
property: no gaps, no duplicate sequence numbers, nothing lost, a leader killed
mid-stream and taken over by the survivor, and an export of the result
verifying through `qed-verify` -- which has never heard of replicas, outboxes
or leaders. ADR-0009 records the design and the three alternatives rejected.

### Changed - `evidence_ref` is a reference, not always a sequence number

`GET /v1/evidence/by-ref/{ref}` now resolves both shapes, and answers
`200 {"seq": null, "pending": true}` for a record that is queued. Not 404: the
record exists and is durable, a 404 would tell a caller their evidence was
lost, and an integration retrying on 404 would give up on a record that was
about to arrive.

`chain_status` -- so `qed status` and `GET /v1/status` both -- now reports
`store`, `write_mode` and `chain_lag_records`, which is SPEC 18's
`qed_chain_lag_records` until there is a `/metrics` endpoint to carry it. A
depth that keeps growing means the leader is gone, or is losing the lock faster
than it can drain.

### Changed - `qed check` exit codes now match SPEC 12.5

**`2` is BLOCK and `3` is REQUIRE_APPROVAL.** They were the other way round
since week 1, which was a guess made before the spec section was read closely,
and it also disagreed with the Claude Code hook's own `EXIT_BLOCK = 2`. Nothing
is released, so this is corrected rather than documented as a deviation.

`1` remains "QED could not decide" -- a missing key, an unreadable proposal, an
unreachable instance. That distinction is the one a pipeline cannot do without:
a refusal is not a malfunction, and conflating them lets a misconfigured runner
look like a policy that allows everything.

### Added - `qed check` in CI (SPEC 12.5)

- **`--server URL`** decides on an instance instead of locally, over a
  HMAC-signed request (`qed/adapters/remote.py`). This is the mode that makes
  sense in CI: no evidence signing key in the runner, the evidence outlives the
  build, and the rules that gate CI are the rules that gate everything else. An
  instance that cannot be reached exits `1` and never `0` -- "probably allowed"
  is the failure this project exists to prevent.
- **`--evidence-out PATH`** writes the chain as JSONL after a local decision,
  so an ephemeral runner leaves something `qed-verify` can check. The whole
  chain, not just the verdict: verification walks linkage from genesis.
- `docs/ci.md` has the exit-code table, both modes and a GitHub Actions
  workflow.

### Added - Helm chart (`deploy/helm/qed`, SPEC 104, 24)

Four things it **refuses to install**, because each is otherwise discovered at
runtime where the symptom is a CrashLoop or a forked chain:

- no evidence signing key -- and the chart will not generate one, because a key
  created by an install hook lives wherever the hook wrote it and one created
  per pod starts a new chain on every restart;
- `replicaCount > 1` on SQLite;
- `evidence.backend: postgres` with no secret holding the DSN;
- SQLite with persistence disabled.

Defaults chosen to be safe rather than convenient: `mode: shadow`, the image
tag pinned to the chart's `appVersion` rather than `latest`, a read-only root
filesystem with one writable mount, `helm.sh/resource-policy: keep` on the
evidence volume, a ConfigMap checksum that rolls the pods when the policy
bundle changes, and no service account token. `tests/deploy/test_helm_chart.py`
renders the chart with `helm template` and parses it.

`deploy/docker-compose.yml` is the same topology on a laptop: two replicas, one
PostgreSQL, one chain. Kill the leader and watch the other take over.

### Added - `evidence.signing_key`

The config field existed and was never read. It now names the private key
wherever it is, which is what a container needs: the chain is on a writable
volume or in a database, the key arrives from a read-only secret mount, and
nesting one inside the other to satisfy a fixed filename is the sort of
arrangement that works until a kubelet orders the mounts differently.

### Fixed - the container had never actually run

Both of these passed every check in the repository and failed the moment
anybody started the image.

- **The runtime base was `distroless/python3-debian12`, which ships Python
  3.11**, while the builder installed wheels for 3.12. The 3.12 extension
  modules landed beside a 3.11 interpreter that could not load them, and the
  first symptom was `ImportError: cannot import name 'ArgsKwargs' from
  'pydantic_core._pydantic_core' (unknown location)`. The runtime is now
  `distroless/base-debian12` with the interpreter copied from the builder and
  its shared-library closure computed by `ldd` (`deploy/stage-libs.sh`) rather
  than listed -- a hand-written list of Debian libraries goes stale on the next
  base bump and fails at import time in production.
- **`qed/compliance/frameworks.yaml` was missing from `package-data`**, so it
  was absent from the wheel, so the image started, bound its port and died on
  the first request with a `FileNotFoundError` pointing inside site-packages.
  `tests/test_packaging.py` now checks the `package-data` patterns against what
  is on disk, so a new data file that is not listed fails here instead of in
  somebody's cluster.

The image also now includes the `postgres` extra: which backend an operator
uses is a property of the deployment, not of the artifact they were handed.

`tests/deploy/test_container.py` builds the image and starts it -- CLI, every
runtime import, the packaged data files, and a decision whose chain is verified
on the host. Marked `slow` and skipped without a Docker daemon; CI runs it in
its own `deploy` job.

### Fixed - `charge_budget`'s daily rollup was refused by PostgreSQL

`ON CONFLICT ... DO UPDATE SET steps_used = steps_used + excluded.steps_used`.
SQLite accepts the bare column; PostgreSQL calls it ambiguous, because
`excluded` has a column of the same name -- which is exactly what the
expression is adding. The existing column is now qualified with the table name.

It is the only upsert in the store that accumulates rather than replaces, and
the cross-backend test that should have caught it called `charge_budget`
without a `principal_hash`, so the branch never ran. The argument is now the
point of that test, and a second test drives a whole decision -- the same
`check_proposal` the API calls -- against PostgreSQL, so the next
dialect divergence in any method on that path fails in CI rather than in a
container.

### Added - a 202 now carries the approval it opened

`POST /v1/proposals` filled `"approval": null` unconditionally, a week-1
placeholder that week 4 never came back to. SPEC 13's optional `approval?` is
now populated with the id, status, approvers, expiry and poll path. Without it
an adapter holding a 202 would have to call `GET /v1/approvals/{id}` before it
could say anything useful -- and it does not know the id yet, which is the
point.

### Added - the PostgreSQL backend (SPEC 15, week 6)

```yaml
evidence:
  store_env: QED_DATABASE_URL
```

SQLite stays the default and runs the whole product on one file. Postgres is
for the one thing SQLite cannot do: more than one replica sharing a chain.

**One store implementation, not two.** The forty repository methods are written
once and run against either backend. Two classes would be two implementations
of the chain's append path, and the day they drift is the day the chain behaves
differently depending on which database somebody deployed. What made that
practical is that the two drivers already agree about more than expected --
both expose `execute(sql, params) -> cursor` and both return rows addressable
by column name -- so `qed/infra/storage/dialect.py` has four fields in it and a
test asserts it stays that small.

- **The migrations are shared, and that was checked rather than assumed.** The
  week-1 scripts carry a comment claiming they sit in the SQL subset both
  engines accept. All four were replayed against a real PostgreSQL 17 before
  the seam was written, and they do -- so there is one set of files and no
  per-dialect directory.
- The SQL is written with `?` and converted for psycopg.
  `tests/evidence/test_store_dialects.py` asserts no SQL string contains a
  quoted `?`, which is the one thing that would make the conversion change a
  statement's meaning.
- Timestamps stay TEXT on both, in the format the record already carries.
  `ts` is hashed, so a native timestamp column would let the backend's own
  precision change the bytes.
- `pg_try_advisory_lock(1734440037)` for the chain leader, non-blocking, with
  `try_become_leader` / `holds_leadership` / `resign_leadership`. The lock is
  session-scoped so a crashed replica releases it, which is the liveness signal
  a leader election needs; a lease in a table would need a heartbeat, a clock,
  and a decision about what to do when the clock is wrong.
- Migrations take a *different* advisory key, transaction-scoped. Two replicas
  starting together would otherwise both run `0001` and the loser's ledger
  insert would fail, crashing a replica during an ordinary rollout. Holding one
  key must not imply holding the other: a replica applying a migration is not a
  replica that may append.
- `psycopg` is an optional extra (`[postgres]`) and asking for Postgres without
  it says what to install. The matrix jobs deliberately run with it *absent*,
  which is how almost everyone will run the product; a separate `postgres` job
  installs it and the service container.

### Fixed - genesis was the one record whose clock nothing could pin

`ChainWriter.ensure_genesis()` took `utcnow()` with no way to override it,
while every other write path accepts a `ts` precisely so a caller can be
deterministic. Since every later `prev_hash` descends from genesis, that made a
whole chain irreproducible from its inputs.

`tests/evidence/test_cross_backend.py` is what noticed: the two backends
produced identical records and different chains, because genesis had taken its
own clock eight milliseconds apart on the two runs. `ensure_genesis(ts=...)`
now exists and `append` passes its own `ts` through, so pinning the first
record pins the genesis before it.

### Changed - `SqliteStore` moved to `qed/infra/storage/store.py`

It gained a sibling, so it lives beside `SqlStore` and `PostgresStore`.
`qed/infra/storage/sqlite.py` re-exports it: fifteen modules import it from
that path and renaming them all would have been churn with no reader benefit.
`ChainWriter` and `Session` are typed on `SqlStore` now rather than the SQLite
one.

37 new tests. 1,805 with Postgres running, 1,788 with it skipped.


### Added - the Python SDK (SPEC 12.4, week 6)

```python
from qed.sdk import Qed, guard

qed = Qed.from_env()


@guard(qed, target=lambda account_id, **_: f"crm:accounts/{account_id}", deletes=True)
def delete_account(account_id: str) -> None: ...
```

The fourth adapter, for the action that has no front: a function in your own
application. The decorator proposes before the call, raises `QedBlocked` or
`QedApprovalPending` if the answer was no, runs the function, and reports what
happened. A refused action never runs, and a test asserts the body was not
entered.

- **`QedUnavailable` is a separate exception from a refusal.** "The policy says
  no" and "I could not find out what the policy says" are different facts, and
  an application that treats them the same will eventually treat an outage as
  permission.
- **It fails closed by default**, unlike the coding-agent hook. An application
  has no human watching, so a QED it cannot reach must stop the action.
  `fail_mode="open"` is a deliberate decision, not a default.
- **Advisory by default** (ADR-001 class A): whoever can edit the code can
  delete the decorator. `enforcement="enforcing"` is for when the credential
  the function needs comes from the broker, so going around QED leaves the
  function unable to authenticate.
- `target`, `summary`, `intent` and `params` may each be callables taking the
  wrapped function's own arguments, because an approver needs to know *which*
  account is being deleted rather than which function was called.
- `writes=True` by default. A hint that under-reports the damage routes a
  destructive call past the blast-radius score; one that over-reports asks a
  person about a harmless call. Only one of those is recoverable.
- The wrapped function's own exception is reported and **re-raised untouched**.
  The application's failure is the application's to handle.
- `Verdict` is a thin view over the kernel's JSON rather than a second model,
  so there is nothing here to drift out of step with `qed.core.schemas`.
- `report()` is the one place in the SDK that swallows an error: the action has
  already happened, and raising would replace the application's own result with
  a reporting failure.
- `examples/sdk/` has governed LangGraph and CrewAI tools. Both run whether or
  not those frameworks are installed, because a framework tool is an ordinary
  Python function and that is what `@guard` wraps -- which is also why there is
  no `qed-langgraph` package to keep in step with somebody else's API.

### Changed - the request signing moved out of `qed/api`

`canonical_string` and `sign` now live in `qed/adapters/signing.py`, with
`qed/api/auth.py` re-exporting them. The SDK has to sign, and importing
`qed.api.auth` to do it pulled FastAPI, Starlette, Click and Pydantic into
whatever application embedded the SDK. An SDK that drags a web framework into
a LangGraph worker is an SDK people route around, and routing around it means
their actions stop being recorded.

It cannot live in `qed/core` or `qed/infra`, which are scanned for any mention
of HMAC so that the evidence chain stays Ed25519-only. Adapter authentication
is a different problem with a different right answer, and keeping it out of
those trees is what lets that invariant stay absolute.

`tests/sdk/test_sdk_is_light.py` holds both halves: `import qed.sdk` loads no
server, and the signer and the verifier still agree byte for byte.

### Fixed - two fields that were on some rows and not others

- `execution_result` reported through `POST /v1/proposals/{id}/result` could
  not carry `duration_ms`, while both proxies record it when they write to the
  chain directly. An auditor would have found the field on some rows and not
  others for no reason a reader could explain. Still an allowlist -- an adapter
  does not get to put arbitrary keys in the chain.
- `approval_decided` written by `qed approve` had no `identity`, which the API
  path has carried since the week-4 work. It now records
  `cli-asserted:--by`, beside the API's `oidc:<issuer>` and
  `adapter-asserted:<id>`. Three paths, three strengths, one field. Found by
  reading the chain after a live SDK run.

82 new tests, 1,764 total.


### Added - the Claude Code hook and `qed install` (SPEC 12.2, week 6)

```
qed install claude-code --human you@acme.com
```

Every `Bash`, file write, MCP call and skill then goes through the same
`check_proposal` the two proxies and `qed check` use, and lands in the same
chain. `docs/hooks.md`; the three decisions that depart from SPEC 12.2 are in
ADR-0008, which exists because the spec was written against the older
exit-code-only hook contract.

- **An ALLOW verdict prints nothing at all.** The contract has a
  `permissionDecision: "allow"` and it *bypasses the permission rules the
  operator configured*. A gate answering `allow` to everything it did not block
  would be granting permissions nobody asked for -- somebody who had denied
  `Bash(rm *)` in their own settings would find QED waving it through. Exit 0
  with no output means "no decision, carry on with the normal flow", which is
  the honest answer from something asked whether to *stop* a call. A test
  asserts the string never reaches stdout.
- **REQUIRE_APPROVAL answers `ask`, not a refusal.** SPEC 12.2 degraded it to
  exit 2 "(hook cannot wait)". It still cannot -- but `ask` hands the call to
  the person at the terminal, which is what the rule asked for. The approval is
  still opened and recorded, so it can also be decided out of band and the
  window applies to the retry.
- **Nothing ever exits 1.** Any non-zero exit that is not 2 is *non-blocking*:
  the call proceeds and the transcript shows a notice. So a traceback would not
  fail closed, it would fail silently open -- the hook documentation warns that
  a mistyped path "silently disables the gate". Every path out of the adapter
  is a deliberate exit, and a fail-open gap writes an `ungated_window`.
- `mcp__postgres__execute_sql` becomes `postgres.execute_sql`, the same
  `action.name` the MCP proxy writes, so **one rule matches the same action
  through either adapter**.
- File paths are recorded relative to the session directory, so the chain does
  not carry somebody's home directory and a rule against `src/*` matches on two
  machines. A shell command targets `host:<hostname>`, because the command is
  the parameters.
- `agent_chain` is real, not asserted: Claude Code sends `agent_id` and
  `agent_type` only inside a subagent, so `["claude-code@host", "sub:Explore"]`
  means one genuinely is acting.
- Always `enforcement: advisory` (ADR-001), and `HookOptions` now refuses an
  identityless construction like the other two adapters do.
- `qed install` merges rather than replacing, leaves other hooks and the rest
  of the file alone, defaults to the gitignored `settings.local.json`, resolves
  the executable to an absolute path, and writes the exec form so a Windows
  path needs no quoting. It is idempotent on the *invocation* rather than the
  path: recreating a virtualenv replaces the entry whose executable moved
  instead of leaving a dead one beside a live one, and a dead entry is
  non-blocking.
- It prints the hardening route (`allowManagedHooksOnly` through managed
  settings) and is clear that hardening is not enforcement. SPEC 12.2's note
  names `allowManagedPermissionRulesOnly`, which is the permissions equivalent
  and does not lock hooks.

Codex is not built: SPEC 12.2 says "implement when API confirmed" and it is
not. A stub that recorded nothing would be worse than its absence, because
`qed doctor` would list an adapter that does nothing.

70 new tests, 1,719 total.


### Added - HTTP forward proxy (`qed proxy`) (SPEC 12.3, week 5)

Point an agent's `HTTPS_PROXY` at QED and every outbound call gets a
verdict from the same `check_proposal` the MCP proxy and `qed check` use.
`docs/http-proxy.md` has the whole picture; the parts worth stating here:

- **Every CONNECT tunnel is recorded as `advisory`, whatever the command line
  asks for.** QED decides whether the connection may be opened, which is
  real and the refusal is real, but once open it carries ciphertext: no
  method, no path, no body, and no way to replace the credential inside. An
  adapter recording `enforcing` there would put a control in the evidence that
  the transport does not allow. The reason travels with the record, and the
  `execution_result` says `visibility: host only` in the row rather than only
  in the documentation.
- A tunnel's evidence is byte counts and a duration. Thin, labelled as thin,
  and still the difference between "an agent moved 41 MB to pastebin.example
  at 02:14" and no record at all.
- **Plain HTTP starts honest too.** Enforcing needs a `kind: http` upstream
  whose credential resolves; with none, the session is advisory and says so at
  startup. The MCP proxy keeps the operator's flag in that case because
  deployments existed before the broker did. This adapter has no such history,
  so it does not inherit the dishonesty. `--enforcement` is a ceiling: it can
  ask for less than the broker holds, never for more.
- `action.target` is a URL. Not cosmetic: `match_upstream` finds a host glob
  by splitting the target on `://`, and the shipped `AG-DAT-003` egress rule
  matches `action.target` against `*://*`. A target in another shape would
  leave both matching nothing, and an egress rule that never fires is
  invisible.
- The query string stays out of the target and goes into the parameters. It
  carries tokens and its order varies between calls that mean the same thing;
  either would make a policy glob leaky or useless.
- The body is not read in `host_path` mode, so `params_hash` covers the
  request line and the headers that describe the body. Stated rather than
  implied; a rule that needs the body needs `mitm` mode, which is post-v1.
- `X-QED-Intent` is the HTTP counterpart of MCP's `_meta.intent`, and is
  stripped before forwarding: it is for QED, not the upstream.
- Refusals are a `403` whose body carries the rule ids, because an agent that
  only logs the status still logs the body with it. `502` upstream, `503`
  kernel-failed-and-closed, `501` for what this build will not forward.
- **Strict request framing.** Both `Content-Length` and `Transfer-Encoding`,
  two disagreeing `Content-Length`s, an obs-fold line, a non-token header
  name, a `CONNECT` without a port, userinfo in a proxied URL: all refused
  with a status rather than resolved. A proxy that resolves an ambiguity can
  be made to disagree with its upstream about where a request ends, and the
  smuggled half would be the half QED never decided. One request per
  connection, for the same reason.
- Binding anything but loopback needs `--allow-non-loopback`. A forward proxy
  on a reachable interface is an open relay, and the chain would attribute
  every request through it to this session's `--human`.
- `inject: {type: env}` on an `http` upstream is refused at startup rather
  than silently dropped per request.
- New rule **AG-DAT-013**: a request to a cloud instance metadata service is
  BLOCKed with no approval path. One unauthenticated GET to a link-local
  address returns the instance role's keys, the workload's own SDK reads it
  in-process rather than through a governed egress path, and this adapter is
  the first one that can see the attempt at all. 46 rules.

### Fixed - a result claimed an enforcement its own proposal denied

The first live run of `qed proxy` put this in one chain, two records apart,
about the same call: the `proposal` recorded `advisory`, correctly, because no
upstream was configured -- and the `execution_result` beside it recorded
`enforcing`, with `assurance: adapter`, because the recording path read the
operator's command-line flag instead of the answer that had just been derived.

**Both proxies had it.** The MCP adapter's `execution_result` was written the
same way, so the fix that arrived with enforcing MCP was half a fix: the
proposal told the truth and the record of what happened did not.

The derived enforcement now travels from the proposal down to the recording
site in both adapters, and falls back to the option only on the fail-open
path, where nothing was decided and so nothing was derived. `assurance`
follows it, so an advisory call is recorded as `self` -- the agent's own
testimony, per ADR-007.1 -- rather than as the adapter's.

### Added - the linter catches a glob that is secretly a character class

`fnmatch` reads `[` as the start of a character class, so
`*://[fd00:ec2::254]*` does not look for that IPv6 literal: it matches any
target whose host begins with one of `f d 0 2 4 5 c e :`. A rule written that
way reads correct and fires on traffic nobody meant it to, in the direction
that blocks real work.

AG-DAT-013 shipped with exactly that mistake, and the first live `qed proxy`
run was refused a CONNECT to example.com by the instance-metadata rule --
`e` was in the accidental set. The golden case written beside the rule used
`api.github.com` and passed the whole time, because `a` was not.

`suspicious_glob` is a **warning**, not an error: a character class is a legal
glob feature, rarely the intended one but not something to forbid. The message
names both the escape (`[[]`) and the predicate the author probably wanted
(`contains`). The golden table now also carries one host per character the
accidental class contained.

### Fixed - masking was rewriting the chain's own identifiers

About **one sha256 digest in four hundred** contains a 13-to-19 digit run that
starts with 2-6 and passes Luhn, so the card-number redactor replaced it with
`[masked:card]`. Masking runs *before* `payload_hash`, so the record still
verified against its own hash and nothing reported a problem -- the
`merkle_root` was simply wrong, and the checkpoint became impossible for
anyone to verify, for ever. `params_hash` and `policy_hash` were exposed at
the same rate.

It surfaced as `tests/evidence/test_chain.py` going red on roughly one push in
a hundred, on whichever runner happened to generate an unlucky signing key.

Two fixes, each sound on its own:

- A digit run flanked by letters is not a card number. The pattern now
  requires a non-alphanumeric boundary, which is what a real card number in a
  payload always has -- whitespace, a quote, a comma, a colon.
- `_STRUCTURAL_KEYS` (`merkle_root`, `params_hash`, `policy_hash`,
  `prev_hash`, `key_id`, `human_hash`, …) are exempt from masking, because a
  redactor has no business rewriting a value the kernel generated. The
  exemption is conditional: the value must look like an identifier *and*
  contain a letter, so a card number, a phone number or a national id -- all
  pure digits -- can never be exempted by sitting under one of those keys.

Old chains are unaffected. `qed-verify` recomputes `payload_hash` from the
payload as stored and never re-runs masking, so a record written under the
earlier pattern set still verifies.

### Fixed - a host glob stopped matching when the target had a port

`host_globs` is documented as matching the host and not the string, but
`_host_of` left the port on. The HTTP proxy found it: it writes
`http://127.0.0.1:8431/v1/orders` whenever the port is not the default, a glob
of `127.0.0.1` then matched nothing, the upstream went unmatched, and the
request ran advisory while the config said enforcing. `target_globs` still
sees the whole string for an operator who does want to distinguish ports.

### Fixed - `qed/adapters/http/` shadowed the standard library

The proxy arrived as `qed/adapters/http/` with tests in
`tests/adapters/http/`, and every test that runs
`python tests/adapters/upstream_server.py` as a subprocess started failing
with `ModuleNotFoundError: No module named 'http.client'` -- three imports
deep inside Starlette, nowhere near the directory that caused it. Running a
file puts its own directory at the front of `sys.path`. Both packages are now
`http_proxy`, and `tests/test_no_stdlib_shadowing.py` catches the next
plausible name (`json`, `types`, `select`, `email`) when the directory is
created rather than a week later.


### Added - enforcing MCP (SPEC 7.2, week 5)

- **`context.enforcement` is derived per action, not asserted by a flag.**
  QED is enforcing for a call if and only if it is holding the
  credential for it. Before this an adapter was told it was enforcing by a
  command-line option, that claim reached the evidence, and a missing
  credential made it silently false.
- Credentials are injected into a stdio upstream **at spawn**, into the
  child's environment. A child receives its environment once, so "resolved
  per request" is true for HTTP and not for stdio, where the TTL cache
  governs re-spawns. Saying so beats implying a freshness the transport
  cannot give.
- `strip_agent_credentials` removes nine credential-shaped headers,
  case-insensitively, *before* the broker's own is attached. An adapter that
  added its header while leaving the agent's would be one where the agent
  still chooses which credential is used.
- `sigv4` reports `needs_signing` rather than faking a header: the signature
  covers the request body, so it cannot be planned ahead, and forwarding
  unsigned would mean the agent's credentials get used after all.
- `ProxyStats.advisory` is printed separately, because a session that was
  entirely advisory looks identical to an enforcing one in every other count.
- With no upstreams configured the adapter keeps whatever the flag says.
  Going silently advisory on an existing install would be the worse surprise.
- The upstream test server gained `echo_env`, which is the only way to show
  the injected credential reached the child process rather than stopping at
  the proxy.

### Fixed - one `Enforcement`, not two

The broker defined its own enum with the same two members. It type-checked
everywhere and compared unequal in exactly the one place it mattered, which
is where mypy found it. The schema's enum is now re-exported.

### Added — credential broker: matching, resolution, posture (SPEC §7, week 5)

- `qed/core/broker/` (pure) matches an action to an upstream;
  `qed/infra/secrets/` resolves `env`, `file` and `vault` references behind a
  TTL cache; `qed/infra/upstreams.py` loads `upstreams.yaml`.
- **`Secret` makes a leak something you have to write on purpose.** `str`,
  `repr`, f-strings, `%`-formatting and `pprint` all render `<redacted>`;
  `json.dumps` refuses outright rather than serialising; `reveal()` is the
  only way to the bytes and is deliberately awkward to type. Sixteen tests,
  each one a different accident -- a log line, a traceback that formats its
  locals, a value nested in a dict being pretty printed.
- `len()` and `bool()` still work, because "set but empty" is something a
  health check needs to say without printing anything.
- **An upstream with no resolvable credential is advisory, whatever the
  config claims.** Config that promises more than it can deliver is worse
  than config that admits the gap, because the claim ends up in the evidence.
- `qed doctor` reports the uncomfortable question per upstream: does the
  qed hold the credential, or is the agent carrying its own? With nothing
  configured it says every adapter is advisory, in those words.
- First match wins, in file order. Not "most specific": specificity between a
  host glob and an environment list is not rankable, and an order nobody can
  predict is worse than one they can read top to bottom.
- `host_globs` matches the host, not the string, so `*.amazonaws.com` does
  not match `ec2.amazonaws.com.evil.test`.
- A missing or malformed `upstreams.yaml` is an error, not an empty set.
  Carrying on would quietly turn every enforcing adapter advisory, and the
  symptom is one nobody notices until it matters.
- An env var that is set but empty is an error: a deployment slip essentially
  every time, and failing loudly beats injecting nothing.
- `broker` leaves `UNIMPLEMENTED_SECTIONS`.
- `docs/credential-broker.md`.

Still to come in week 5: enforcing MCP and the HTTP forward proxy, the parts
that strip an agent-supplied `Authorization` and attach the broker's own.

### Added — approval service, core and CLI (SPEC §9, week 4)

- A `REQUIRE_APPROVAL` verdict now resolves against what a human has already
  said about that exact action: an open window makes it ALLOW, a recent
  denial makes it BLOCK, a pending request links to it, and otherwise a
  request is opened. All four happen before the verdict is written, so the
  chain records the decision that was acted on.
- **Separation of duties is enforced, not reported.** The approver may not be
  the principal (`AG-SOD-001`), may not be a service identity, and must be in
  the group the rule named (`AG-SOD-002`). A refused attempt is written to the
  chain: somebody trying to approve their own production delete is exactly
  what an auditor wants to find later, and a refusal that leaves no trace is
  indistinguishable from an attempt that never happened.
- Dedupe on `sha256(principal | name | target | params_hash)`. Parameters are
  in, because an approval for `DROP TABLE orders_archive` must not cover
  `DROP TABLE orders`. Environment and time are out, because two identical
  actions a minute apart are one question and an approver should see one
  request, not forty.
- `--window` grants every identical action for a period, keyed on the dedupe
  key so it covers *that action* rather than that person or that rule.
  Windows are not extendable. The length is the smallest of the request, the
  rule ceiling and the service ceiling; an approver cannot widen a rule's own
  bound by asking.
- The rule's timeout, approvers and window ceiling are copied onto the
  request at creation, not looked up at decision time. The bundle can be
  reloaded in between, and an approver should be bounded by the rule in force
  when the action was proposed. Where rules disagree the tighter one wins.
- `qed approve` and `qed approvals [--expire]`; `approval_requested`,
  `approval_decided` and `approval_expired` reach the chain.
- `0004_approvals.sql` adds `principal_hash` and `window_max_seconds`.
  Without the principal on the row, "the approver is not the principal"
  cannot be checked at decision time -- only claimed.
- `docs/approvals.md`.

Not yet: Slack Block Kit, `/events` SSE, the web approval page. The decision
path they would call is finished and is the one `qed approve` uses.

### Added — baseline pack, 15 rules to 45 (SPEC §22 week 3)

Thirty new rules across the five existing families: blast radius 10, budget 7,
data 12, identity 8, skills 8. 29 enforce, 16 shadow; 18 BLOCK, 27
REQUIRE_APPROVAL. The golden table goes from 74 cases to 107 and every rule
has one, which `test_every_shipped_rule_is_exercised` enforces.

The theme of the second set is that it mostly does not read the declared
hints. The first fifteen trust what the adapter said; these match the verb,
the target, or the absence of something, because an adapter that forgot to set
`deletes` on a teardown call is exactly the case the hints cannot catch.

Four of them are about the actions that make later actions invisible or
unrecoverable -- audit logging off, encryption off, backups weakened, data
made public -- which are worth blocking on their own terms whatever the agent
was trying to achieve.

### Fixed — three rules I got wrong, caught by the existing suites

- **`` does not bound a snake_case verb.** `terminate` never matches
  `terminate_instances`, because `_` is a word character, and tool names are
  full of snake_case. AG-BLR-007 and AG-BLR-010 silently matched nothing until
  their own cases failed.
- **AG-SKL-007 flagged `resources/read`**, which is an MCP protocol method and
  entirely ordinary. The regex only allowed the `server.tool` shape. Caught by
  the MCP golden table, which builds proposals through the real adapter rather
  than hand-writing them -- the exact gap its docstring says it exists to
  close.
- **AG-BLR-007 blocked single-instance teardown**, escalating a documented
  REQUIRE_APPROVAL to BLOCK with no approval path. Narrowed to the verbs that
  take a whole system away; AG-BLR-003 already handles one instance, with a
  route for a person to say yes.

Two more were over-broad rather than wrong and were narrowed before they
shipped: AG-BUD-005 fired on reads (ambient noise is how a shadow rule gets
ignored) and AG-IDN-004 was harsher than the AG-BLR-004 it backs up.

### Added — `history` in policy cases

`derived.history` is a documented field path and rules read it, but a case
could not set it, so any rule keyed on call or block counts was untestable.
An untestable rule is one nobody can change safely.

### Added — `qed policy test` (SPEC §14)

- Runs cases you write against the rules you have loaded. Touches nothing: no
  chain, no store, no network. Exit 0 all passed, 1 a case failed.
- `expect.rules` is the **exact** set of rule ids and is required, not
  optional. A case that checks only the decision passes when the right answer
  arrives from the wrong rule, which is worse than no case because it reads
  like coverage. Pinning the exact set means a case fails both when a rule
  stops firing and when an unrelated one starts -- the second is what catches
  a rule widened by accident.
- Every case is evaluated twice, the second time against a reshuffled bundle.
  ADR-002.2 says a decision must not depend on rule load order and this is the
  only thing that shows it; rule authors get the check on their own rules for
  free. `--no-order-check` opts out while iterating.
- `--coverage` lists loaded rules no case mentions.
- A case whose proposal does not validate is a failing case, not an exception,
  so one malformed entry does not hide every case after it.
- `docs/policy-testing.md`.

### Changed — the golden suite and the CLI share one comparison

`tests/policy/test_golden.py` now compares through `qed.core.policy.cases`,
the same code `qed policy test` uses. Two comparison routines would drift and
the one that drifted would be the user's; ours is the one with a CI job behind
it. The 74 golden cases still each run twice -- the shuffle moved inside
`run_case` rather than being a separate parametrized test, which is why the
total test count falls while coverage does not.

### Added — mandate lifecycle (SPEC §6.5)

- `qed mandate sign | list | revoke`, completing §6. Mandates were already
  consumed by `qed check --mandate`, the MCP proxy and the API envelope;
  there was no way to issue, store or withdraw one.
- `qed/core/mandates.py` (pure): the signing payload, signature verification
  and the active/inactive question. Ed25519 only, with no algorithm field read
  off the document -- the same rule as the token path.
- **What is signed is the document minus `signature` and minus `revoked_at`.**
  A signature cannot cover itself; the second exclusion is the one that
  matters. Revocation is an act of QED, recorded in the chain, not an
  edit the signer authorised, so a revoked mandate still verifies against the
  signature its issuer produced. Including `revoked_at` would mean revoking a
  mandate destroyed the proof of who granted the authority -- exactly the
  record an investigation needs.
- The document is stored whole, as the canonical JSON that was signed.
  Rebuilding it from columns risks bytes that differ from what the signer
  produced, and a signature that no longer verifies is indistinguishable from
  a forged one.
- `mandate_issued` and `mandate_revoked` reach the evidence chain. Revoking
  twice is refused rather than recorded twice.
- An unknown signing key is a failure, not a skip: treating "this instance
  does not hold that key" as "probably fine" is how an unsigned document gets
  accepted.

### Added — delegation (SPEC §6), week 3

- **`POST /v1/token`** (RFC 8693): an IdP token in, a narrower budgeted qed
  token out. Scope is intersected with what the subject's groups hold, budget
  is capped per axis, lifetime is the smallest of the request, an hour, the
  parent's remaining life and the mandate's. `refused_scope` comes back so a
  misconfigured agent fails at the exchange rather than at its first action.
- **`qed login`** (RFC 8628 device flow) and **`qed token`**. Both were
  already in SPEC §14's list of 18, so no spec update was needed. The refresh
  token goes to the OS keychain, or a 0600 file with a warning where there is
  none.
- **`GET /.well-known/jwks.json`**, outside `/v1` on purpose: every `/v1` route
  refuses an unsigned request and that test has no exemption list.
- `qed/core/delegation/` (pure) and `qed/infra/{tokens,jwks}.py` (I/O).
- `deploy/keycloak/`: a real Keycloak with the realm imported, and `demo.sh`,
  which runs the week-3 exit criterion end to end.
- `docs/delegation.md`.

### Fixed — three things only a real identity provider showed

Found by running the demo against Keycloak 26 instead of a fixture. All three
were invisible to the synthetic tests, because those built claims the way the
qed itself writes them.

- **`scope` is a space-delimited string** (RFC 6749 §3.3), not a list. Both
  forms are accepted now.
- **A token could declare its own kind.** `TokenClaims.token_type` defaulted to
  `"qed"`, so an IdP token — which carries no such claim — arrived looking
  qed-issued and was handed to the narrowing check as its own parent, failing
  every exchange. Whether a token is qed-issued is decided by *which key
  verified it*; the field is gone and a test asserts nothing reads it again.
  This is the same rule as never reading `alg` from the token.
- **A narrowing violation during mint escaped as a 500.** It is a caller asking
  for more than the subject token holds, so it is a 400.

### Fixed — `--config` on the commands that open a session

`export`, `status`, `checkpoint` and `verify` opened a session without a config
path, so they read the default `instance_id` and refused to touch a chain
written by any deployment that had set one. The demo hit it on its first
complete run.

### Changed — Keycloak realm requests the `basic` client scope

Keycloak 26 omits `sub` from the access token without it. A token with no
subject cannot name a principal, so QED refuses it — correctly, but the
shipped realm should not produce one.

### Added — budget ledger (SPEC §8), week 3

- **Budgets are persisted and charged.** `check_proposal` previously passed an
  empty `BudgetState` into the engine, so `derived.budget.*` was always zero
  and the three AG-BUD-* rules could never fire against stored state. The caps
  now live in `budgets` next to the usage, a decision reads them, and an action
  that runs is charged.
- `qed.core.budget` holds the arithmetic and stays pure: `charge_for` (cost
  from the adapter's estimate), `apply_charge`, `newly_exhausted`. The atomic
  read-modify-write is `SqliteStore.charge_budget`, under the same
  `BEGIN IMMEDIATE` write lock `append_evidence` uses and for the same reason —
  two adapters charging one token must not both read the same `steps_used`.
- **A charge follows what happened, not what was decided.** In enforce mode a
  BLOCK stops the action and nothing is spent. In shadow mode — the shipped
  default — the adapter proceeds whatever the verdict says, the tokens are
  really spent upstream, and the ledger says so. `effective_decision` already
  encoded that difference.
- Usage may exceed its cap and is not clamped. Clamping would make the ledger
  disagree with what was spent, and the overshoot is what tells an operator the
  cap was set too low.
- `first_seen` is set by the first charge, not at issuance: a `seconds` budget
  that started ticking when a token was minted would punish an agent for the
  gap before it was used.
- Per-principal daily aggregate (`budget_daily`), kept as its own table so a
  retention purge of payloads cannot erase counts a policy reads.
- **No evidence record per charge.** SPEC §8 writes one only on exhaustion, and
  §6.2 writes `budget_update` only when a token is issued. A record per allowed
  action would double the chain, restate what the verdict record already
  implies, and put a signature and an insert on the hot path the week-7 p95
  target has to defend. The first draft of this change did write one; the
  record counts in eleven existing tests were what caught it.
- 41 tests: arithmetic, ledger, migration, and the runtime rules above.
  End-to-end on the CLI: a 2-step token allows two actions, the third is
  blocked by the AG-BUD-001 short-circuit, exactly one `budget_exhausted` sits
  after the verdict that caused it, and `qed-verify` still passes on the
  resulting chain.

### Changed — migrations are applied once

- `SqliteStore.migrate` replayed every script on every open, which worked only
  while every statement was `CREATE TABLE IF NOT EXISTS`. SQLite has no
  `ADD COLUMN IF NOT EXISTS`, so 0002 could not be written that way. A
  `schema_migrations` ledger now records what has run. An existing database has
  no ledger, so 0001 is replayed there once — safe precisely because it is
  idempotent, which is why no backfill was needed.

### Added — licence applied, name settled (SPEC §24.1, §24.2)

- **Apache-2.0 is applied.** `LICENSE` (verbatim, 202 lines) and `NOTICE` at
  the root, and the same two files copied into `packages/qed-verify/` —
  copied, not referenced, because PEP 639 `license-files` globs cannot escape
  a project directory. CI asserts the two licence texts stay byte-identical,
  since a verifier shipped under a stale licence text is the kind of detail an
  auditor is paid to notice.
- `license = "Apache-2.0"` in both `pyproject.toml` files as an **SPDX
  expression**, not the `{text = ...}` table: setuptools 77 deprecated the
  table and now treats a `License ::` classifier next to the expression as an
  error, so there is no such classifier.
- The `Private :: Do Not Upload` classifier is gone from both projects. A PyPI
  upload is no longer refused by its own metadata.
- `PATENT-AND-LICENCE-QED.md` is deleted. **SPEC §24.2 closed on 2026-10-08:
  Valqore holds no patent filings and has nothing pending**, so the
  irrevocable Apache-2.0 §3 grant transfers nothing. It was answered before
  distribution, which was the entire purpose of withholding the licence.
- The CI job *No LICENSE file until SPEC 24.2 closes* now asserts the
  opposite: both licence files present, both projects declaring Apache-2.0,
  the guard-rail classifier not back, and the qed-verify copy identical.
- **SPEC §24.1 closed: the product is "Valqore QED".** `qed` stays the
  command, the import package and the repository name. Zero refactor — the
  evidence format already carries no product name (ADR-0006), so nothing in a
  chain written today depends on this choice.

### Still not public

The remote stays private until the PyPI, npm, GHCR, Homebrew-tap, domain and
EUIPO/USPTO reservations are in place (`REPO-AND-PUBLICATION-PLAN.md` §5).
Applying a licence is reversible for as long as nobody has received the code;
publishing is not.

### Changed — evidence format

- **Breaking, pre-release.** The hash domain separators no longer carry the
  product name (ADR-0006). `"gate-genesis:"` becomes
  `"evidence-chain/1:genesis:"`, `"gate-principal:"` becomes
  `"evidence-chain/1:principal:"`, and `chain_format` / `chain-format` becomes
  `evidence-chain/1`. Genesis hashes and principal hashes therefore change.
  Nothing outside the test suite has written a chain, so there is nothing to
  migrate; doing this after a design partner runs the kernel would have meant
  either invalidating their evidence or shipping a retired name in the format
  forever. SPEC §24.1's "the name is a placeholder, a rename is a single
  refactor" is true after this change and was not true before it.
- `qed/core/evidence/format.py` is the single definition. `qed-verify` keeps
  its own copy, as SPEC §10.7 requires, and `tests/evidence/test_format_constants.py`
  checks the two agree, pins the exact bytes against digests recorded outside
  the package, and fails if a candidate product name appears in a hash input.

## [0.1.0] — 2026-10-07

Weeks 1 and 2 of the SPEC §22 build order.

> **Tagged locally, not published.** SPEC §22 week 2 also makes the repository
> public as `v0.1.0`. At this tag that step was waiting on the three pre-repo
> decisions — patent scope, product name, licence timing. All three closed on
> 2026-10-08; see [Unreleased]. The public push now waits only on the name
> reservations in `REPO-AND-PUBLICATION-PLAN.md` §5.

### Added — week 2 (SPEC §22)

- `qed/adapters/mcp/`: the MCP proxy. MCP server toward the agent, MCP client
  toward the upstream, over stdio or Streamable HTTP, on the official `mcp` SDK.
  `initialize` keeps the upstream's `serverInfo` and adds a note to
  `instructions`; capabilities are mirrored rather than claimed, so the proxy
  never advertises `prompts` to a client whose upstream has none. `resources/read`
  and `prompts/get` are forwarded, recorded and never refused (SPEC §12.1).
- `qed/adapters/mcp/intent.py`: tool-call classification into the SPEC §3.1
  hints. Reads the arguments as well as the tool name. See "Changed from the
  spec" below — this is the week 1 review's carry-forward item.
- `qed/adapters/mcp/targets.py`: `target_template` with `{server}`, `{tool}`,
  `{env}` and `{args.<dotted.path>}`. Validated at startup; substituted values
  are sanitised, because a tool argument is attacker-influenced input.
- `qed/adapters/common.py`: proposal building shared by every adapter —
  `params_hash` over the whole parameters, a bounded `params_redacted` that
  honours the SPEC §17 16 KB limit, ULID proposal ids.
- `qed/api/`: FastAPI app. `POST /v1/proposals`, `GET /v1/proposals/{id}`,
  `POST /v1/proposals/{id}/result`, `GET /v1/evidence`,
  `GET /v1/evidence/by-ref/{ref}`, `GET /healthz`, `GET /readyz`. RFC 9457
  `problem+json` throughout, including for 404s and validation failures.
  `readyz` is false without a signing key, with a broken policy bundle, or
  without usable adapter authentication (SPEC §17).
- `qed/api/auth.py`: adapter authentication. `X-QED-Adapter-Id` plus an
  HMAC-SHA256 over method, path, timestamp, nonce and body digest. Secrets come
  from environment variables named in `qed.yaml`, never from the file itself.
- `qed/core/evidence/export/oscal.py`: OSCAL 1.1.2 `assessment-results`. One
  observation per evidence record, one finding per (rule hit, control), public
  keys and checkpoint roots in `back-matter`. All identifiers are derived
  version-5 UUIDs, so the same range exports byte-identically every time.
  Validated against the vendored NIST schema in CI (SPEC §10.8, MUST pass).
- CLI: `qed serve` and `qed mcp`; `qed export --format oscal`.
- `deploy/Dockerfile`: two-stage, distroless, non-root, no shell in the runtime
  image, no `VOLUME` line (an anonymous volume is how an evidence chain
  disappears on `docker run`).
- `qed/core/evidence/hashing.py::principal_hash`: one definition of how a human
  principal is hashed, so the proxy today and week 3's token verification
  attribute to the same principal.
- `docs/api.md`, `docs/mcp-proxy.md`, `docs/oscal.md`; `docs/assurance-classes.md`
  updated for the three classes that now exist.
- Tests: the week 2 exit criterion end to end against a real MCP server process
  (`tests/adapters/`), API and auth suites (`tests/api/`), OSCAL schema
  validation with negative controls (`tests/evidence/test_oscal_schema.py`), and
  14 golden cases built through the real adapter path
  (`tests/policy/test_golden_mcp.py`). 922 tests, up from 595.

### Fixed — week 2

- `qed/core/evidence/masking.py`: the card-number masker corrupted identifiers
  qed itself generates. Luhn is a checksum, not an identifier — a run of
  eighteen zeros passes it exactly, because the sum is 0 and 0 is divisible by
  10 — so the ULID-shaped `token_jti` `01JB000000000000000000JTI0` was rewritten
  to `01JB[masked:card]JTI0` *inside the chain*, in every proposal record. The
  recorded token then no longer matched the token the API and the week 3 budget
  ledger know about, and a corrupted identifier is indistinguishable from a
  redacted one. A candidate now also has to have more than one distinct digit
  and an issued-card prefix (2–6). Every real card range is still masked.

  This changes `payload_hash` for records whose payload contains such a run.
  Nothing has been released and no fixtures existed, so no chain in the world
  is affected; the hash algorithm itself is unchanged and existing records still
  verify, since each was hashed over whatever it stored.

### Changed — week 2

- `qed mcp` requires `--human` or `--mandate`. Without identity, `evaluate`
  short-circuits to a synthetic `AG-IDN-007` BLOCK *before* any rule in the
  bundle runs, so the chain would fill with identical identity blocks in which
  no policy rule had ever been evaluated — and in shadow mode nothing would be
  stopped and nothing would look wrong. `--human` is recorded as
  adapter-asserted in `client_fingerprint`, which SPEC §3.1 defines as advisory
  and never enforced on. Verified identity is week 3.
- `qed/config.py`: `api` and `adapters` sections are now read, and removed from
  `UNIMPLEMENTED_SECTIONS`.
- `SqliteStore`: added `get_proposal`, `evidence_at`, and a `types` filter on
  `iter_evidence`.
- SPEC §20.3: `jsonschema` added to the dev/test dependencies, for the OSCAL
  schema check. SPEC §10.8 permits JSON Schema in place of `oscal-cli`, which
  would put a JVM in CI.
- `mcp` is pinned `>=2.3,<3`. The 2.0 SDK replaced the decorator-based low-level
  server with the `on_*` callbacks the proxy uses, so a 1.x resolution would not
  import.

### Changed from the spec — week 2

- **`mcp/gateway.py` is not ported as SPEC Appendix B says.** Its blast-radius
  function reads:

  ```python
  try:
      from valqore.agents.action_intent import normalize

      ...
  except Exception:
      nb, nct = "low", "unknown"
  ```

  `action_intent` imports `valqore.codegen.validate` at module level, which
  pulls in the IaC parser and the rule engine. The Phase-0 inventory measured
  import isolation with `sys.modules`, which only sees top-level imports of
  already-loaded modules, so that chain did not show up. Ported as written into
  a tree with no `valqore` package, the import raises, the bare `except`
  swallows it, and the function returns `low` for everything. Nothing errors and
  nothing logs; blast radius silently degrades to matching the tool name, and
  `execute_sql` carrying `DROP TABLE orders` stops routing to approval. In
  shadow mode nobody would notice, and enforce starts in week 10.

  The useful half — the verb tables, earned on tools agents really call — is
  written out in `qed/adapters/mcp/intent.py` with no import that can fail.
  Valqore's "sensitive → high" half is deliberately left out: the kernel's
  `blast_radius.py` already scores that surface, already reads `params_redacted`,
  and is inside the policy hash where an auditor can replay it.
  `tests/adapters/test_import_boundary.py` holds both halves of the line — an
  import allowlist for `intent.py`, and a check that no broad `except` on the
  decision path neither logs, records nor refuses.

### Added — week 1 (SPEC §22)

- Repo skeleton, `ruff` + `mypy --strict` + `pytest` in CI, no-network and
  no-LLM import guards on `qed.core`.
- `qed/core/schemas.py`: full SPEC §3 domain model on Pydantic v2, frozen and
  `extra="forbid"`. Timestamps are RFC 3339 UTC at millisecond precision with a
  deterministic serializer.
- `qed/core/jcs.py`: RFC 8785 canonical JSON, used for every hash.
- `qed/core/evidence/`: record construction, SPEC §10.2 hash, Ed25519
  signatures, Merkle checkpoints, secret/PII masking at write.
- `qed/infra/storage/sqlite.py` + forward-only migrations: the evidence ledger
  and the SPEC §15 tables week 1 needs.
- `qed/infra/keys/file.py`: file-backed Ed25519 keys, `qed keys init`.
- `qed/core/policy/`: loader (rules, overrides, disables), linter (all SPEC
  §4.3 error classes), predicate evaluator (SPEC §4.4), engine (SPEC §5),
  deterministic blast-radius table.
- `qed/core/policy/packs/agent-baseline/`: 15 baseline rules.
- `packages/qed-verify/`: standalone verifier, `cryptography` only.
- CLI: `keys init`, `check`, `policy lint|explain`, `export`, `verify`.
- 62 golden policy cases; chain, Merkle, masking, JCS, lint and CLI suites.

### Deliberately not added

- No `LICENSE` file and no `license` metadata, because SPEC §24.2 (patent
  scope) had to close first — the Apache-2.0 patent grant is irrevocable once
  distributed. Lifted in [Unreleased] on 2026-10-08, when §24.2 came back
  clean.

### Changed from the spec

- `qed/core/policy/blast_radius.py` is **written fresh**, not ported from
  Valqore `governance/blast_radius.py`. See `docs/adr/0001-blast-radius-table.md`.
