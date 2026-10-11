# Deploying QED

Three ways, in order of how much they ask of you: a process, a container, a
Helm release. All three run the same binary and write the same chain; what
changes is who holds the evidence signing key and how many replicas may write.

## The one rule that shapes everything

**Exactly one process may append to a chain at a time.**

Every record carries `seq` and `prev_hash`, so appending means reading the tip,
computing the next link and writing. Two writers read the same tip. Either the
primary key on `hash` refuses the loser — and a decision that was already
delivered has no evidence — or both commit and the chain forks. A forked chain
still verifies record by record. It just stops being a chain, and nothing says
so until an auditor walks it.

That is why the backend decides the topology, not a flag:

| Backend | Replicas | Why |
|---|---|---|
| SQLite (default) | **1** | one process writing for itself; zero configuration |
| PostgreSQL | **any** | exactly one holds the advisory lock and drains the outbox |

On the PostgreSQL path, every replica serves the API and decides; the decider
writes its record durably to `evidence_outbox` and answers immediately, and
whichever replica holds `pg_try_advisory_lock(1734440037)` assigns `seq`,
`prev_hash` and the signature afterwards (ADR-0009). So decision latency is
independent of chain latency, and `evidence_ref` may be an outbox id rather
than a sequence number until the leader has caught up —
`GET /v1/evidence/by-ref/{ref}` resolves both, and answers `200 {"seq": null,
"pending": true}` for one that is still queued.

Watch `chain_lag_records` in `qed status` and `GET /v1/status`. A depth that
keeps growing means the leader is gone, or is losing the lock faster than it
can drain.

## A process

!!! warning "`valqore-qed` is not on PyPI yet"
    The name reservations in SPEC §24.1 are the publication gate, and
    publishing is the irreversible step. Until that is done, install from
    the repository: `git clone https://github.com/valqore/qed && cd qed &&
    pip install -e .`

```bash
pip install valqore-qed
qed keys init --dir /var/lib/qed
qed serve --dir /var/lib/qed --host 0.0.0.0
```

`/readyz` answers 503 until there is a signing key and a way to authenticate
adapters (SPEC §17). Read the `blockers` field; it says which.

## The container

!!! warning "The image is not on GHCR yet"
    `release.yml` builds it, starts it on both architectures and attaches it to
    the GitHub Release, but pushing is behind `PUBLISH_GHCR` until SPEC §24.1's
    reservations are done. Until then, build it: `docker build -t qed -f
    deploy/Dockerfile .`

```bash
docker run --rm -v qed-state:/var/lib/qed ghcr.io/valqore/qed:1.0.0 \
  keys init --dir /var/lib/qed

docker run --rm -p 8710:8710 -v qed-state:/var/lib/qed \
  ghcr.io/valqore/qed:1.0.0
```

Distroless and non-root (SPEC §20.4): no shell, no package manager, no pip. A
policy kernel that can be shelled into is a policy kernel an attacker can
reconfigure.

`qed keys init` runs **once, against the volume**, and the image deliberately
does not generate a key on start. A key created inside an ephemeral container
disappears with it, and every restart would begin a new chain whose genesis
claimed to be the same instance.

The image includes the `postgres` extra, because which backend an operator uses
is a property of the deployment and not of the artifact they were handed.

### Two replicas and a database, on a laptop

```bash
qed keys init --dir deploy/state
docker compose -f deploy/docker-compose.yml up --build

curl -s localhost:8710/readyz | jq     # replica a
curl -s localhost:8711/readyz | jq     # replica b

docker compose -f deploy/docker-compose.yml kill qed-a
# the survivor takes the lock on its next tick and the chain continues
```

Both replicas share one signing key, because the chain is one chain: whichever
replica is leading signs, and a record signed by a key the others do not have
would make the export unverifiable from the next record on.

## Helm

```bash
qed keys init --dir ./qed-keys
kubectl create secret generic qed-signing-key \
  --from-file=evidence-key.pem=./qed-keys/evidence-key.pem

helm install qed ./deploy/helm/qed \
  --set signingKey.existingSecret=qed-signing-key
```

Keep `./qed-keys/public/` — that is the half an auditor verifies an export
with, and the half that is safe to publish.

### What the chart refuses to install

Each of these is something the pod would otherwise discover at runtime, where
the symptom is a CrashLoop or a forked chain. `helm install` is the last moment
at which the answer can be a sentence instead of a pager.

* **No `signingKey.existingSecret`.** An unsigned decision is not evidence. The
  chart will not generate a key: one created by an install hook lives wherever
  the hook wrote it, and one created per pod starts a new chain on every
  restart.
* **`replicaCount > 1` with `evidence.backend: sqlite`.** See the one rule
  above.
* **`evidence.backend: postgres` with no `existingSecret` for the DSN.** The DSN
  carries a password and is never rendered into a manifest; `qed.yaml` names the
  environment variable instead.
* **SQLite with persistence disabled**, which would put the chain on a
  filesystem that is deleted with the pod.

### HA

```yaml
replicaCount: 3
evidence:
  backend: postgres
  postgres:
    existingSecret: qed-db     # key `dsn`
podDisruptionBudget:
  enabled: true
```

```bash
kubectl create secret generic qed-db \
  --from-literal=dsn='postgresql://qed:…@pg:5432/qed'
```

### What the defaults are, and why

**`config.mode: shadow`.** A kernel installed in enforce mode starts refusing
actions before anybody has seen what its rules do, and the first thing an
operator learns about QED should not be an outage. Run it for a week, read the
evidence, then set `enforce` — SPEC §22's week-2 criterion is that this is a
config change and nothing else.

**`image.tag` pinned to the chart's `appVersion`.** A chart whose default is
`latest` installs something different every week, and the chain records
`engine_version` with every decision it makes.

**`readOnlyRootFilesystem: true`, one writable mount.** The same reason the
image is distroless.

**`helm.sh/resource-policy: keep` on the evidence volume.** An auditor asking
about a decision from six months ago is asking about a record `helm uninstall`
would otherwise have deleted. Remove the claim deliberately, after exporting.

**A ConfigMap checksum on the pod template.** The chain records `policy_hash`
with every verdict; without the rollout, that hash could name rules a ConfigMap
replaced hours earlier.

**No service account token.** QED calls no Kubernetes API. One mounted anyway
would be a credential in a pod with no use for it.

### Where the signing key is mounted

In its own directory — `/etc/qed/keys`, read-only — with
`evidence.signing_key` in `qed.yaml` pointing at it. The key and the chain want
different storage: a secret that must not be writable, and a database or volume
that must be. Nesting the secret mount inside the writable one to satisfy a
fixed filename is the sort of arrangement that works until a kubelet orders the
mounts differently.

## Upgrading

The migrations are forward-only and run on start, under an advisory lock on
PostgreSQL so that several replicas starting at once apply them once. A
`schema_version` change to `EvidenceRecord` is always accompanied by an ADR and
by `qed-verify` keeping the ability to verify every prior version (SPEC §25.6),
so an upgrade never invalidates evidence already written.

Before anything irreversible, export:

```bash
qed export --dir /var/lib/qed > chain-$(date +%F).jsonl
qed-verify chain-$(date +%F).jsonl --keys /var/lib/qed/public --instance-id <your id>
```

## Releasing

`.github/workflows/release.yml`, on a `v*` tag.

**Publishing is off until somebody turns it on.** SPEC §24.1's name
reservations — PyPI `valqore-qed` and `qed-verify`, the GHCR path, the Homebrew
tap — are not done, and publishing is the irreversible step: a version on PyPI
cannot be unpublished and reused, and an image pushed under a name somebody
else later owns is a mess to undo.

So a tag today produces the whole release and pushes none of it: the version
gate, the full test suite, both wheels (checked for the data files they read at
runtime), the container built *and started* on both architectures, the Helm
chart linted and packaged, and a GitHub Release with all of it attached. Two
repository variables turn the rest on:

| Variable | What it enables |
|---|---|
| `PUBLISH_GHCR=true` | push the multi-arch image, cosign keyless signature, SBOM attestation, Helm chart to `oci://ghcr.io/valqore/charts` |
| `PUBLISH_PYPI=true` | publish both wheels via trusted publishing |

Settings → Secrets and variables → Actions → Variables.

### Bump before you tag

```bash
# qed/version.py is the only literal; everything else is checked against it
vim qed/version.py            # VERSION = "1.0.0"
pytest tests/test_version.py  # the chart, the Dockerfile label, the docs
# move the [Unreleased] entries under `## [0.7.0] — <date>` in CHANGELOG.md
git commit -am "release: 1.0.0" && git tag v1.0.0 && git push --tags
```

The workflow refuses a tag that disagrees with `qed/version.py`, and refuses
one with no matching `## [x.y.z]` changelog section. Both are guard rails for
mistakes already made: a release whose artifacts all report the previous
version cannot be fixed without deleting the tag, and notes built from
`[Unreleased]` change the next time anybody edits the file.
