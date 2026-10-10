# Validating a release

The test suite is 2,250 tests and green. This page is about the things it
cannot see, because every one of them has shipped at least once.

The pattern is consistent enough to name: **a test that imports the source tree
is not a test of the thing you ship.** The suite runs against a repo checkout,
on one architecture, in one process, with `qed` importable from `.`. A release
is a wheel installed somewhere else, a container on two architectures, and
several replicas starting at the same moment.

## What a green suite has missed

| What shipped | Why the suite could not see it |
|---|---|
| A container that could not import pydantic | the Dockerfile assertions read text; nothing started the image |
| A wheel missing `compliance/frameworks.yaml` | the checkout has the file |
| An arm64 image with every library in the wrong directory | the container test only built for the host |
| A replica dying on startup in HA | one process in the suite, two in the stack |
| `terraform.destroy` in prod returning ALLOW | no case asserted the tool-name spelling |
| Masking eating a public key under `strict` | the record still verified against its own hash |
| Ten control catalogues missing from the wheel | the test for exactly this matched them with `fnmatch`, whose `*` crosses a `/` |

Each is now guarded, and the guards are the point of the list: it is not that
these bugs existed, it is that the *class* keeps recurring.

The last row is worth dwelling on, because the guard was already there and
still let it through. `tests/test_packaging.py` was written after the
`frameworks.yaml` bug, precisely to check `package-data` against what is on
disk -- and it used `fnmatch`, which has no notion of path segments, while
setuptools expands those patterns with `glob`, which does. So
`compliance/*.yaml` appeared to cover `compliance/packs/eu_ai_act.yaml` and did
not. **A guard written in a different matcher than the thing it guards is not a
guard**, and the only reason this surfaced is that one test starts the real
image and drives it.

## The checks

### Install the wheel and drive it from somewhere else

```bash
python -m build --outdir dist .
python -m build --outdir dist packages/qed-verify
python -m venv /tmp/clean && /tmp/clean/bin/pip install dist/*.whl
cd "$(mktemp -d)"                       # no source tree on the path
/tmp/clean/bin/qed keys init --dir ./state
/tmp/clean/bin/qed check proposal.json --dir ./state
/tmp/clean/bin/qed export --dir ./state > chain.jsonl
/tmp/clean/bin/qed-verify chain.jsonl --keys ./state/public
```

The `cd` matters. Run it in the repo and a missing data file is masked by the
checkout; the wheels job in `release.yml` does the same thing for the same
reason.

### Tamper with something that is actually different

A chain decided in shadow mode is all ALLOW, so setting a verdict to ALLOW
tampers with nothing — and a verifier that correctly accepts an unmodified
chain looks like one that accepts a forged one. Flip the value to something
else and assert the bytes changed before concluding anything:

```python
current = record["payload"]["verdict"]["decision"]
record["payload"]["verdict"]["decision"] = "BLOCK" if current != "BLOCK" else "ALLOW"
assert new_line != old_line, "the tamper changed nothing"
```

### Use a fresh proposal id each time

Ids are single-use. Reusing one is a 409 that writes nothing, which silently
empties any assertion about the records that were supposed to follow — a
post-rotation check that reused an id left the chain with no post-rotation
records at all, and the "verifies across the rotation" assertion then passed
without a rotation in it.

### Pick a key by key id, not alphabetically

`sorted()` over `ed25519_<hex>.pem` has nothing to do with which key is
current. Picking the wrong one made "a chain must not verify without the
retired key" pass for the wrong reason.

### Start both architectures

```bash
pytest tests/deploy -m slow        # builds and starts the foreign arch under emulation
```

Skipped without emulation rather than passing on the easy half.

### Start more than one replica

```bash
qed keys init --dir deploy/state
docker compose -f deploy/docker-compose.yml up --build
curl -s localhost:8710/readyz | jq .ready
curl -s localhost:8711/readyz | jq .ready
```

Both, not one. The startup race only appeared because *both* were checked — the
survivor looked perfectly healthy.

## The full pass

`tests/perf` and `tests/deploy -m slow` are excluded from the matrix and run in
their own CI jobs. A release pass is:

```bash
pytest -q                                      # everything, including slow and perf
QED_TEST_POSTGRES_DSN=postgresql://... pytest -q
pytest tests/deploy -q -m slow                 # both architectures
pytest tests/perf -q -m perf -s                # p95, with the distributions printed
docker compose -f deploy/docker-compose.yml up --build -d && ...
helm template qed deploy/helm/qed --set signingKey.existingSecret=k
```

Plus the one thing no automation covers: install the wheel on a machine that
has never had the source, and follow `README.md` from the top. Every gap in the
table above would have been found in the first five minutes of doing that.
