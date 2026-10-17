# Validating a release

The test suite is 2,727 fast tests and green. This page is about the things it
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
| Both arm64 tests skipping one step after the emulator was installed | a probe that could not tell "no emulator" from "the registry did not answer" |
| An imported catalogue that stopped the kernel deciding | nothing had tested an import against the installed rules |
| `policy_loaded` saying `unsigned: false` after an unsigned import | the policy hash does not change, so the record is never re-emitted |
| `evidence.checkpoint.every_records` being ignored | the default matches the spec, so only a tuned value shows it |
| A traceback from `qed policy lint` on a malformed rule file | every test fixture is valid YAML |
| `UnicodeDecodeError` from a pack bundle with one stray byte | every test bundle was written by the test |
| A frozen binary telling a Python-less user to run `pip install` | the build succeeded; nothing ran the binary |
| **A mandate's signature was never verified** | `verify_mandate` was unit-tested from week 3 and nothing called it |
| `README.md` citing `tests/policy/test_determinism.py` | no test asserts that a cited path exists |
| A format spec that would have frozen the secret-masking patterns | the sentence was true; the conclusion drawn from it was not, and no test reads a conclusion |
| Eleven weeks of "cross-version fixtures in CI" with no fixtures | the test that looked like one regenerates its own input |
| A frozen fixture's public keys, matched by `.gitignore`'s `*.pem` | the files were on disk, so everything passed locally |
| A byte-pinned fixture written with CRLF on Windows | the pin matched on the machine that made it |
| **`qed-verify` printing `OK` over a check it had skipped** | every test supplied `--instance-id`, so no test ever saw the output an auditor following the README would get |
| A repository about to publish a defect list for the commercial product | no test reads a document the way an outsider would |
| **`v1.0.0` shipped with no way to ask it its version** | nothing in the suite asks the binary what it is, and the Homebrew formula's test block avoids `--version` on purpose -- correct reasoning about the *test*, mistaken for a reason the flag need not exist |

Each is now guarded, and the guards are the point of the list: it is not that
these bugs existed, it is that the *class* keeps recurring.

## The mandate signature, which is the worst of them

A mandate is what lets an action with no human behind it proceed at all:
`AG-IDN-007` BLOCKs an unattended proposal that carries no mandate. So forging
one converts a refusal into a decision, and until week 11 forging one meant
editing a JSON file.

`verify_mandate()` was written in week 3 and unit-tested the same day: tamper
with a mandate, assert it raises. **Those tests passed for eight weeks because
they called the function. Nothing else did.** Every consumer parsed a mandate
with `Mandate.model_validate_json` -- schema, not signature -- and handed it to
the engine. `qed.core` had deliberately declined the job ("signature
verification is the token layer's job") and no token layer picked it up.

Three things make this the most instructive entry on the page:

1. **Coverage was not the problem.** The function was covered. The missing
   assertion was that the path an operator actually uses calls it, which is a
   different kind of test and the kind this project keeps having to add.
2. **`SECURITY.md` documented it as fixed-by-week-3.** A known limitation with
   a due date is worse than an unknown one, because everybody stops looking.
3. **It was found by executing the documentation.** Writing
   `docs/onboarding-shadow-to-enforce.md` meant running every command in it,
   including one with a mandate, and the only reason to try a forged one was
   that the guide claimed the signature mattered.

That last point is now policy: **a command in a document must have been run.**
Three passages of the onboarding guide were wrong on the first draft -- a flag
that is positional, a config block with the wrong keys, and output invented
from the help text -- and all three would have shipped had the page been
written from the source rather than from a terminal.

## The two week-12 entries, which are about tests rather than code

Neither of these was a bug in `qed`. Both were a test or a document that could
not have failed, which is worse value for the same green tick.

**"Cross-version fixtures in CI" existed as a sentence for eleven weeks.**
SPEC §25.6 promised that a `schema_version` bump keeps `qed-verify` able to
verify every prior version, with fixtures in CI to prove it. There were no
fixtures. What there was is `tests/evidence/test_chain.py`, which writes a chain
with the real signer and the real store and verifies it with the real verifier,
end to end -- a good test that cannot see this failure at all, because a
producer and a verifier that change together pass it, while the records already
in a customer's database do not change with them.

The shape to look for: **a test that regenerates its own input is not a test of
compatibility.** It is a test that today's code agrees with itself. The fix was
to commit an export produced once, pin its digest in the test file rather than
inside the fixture, and make a `schema_version` bump fail until it has a fixture
of its own (ADR-0015).

**A document froze the wrong thing.** The draft `docs/evidence-format.md` said
the masking pattern set "is part of the format: changing it changes record
hashes for future records". Every clause there is true. The conclusion is wrong:
masking runs before hashing, so a new pattern changes what future records
*contain* and cannot change one already written, and a verifier never re-derives
a mask. Freezing 1.0 as written would have frozen the secret-detection patterns
for the life of the product.

No test could have caught it, and that is the entry. A guard can check that a
document's cited paths exist (`tests/docs/test_claims.py`) and that its commands
run; it cannot check that an inference drawn in prose is sound. The only control
for that is writing down what a commitment covers in two explicit tables --
inside the freeze, outside the freeze -- before committing to it, which is what
the page now does. A promise whose boundary is implied is a promise nobody can
check.

## Two things the fixture itself nearly shipped broken

Both were caught between writing the fixture and committing it, by asking what
a *different machine* would see. Both are in the table above because they are
the recurring class, not because they reached a release.

**`.gitignore` matched the fixture's public keys.** Line 15 is `*.pem`, under
the comment "never commit keys or chains" -- correct for a private key, and it
matched the two **public** ones the frozen chain cannot be verified without.
The first commit would have published a chain with no keys. Locally nothing
would have shown it: the files are on disk and every test passed. In CI it
would have surfaced as `unknown_key` on a frozen fixture, which reads like a
format regression rather than a missing file.

`.gitignore` now carries an explicit negation for
`evidence-format-*/public/*.pem`, and
`test_every_fixture_file_is_tracked_by_git` asks git what it is tracking rather
than asking the filesystem what exists -- the same correction as the packaging
guard that used `fnmatch` while setuptools expands with `glob`: ask the thing
that actually decides.

**The fixture was written with CRLF.** The generator used
`Path.write_text`, which on Windows translates every `
` to `
`. The test
pins a sha256 over the fixture's bytes, and `.gitattributes` checks the
repository out as LF everywhere -- so the pin matched on the machine that made
it and would have failed on every other one, again reading as a format
regression.

The generator now writes bytes, `test_no_fixture_file_carries_a_carriage_return`
asserts it on the bytes rather than trusting `.gitattributes`, and
`.gitattributes` says what depends on its rule. This is the week-11
Windows/Linux asymmetry in the worse direction: that one failed locally and
passed in CI, which is the direction you find out about.

The general shape, for the next fixture: **a byte-pinned artefact has two
hidden dependencies, the version-control system's filters and the platform's
line endings, and neither is visible from the machine that produced it.**

## A guard written in a different matcher than the thing it guards

The `fnmatch` row is worth dwelling on, because the guard was already there and
still let it through. `tests/test_packaging.py` was written after the
`frameworks.yaml` bug, precisely to check `package-data` against what is on
disk -- and it used `fnmatch`, which has no notion of path segments, while
setuptools expands those patterns with `glob`, which does. So
`compliance/*.yaml` appeared to cover `compliance/packs/eu_ai_act.yaml` and did
not. **A guard written in a different matcher than the thing it guards is not a
guard**, and the only reason this surfaced is that one test starts the real
image and drives it.

## Read the product as somebody who has not seen it

Two of the rows above came from one exercise that is not a test and cannot be:
installing the package into an empty virtualenv and following the documentation
literally, as a first-time user, a security reviewer and an auditor in turn.

The suite could not have found either. `qed-verify`'s tests all passed
`--instance-id`, because the person writing them knew it mattered; the
documented quick start omitted it, so the output an auditor would actually see
was output no test had ever rendered. A test asserts what its author already
knows. It cannot notice that the one command in the README produces a weaker
result than the README implies, and it cannot notice that a planning document
left in the repository would, on publication, hand the world a list of named
defects in the product that funds this one.

The practice that follows: before anything irreversible — a release, a
publication — read the repository as an outsider, run the commands exactly as
written, and treat the gap between what a command prints and what a reader
concludes from it as a defect in the product rather than in the reader.

### Reading it a second time, as a buyer

The same exercise with a different reader — somebody deciding whether to run
this, who will type the first command on the page and believe the capability
table — found five more, and none of them are subtle once named.

| What a buyer hit | Why no test could see it |
|---|---|
| The first line of `docs/index.md`'s "Thirty seconds" was `pip install valqore-qed`, which fails: the name is not registered and `release.yml` holds the publish behind `PUBLISH_PYPI`. Four more pages said the same, and `docs/deployment.md` also offered `docker run ghcr.io/valqore/qed:1.0.0` against an image never pushed | The suite installs from the working tree, which is the one way of installing that always works. `docs/deployment.md` explained the gate correctly — 140 lines below the commands, under "Releasing" |
| The capability table advertised a "**Web approval page** with OIDC human login" and linked to a private repository. `qed/api/ui.py` contains no UI by design, so the capability is unobtainable for everyone outside this organisation, through a link that answers 404. Meanwhile Slack approvals, which are built and better, were not in the table at all | No test reads a table as a promise. `tests/docs/test_claims.py` checked that every cited *path* resolves, and `qed/api/ui.py` resolves |
| `qed mcp` ended every REQUIRE_APPROVAL with "No approval route is configured in this build (approvals land in week 4)", ten weeks after the approval service shipped, while the kernel had just filed a request and the two other adapters were already reporting its id | **A test asserted the stale sentence** — `assert "week 4" in text` — and was green. That is the worst version of this failure: the suite was not silent, it was arguing for the bug |
| `docs/api.md` said "**No rate limits.**" Rate limits are on by default, per adapter *and* per principal, answering 429 — which was missing from the same page's list of status codes | The limiter has tests. Nothing compares the limiter's existence to the sentence denying it |
| Twenty-one statements in source and docs promised work that had shipped, and three of them were strings a user sees | Every one was true when written. Staleness has no failing assertion unless something is written to look for it, which `tests/test_no_stale_promises.py` now does |

The common shape is worth stating once, because it is the same shape as the
product's own subject: **a claim and the thing it claims about were checked
separately, and nothing checked them against each other.** A control in a
report nobody enforces, a cited test path that resolves to a module containing
nothing, a message asserting a limitation the code had removed. The fix in
each case was not more tests of the code. It was a test that reads the
sentence and the code together — which is what `test_claims.py`,
`test_repo_protection.py` and `test_no_stale_promises.py` each do, and what
`test_threat_model.py` has done since week 11.

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
QED_REQUIRE_EMULATION=1 pytest tests/deploy -m slow   # ...and refuses to skip
```

Skipped without emulation rather than passing on the easy half -- which leaves
one more way to pass without testing anything, so CI sets
`QED_REQUIRE_EMULATION=1`: it installs the emulator a step earlier, and there a
skip is a green run with the test that caught the last arm64 bug not having
run.

The probe pulls its image in a separate step from starting it, because one
probe that did both returned the same `False` for "this machine has no
emulator" and "the registry did not answer just then" -- and the second of
those made the arm64 tests vanish from a run that had installed the emulator.

### Import a catalogue, then decide something

```bash
qed packs verify bundle.qedpack.json --public-key pack.pem
qed packs import bundle.qedpack.json --public-key pack.pem --dir .qed
qed check examples/proposals/github-read.json --dir .qed   # must still decide
qed export --dir .qed | qed-verify - --keys .qed/public
```

The `check` is the point, and it is the step that was missing. An imported
catalogue *replaces* the shipped one, an uncatalogued control is a lint error,
and the engine refuses to decide against a bundle with errors -- so a bundle
that drops a control an installed rule cites switches the kernel off. The
import refuses that now, before writing anything, but the sequence above is
what proves it: verifying the bundle and reading the coverage report both
looked perfectly healthy while `qed check` answered "refusing to decide".

Then read the chain. An unsigned import must show `unsigned: true` in the
**next** `policy_loaded`, not only in its own `admin_action`:

```bash
qed export --dir .qed | grep policy_loaded | tail -1
```

### Anchor two checkpoints to a log you can watch

```bash
# a stub log on loopback; plain http is allowed there and nowhere else
qed checkpoint --dir .qed --config qed.yaml     # publishes checkpoint 1
qed checkpoint --dir .qed --config qed.yaml     # publishes checkpoint 2
qed export --dir .qed --config qed.yaml | grep -o '"previous_receipts":[^]]*]'
```

Two checkpoints, not one, because the receipt for the first appears in the
*second* one's payload -- a receipt cannot live inside the record it describes.
Watch what the log receives: it must be six values (`log_id`, `seq`, `hash`,
`merkle_root`, `key_id`, `sig`) and nothing from the payload, because a
checkpoint payload carries the previous checkpoint's receipts and those name
your buckets.

Two bugs came out of running exactly this. `every_records: 1` was ignored, so
nothing was ever due; and the first version of the script looked for
`published_to` in the payload when the field is `previous_receipts` -- **that
one was my mistake, not the code's**, and it is in this list because a
validation script that cries wolf is worse than none. Check the field name
before reporting the bug.

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
