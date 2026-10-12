# Changelog

All notable changes to this project. Format: [Keep a Changelog]. Versioning:
semver, with `schema_version` of `ActionProposal` / `EvidenceRecord` tracked
independently (SPEC §25.6).

## [Unreleased]

## [1.0.0] — 2026-10-11

**The evidence format is frozen.** That is what the major version means here,
and it is the only promise in this release that cannot be walked back: a record
written under `schema_version: "1.0"` verifies under every later verifier,
forever, and the repository now contains the records that prove it rather than a
sentence saying so.

Weeks 11 and 12 of the twelve-week plan (SPEC §22). Week 11's security fix is
below, under its own heading, because it is the more serious entry.

The sections below run newest first, so the pre-publication pass that rewrote
this repository's history sits above the format freeze it shipped with. Both
are this release. The freeze is what the major version means; the pass is what
made the repository publishable, and it is recorded here because the commits
that would have shown the work no longer exist.

### Fixed — two green tests asserting the two halves of a contradiction

`.github/rulesets/main.json` set `require_code_owner_review: true` while
`.github/CODEOWNERS` gives one person every path, `required_approving_review_count`
is `0` and `bypass_actors` is empty. GitHub does not let anybody approve their
own pull request, so every pull request would have needed an approval that
could not be given, with no override — `main` would have been a branch nobody
could merge into.

`tests/docs/test_repo_protection.py` had a test pinning the count at zero whose
docstring spells out that exact danger, and, eleven lines above it, a second
test *requiring* the flag that makes the zero irrelevant. Both passed. Neither
knew the other existed. A control that reads as present while something else
makes it inert is the failure this product exists to remove, and here it was in
the file written to prevent it.

It survived only because it had never run: rulesets are refused on a private
repository, so `apply.sh` could not install the trap. It would have sprung in
the minute after the repository went public.

`require_code_owner_review` is now `false`, for the same reason the approval
count is zero, and `.github/rulesets/README.md` says so where it already
explained the count. Nothing is lost: GitHub still requests review from the
owners in `CODEOWNERS`; only the blocking requirement goes, and it becomes safe
to turn on in the same change that gives the repository a second maintainer.

The replacement test is written against the property rather than the flag:
while `bypass_actors` is empty and the approval count is zero, no parameter may
require a human approving review by any route. Verified by putting the old
value back — it fails and names the parameter.

### Changed — the history was rewritten once, and this is the only account of it

Two planning documents and one spec section came out of the tree before
publication, and removing a file in a new commit leaves it readable in every
earlier commit, in every clone and in every fork. The remote was private with
zero forks and zero clones, so the whole history was rewritten instead:
seventy-eight commits, every hash new, the old history kept locally as a
bundle. This entry is the record, because after this the commits that would
have shown the work do not exist.

**What came out.** `ARCHITECTURE_PLAN.md` from the seventy-one commits that
carried it, `REPO-AND-PUBLICATION-PLAN.md` from seventy, and spec §28 from
seventy-one. Appendix B's one row that inventoried the predecessor's feature
set got the wording the working tree already had.

**What came out that was not a file.** The commit that removed those documents
described their contents in its own message, and the changelog entry announcing
the removal summarised the same material. Three further commit messages, and
nine files in their earlier versions, explained a control in this product by
pointing at a finding about the commercial engine; several named the private
inventory document the finding came from, and one of them -- the test that
forbids an HMAC signing path -- stated a paying product's default signing
algorithm and cited the removed plan's section number for the rest. Each keeps the technical point -- it
is why `check_separation_of_duties` refuses three times instead of warning once
-- and loses the attribution.

That is the shape worth keeping from this: **a purge that explains in public
exactly what it purged has purged nothing.** The files were checked against the
decision and the decision was checked against the files; nothing checked the
prose that announced it. It is the same failure as a control reported in an
export that nothing enforces, found this time in our own repository.

**What went in.** Every commit now carries `Signed-off-by`, which SPEC §25.1
has required since week 1 and which exactly one commit of the seventy-eight
had; the cutoff documented in `CONTRIBUTING.md`, `ci.yml` and the 1.0.0 entry
is therefore gone rather than explained. Five commits were authored by a
placeholder identity -- `Developer-Backend <agent@valqore.local>` and
`<noreply@anthropic.com>`, one of them the first commit in the repository and
one of them the commit tagged `v0.1.0` -- and now carry the maintainer who owns
the copyright. Their `Co-Authored-By` lines are unchanged, so what a model
wrote is still on the record.

Every author and committer date is byte-identical, the seventy-three commits
that already named the maintainer are untouched in their authorship, the four
tags still point at the same logical commits, and the tree at `main` is
unchanged except for this file.

### Fixed — the build spoke in the future tense about work that had shipped

Twenty-one statements across the source and the documentation promised things
that already existed, or blamed a week of the build order for a gap that is
simply open. Each was true when it was written in week 1 or 2 and nobody
revisited it. A reader cannot tell a stale promise from a real limitation, so
each one costs exactly what a real gap costs — while hiding the real gaps in
the noise.

Three were not comments.

**`qed mcp` told an agent that approvals do not exist.** Every
REQUIRE_APPROVAL through the MCP proxy — the adapter the README demonstrates
first — ended with `No approval route is configured in this build (approvals
land in week 4)`. The approval service shipped in week 4. `check_proposal`
files a request and writes `approval_requested` with its id, approvers and
expiry *before* it answers, whether or not a Slack channel is configured, and
`POST /v1/proposals` has been returning that id in its `approval` field all
along. The HTTP proxy and the Claude Code hook both already put the id in their
message. Only the oldest adapter said there was nothing to wait for, moments
after a request had been filed for it.

It now reads: `Approval apr_… is open; qed approvals lists it. Retry once
agreed.` The expiry that SPEC §12.1 also asks for is still missing and is now
described as missing: it lives on the stored request and on the record, and
`Appended.record` is `None` while the HA outbox holds one, so putting it in
that string means a store lookup on the decision path or a new field on
`Verdict` — a decision, not an oversight.

The test for that message asserted the stale sentence — `assert "week 4" in
text, "be honest that there is no approval route yet"` — and was green for ten
weeks. A test pinning a stale claim is worse than no test: it makes the
staleness look deliberate and fails on anybody who fixes it. It now asserts
that the id the agent is told is the id in the chain.

**`docs/api.md` said rate limits do not exist.** "**No rate limits.** SPEC
§13's 100 proposals/s per adapter is week 10." They are enforced, on by
default, per adapter *and* per principal — `per_adapter_rps: 100`,
`per_principal_rps: 20` — answering `429` with `Retry-After`, and `429` was
missing from the page's list of status codes. An integrator would have read
"no limits", built against it, and met the lower limit of the two in
production. The page now documents both, the default values, and why the
per-principal limit is the smaller one: a runaway agent loop arrives under a
legitimately registered adapter.

**Two CLI strings** named week 3 as the arrival of verified identity:
`--token-jti`'s help (`(week 3: real)`) and the `--human` warning. Both now
describe what is true — `--human` is the adapter's assertion, `--mandate` is
signed, and identity is proven on the API path.

**The OSCAL exporter still stated the circularity** corrected in `docs/oscal.md`
yesterday: "the document an auditor receives contains everything needed to
verify the chain it describes". The keys in `back-matter` are the keys the
exporter says it used; checking an export against them is circular, because
whoever produced the file chose both halves. The docstring now says so and
points at conformance requirement 11. Its next paragraph had also been left
half-edited mid-sentence when the catalogues landed, which is its own small
lesson about editing prose in a docstring nobody renders.

**`qed/compliance/loader.py` described another product's internals** — a file
path, a rule count and a mapping-line count belonging to the commercial engine
— in a note addressed to whoever would do week 8. Reworded to the part that
matters and is this project's own: an imported mapping is keyed to a rule this
project does not share, so every mapping would dangle; titles transfer, links
do not, and every link here was written by hand.

The rest were docstrings and comments in `qed/api/`, `qed/config.py`,
`qed/adapters/mcp/`, `qed/core/evidence/` and four documentation pages, each
now describing the build as it is. Two were real gaps wearing a week number,
and both are now stated as gaps: export streaming is not implemented on either
store, and `qed adapters add` with per-adapter rotation (SPEC §12.6) does not
exist — registration is a list in `qed.yaml` and rotation is editing it.

`tests/test_no_stale_promises.py` keeps it from coming back: no file under
`qed/` or `packages/` may promise a week. There is no future week left, so the
future tense is a bug by construction, and the guard carries tests in both
directions so it neither rots into silence nor starts flagging the honest
history ("the week-1 bug", "moved here in week 6") that the next reader wants.

### Fixed — read as a buyer: three commands that cannot work, and a page that does not exist

A pass through the repository as somebody evaluating it rather than building
it, which is a different reader: they run the first command on the page and
believe the capability table.

**Install commands that fail.** `docs/index.md`'s "Thirty seconds" — the first
thing a visitor to the documentation site runs — opened with
`pip install valqore-qed`. The name is not registered; SPEC §24.1's
reservations are the publication gate and `release.yml` holds both publishes
behind `PUBLISH_PYPI` and `PUBLISH_GHCR`. So the command answers "No matching
distribution found", and the same command appears in
`docs/onboarding-shadow-to-enforce.md`, `docs/ci.md` and `docs/deployment.md`,
which also offers `docker run ghcr.io/valqore/qed:1.0.0` against an image that
has never been pushed. `docs/deployment.md` *did* explain all of this —
140 lines below the commands, under "Releasing". That is the exit-code bug
again: a document accurate as a whole and wrong at the only place anybody
reads. Each command now carries the caveat and the alternative where it is
written, and `tests/docs/test_claims.py` fails if an unavailable install
command appears on a page that does not say so. A second test fails when
`release.yml` stops gating a publish, because by then the caveats are the
false statement and have to go.

**A capability nobody outside this organisation can have.** The table said
"**Web approval page** with OIDC human login" and cited `qed/api/ui.py`. That
module contains no UI by design (SPEC §20.4 keeps the AGPL pages out of the
Apache wheel) and the `qed-ui` repository it linked to is private, so the row
advertised a page a reader cannot obtain through a link that answers 404. What
exists today is better than what the row claimed and was missing from the
table entirely: Slack Block Kit approvals where the click is resolved through
`users.info` to an identified person rather than a workspace member, `qed
approve` on the CLI, and `POST /v1/approvals` with a verified OIDC bearer. The
row now names those, and a second row says plainly that the web pages are in a
package that is not published.

**Three places still named a defect in the commercial engine.**
`qed/core/approval/model.py`, `docs/approvals.md` and ADR-0014 each explained
this control by pointing at a finding about the shipping commercial engine. The
lesson is the right one and it is why the function refuses three times instead
of warning; naming a paying product as the example in an Apache-2.0 repository
is not, and restating the finding in order to announce its removal is the same
disclosure in a different file, which is what the first draft of this entry
did. Reworded in all three, lesson kept, attribution gone — the same
correction made last commit for `human_auth.py` and ADR-0008, which this pass
found had missed three. A fourth place, `tests/approval/test_model.py`,
mirrored the docstring and was missed again, because both passes went looking
for the file rather than for the sentence.

### Added — the rules that protect `main` are files, not a settings page

`GOVERNANCE.md` has told a reader since week 11 that maintainers' changes go
through the same CI as anybody else's, with "no bypass and no admin merge".
Nothing enforced it. Every commit in this repository went to `main` directly,
and the reason is not negligence: protected branches and rulesets are refused
on a private repository on this plan — `GET /repos/valqore/qed/rulesets`
answers `403 Upgrade to GitHub Pro or make this repository public` — so there
has been no setting to switch on. A promise in a document with nothing behind
it is the exact failure this product exists to remove, which made it worth
fixing before publication rather than after.

`.github/rulesets/main.json` and `tags.json` now hold the rules as the JSON the
REST API takes: a pull request is required, all ten checks `ci.yml` runs on one
are required, a stale branch must rebase before merging, `main` cannot be
force-pushed or deleted, a `v*` tag cannot be moved or deleted, merges are
squash-only with linear history enforced, and `bypass_actors` is empty — which
is the single line that makes "no admin merge" true. `.github/rulesets/apply.sh`
installs them and the repository settings that cannot be expressed as a ruleset
(squash-only, branch deletion on merge, Discussions on, private vulnerability
reporting, Dependabot alerts, secret scanning with push protection). It prints a
plan and changes nothing without `--apply`, reports each refusal by name instead
of abandoning the rest, and is idempotent, because two rulesets named `main`
both apply and neither is the one you edited.

`required_approving_review_count` is `0`, and the reason is in
`.github/rulesets/README.md`: with one maintainer and no bypass actor,
requiring an approval nobody can give is not strictness, it is a repository
nobody can merge into — and the usual repair, adding the maintainer as a bypass
actor, is precisely the admin merge this project says does not happen here.

`tests/docs/test_repo_protection.py` derives the required-check list from
`ci.yml`, including the four `check` matrix cells, and fails in both directions:
a job that is not required is a check that can fail with the merge button
green, and a required context no job reports is a pull request that waits
forever. It also ties the approval count to the sentence in `GOVERNANCE.md`
saying nobody has reviewed this repository, so the day a second maintainer
arrives the ruleset has to change with it. `GOVERNANCE.md` now states both
halves plainly: nothing protects `main` today, and here is the file that will.

Also: `.hypothesis/` is ignored explicitly. Hypothesis writes its own
`.hypothesis/.gitignore` containing `*`, so 814 cache files have been staying
out of the repository by a library's courtesy rather than by this repository's
decision. The merged `week-2` branch is deleted.

### Fixed — the verifier reported a pass over a check it had skipped

`qed-verify` printed `result : OK -- chain is contiguous, unmodified and
signed` whether or not `--instance-id` was supplied, and `--json` carried no
field recording the difference. Without the flag the genesis binding does not
run, and the genesis binding is the only check in the verifier that reaches
outside the file it was given: linkage, recomputed hashes, canonicalisation,
signatures and Merkle roots are all satisfied exactly as well by records
fabricated this morning and signed with a key generated for the purpose. So the
tool whose entire job is not overstating what it knows was overstating what it
knew — and the quick start in `README.md` omitted the flag, which made the weak
invocation the documented one.

The report now carries `genesis_bound_to` and `unchecked`, plus a `complete`
property that is true only when every check ran *and* passed. `summary()` prints
a `bound to` line naming the instance or `NOTHING`, and an unbound pass reads
`OK SO FAR -- ... but 1 check(s) did not run` followed by what did not run. The
CLI repeats it on stderr, and `--require-complete` turns the omission into exit
1, which is what a pipeline needs: a pipeline reads the exit code and nobody
reads the summary.

`qed verify <file>` had the same hole — it passed `instance_id=None` for an
explicit file — and now takes `--instance-id`. It deliberately does *not* default
to the local instance id when verifying a file, because binding a foreign export
to the local identity would turn a real check into a coincidence.

The second half of this is that the instance id and the public keys must reach
an auditor **out of band**. Both are in the export — the id in the genesis
payload, the key id on every record — so reading either out of the file and
checking the file against it is a tautology, and a forged chain labelled with
any instance id and signed with a laptop key passes it completely. Nothing said
so. `docs/oscal.md` said the opposite, presenting the keys embedded in the
OSCAL `back-matter` as "what is needed to check it". That paragraph is rewritten,
`THREAT_MODEL.md` gains limitation 11 and splits its substitution row into the
operator's case (covered) and the wholesale-forgery case (auditor-side, partial),
and `docs/evidence-format.md` makes it conformance requirement 11 plus a MUST
NOT against taking either value from the material under review.

Requirement 11 is a new obligation on verifiers added after the format froze, so
the in-freeze/out-of-freeze table now says explicitly which of the two the freeze
is about: record bytes, not what a verifier has to tell its user. No record
changed and no previously valid chain became invalid.

### Fixed — `README.md` had the exit codes backwards

It listed `2` REQUIRE_APPROVAL and `3` BLOCK; `qed/runtime.py` has
`EXIT_BLOCK = 2` and `EXIT_APPROVAL = 3`, and `README.md` itself got it right
140 lines further down. Neither place mentioned that **shadow mode always exits
0** — which a newcomer meets immediately, because shadow is the default and the
quick start's first `qed check` prints `REQUIRE_APPROVAL` and exits 0 two lines
above the table that says 3.

### Added — the repository files GitHub reads rather than a human

`CODE_OF_CONDUCT.md` as a file (it existed only as a section inside
`CONTRIBUTING.md`, which satisfies a reader and not GitHub's community profile),
`.github/CODEOWNERS`, `.github/dependabot.yml`, `.github/PULL_REQUEST_TEMPLATE.md`
and three issue templates with blank issues disabled, so no reporter can bypass
the one that says a vulnerability does not belong in a public issue.

One of the templates is for reporting that **a claim this project makes is not
true**. Every overclaim found so far was found by a person reading the product
rather than by the suite, including two this week, so there is now a front door
for it.

`tests/docs/test_community_health.py` checks all of it, because each of these
fails silently: a template with a YAML error is ignored without a warning, and a
`CODEOWNERS` line naming a team that does not exist is dropped — which is why
the owner is spelled as a user. A protection that reads as present and is absent
is the same shape as a compliance control nobody enforces, which is the failure
this product exists to remove.

### Removed — commercial planning material, and its history

A pre-publication read of this repository as an outsider rather than as its
author found four documents that would have become public on the first push,
and one of them was a liability rather than an embarrassment.

`ARCHITECTURE_PLAN.md`, the planning-phase draft the spec superseded, carried a
section assessing the shipping commercial engine against this design, row by
row, and several of those rows are unfixed. Under a public Apache-2.0 licence,
in a repository carrying the same brand, that section is an unpatched-defect
list for a product customers pay for — so this entry does not summarise it.
Naming the rows in a public changelog publishes them exactly as surely as
publishing the file would, which is what the first draft of this entry did.
The rows are kept privately, against the product that has to fix them.
`REPO-AND-PUBLICATION-PLAN.md` held internal publication sequencing. Spec
§28 held the funding application: targeting, revenue model, moat sequencing
and prepared answers about named competitors, none of which is a specification
of this product.

All three are now kept privately and are **purged from every commit in this
repository's history**, not deleted in a new one. Deleting a file in a later
commit leaves it readable in all 71 earlier ones and in every clone, which is
the mistake `.gitleaks.toml` was written to prevent and the reason this
happened before the remote went public rather than after. The repository had
zero forks and zero clones at the time of the rewrite. The same pass rewrote
the removal commit's own message and this entry, because a purge that explains
in public precisely what it purged has purged nothing.

Two source comments and one ADR attributed a compliance finding to the
planning-phase review of the predecessor; each keeps the technical point, which
is why the human-authentication work in this product exists, and drops the
attribution. Spec Appendix B stays — every row names a module path or a
capability already published on the product's own site, and four places in the
code and the ADRs cite it. The spec gains a scope line saying that commercial
planning is deliberately not in it.

`DESIGN_DECISIONS.md` also stays. It is the design rationale for this product,
written in Turkish during the planning phase, superseded by the spec, and cited
by the public ADR index as the record of what was decided before any code
existed. Nothing in it concerns the other product.

### Added - evidence format 1.0, frozen against a committed fixture (ADR-0015)

SPEC §25.6 has promised "cross-version fixtures in CI" since week 1. There were
none. The suite had something that looked like one -- `test_chain.py` writes a
chain with the real signer and store and verifies it with the real verifier --
and it cannot see the failure that matters, because a producer and a verifier
that change together pass it while the records already in a customer's database
do not change with them.

`tests/evidence/fixtures/evidence-format-1.0/` is now a real export produced on
10 October 2026 and never regenerated: fourteen records over five simulated
days, with genesis, `policy_loaded`, three real proposals from
`examples/proposals/` deciding ALLOW / REQUIRE_APPROVAL / BLOCK, an approval
decided by a different human through the real separation-of-duties check, a
signing-key rotation, two Merkle checkpoints, a retention purge that recorded
itself, and one proposal whose payload is gone. Both public keys are committed;
no private key is, so the chain cannot be extended.

`tests/evidence/test_frozen_format.py` checks four things against those bytes:

| Layer | What only it can catch |
|---|---|
| `qed-verify` verifies the export | the auditor's whole position, in one line |
| `record_hash` -- the *producer's* function -- recomputes every frozen hash | that the producer still **writes** 1.0, not just that the verifier reads it |
| `qed.core.jcs` and `qed_verify.jcs` agree on every frozen payload | a divergence between two deliberately separate canonicalisers |
| twelve mutations each produce the documented failure code | that the conformance table in the fixture's README is tested, not asserted |

The fixture's digest is pinned **in the test file**, not in the fixture: a
checksum a regeneration rewrites alongside the thing it describes verifies
nothing. Refreshing it is therefore a deliberate edit in two places, with a
failure message explaining why it is almost certainly wrong.

And the freeze is a rule rather than a habit:
`test_every_schema_version_the_code_can_write_has_a_fixture` reads the
`schema_version: Literal[...]` declarations out of `qed/core/schemas.py` and
fails until each has a fixture directory. A bump to `"1.1"` is red until 1.1 has
records of its own, and 1.0 goes on being verified beside it.

### Changed - `docs/evidence-format.md` is a specification, not a draft

It carries a status line, two tables drawing the line between what freezing
covers and what it does not, and a **conformance section**: ten MUSTs, three
MUST NOTs, and an acceptance test an independent implementer runs against the
committed fixture. The MUST most often got wrong is called out -- an unsupplied
`key_id` is a **failure, not a skip**, or a verifier reports a forged chain as
clean.

**One claim in it was backwards, and freezing it would have been expensive.**
The draft said the masking pattern set "is part of the format: changing it
changes record hashes for future records". Both halves of that sentence are
true and the conclusion was wrong. Masking runs before hashing, so a new
pattern changes what *future* records contain; it cannot change a record
already written, and a verifier never re-derives a mask -- it hashes the payload
as it finds it. Published as written, 1.0 would have frozen the
secret-detection patterns for the life of the product. The pattern set is
producer-side policy and is now explicitly outside the freeze.

### Added - a landing page (`landing/index.html`)

One file, no build step, no external request -- no CDN font, no analytics
script. That is a constraint, not minimalism: the product's first claim is that
zero bytes leave by default, and a page that contradicts it above the fold is
not a landing page for this product.

The terminal transcript on it is real output from a run on 10 October 2026, and
`tests/docs/test_landing.py` keeps it honest in three ways: every command shown
is one the CLI registers, every number is re-derived from its source (46 rules,
16 of them shadow, p95 4.5 ms, 35 of 76 controls), and a deny-list of thirteen
phrases -- "trusted by", "SOC 2 compliant", "tamper-proof", "% compliant" --
must not appear. `tamper-proof` is on that list because the chain detects
modification and does not prevent it, and `qed doctor` says so.

The page carries a visible pre-launch notice, because `pip install valqore-qed`
does not work: the names are unreserved. `landing/README.md` has the launch
checklist and says to remove the notice in the same commit that turns publishing
on. A test asserts publishing is still gated, so the two cannot drift apart
quietly.

### Changed - version 1.0.0 everywhere

`qed/version.py` is still the one literal; `pyproject.toml` (both of them), the
Helm chart, the Dockerfile label and `docs/deployment.md` follow it, and
`tests/test_version.py` checks all five. `ENGINE_VERSION` -- which goes into
every verdict record -- now reads `1.0.0`.

**The tag is not the format.** `schema_version` stays `"1.0"` and is
independent of the package version by design (SPEC §25.6): the next release
that changes nothing about records will be `1.0.1` and the records will still
say `1.0`.

### Fixed - two ways a byte-pinned fixture almost shipped broken

Neither reached a release; both are in `docs/validation.md` because the class
is what matters, and a byte-pinned artefact turns out to have two hidden
dependencies that are invisible from the machine that produced it.

**`.gitignore`'s `*.pem` matched the fixture's public keys.** The rule sits
under "never commit keys or chains" and is right for a private key. The first
commit would have published a chain with nothing to verify it against, and
locally every test passed because the files were on disk. In CI it would have
surfaced as `unknown_key` on a frozen fixture, which reads like a format
regression. There is now an explicit negation for
`evidence-format-*/public/*.pem`, and a test that asks **git** what it tracks
rather than asking the filesystem what exists -- the same correction as the
packaging guard that used `fnmatch` while setuptools expands with `glob`.

**The fixture was written with CRLF.** `Path.write_text` translates on Windows,
and the digest is over bytes while `.gitattributes` checks the repository out as
LF -- so the pin matched on one machine and no other. The generator writes bytes
now, a test asserts it on the bytes, and `.gitattributes` says what depends on
its rule.


### Security - a mandate's signature was never verified (week 11)

**A forged mandate authorised unattended action.** Found while writing the
onboarding guide, by trying the thing the documentation describes.

A mandate is what lets an action with no human behind it proceed at all:
`AG-IDN-007` BLOCKs an unattended proposal that carries no mandate. Two correct
decisions composed into a hole, the same shape as ADR-0012's remote kill
switch:

* `qed.core` holds no keys, so `mandate_validity` checks the window and
  revocation only and says as much -- "signature verification is the token
  layer's job".
* Every consumer -- `qed check`, the hook, the MCP and HTTP proxies,
  `POST /v1/proposals` -- parsed a mandate with `Mandate.model_validate_json`,
  which validates the schema and not the signature, and passed it straight to
  the engine.

Nobody was the token layer. Measured on the same proposal:

| Mandate | Decision | Derived |
|---|---|---|
| none | **BLOCK** (AG-IDN-007) | `present: false` |
| genuine | REQUIRE_APPROVAL | `present: true, within: true` |
| `signature.sig` replaced with 86 `A`s | REQUIRE_APPROVAL | `present: true, within: true` |

So writing a JSON file turned a BLOCK into a normal decision. Anyone who could
write a file could manufacture the authority for an unattended agent.

`verify_mandate()` had existed since week 3 and was unit-tested from that day:
tamper with a mandate, assert it raises. Those tests passed for eight weeks
because they called the function. **Nothing else did.** `SECURITY.md` listed
this as a week-1 limitation to be fixed in week 3, and the function was written
while the caller never was.

**Fixed at the one choke point**, `check_proposal`, rather than at each of the
seven places a mandate is parsed -- seven sites is seven chances to forget, and
the eighth caller would be the one that got it wrong. Verification happens
*before* the proposal record is appended, so a refusal leaves the id unused and
the agent can retry with a real mandate.

`MandateError` joined `OPERATOR_ERRORS`, so the refusal is one line and exit 1
rather than a traceback:

```
qed: mandate md_01JB00000000000000000001 does not match its signature
     (the document was changed after it was signed)
```

That parenthetical exists because `InvalidSignature` carries no message, so
interpolating it produced "does not match its signature: " with nothing after
the colon -- on the one refusal where an operator most needs to be told what
happened.

**`qed policy explain` still does not verify, and now says so.** It takes no
`--dir`, so it has no public keys; its JSON reports `"mandate": {"present":
true}` either way, and an operator using it to find out whether a mandate works
would read that as a mandate that will work. It prints a yellow line saying the
signature was not checked and that `qed check` refuses a forged one.

`tests/delegation/test_mandate_is_verified_at_runtime.py` holds it, including a
structural test that no module outside `qed/runtime.py` builds an
`EvalContext` with a mandate in it. That test found the two remaining bypasses
on its first run -- `policy explain` and the policy-case fixtures -- which is
why both are now named exemptions with reasons rather than silent ones.

### Added - SECURITY.md disclosure process, CONTRIBUTING.md, GOVERNANCE.md (week 11)

`SECURITY.md` had a disclosure section reading "there is no public disclosure
process to follow; the full process lands with the public launch (week 11)".
This is week 11. It now has the channels, a response timetable, safe harbour,
and explicit scope -- including an out-of-scope list, because "the
documentation already says this is absent" is the commonest report a project
like this gets.

Its "Known limits in **week 1**" section had been stale for ten weeks, listing
"no authentication anywhere", "no approval service" and "no credential broker",
all of which shipped in weeks 3-5. Replaced with a pointer to
`THREAT_MODEL.md` and the four limitations people most often assume away.

`CONTRIBUTING.md` is new: the DCO, the definition of done, and a table of
changes that will be refused with the reason for each -- an LLM in the decision
path, an HMAC signing path, a development fallback key. Better to know in
advance than in review.

**The DCO is now actually checked.** SPEC §25.1 has required a `Signed-off-by`
line since week 1 and nothing enforced it; at this release no commit carried
one. The new `dco` job checks the commits a pull request adds, which is what a
DCO is for: contributions from people who are not the maintainer. The cutoff
this entry originally documented is gone -- the pre-publication history rewrite
signed off every commit instead. See the entry above.

`GOVERNANCE.md` gained "who decides", and the first draft of that section said
"two maintainers, named in the repository's metadata". Both halves were false:
there is one maintainer and `pyproject.toml` declared no authors at all. A
governance document inventing a second reviewer is the same failure as a
coverage percentage with no catalogue behind it (ADR-0011), so it now says one
maintainer, that **nothing here has been reviewed by a second person**, and
that the structural tests are what substitutes for one. `authors` is declared
in `pyproject.toml` so the document points somewhere real.

### Fixed - a root document cannot link relatively (week 11)

`strict: true` caught this the moment the governance docs gained
cross-references. `[THREAT_MODEL.md](THREAT_MODEL.md)` resolves on GitHub,
where the reader is at the repository root, and not on the site, where the page
is `/security/` and the target is `../threat-model/`. There is no spelling that
satisfies both, so root documents use backticked filenames, which are correct
in both contexts. Guarded twice: statically, and by the build.

`README.md` promised `tests/policy/test_determinism.py` for the invariant "same
inputs produce byte-identical verdicts". No such file exists; the test is
`tests/policy/test_engine.py::TestDeterminism`. The invariant was enforced and
the sentence claiming so pointed at nothing, which is worse than no table at
all. `tests/docs/test_claims.py` now checks that every path any document cites
resolves, and refuses to pass if its own pattern matches suspiciously few.


### Added - the docs site, and the guide that says how to reach enforce (week 11)

SPEC §26 names mkdocs-material; `mkdocs.yml` is it, and
`docs/onboarding-shadow-to-enforce.md` is the page SPEC §24 has had in the file
listing since week 1 with nothing behind it.

The guide exists because **three separate dials all have to point at "enforce"
before a `BLOCK` stops anything** -- the instance `mode`, each rule's `mode`,
and whether the credential broker holds the credential at all -- and turning
the wrong one is how an operator ends up with a chain full of enforcing
verdicts in front of an agent that was never gated. Every command on the page
was run to write it, and the output is quoted rather than invented. Three
passages were wrong on the first draft and are now what the tool actually
prints: `qed policy test` takes the case file positionally, the broker's
`upstreams.yaml` uses `credential: {source, ref, inject}`, and `qed doctor`
ends with a table and a count rather than a sentence.

That last one is worth keeping. An upstream whose credential cannot be resolved
does not fail -- it degrades to advisory and says so:

```
UPSTREAM             MODE       INJECT   CREDENTIAL
postgres-prod        ADVISORY   env      unavailable: $PROD_DATABASE_URL is not set, ...

0 enforcing, 1 advisory
```

`0 enforcing` is the number to read. The presence of a `broker:` block is not.

**Normative documents are included, not copied.** `THREAT_MODEL.md`,
`GOVERNANCE.md`, `SECURITY.md`, `CHANGELOG.md` and `QED_SPEC.md` stay at the
repository root, where GitHub and a fresh clone look for them; the site reaches
them through `pymdownx.snippets`, which ships with the theme. One copy of each,
and `tests/docs/test_site.py` fails if one is ever duplicated into `docs/`.

**`tests/docs/test_site.py` asserts the nav and `docs/` are the same set, in
both directions.** `mkdocs build` will happily publish a page that no nav entry
points at: reachable by URL, invisible to a reader, green build, wrong
artifact. That is the same shape as the wheel that shipped without
`compliance/packs/*.yaml`, and `docs/validation.md` keeps the list.

It found a bug in itself on the first run, which is the direction worth
recording: `test_no_root_document_was_copied_into_docs` used `Path.exists()`,
and Windows is case-insensitive, so `docs/governance.md` -- the stub that is
supposed to be there -- answered `True` to `(docs / "GOVERNANCE.md").exists()`.
Written that way the test failed on Windows and would have passed in CI on
Linux, which is the worse of the two directions. It now compares against the
real directory listing.

### Added - examples/README.md and a gap report that runs (week 11)

`examples/onboarding/gap_report.py` answers "how far is this instance from
`mode: enforce`?". Every verdict carries `decision` and `would_decision`; the
records where they differ are exactly the work remaining, and the script counts
them per shadow rule:

```
2 verdict(s); 1 would have decided differently under enforce

 COUNT  RULE             WOULD MOVE
     1  AG-SKL-003       ALLOW -> REQUIRE_APPROVAL
```

Stdlib only, and it reads an **export** rather than the instance -- the same
file an auditor is handed, with no access to the database that produced it. An
empty report explicitly says it may mean "not enough traffic" rather than
"ready".

`examples/README.md` indexes what runs, and says what is deliberately absent:
there is no Okta or AWS AgentCore example, because one written against a
service it had never touched would be a configuration file presented as a
tested integration.

**`examples/` is now in mypy's scope.** An example is code a reader copies, so
one that does not type-check teaches the habit. Adding it caught
`gap_report.py` having shipped with an `object` parameter and a `type: ignore`,
because nothing had been checking. 119 source files became 122.

### Fixed - two lint errors that said what was refused and not what to do

`AG-BUD-002`'s own comment said "Flip to enforce deliberately." Both obvious
ways to do that are hard errors, and nothing anywhere documented the one that
works.

ADR-002.4 settles the direction -- an override may only soften or narrow, and
"for hardening, a new rule is written, not an override" -- and that is right: an
overlay file that could silently *tighten* central policy can break production
from a directory nobody reviews. The defect was that neither refusal named the
alternative, while the `verdict -> ALLOW` case next to them already did:

```
override_hardening: an override may only soften or narrow:
  mode shadow -> enforce (write your own rule with your own rule_id)
duplicate_rule_id: already defined in skills.yaml;
  write your own rule with your own rule_id, or use `override:` to soften this one
```

Three baseline rules carried comments implying a promotion path that errors
(`budget.yaml`, `data.yaml`, `skills-extended.yaml`); they now name the real
mechanism, and `data.yaml` additionally says not to edit the shipped file,
since it lives in the wheel and an upgrade replaces it.


### Added - qed governs its own admin operations (week 10)

Every rule in the baseline pack constrains an agent. The operator has been the
one actor no rule touches, and the operator is who rotates the signing key,
replaces the control catalogues, and edits the policy an agent is judged by.
"Who governs the thing doing the governing" is the first question an auditor
asks about a governance product, and until now the answer was "nobody".

`qed keys rotate` and `qed packs import` can now require an approval, with the
same separation of duties an agent's action gets -- the same
`ApprovalRequest`, the same `qed approve`, the same
`check_separation_of_duties`. Not a second approval system: two would be two
places for the SoD check to live, and the one that mattered would be the one
nobody tested.

```yaml
admin:
  self_governed: true
  approvers: ["group:platform-oncall"]
  operations: [keys_rotate, packs_import]
```

**Off by default**, because it needs a second person and the common case is one
operator on a laptop -- on by default would make `qed keys rotate` fail on
first use, which teaches people the feature is an obstacle. What keeps that
honest is that `qed doctor` reports it either way, in yellow, with the sentence
an auditor would write. And the record carries `self_governed: false` rather
than omitting the field, so a rotation that was unapproved *by configuration*
is distinguishable from one that evaded a gate.

**Break-glass exists and costs a permanent record.** The reason to rotate a key
is that it may have leaked, which is exactly when the approver is asleep. A gate
with no break-glass does not stop the rotation -- it moves it outside the tool,
where the operator sets `self_governed: false`, rotates, sets it back, and
nothing records any of it. So `--break-glass "<reason>"` proceeds, the reason is
required, the command prints red, and the `admin_action` says `break_glass:
true` for good.

**An approval is bound to one operation and spent once.** The operation lives
inside the synthetic proposal id the approver decided on, so an approval granted
for a catalogue import cannot rotate a key -- a smaller ask spent on a larger
one. Single use is read out of the chain rather than from a column: the
`admin_action` carrying an approval id *is* the receipt, and a column could
disagree with the chain after a restore.

**What it does not prove.** On the CLI `--by` is self-asserted, as
`qed approve --by` always has been. Self-governance there buys that two separate
invocations naming two separate subjects are required: a real obstacle to a
careless action, none at all to a determined operator who lies about who they
are. ADR-0014 and `docs/approvals.md` say so rather than leaving it to be
discovered.

### Added - the single-file binary, and a Homebrew formula that is not published (week 10)

SPEC §24.1's Homebrew path: one file, no Python on the machine. `deploy/qed.spec`
builds it with PyInstaller; the release workflow builds three (macOS arm64,
macOS x86_64, Linux x86_64) with a `.sha256` beside each, because the formula
downloads by checksum.

Per OS, because PyInstaller freezes the interpreter it runs on and there is no
cross-compilation. macOS arm64 and x86_64 are separate builds rather than a
universal2 binary: a universal build needs universal wheels for `cryptography`
and `pydantic-core`, and those are not what pip resolves.

**Building proves almost nothing, which the first build demonstrated.** It
succeeded, and then `qed verify` inside the binary answered *"qed-verify is not
installed: pip install ./packages/qed-verify"* — advice a brew user with no
Python cannot take. `qed_verify` is an editable install in
`packages/qed-verify/`, so `collect_submodules` resolved its names through the
editable finder while the bundler still needed the directory on `pathex`. One
line, and only a test that *runs* the binary would ever have found it.

So the tests run it: `policy lint` (which resolves every rule's control
references against the compliance catalogues, so a clean lint proves both sets
of bundled YAML arrived — more than a `--help` that only proves the bootloader
works), `packs list --json` for all ten catalogues, then `keys init`, `check`
and `verify` against a real chain. The static half of the file checks that the
spec's data patterns agree with the wheel's `package-data`, since two lists of
the same files are two chances to be wrong.

**The Homebrew formula is a template and deliberately not publishable.** The tap
is `valqore/tap`, which does not exist: SPEC §24 lists reserving it among the
names needed before the first public push, and publishing is the irreversible
step. The template lives here so the binary and the formula that installs it
change together, with a test asserting it names every platform the release
matrix builds — a label added there and not here is a platform nobody can
`brew install`.

Its `test do` block runs `policy lint` and verifies a chain rather than checking
`--version`, because a `--version` passes on a binary whose data files are
missing. The wheel shipped exactly that bug once and the container shipped it
again.

`pyinstaller` joins the dev extras, and SPEC §20.3 is amended to list it per
§23's "no new dependency without a spec update" — §24.1 already named it as the
mechanism. It has to be installed in CI rather than skipped politely, because
the `deploy` job fails on any skip.

### Added - `THREAT_MODEL.md`, and a test that keeps it true (week 10)

SPEC §17 has named this file since week 1 and nothing was behind it. It is the
document the first auditor session opens with.

It is written for somebody deciding whether the evidence is worth anything, so
it **leads with the limits**: the "What qed does not protect against" section is
eleven numbered items and is deliberately longer than the STRIDE table. The
first one is the one that matters most -- *on most paths qed does not stop
anything*. An adapter enforces only where it holds the credential the action
needs; everywhere else the agent holds its own and qed decides and records. What
the evidence supports is "this is what the agent proposed and what policy
concluded", not "this is what the agent was able to do".

The other ten, briefly: CLI identity is self-asserted; an operator with the
signing key can rewrite the chain and only a published anchor catches it;
break-glass bypasses self-governance by design; rate limits are per process;
the clock is not verified against anything; a signed bundle is only as
trustworthy as its publisher; shadow mode is the shipped default; the kernel
judges what the adapter tells it; coverage is a property of the rules, not of
qed; and four things are not built.

There is also a table of SPEC §17's nine MUSTs with the state of each, which is
the quickest way for an auditor to find the two that are qualified: admin
self-governance is off by default, and supply-chain signing is gated off until
the name reservations are done.

**`tests/test_threat_model.py` checks the claims that are checkable** -- every
rule id it cites exists, every number matches the constant, every file and ADR
it points at is there, every config key resolves on the real model, and the
limitations section is longer than the controls. Not a lint pass on prose: the
same discipline as `tests/test_packaging.py`, which exists because a list
nobody verified was wrong.

It earned itself immediately. It caught the advisory-adapter concession
attributed to **ADR-0001, which is the blast-radius table**; a MUST table with
**eight** of nine rows; two cited things that were not in the document at all;
and the limitations section being *shorter* than the STRIDE table, which the
document's own opening claims it is not. Four errors in a document I had just
finished writing, found by a test rather than by rereading it.

### Added - fuzzing the parsers, and the two bugs it found (week 10)

SPEC §17's "fuzz on parsers", with `hypothesis` -- already in §20.3's dev/test
set, so the dependency was reserved for exactly this.

Every test asserts the same property, and it is a security one rather than a
correctness one: **a malformed input produces a refusal, never a crash.** A
parser that raises something its caller does not expect turns a 400 into a 500,
and a 500 on the decision path is an adapter in `fail: closed` blocking an
agent's work because somebody else sent bad JSON. So each test names the
exception the caller handles and asserts nothing else escapes -- "it did not
crash" is too weak, because a `KeyError` instead of a `ValidationError` is still
a crash to the route above it.

Five targets: the JCS canonicaliser (which sits under every signature in the
product), the proposal schema, the policy loader, the pack-bundle envelope, and
the config loader. A test at the bottom asserts each is named, so a parser added
later and not fuzzed is a visible omission.

**It found two.**

`load_bundle` raised whatever `yaml` raised -- `ScannerError` for an
unterminated quote, `ReaderError` for a stray control character -- so
`qed policy lint`, the command whose entire job is to say what is wrong with a
rule file, answered with a traceback. Unreadable files are findings now:

```
ERROR [invalid_yaml] broken.yaml: this file is not valid YAML: while scanning
a quoted scalar ... found unexpected end of stream
```

`load_bundle_file` decoded a pack bundle as UTF-8 *outside* its own try, so a
single `` raised `UnicodeDecodeError` instead of `BundleRejected`. That one
matters more than it looks: a bundle is the one input in this product that
comes from a third party by design.

**And three of the failures were my tests being wrong, which is worth
recording.** `json.loads(canonicalize(x)) == x` is too strong: JCS (RFC 8785)
serialises an integral double without a decimal point, so `6.0e16` comes back
as an int. And two strategies generated integers at `2**53`, which `jcs.py`
refuses on purpose -- a number two JSON parsers read differently is a payload
hash two verifiers disagree about. The code was right in all three cases; the
properties now say what they actually depend on.

### Added - rate limits on the API (week 10)

SPEC §13: *"per adapter 100 proposals/s default; per principal 20/s. 429 with
`Retry-After`."* Token buckets in `qed/core/ratelimit.py`, spent in the
proposals route.

**A rate limit on a gate is a kill switch under load, and that shaped every
decision here.** Every other service answers a 429 by making somebody wait;
an adapter in `fail: closed` that cannot reach a decision treats it as a
refusal, so throttling the kernel stops the agent's work. The limit exists for
the case it is actually for -- one misbehaving adapter, or one principal in a
loop, consuming the capacity every other adapter needs.

Which is why the bucket holds **three seconds' worth**, not one. A textbook
bucket has capacity equal to the rate, and the spec's per-principal limit is
20/s -- so an agent that makes thirty tool calls while working out what to do
next would be refused. That is not an abusive agent; it is an ordinary one. The
sustained rate stays exactly what the spec says, and only the first burst is
free. The suite found this rather than reasoning finding it: a test that sent
thirty proposals against the shipped defaults went red.

Three more calls worth naming:

- **A refusal writes nothing to the chain.** The attack this stops is a caller
  flooding the API, and recording every refusal would let them flood the
  evidence chain instead -- the one thing that has to stay readable. Refusals
  are counted for `/metrics` and `/v1/status`.
- **`Retry-After` is computed**, not guessed, and never zero when the bucket is
  empty. A client told to retry in one second when the bucket needs three is a
  client that gets refused again, and three of them doing it in lockstep is a
  thundering herd of our own making. `Problem` carries response headers now,
  because a client should be able to back off without parsing a problem
  document.
- **It is per process**, and says so in `/v1/status`: four replicas with
  `per_adapter_rps: 100` admit 400/s between them. A shared limiter would need
  Redis, or the database on every request -- which costs more than the work it
  protects. An operator sizing a limit divides by their replica count.

The config lives under `api.rate_limit`, not the spec's `adapters.rate_limit`:
in this build `adapters` is a *list* of credentials, so a mapping with
`rate_limit` in it would not parse at all. `0` means off rather than "refuse
everything", because zero reads as "no limit" to everyone who has ever written
a config file; negative is refused outright.

Authentication still comes first, and must: a 429 for an unauthenticated caller
would tell them an adapter id exists, and would let an anonymous flood spend a
real adapter's allowance.

### Added - `pip-audit` in CI, and the clock warning (week 10)

The last two of SPEC §17's nine MUSTs with nothing behind them.

**`pip-audit`** runs as its own job, and twice. Its own job because it fails for
reasons that have nothing to do with the code -- an advisory published overnight
turns a green commit red -- and when that happens the useful information is
"which dependency, which advisory", not "the matrix is red". It also runs on a
daily schedule, because a vulnerability in a pinned dependency does not wait for
somebody to push.

Twice because the two questions are different and neither answer covers both.
The environment audit sees the versions actually installed, transitive ones
included, which is where a vulnerability usually turns up. It cannot be
`--strict`: `valqore-qed` and `qed-verify` are editable installs, and `--strict`
counts anything it could not audit as a failure. The declared-set audit is the
strict one -- it resolves exactly the dependencies this project chose, so
nothing can be quietly left out. That mattered: the first attempt used
`--strict` on the environment and would have gone red on our own packages the
moment it ran.

**The clock check** reports when the newest record's timestamp is more than five
seconds in the future -- the signature of a clock that has gone backwards, after
which an export sorted by `ts` does not read in the order things happened. It
warns rather than refusing, because `seq` and `prev_hash` fix the order and
halting on a clock would trade a cosmetic problem for an outage.

It does **not** query an NTP server, and says so in its own output
(`"measured": "newest record ts vs system clock; no NTP query"`). The kernel is
offline by design, and a governance component that reached for the network to
decide whether to trust itself would be a new dependency in the decision path.
The spec says "NTP drift"; this is a weaker, local signal, and naming it
`drift` with the measurement beside it is the honest version.

`qed status` carries it and `qed doctor` prints the sentence. Both, because
`doctor` builds its own report rather than reusing `chain_status` -- which is
how the first version computed the warning correctly and printed nothing.

### Fixed - an invalid `qed.yaml` printed a pydantic traceback

Found while testing the above, and nothing to do with it: `mode: nonsense`
produced forty lines of frames and a URL, with the answer -- *mode must be
shadow or enforce* -- somewhere in the middle. Every command did this, for a
one-character typo in a config file.

`ConfigError` carries the file path and the field path now, and the CLI's group
handler prints it as a sentence like any other statement about the operator's
own setup:

```
qed: /etc/qed/qed.yaml is not valid:
  mode: Input should be 'shadow' or 'enforce'
```

It was found because a validation test asserted on output that did not exist --
the assertion was right and the output was empty, because the exception had
never been caught.

### Added - signed control catalogues, and the air-gap import (week 9)

`qed packs import` and `qed packs verify`, with `qed/remote/packs.py` behind
them. A bundle is one JSON envelope carrying catalogues in the same shape as
the YAML files that ship with qed, signed with a **pack key** -- not the
evidence key, because the evidence key says what this instance did and a pack
key says what a publisher published. One key doing both would let an instance
sign its own catalogue and the signature would prove nothing about where the
control titles came from.

The signature covers everything except itself, `key_id` and `issued_at`
included: a signature over the catalogues alone would let anyone restate which
key signed a bundle, or move the date to defeat the rollback check. There is no
default key and the bundle's own `key_id` is not trusted as the answer --
`--public-key` has to arrive by some route other than the bundle, or the
signature is checking the bundle against itself.

`verify` is separate from `import`: whether to trust a catalogue is a decision
somebody should make with the contents in front of them, and a command that
showed you the contents by installing them would not be giving you the choice.

Every import appends an `admin_action` -- bundle hash, issuer, `issued_at`, key
id, frameworks, whether it was signed. A control title an auditor reads has to
be traceable to a moment and a key.

Unsigned import is possible, takes a flag, and is loud: the record says
`unsigned: true` and the command prints `UNSIGNED`. Refusing outright would
push people to edit the installed files by hand, where nothing would record it.

### Changed - DORA deepened to article level; ISO 42001 deliberately not

SPEC §22 week 9 asks for both. One could be done honestly and one could not,
and the difference is worth more than the half that shipped.

**DORA is now `depth: article`.** The catalogue covers Chapter II, "ICT risk
management" -- all twelve articles, 5 to 16 -- with the Regulation's own
headings, checked against the consolidated text on EUR-Lex rather than written
from memory. That caught one: Article 8 is titled **"Identification"**, and the
label this catalogue carried before was a paraphrase of what the article is
about.

Fifteen baseline rules now map to Article 9 ("Protection and prevention", whose
9(4)(c) and 9(4)(d) ask for policies limiting access to what is required and
for change-management procedures) and Article 10 ("Detection", whose 10(1) asks
for mechanisms to promptly detect anomalous activities). Coverage is 3 of 12 --
25% -- and the nine unmapped articles each say why, as a claim about the kernel
rather than a reading of the Regulation. Article 11 and Article 12 are named as
the near misses rather than quietly left out.

**ISO 42001 stays at `depth: pack`, with the reason written into the
catalogue.** The deepening it needs is its **Annex A** controls, and ISO/IEC
42001 is not freely published: the text is sold and the Annex A titles are not
available from an authoritative public source. ADR-0011 says control titles are
written against the standard's own published material and never from memory,
and this is exactly the case it was written for. A plausible Annex A list
recalled from training would be the worst possible outcome -- not a title
slightly wrong, but a *whole catalogue* that looks verified and is not, attached
to real rules, in a document an auditor reads as authoritative.

So the eight management-system clauses (4-10, whose titles come from the
published ISO harmonised structure) each carry a note saying why a kernel
cannot serve them, and the file states the two things that would unblock the
real work: a licensed copy of the standard, or a design partner who holds one.
Week 9's signed import is the second route -- a partner can publish an ISO 42001
pack without it passing through this repository at all.

**Also fixed, in my own tooling.** The first script that added these mappings
used a lazy `.*?` between the rule id and its `compliance:` block, so for a rule
it could not match it slid forward and inserted into a *later* rule. Five rules
briefly claimed articles nobody had chosen for them -- a compliance claim
attributed to the wrong rule, which is precisely the thing that reaches an
auditor looking real. Caught by diffing the result against the intended set
before committing anything. The rewrite splits each file into rule blocks first
and asserts afterwards that the rules carrying a DORA mapping are exactly the
ones asked for.

### Added - the transparency-log anchor client (week 9)

`qed/remote/anchor.py`, a fourth checkpoint publisher: `{type: qed-anchor, url,
log_id}`. The first one that sends anything to a third party, and for that
reason the only one that does not copy the whole checkpoint record.

It POSTs six values -- `log_id`, `seq`, `hash`, `merkle_root`, `key_id`, `sig`
-- and nothing else. The record was not an option: SPEC §10.4 requires a
checkpoint payload to carry the *previous* checkpoint's receipts, and a
receipt's `target` is an `s3://bucket/key` or a git remote. Posting the record
would hand an anchor service a running inventory of the operator's bucket names,
arriving as a side effect of a feature whose whole premise (invariant §1.7) is
that it carries hashes and signatures only. A test renders the body and fails if
a bucket name or git remote appears in it.

Every value sent is one the auditor already holds, so the log learns nothing new
and the auditor can check the log's entry against their own export. The honest
consequence: the log cannot verify that the signature covers a meaningful
payload, because it never sees the payload. It does not need to -- a
transparency log witnesses that a value existed at a time.

`log_id` is **required**, with no default. `instance_id` names a company and an
environment (and is not on the record at all), and deriving one from the signing
key would move an instance's entries to a new scope at the next rotation,
splitting its own history in the log. The name your entries carry in somebody
else's log is your decision.

`https` is enforced rather than warned about; a `token:` in `qed.yaml` is
refused with a pointer to `token_env`; the token goes in a header and never in
the body; the environment is read at publish time so a secret arriving after
startup still works. The receipt keeps the status plus the attestation fields a
log actually returns and drops the rest, because a receipt lands in the
immutable chain and a log answering with a kilobyte would put a kilobyte there
for good.

Plain `http` is allowed to **loopback only**, matched on the literal host so no
DNS name can resolve its way in. The guard was doing real harm without that: a
local relay or sidecar holding the log credential and talking https onward is a
legitimate deployment, and an operator blocked from `http://127.0.0.1` turns the
publisher off instead, which is strictly worse than anchoring through a relay.

Tested against a real HTTP server in a thread rather than a mocked `httpx`: the
thing worth asserting is what crosses the wire, and a mock tells you what the
code meant to send. Then driven end to end -- two checkpoints through the CLI
against a stub log -- which is how both of the fixes below were found. ADR-0013
has the decisions. The log itself stays out of this repository (SPEC §24.2).

### Fixed - `evidence.checkpoint.every_records` was parsed and never read

`ChainWriter.checkpoint` compared against the module constants directly, so
`every_records` and `every_seconds` in `qed.yaml` were validated, reported by
`qed doctor`, and ignored. The defaults match SPEC §10.4, so an operator who
left them alone saw correct behaviour and an operator who tuned them saw none.

Found by running it, which is the only way this kind is ever found: an
end-to-end script set `every_records: 1`, wrote nine records, and
`qed checkpoint` answered *"nothing to checkpoint yet"*. Twice, before I stopped
assuming the script was wrong.

The thresholds are instance attributes now, filled by the session from the
config; the constants remain the defaults. Five tests, two of which fail if the
fix is reverted -- including one that asserts a *large* `every_records` keeps a
long chain undue, so reading the attribute and then ignoring it would not pass.

This is the same shape as `observability` sitting in `UNIMPLEMENTED_SECTIONS`
while the code read it: a config key and the code that should read it, drifting
apart quietly, with the defaults hiding it.

### Fixed - an import could stop the kernel deciding

Found by running it, before any of this had tests. An imported catalogue
*replaces* the shipped one for its framework, so a bundle that does not list a
control an installed rule cites leaves that rule citing nothing -- which week 8
made a lint **error**, and the engine refuses to decide against a bundle with
errors.

A three-article DORA bundle replaced the shipped catalogue's one article. The
import succeeded. The next `qed check` answered *"the policy bundle has errors;
refusing to decide against a broken bundle"*, and the instance governed
nothing.

So the import now checks the bundle against the loaded rules **before anything
is written**, names the rules it would orphan, and refuses. The alternative --
downgrading an unknown control to a warning when the catalogue was imported --
would put the untraceable OSCAL line back, which is the thing the error exists
to prevent. `--allow-orphaned-rules` for somebody who means it.

This is the supply-chain shape of the feature: a publisher who drops a control
should not be able to switch your kernel off.

### Fixed - the same leadership race, in the file I did not check

0.7.0 fixed `test_a_dead_connection_releases_it`, which asserted the
*immediate* retry after a leader's connection closed. The same assumption lived
in three more places in `tests/evidence/test_ha_outbox.py`, and one of them
failed on the next full run.

PostgreSQL releases a session's advisory locks when it reaps the backend, not
when `close()` returns. There is one `take_over()` helper now, in
`tests/evidence/helpers.py`, used by both files -- fixing one site and leaving
the duplicate is how this came back a day later.

The three sites in `tests/api/test_leader_loop.py` are **not** affected and were
left alone: they follow `resign_leadership()` or `loop.stop()`, where the same
session issues the unlock and the release is synchronous. The race only exists
when the connection dies.

### Fixed - a failure message that promised output nobody could see

The arm64 guard added in 0.7.0 failed on the release tag exactly as designed --
and said *"the probe printed which"* with no probe output anywhere in the log.
The probe ran at import, which is collection time, and pytest discards
module-level stdout under `-q`.

`emulation_available()` returns the reason now instead of printing it, and the
assertion interpolates it. A new test asserts the pairing holds in both
directions, and does not skip when emulation works -- because the `deploy` job
fails on any skip, so a test that skipped on a healthy runner would turn it
red.

A guard that reports its symptom and not its cause is half a guard, and the
half it keeps is the one nobody can act on.

## [0.7.0] — 2026-10-10

Week 8: control catalogues, so a control reference in a rule means something to
the auditor who reads the export.

**What this release does not contain** is the other half of SPEC §22's week 8:
the auditor session, and the deepening of the EU AI Act and NIST AI RMF
mappings that the session is supposed to steer. The *mechanism* is complete and
the catalogues are honest about where the mapping is not: EU AI Act is 4 of 9
articles with a stated reason for each of the other five, and the NIST AI RMF
catalogue lists 5 subcategories of roughly seventy and is marked `partial` for
exactly that reason. Moving those numbers by writing rules to cover more
controls is the overclaim this entire release refuses, so they move after
somebody who audits for a living has looked at it.

### Added - control catalogues, so a control reference means something

A rule could always say `compliance: [{framework: eu_ai_act, control: "Art.
14"}]`, and until now nothing said what `Art. 14` *is*. The OSCAL export handed
an auditor a list of identifiers with no titles, and no way to tell a thorough
mapping from a decorative one.

`qed/compliance/packs/<framework>.yaml` now carries 65 controls across 10
frameworks -- the EU AI Act high-risk articles, NIST AI RMF, the OWASP Agentic,
LLM and MCP Top 10s, SOC 2, NIST CSF, ISO 27001, ISO 42001 and DORA -- each with
a label, the framework's `source` URL, and the edition where the identifiers
depend on it. The labels and sources travel into every OSCAL finding, whose
target title now reads `eu_ai_act Art. 14 -- Human oversight`, with
`control-label`, `catalogue-source` and `mapping-depth` in its props.

`qed packs list` is the coverage report, and most of the work went into what it
refuses to say:

- **A percentage needs a complete catalogue.** SOC 2 is 9 of 9 and prints
  `partial`, because those nine are the criteria this rule set maps to and not
  all of SOC 2. A percentage over a curated list reads as *complete* and is
  not. Only a `catalogue: complete` file gets a number: EU AI Act 44.4%, OWASP
  Agentic 70%, OWASP LLM 30%, OWASP MCP 10%.
- **And a percentage never prints without its scope.** `eu_ai_act 44.4%` reads
  as a share of the Regulation; it is 4 of the 9 articles this catalogue covers,
  out of 113. Every pack states its scope, the coverage report prints it beside
  the table, and a `complete` catalogue is complete *for that scope* and not for
  the whole standard.
- **An unmapped framework still gets a catalogue.** ISO 42001 is 0 of 8, with
  all eight clauses named. Omitting the file would have made it look like a
  framework nobody had considered; a visible zero is a gap somebody can close.
- **The unmapped controls are listed by name**, because the first question an
  auditor asks is which controls you do *not* claim.
- **A deliberate gap says why.** The five unmapped EU AI Act articles each
  carry a `note` that prints under the table. A note is a claim about *this
  kernel* -- "nothing here records a risk management process" -- and never a
  reading of the standard, because "this does not apply to us" is a legal
  opinion and has no business in a YAML file. A stated reason is something an
  auditor can disagree with; a bare absence they can only guess at, and now
  means exactly "not mapped yet".
- `depth` (`article` / `category` / `pack`) says how deep a mapping goes, not
  how good it is, and rides on every finding.

`docs/compliance.md` is the page for all of it. NIST CSF records `version: 1.1`
on purpose: `PR.AC-4` is a 1.1 identifier and does not exist in 2.0, where the
family became `PR.AA`, and a mapping to a retired identifier is one nobody can
follow.

### Added - `qed policy normalize-frameworks`

`EU AI Act`, `eu-ai-act` and `AI Act` all normalise to `eu_ai_act` on read, so a
rule decides correctly whichever it writes. What normalising on read does not do
is *group*: two spellings are two rows in the coverage report and two control
sets in an OSCAL export, with nothing telling the reader they are one framework.
This rewrites them in place, or reports and exits 1 with `--check`.

It is a text substitution on the `framework:` value and nothing else. A YAML
round-trip would reformat every comment and quote style in a rule file somebody
wrote by hand, and the diff would be unreviewable.

### Changed - an uncatalogued control is now an error

`qed policy lint` used to warn when a rule cited a control nothing defined.
That is now an error, and `qed decide` refuses to run against a bundle with
errors, because a control id that is nearly right reaches the OSCAL export
looking exactly like a real mapping -- and the first person to notice is the
auditor who goes looking for the control and finds nothing.

### Fixed - the ten new catalogues shipped in no wheel

`tests/test_packaging.py` exists because `qed/compliance/frameworks.yaml` was
once missing from `package-data`, so the container started and died on its first
request. It matched with `fnmatch`, whose `*` crosses a path separator -- so
`compliance/*.yaml` looked as though it covered
`compliance/packs/eu_ai_act.yaml`. setuptools expands these patterns with the
`glob` module, where it does not.

The result was a container that built cleanly, loaded its rules, found no
catalogue for any control they cite, and refused to decide against a bundle it
reported as broken. Only the container test saw it; 2,346 tests against the
checkout were green, because the checkout has the files.

The matcher is `PurePosixPath.match` now, which segments the way setuptools
does, and removing the pattern fails ten tests by name instead of none.

### Fixed - an unreachable PostgreSQL hung instead of erroring

libpq has no default `connect_timeout`, and this never set one. A database that
does not answer -- a wrong port, a security group that drops rather than
refuses, a server that went away -- waited on the operating system's connect
timeout instead: measured at **over a minute** on Windows with nothing
listening.

`qed serve` and `qed doctor` both open the store, so the operator-visible
symptom was a command that printed nothing for a minute, which reads like a
wedged process rather than a database that is down. Now `PostgresUnavailable`
in ten seconds, naming the cause. A `connect_timeout=` already in the DSN wins:
an operator who wrote one meant it.

Found by accident, which is the only honest way to describe it: a test run
stalled after the local Postgres container stopped, and chasing the stall
found a real hang underneath it.

### Fixed - the arm64 tests could vanish from a green CI run

The emulation probe ran `docker run --platform <foreign> busybox true` and read
its exit code. That returns the same `False` for "this machine has no emulator"
and "the registry did not answer just then", and the second of those happened:
the `deploy` job skipped both arm64 tests one step after installing the
emulator. The job's own "something skipped" guard caught it, which is why that
guard exists -- but it named the symptom and not the test.

The pull is now its own step, so a registry failure prints as one. And because
that job installs the emulator itself, it sets `QED_REQUIRE_EMULATION=1`: the
tests then run and fail by name rather than skipping, since a skip there is a
green run with the test that caught the last arm64 bug not having run.

Every probe in that file also has a timeout now. They run at import, which is
collection time for the whole suite, and an unbounded `subprocess.run` there is
a suite that hangs with no test name to blame -- and it is `docker` being
asked, so a busy daemon is the ordinary case.

While there: the job ran `pytest tests/deploy` twice, building the container
twice for one result. Once now.

### Fixed - a leadership test raced the Postgres backend reaper

`test_a_dead_connection_releases_it` closed the leader's connection and
asserted the *immediate* retry took the lock. `close()` sends a terminate and
returns; PostgreSQL releases that session's advisory locks when it reaps the
backend, so the next `pg_try_advisory_lock` can arrive first. It passed on
every local run and failed on CI.

The race was in the test, but it names a real property of the takeover: a
crashed leader's lock frees up *shortly* after the crash, not instantly, which
is why `qed/api/leader.py` asks every tick rather than once. The test now waits
up to ten seconds and says what a longer stall would mean.

### Fixed - `qed packs list` printed a section sign

A unicode escape for the section sign sat in a CLI string, and a Windows
console at the default code page cannot encode it. The ASCII assertion on
command output is a week-1 lesson that this file had not yet learned.

## [0.6.1] — 2026-10-10

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
EUIPO/USPTO reservations are in place (SPEC §24.1).
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
> 2026-10-08; see [0.6.0]. The public push now waits only on the name
> reservations in SPEC §24.1.

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
  distributed. Lifted in [0.6.0] on 2026-10-08, when §24.2 came back
  clean.

### Changed from the spec

- `qed/core/policy/blast_radius.py` is **written fresh**, not ported from
  Valqore `governance/blast_radius.py`. See `docs/adr/0001-blast-radius-table.md`.
