# Governance

## The open-core boundary — five tests (SPEC §25.2)

A component is **open and local** if any of these hold:

1. it is in the decision path;
2. it carries customer data;
3. auditors must be able to verify it independently.

It **may** be a remote or optional API if:

4. its value grows with time or with the network — freshness, external
   witnessing, shared intelligence.

It is **closed and commercial** if:

5. it only makes sense at scale — multi-tenant, multi-auditor, multi-year.

### Red lines

- The kernel alone, offline, produces evidence an auditor will accept. If that
  ever stops being true, the product is broken, not the pricing.
- No commercial feature ever removes or caps an open capability. There is no
  "30-day chain in the free tier".
- Everything under `qed.remote.*` is opt-in, outbound-only, carries hashes and
  signatures but never customer data, and degrades gracefully when switched off.
  Zero bytes leave by default.

## Repository split

| Repo | Contents |
|---|---|
| `qed` (this one) | kernel, adapters, policy language, baseline pack, `qed-verify`, docs, Helm, examples |
| `qed-ui` | live UI, approval pages, SSE client |
| `qed-cloud` | multi-tenant evidence vault, auditor portal, transparency log, signed pack feed, SSO/RBAC, long retention |

No proprietary code ever enters this repository. Git history is irreversible, so
this is a rule about the first commit, not about the current state.

Valqore-ported modules arrive as a single commit labelled
`imported from valqore-engine <sha>`, without private history.

## Licensing

**Apache-2.0** (SPEC §25.1), applied in full: `LICENSE` and `NOTICE` at the
root, and `license = "Apache-2.0"` in both `pyproject.toml` files.

SPEC §24.2 — Valqore patent scope — closed on 2026-10-08: no filings, nothing
pending. That order mattered. The Apache-2.0 §3 patent grant is perpetual and
irrevocable the moment the code is distributed, so the only way to apply the
licence as a formality rather than as a decision was to establish first that
there is nothing to grant.

Apache-2.0 §6 grants no trademark rights. `NOTICE` says what that leaves a
fork free to do, which is everything except claim the product name.

## Relationship to Valqore

One-directional. `qed` has **zero** imports from Valqore. Valqore becomes a
consumer in v1.x (`qed.propose(kind="iac")`) and deletes its own
`approvals.py` and `mcp/gateway.py` at that point.

QED does not do IaC or Kubernetes manifest scanning. That stays in Valqore,
permanently (SPEC §1.3).

## Changing the evidence format

The evidence format is the product's only real promise: a record written today
must verify in seven years. Therefore:

- any change to hashing, to record fields, or to the masking pattern set is a
  `schema_version` bump with an ADR;
- `qed-verify` must keep verifying every prior version, with cross-version
  fixtures in CI;
- `docs/evidence-format.md` is the specification, and it is published.

## Decisions

Anything the spec does not settle gets an ADR in `docs/adr/`, numbered, with
context, the decision, consequences and the alternatives that were rejected.
"The spec was silent so I picked one" is fine; "the spec was silent so nobody
knows why it works this way" is not.

An ADR is not revised after the fact. A decision that turns out wrong gets a
new ADR that supersedes it, because the reasoning that led somewhere wrong is
part of the record — and because an audit trail product that quietly edits its
own history has a credibility problem that no feature fixes.

## Who decides

**One maintainer: Tunc Celik (`tunc@valqore.io`), declared in
`pyproject.toml`.** SPEC §22 plans for two engineers and there is currently
one, and this section says so rather than describing a review process that
cannot happen. A governance document that invents a second reviewer is the same
failure as a coverage percentage with no catalogue behind it.

What follows from that, stated plainly because it is the honest version:

- **Nothing in this repository has been reviewed by a second person.** Every
  commit has passed CI, `ruff`, `mypy --strict` and the full suite, and none
  has had another pair of eyes on the reasoning.
- **The checks are what substitutes for a reviewer**, which is why so many of
  them are structural rather than stylistic: the AST scans on `qed.core`, the
  packaging guard, the nav guard, the threat-model guard. A test can refuse a
  change at 3am; a policy about two approvals cannot, if there is only one
  person.
- This is the same observation ADR-0014
  makes about the operator — the one actor no rule constrains — applied to the
  project itself.

When there is a second maintainer, these become the rules, and this paragraph
becomes a statement about the past:

- **Any maintainer may merge** a change that passes CI and the definition of
  done in `CONTRIBUTING.md`.
- **Two must agree** on: anything that changes the evidence format or
  `schema_version`; a new dependency; a change to the open-core boundary at the
  top of this document; and anything that relaxes an invariant in
  `SECURITY.md`.
- **A disagreement that does not resolve** ends with the change not being made.
  The default is the status quo, which for a kernel other people's controls
  depend on is the right bias.

There is no voting, no RFC period and no formal escalation, because inventing
process for one or two people produces theatre rather than governance.

## Contributions

`CONTRIBUTING.md` has the mechanics. The governance-relevant
parts:

- **DCO, not CLA**, on this repository (SPEC §25.1). Contributors keep their
  copyright and assert the right to contribute under Apache-2.0. `qed-ui` uses
  a CLA because it is AGPL and may need relicensing; this one will not be
  relicensed.
- **No contributor is asked to assign copyright**, and no contribution is
  taken under terms different from the licence everyone else gets.
- **Maintainers' changes go through the same CI** as anybody else's. There is
  no bypass and no admin merge.

### What enforces that

The sentence above is the kind of claim this product exists to be suspicious
of: a control described in a document while nothing checks it. Two honest
statements, in order.

**Today, nothing enforces it.** Every commit in this repository went straight
to `main`. Protected branches and rulesets require a public repository or a
paid plan, and this one is private on a free one, so there is no setting to
turn on yet -- `GET /repos/valqore/qed/rulesets` answers `403 Upgrade to GitHub
Pro or make this repository public`. The paragraph above said what the rules
will be; this one says what they are.

**From publication, the rules are files.** `.github/rulesets/main.json` and
`tags.json` hold the ruleset that requires a pull request, requires every one
of the ten checks `ci.yml` runs, requires a stale branch to rebase first,
forbids force-pushing or deleting `main`, forbids moving a `v*` tag, and leaves
`bypass_actors` empty -- which is the one line that makes "no admin merge"
true. `.github/rulesets/apply.sh` installs them, and
`tests/docs/test_repo_protection.py` derives the required check list from
`ci.yml` and fails when a job is added without being required, because that is
how a merge button goes green over a check that can fail.

Approvals are set to zero while there is one maintainer, for the reason above:
requiring an approval nobody can give, with no bypass, is a repository nobody
can merge into, and the usual repair is the admin merge this section says does
not happen. A test ties that zero to the sentence saying nobody has reviewed
this code, so the day that stops being true, the ruleset has to change too.

Anybody can read the JSON. Anybody with the repository open can compare it to
what is installed: `gh api repos/valqore/qed/rulesets`.

## Support and response

One commitment, because it is the only one worth making at this size: **every
issue gets a human response within 24 hours on a working day.** Not a fix — a
response. For a security report the timetable is in
`SECURITY.md`.

A weekly changelog post goes in GitHub Discussions.

## Trademark, and what a fork may do

Apache-2.0 §6 grants no trademark rights, and `NOTICE` says what that leaves a
fork free to do: everything except claim the product name or use the logo. Fork
it, sell it, run it, change it, and call it something else.

Specifically permitted and worth naming, since projects sometimes imply
otherwise: running QED commercially, offering it as a managed service, and
keeping your modifications private. The licence means it and no later document
will take it back.
