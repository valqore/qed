# What protects `main`, written down

`GOVERNANCE.md` says maintainers' changes go through the same CI as anybody
else's, with no bypass and no admin merge. That sentence is worth nothing on its
own: branch protection is a checkbox in a settings page nobody can see, in a
repository most readers cannot administer, and a claim about it is unfalsifiable
from outside. So the rules live here as the JSON that produces them, and
`tests/docs/test_repo_protection.py` checks the parts that can drift.

`apply.sh` installs them. It is idempotent and prints a plan unless given
`--apply`.

## Two things to know before reading the JSON

**Nothing protects `main` today.** Protected branches and rulesets require a
public repository or a paid plan, and this one is private on neither
(`GET /repos/valqore/qed/rulesets` answers `403 Upgrade to GitHub Pro or make
this repository public`). Every commit so far went straight to `main`, which
`GOVERNANCE.md` also says. The rules below therefore take effect in the same
minute the repository becomes public — not later, and not when somebody
remembers, which is why they are a script and not a paragraph in a runbook.

**`required_approving_review_count` is `0`, on purpose.** There is one
maintainer. Requiring one approval with no second human and an empty
`bypass_actors` would not be strictness, it would be a repository nobody can
merge into -- and the repair, adding the maintainer as a bypass actor, is
exactly the admin merge `GOVERNANCE.md` says does not happen here. So the pull
request is mandatory, CODEOWNERS review is requested, conversations must be
resolved, every check must pass, and the branch must be current -- and the
count stays at `0` until there is somebody to do the approving. A test ties
that number to the sentence in `GOVERNANCE.md` that says nobody has reviewed
this repository, so the two cannot drift apart silently.

**`require_code_owner_review` is `false` for exactly the same reason, and was
`true`.** `CODEOWNERS` gives one person every path, GitHub does not let anybody
approve their own pull request, and `bypass_actors` is empty — so requiring a
code owner's approval required an approval that could not be given. It is the
unmergeable repository the paragraph above avoids, reached by a different
parameter, and it was caught before publication only because the rulesets had
never been applied: they are refused on a private repository, so the trap could
not spring.

Two tests asserted the two halves of it. One pinned the count at zero and
explained why; the other demanded the flag that makes the zero irrelevant. Both
passed, because neither knew the other existed — a control reported as present
while something else makes it inert, which is the failure this product exists
to remove, found in the file written to prevent it. There is now a test on the
*property*: while `bypass_actors` is empty and the count is zero, no parameter
may require a human approving review, by any route. Turn the flag back on
together with a second maintainer, or that test fails and names it.

Nothing is lost meanwhile. GitHub still requests review from the owners in
`CODEOWNERS` on every pull request; only the blocking requirement is off, which
is what the sentence above already described.

## The rest of the choices

- **Ten required checks, not one.** `required_status_checks` names every job
  `ci.yml` runs on a pull request, including the four `check` matrix cells and
  the slow `deploy` job that builds the arm64 container. A missing context is a
  check that can fail while the merge button stays green. The test derives the
  list from `ci.yml` and fails when a new job is not required, because adding a
  job and requiring it are two different motions.
- **`strict_required_status_checks_policy`** -- a stale branch must rebase
  before merging. The green run has to be a run of what will be on `main`.
- **Squash only**, with `required_linear_history`. One change is one commit with
  one message, which is the shape the history already has.
- **`bypass_actors` is empty.** This is the only line in the file that makes the
  `GOVERNANCE.md` sentence true, and the easiest one to quietly add an entry to.
- **Tags `v*` cannot be deleted or moved.** A release tag is what a user
  verifies a signature against; a tag that can move is a version number that
  does not identify a build.
- **Commit signature verification is not required.** Not because it is
  worthless -- because turning it on while the maintainer's commits are not
  signed would block the only person who can merge, and a rule that gets
  switched off an hour later teaches the wrong lesson. It goes on when signing
  is set up, and `SECURITY.md` says what is signed today: releases and evidence
  records, with keys, not commits.
