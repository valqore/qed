# Deployment environments

One file per GitHub Actions environment, named after the environment. Same
argument as `../rulesets/`: an environment is a settings page, so a sentence
claiming that publishing needs an approval is unfalsifiable from where a reader
stands. The file makes the intent reviewable and `../rulesets/apply.sh`
installs it.

## `pypi.json`

Gates `release.yml`'s `pypi` job, which is the only step in the release that
cannot be undone. A release file can be deleted from PyPI; **its version string
can never be reused**, by this project or anybody. So the tag means "build it"
and a person means "publish it".

Three fields are choices rather than defaults, and each one has a reason that
is easy to get backwards.

`"reviewers"` names a **login**, not the numeric id the API wants. `apply.sh`
resolves it. A number in this file would be unreadable and would silently keep
working after the account it points at stopped being a maintainer.

`"prevent_self_review": false`, because `GOVERNANCE.md` says there is one
maintainer and nothing here has been reviewed by a second person. A rule
forbidding you to approve your own run is a control when there are two people
and a deadlock when there is one. **When a second maintainer arrives this
should flip**, and the test in `tests/docs/test_repo_protection.py` ties it to
the maintainer count so the two cannot drift apart quietly.

`"deployment_branch_policy": null`, deliberately. A tag-only policy reads as
tighter and would break `release.yml`'s `workflow_dispatch` path, which can
reach the `pypi` job from any ref; the workflow's own `on:` already decides
when that job can run at all. A policy that forbids the dispatch path would
turn a recoverable mistake -- publishing from a branch -- into a release that
cannot be run at all.

## What no file here can tell you

This directory is the **intent**. The live configuration is the truth, and the
two can disagree -- somebody edits the settings page, or `apply.sh` was never
run after a change. Read the truth with:

```
gh api repos/valqore/qed/environments/pypi \
  --jq '{policy: .deployment_branch_policy,
         rules: [.protection_rules[] | {type, prevent_self_review,
                 reviewers: [(.reviewers // [])[] | .reviewer.login]}]}'
```

The gate was exercised end to end before it was wired into `release.yml`, on
2026-11-02, because a gate that has never gated is a guess. A throwaway
workflow declaring this environment (run `41464363390`) sat at `waiting` with a
pending deployment naming the reviewer, and ran to success once approved. Both
halves were observed: that it stops, and that it can be released.
