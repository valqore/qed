"""What protects `main`, checked against what claims to protect it.

`GOVERNANCE.md` tells a reader that maintainers' changes go through the same CI
as anybody else's, with no bypass and no admin merge. Branch protection is a
settings page nobody outside the repository can see, so that sentence is
unfalsifiable from where a reader stands -- and the most likely way for it to
become false is not malice. It is adding a CI job and not adding it to the
required list, which leaves a check that can fail while the merge button stays
green.

So the rules are files (`.github/rulesets/`), and these tests hold the files to
the two documents that describe them: `ci.yml`, which says what must pass, and
`GOVERNANCE.md`, which says who may merge. Nothing here talks to GitHub -- the
files are the source and `apply.sh` installs them, which it did when the
repository went public on 2026-10-19 (rulesets are refused on a private
repository on this plan, which is why it waited).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
RULESETS = ROOT / ".github" / "rulesets"
ENVIRONMENTS = ROOT / ".github" / "environments"
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def ruleset(name: str) -> dict[str, Any]:
    loaded = json.loads((RULESETS / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def rule(ruleset_: dict[str, Any], type_: str) -> dict[str, Any]:
    found = next((r for r in ruleset_["rules"] if r["type"] == type_), None)
    assert found is not None, f"no {type_} rule"
    return found


def has_rule(ruleset_: dict[str, Any], type_: str) -> bool:
    return any(r["type"] == type_ for r in ruleset_["rules"])


def required_contexts() -> set[str]:
    checks = rule(ruleset("main.json"), "required_status_checks")
    return {c["context"] for c in checks["parameters"]["required_status_checks"]}


def pull_request_contexts() -> set[str]:
    """Every status context `ci.yml` reports on a pull request.

    A matrix job reports one context per cell, named `job (val, val)` in the
    order the matrix keys are declared -- `check (ubuntu-latest, 3.12)`. That
    spelling is not documented anywhere a test can read, which is why
    `apply.sh` ends by saying to open a pull request and look at the merge
    button: a context required under a name Actions never reports is a check
    that blocks the merge forever, the opposite failure and just as quiet.
    """
    # `yaml.safe_load` reads the `on:` key as the boolean `True` under YAML 1.1,
    # which is a small trap worth naming rather than working around silently.
    config = yaml.safe_load(CI.read_text(encoding="utf-8"))
    triggers = config.get("on", config.get(True))
    assert triggers is not None and "pull_request" in triggers, (
        "ci.yml does not run on pull requests, so nothing can be required of one"
    )

    contexts: set[str] = set()
    for job_id, job in config["jobs"].items():
        guard = str(job.get("if", ""))
        if "github.event_name" in guard and "pull_request" not in guard:
            continue  # a job that cannot run on a pull request cannot be required
        matrix = job.get("strategy", {}).get("matrix")
        if not matrix:
            contexts.add(job_id)
            continue
        axes = [values for values in matrix.values() if isinstance(values, list)]
        combinations: list[tuple[Any, ...]] = [()]
        for axis in axes:
            combinations = [(*combo, value) for combo in combinations for value in axis]
        for combo in combinations:
            contexts.add(f"{job_id} ({', '.join(str(v) for v in combo)})")
    return contexts


class TestEveryRulesetFile:
    @pytest.mark.parametrize("name", ["main.json", "tags.json"])
    def test_it_is_installable(self, name: str) -> None:
        """The shape the REST API requires. A ruleset rejected at publication
        is a ruleset that is not installed, and the script moves on."""
        data = ruleset(name)
        assert data["enforcement"] == "active", "a ruleset in `evaluate` mode blocks nothing"
        assert data["target"] in {"branch", "tag"}
        assert data["name"]
        assert data["rules"]
        assert data["conditions"]["ref_name"]["include"]

    @pytest.mark.parametrize("name", ["main.json", "tags.json"])
    def test_nobody_may_bypass_it(self, name: str) -> None:
        """`GOVERNANCE.md`: "no bypass and no admin merge". This is the line in
        the file that makes that sentence true, and the one most easily
        softened by one entry on an afternoon when CI is being annoying."""
        assert ruleset(name)["bypass_actors"] == []

    @pytest.mark.parametrize("name", ["main.json", "tags.json"])
    def test_history_cannot_be_rewritten_or_erased(self, name: str) -> None:
        """For `main` this is the audit trail of a product whose argument is
        audit trails. For a tag it is worse: a tag that can move is a version
        number that does not identify a build, and a release signature is
        checked against a tag."""
        data = ruleset(name)
        assert has_rule(data, "deletion"), "the ref can be deleted"
        assert has_rule(data, "non_fast_forward"), "the ref can be force-pushed"


class TestMainRequiresTheWholeSuite:
    def test_every_pull_request_job_is_required(self) -> None:
        """The drift this file exists to catch."""
        missing = sorted(pull_request_contexts() - required_contexts())
        assert not missing, (
            "ci.yml runs these on a pull request and the ruleset does not require "
            f"them, so each can fail with the merge button green: {missing}"
        )

    def test_nothing_is_required_that_cannot_report(self) -> None:
        """The opposite direction, which fails closed instead of open: a
        context no job produces is never reported, so the pull request waits
        for it forever."""
        unknown = sorted(required_contexts() - pull_request_contexts())
        assert not unknown, f"required contexts that no job reports: {unknown}"

    def test_a_stale_branch_must_rebase_first(self) -> None:
        """Otherwise the green run is a run of something that was never on
        `main`, which is how two individually passing changes merge into a
        broken default branch."""
        parameters = rule(ruleset("main.json"), "required_status_checks")["parameters"]
        assert parameters["strict_required_status_checks_policy"] is True

    def test_a_pull_request_is_mandatory(self) -> None:
        assert has_rule(ruleset("main.json"), "pull_request")

    def test_the_merge_shape_is_one_commit(self) -> None:
        """Squash only, with linear history enforced: the history already has
        one change per commit with one long message, and
        `required_linear_history` would reject a merge commit anyway."""
        data = ruleset("main.json")
        assert has_rule(data, "required_linear_history")
        assert rule(data, "pull_request")["parameters"]["allowed_merge_methods"] == ["squash"]

    def test_code_owner_review_is_requested_and_not_required(self) -> None:
        """`require_code_owner_review` is `false` for the same reason
        `required_approving_review_count` is `0`, and it was `true`.

        `.github/CODEOWNERS` gives one person every path. GitHub does not let
        anybody approve their own pull request, so requiring a code owner's
        approval requires an approval that cannot be given -- and with
        `bypass_actors` empty there is no override. That is the repository
        nobody can merge into that the test below spends a docstring avoiding,
        reached by a different parameter.

        Two tests asserted the two halves of that: one pinned the count at zero
        and explained why, the other demanded the flag that makes the zero
        irrelevant. Both passed. Neither knew about the other, which is the
        shape of a compliance control reported in an export while nothing
        enforces it -- found here in the file written to prevent it.

        Nothing is lost by turning it off. GitHub still requests review from
        the owners named in `CODEOWNERS` on every pull request, which is what
        `.github/rulesets/README.md` already described ("CODEOWNERS review is
        requested"); only the blocking requirement goes. When a second
        maintainer arrives this becomes safe to turn on, and the count below
        stops being zero in the same change.
        """
        parameters = rule(ruleset("main.json"), "pull_request")["parameters"]
        assert parameters["require_code_owner_review"] is False
        assert parameters["dismiss_stale_reviews_on_push"] is True
        assert parameters["required_review_thread_resolution"] is True

    def test_nothing_requires_an_approval_that_cannot_be_given(self) -> None:
        """The invariant the two tests above were each half of.

        While `bypass_actors` is empty and the approval count is zero, no
        parameter may require a human approval, by any route. This is the test
        that would have failed when `require_code_owner_review` was `true`,
        and it is written against the property rather than against one flag so
        that the next parameter with the same effect also trips it.
        """
        data = ruleset("main.json")
        parameters = rule(data, "pull_request")["parameters"]
        if data["bypass_actors"] or parameters["required_approving_review_count"]:
            pytest.skip("there is a second maintainer or a bypass; the trap does not apply")
        requires_a_human = {
            name: value
            for name, value in parameters.items()
            if name in {"require_code_owner_review", "require_last_push_approval"} and value is True
        }
        assert not requires_a_human, (
            f"{sorted(requires_a_human)} require an approving review, while the approval "
            "count is 0 and bypass_actors is empty. One maintainer cannot approve their "
            "own pull request, so main would be unmergeable."
        )


def test_the_approval_count_matches_the_number_of_maintainers() -> None:
    """The one number here that is a judgement, tied to the sentence that
    justifies it.

    Zero approvals is honest while there is one maintainer: requiring one, with
    nobody to give it and `bypass_actors` empty, is a repository nobody can
    merge into, and the usual repair -- adding the maintainer as a bypass actor
    -- is precisely the admin merge `GOVERNANCE.md` says does not happen.

    When a second maintainer arrives, that document stops saying nobody has
    reviewed this code. This test then fails, here, naming the ruleset -- which
    is the point. Changing a governance document and changing what the merge
    button requires are two motions, and the second is the one that gets
    forgotten.
    """
    count = rule(ruleset("main.json"), "pull_request")["parameters"][
        "required_approving_review_count"
    ]
    unreviewed = "**Nothing in this repository has been reviewed by a second person.**"
    governance = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    if count == 0:
        assert unreviewed in governance, (
            "GOVERNANCE.md no longer says this repository is unreviewed, so somebody "
            "can approve: require an approval in .github/rulesets/main.json"
        )
    else:
        assert unreviewed not in governance, (
            "the ruleset requires an approval that GOVERNANCE.md says nobody can give"
        )


def test_the_installer_defaults_to_a_plan() -> None:
    """A script that writes to a live repository on an accidental invocation is
    not the right tool for publication day."""
    script = (RULESETS / "apply.sh").read_text(encoding="utf-8")
    assert "--apply" in script
    assert "APPLY=0" in script, "the default is not a dry run"
    assert '"$HERE"/*.json' in script, "the script does not install every ruleset here"


def test_the_installer_installs_the_environments_too() -> None:
    """Otherwise `.github/environments/` is documentation.

    A file describing an approval gate that nothing installs is worse than no
    file: it reads as a control and is a wish. This asserts the glob rather
    than the word `environments`, because a mention in a comment is not an
    installation -- the failure #48 keeps producing.
    """
    script = (RULESETS / "apply.sh").read_text(encoding="utf-8")
    assert '"$ENVS"/*.json' in script, (
        "apply.sh does not install every environment in .github/environments/"
    )
    assert "environments/$env_name" in script, "apply.sh does not PUT the environments it reads"


def test_the_governance_promise_is_still_the_one_being_kept() -> None:
    """If this sentence is rewritten, everything above is enforcing a claim the
    project no longer makes."""
    governance = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    assert "no bypass and no admin merge" in governance


def release_workflow() -> dict[str, Any]:
    loaded = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def jobs_publishing_to_pypi() -> set[str]:
    """Every job with a step that uploads to PyPI, found by the action it uses.

    Found by action rather than by job name so that a second publishing job --
    the plausible way this gate gets bypassed -- is covered the day it is
    added, not the day somebody remembers to add it to a list here.
    """
    publishers = set()
    for name, job in release_workflow()["jobs"].items():
        for step in job.get("steps") or []:
            if "gh-action-pypi-publish" in str(step.get("uses", "")):
                publishers.add(name)
    return publishers


class TestPublishingToPyPINeedsAHuman:
    """The one step in the release that cannot be taken back.

    A container tag can be overwritten, a package version deleted, a GitHub
    release edited. PyPI is different in kind: a release file can be deleted
    but **its version string can never be reused**, by this project or anybody.
    Publishing by mistake does not cost a re-run, it costs the number.

    So `release.yml`'s `pypi` job declares an `environment`, and that
    environment carries a required reviewer. What the tests below can see is
    the workflow and the declared environment -- both files. **What no test
    here can see is the live environment**, which is a settings page, same
    blind spot the module docstring describes for branch protection. The file
    is the intent; `gh api repos/valqore/qed/environments/pypi` is the truth,
    and `apply.sh --apply` is what makes them agree.

    Nor can anything here see PyPI's own trusted-publisher configuration, which
    has an optional environment field of its own. Left blank, this gate is the
    only thing in front of a publish; set to `pypi`, PyPI refuses an OIDC token
    minted anywhere else.
    """

    def test_the_pypi_job_declares_an_environment(self) -> None:
        job = release_workflow()["jobs"]["pypi"]
        assert job.get("environment") == "pypi", (
            "the pypi job does not run in the `pypi` environment, so a tag "
            "publishes with no human in the loop"
        )

    def test_every_job_that_publishes_is_gated(self) -> None:
        """Not only the one that exists today."""
        publishers = jobs_publishing_to_pypi()
        assert publishers, (
            "no job uses pypa/gh-action-pypi-publish -- this test has stopped "
            "watching anything, so find how publishing happens now"
        )
        jobs = release_workflow()["jobs"]
        ungated = {n for n in publishers if not jobs[n].get("environment")}
        assert not ungated, f"{sorted(ungated)} publish to PyPI with no environment"

    def test_every_declared_environment_exists_as_a_file(self) -> None:
        """A name in a workflow creates the environment on first use, with no
        protection rules at all.

        That is the quiet failure: a typo, or a new job naming `release`
        instead of `pypi`, gets a *green* run through an environment that gates
        nothing. The workflow naming an environment and the repository
        declaring one have to be the same set.
        """
        named = {
            str(job["environment"])
            for job in release_workflow()["jobs"].values()
            if job.get("environment")
        }
        declared = {path.stem for path in ENVIRONMENTS.glob("*.json")}
        assert named <= declared, (
            f"{sorted(named - declared)} named in release.yml with no file in "
            ".github/environments/, so apply.sh will not give it any rule"
        )

    def test_the_declared_environment_requires_a_reviewer(self) -> None:
        spec = json.loads((ENVIRONMENTS / "pypi.json").read_text(encoding="utf-8"))
        reviewers = spec.get("reviewers") or []
        assert reviewers, "the pypi environment declares no required reviewer"
        for entry in reviewers:
            assert entry.get("login"), (
                "a reviewer is named by numeric id; use a login so the file "
                "says who, and so it breaks when they stop being a maintainer"
            )

    def test_self_review_tracks_the_number_of_maintainers(self) -> None:
        """Same shape as the approval-count test above, and the same trap.

        `prevent_self_review` is a control when there are two people and a
        deadlock when there is one: the sole maintainer cuts the tag, so the
        sole maintainer is the one who cannot approve it, and the release stops
        forever with no way out but editing the settings page mid-release.

        When a second maintainer arrives, `GOVERNANCE.md` stops saying this
        code is unreviewed and this test fails here, naming the file. Changing
        a governance document and changing what the gate requires are two
        motions and the second is the one that gets forgotten.
        """
        spec = json.loads((ENVIRONMENTS / "pypi.json").read_text(encoding="utf-8"))
        unreviewed = "**Nothing in this repository has been reviewed by a second person.**"
        governance = (ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
        if spec.get("prevent_self_review"):
            assert unreviewed not in governance, (
                "the pypi gate forbids self-review while GOVERNANCE.md says there "
                "is nobody else to approve -- the next release would never publish"
            )
        else:
            assert unreviewed in governance, (
                "GOVERNANCE.md no longer says this repository is unreviewed, so "
                "somebody else can approve a publish: set prevent_self_review "
                "in .github/environments/pypi.json"
            )

    def test_the_gate_does_not_hold_the_recoverable_steps(self) -> None:
        """The asymmetry is deliberate, so pin it.

        `release` does not wait on `pypi`, which means the GitHub release, the
        signed image and the chart all land without an approval and only the
        irreversible step is held. Adding `pypi` to `release`'s `needs` would
        make every release wait on a human for steps that can simply be redone
        -- and would be an easy thing to add while tidying a graph.
        """
        needs = release_workflow()["jobs"]["release"]["needs"]
        assert "pypi" not in needs, (
            "the release job now waits on the approval gate, so nothing in a "
            "release lands until somebody approves PyPI"
        )
