"""`qed demo` (SPEC §14).

The demo is the first thing a stranger runs, so the test is less about the
rendering than about the four promises the command makes:

1. What it says the pack decides is what the pack decides. Each
   :class:`qed.demo.Scene` carries its expected verdict, and the first test
   here checks every one against the shipped baseline pack. A rule change that
   moves a scene fails this test instead of surprising somebody's first run.
2. It exits 0 although it contains a BLOCK.
3. Every record it writes is marked `dev`, so the chain cannot be mistaken for
   evidence after it is exported.
4. The commands it prints next actually work, and the chain it wrote verifies.

Everything goes through the real CLI, the real SQLite store and the real
standalone verifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qed.cli import app
from qed.core.policy.engine import evaluate
from qed.core.schemas import BudgetState, Decision, EvalContext, utcnow
from qed.demo import SCENES, run

runner = CliRunner()


class TestTheScenesDecideAsAdvertised:
    """Each scene's `expect` against the pack that ships, not against a mock.

    `baseline_bundle` is the session-scoped fixture from `tests/conftest.py`:
    the shipped pack, loaded once.
    """

    @pytest.mark.parametrize("scene", SCENES, ids=[s.key for s in SCENES])
    def test_the_expected_decision_is_the_real_one(self, scene, baseline_bundle) -> None:
        proposal = scene.build()
        verdict = evaluate(
            proposal,
            baseline_bundle,
            BudgetState(token_jti=proposal.principal.token_jti),
            EvalContext(now=utcnow()),
        )
        assert verdict.decision is scene.expect, [h.rule_id for h in verdict.hits]

    @pytest.mark.parametrize("scene", SCENES, ids=[s.key for s in SCENES])
    def test_the_shadow_scene_is_the_only_one_that_would_differ(
        self, scene, baseline_bundle
    ) -> None:
        """`would_decision` is the shadow story. Exactly one scene tells it, and
        the others must not: a demo where every line says "would be BLOCK" is a
        demo of a policy nobody has tuned."""
        proposal = scene.build()
        verdict = evaluate(
            proposal,
            baseline_bundle,
            BudgetState(token_jti=proposal.principal.token_jti),
            EvalContext(now=utcnow()),
        )
        expected = scene.expect_would or scene.expect
        assert verdict.would_decision is expected

    def test_one_scene_carries_a_shadow_rule(self) -> None:
        assert sum(1 for scene in SCENES if scene.expect_would is not None) == 1

    def test_all_three_decisions_appear(self) -> None:
        assert {scene.expect for scene in SCENES} == {
            Decision.ALLOW,
            Decision.BLOCK,
            Decision.REQUIRE_APPROVAL,
        }

    def test_the_keys_are_unique_and_sort_in_order(self) -> None:
        keys = [scene.key for scene in SCENES]
        assert keys == sorted(keys) == list(dict.fromkeys(keys))


class TestTheCommand:
    @pytest.fixture
    def done(self, tmp_path: Path):
        state = tmp_path / "qed-demo"
        result = runner.invoke(app, ["demo", "--dir", str(state)])
        assert result.exit_code == 0, result.output
        return state, result.output

    def test_it_exits_zero_even_though_it_blocks(self, done) -> None:
        """`qed check` returns the verdict as its exit code; the demo returns
        whether the demo ran. Pasting it into a pipeline must not fail it."""
        _, output = done
        assert "BLOCK" in output

    def test_every_decision_class_is_shown(self, done) -> None:
        _, output = done
        for decision in ("ALLOW", "REQUIRE_APPROVAL", "BLOCK"):
            assert decision in output

    def test_the_chain_verifies(self, done) -> None:
        state, output = done
        assert "verified: contiguous, unmodified, signed" in output
        verify = runner.invoke(
            app, ["verify", "--dir", str(state), "--config", str(state / "qed.yaml")]
        )
        assert verify.exit_code == 0, verify.output
        assert "result    : OK" in verify.output

    def test_every_record_is_marked_dev(self, done) -> None:
        """In the record, not in the prose around it: an export of this chain
        says what it is wherever it ends up."""
        state, _ = done
        export = runner.invoke(
            app, ["export", "--dir", str(state), "--config", str(state / "qed.yaml")]
        )
        assert export.exit_code == 0, export.output
        records = [json.loads(line) for line in export.stdout.splitlines() if line.strip()]
        assert records
        assert all(record["dev"] is True for record in records)

    def test_the_proposals_it_wrote_can_be_explained(self, done) -> None:
        """The `Next` section points at a file; the file has to be a proposal
        the next command can read."""
        state, _ = done
        for scene in SCENES:
            path = state / "proposals" / f"{scene.key}.json"
            assert path.is_file()
        explained = runner.invoke(
            app, ["policy", "explain", str(state / "proposals" / f"{SCENES[1].key}.json")]
        )
        assert explained.exit_code == 0, explained.output
        assert json.loads(explained.stdout)["verdict"]["decision"] == SCENES[1].expect.value

    def test_it_cannot_be_committed_by_accident(self, done) -> None:
        state, _ = done
        assert (state / ".gitignore").read_text(encoding="utf-8").splitlines()[-1] == "*"

    def test_a_second_run_extends_the_chain(self, done) -> None:
        """Rather than failing on the key it already has, or writing a second
        genesis. A new key mid-chain is a discontinuity the writer refuses
        (ADR-0010), so `prepare` keeps the one that is there."""
        state, _ = done
        again = runner.invoke(app, ["demo", "--dir", str(state)])
        assert again.exit_code == 0, again.output
        assert "1 genesis" in again.output
        assert "10 proposal" in again.output

    def test_it_needs_no_network(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Asserted by removing the network, not by saying so in the help text.

        A demo that reaches out is a demo that fails on a locked-down laptop,
        which is exactly the machine it most needs to work on.
        """
        import socket

        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("the demo opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        result = runner.invoke(app, ["demo", "--dir", str(tmp_path / "offline")])
        assert result.exit_code == 0, result.output


def test_run_is_usable_without_the_cli(tmp_path: Path) -> None:
    """`run` is the demo; the CLI command is a renderer over it. Keeping it
    importable is what lets a test assert the decisions without parsing text."""
    steps, session = run(tmp_path / "state")
    try:
        assert [step.scene.key for step in steps] == [s.key for s in SCENES]
        assert all(step.outcome.verdict.decision is step.scene.expect for step in steps)
    finally:
        session.close()
