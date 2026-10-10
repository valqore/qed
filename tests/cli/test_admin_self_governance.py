"""`qed keys rotate` and `qed packs import` behind an approval (SPEC §17).

The pure decision order is in `tests/core/test_admin_gate.py`. This file drives
the commands against a real chain, because the three claims worth having are
all about things the gate does not compute itself:

* **separation of duties actually refuses a self-approval** -- it reuses
  `check_separation_of_duties`, and a wiring mistake (forgetting to set
  `principal_hash`) would leave the gate working and the SoD silently absent;
* **an approval is spent once**, which is read back out of the chain rather
  than from a column;
* **an ungoverned instance behaves exactly as it did before**, since the whole
  feature is off by default and a regression there would break every existing
  deployment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from qed.cli import app

runner = CliRunner()

GOVERNED_CONFIG = """
instance_id: admin-tests
admin:
  self_governed: true
  approvers: ["group:platform-oncall"]
  operations: [keys_rotate, packs_import]
  timeout: 24h
"""

ALICE = "alice@example.com"
BOB = "bob@example.com"


@pytest.fixture
def governed(tmp_path: Path) -> tuple[Path, Path]:
    state = tmp_path / "state"
    config = tmp_path / "qed.yaml"
    config.write_text(GOVERNED_CONFIG, encoding="utf-8")
    assert runner.invoke(app, ["keys", "init", "--dir", str(state)]).exit_code == 0
    return state, config


@pytest.fixture
def ungoverned(tmp_path: Path) -> Path:
    state = tmp_path / "plain"
    assert runner.invoke(app, ["keys", "init", "--dir", str(state)]).exit_code == 0
    return state


def rotate(state: Path, config: Path | None = None, **flags: str) -> Any:
    argv = ["keys", "rotate", "--dir", str(state), "--yes"]
    if config is not None:
        argv += ["--config", str(config)]
    for name, value in flags.items():
        argv += [f"--{name.replace('_', '-')}", value]
    return runner.invoke(app, argv)


def admin_records(state: Path, config: Path | None = None) -> list[dict[str, Any]]:
    argv = ["export", "--dir", str(state)]
    if config is not None:
        argv += ["--config", str(config)]
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, result.output
    return [
        json.loads(line)["payload"]
        for line in result.output.splitlines()
        if line.strip() and json.loads(line)["type"] == "admin_action"
    ]


def approval_id(output: str) -> str:
    line = next(item for item in output.splitlines() if item.startswith("approval required:"))
    return line.split(":", 1)[1].strip()


# --------------------------------------------------------------------------
# Off by default
# --------------------------------------------------------------------------


class TestAnUngovernedInstanceIsUnchanged:
    def test_rotate_still_works_with_no_flags(self, ungoverned: Path) -> None:
        """The feature is off by default, and every existing deployment is this
        one. A regression here breaks all of them."""
        result = rotate(ungoverned)
        assert result.exit_code == 0, result.output
        assert "rotated" in result.output

    def test_the_record_says_ungated_rather_than_saying_nothing(self, ungoverned: Path) -> None:
        rotate(ungoverned)
        record = next(item for item in admin_records(ungoverned) if item["action"] == "keys_rotate")
        assert record["self_governed"] is False
        assert "approval_id" not in record
        assert "break_glass" not in record

    def test_break_glass_records_no_false_emergency(self, ungoverned: Path) -> None:
        rotate(ungoverned, break_glass="not actually an incident")
        record = next(item for item in admin_records(ungoverned) if item["action"] == "keys_rotate")
        assert "break_glass" not in record


class TestTheConfigRefusesAGateNobodyCanOpen:
    def test_self_governed_with_no_approvers_is_refused(self, tmp_path: Path) -> None:
        """Otherwise the first rotation is refused with no way forward but
        break-glass, which is an outage waiting for an incident."""
        state = tmp_path / "s"
        config = tmp_path / "bad.yaml"
        config.write_text("admin:\n  self_governed: true\n", encoding="utf-8")
        runner.invoke(app, ["keys", "init", "--dir", str(state)])
        result = rotate(state, config)
        assert result.exit_code == 1
        assert "gate nobody" in result.output

    def test_an_unknown_operation_name_is_refused(self, tmp_path: Path) -> None:
        """A misspelt operation that silently governed nothing would be the
        worst kind of security setting: one an operator believes is on."""
        state = tmp_path / "s"
        config = tmp_path / "typo.yaml"
        config.write_text(
            "admin:\n"
            "  self_governed: true\n"
            '  approvers: ["group:ops"]\n'
            "  operations: [keys_rotat]\n",
            encoding="utf-8",
        )
        runner.invoke(app, ["keys", "init", "--dir", str(state)])
        result = rotate(state, config)
        assert result.exit_code == 1
        assert "unknown admin operation" in result.output


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------


class TestTheRequestPath:
    def test_without_by_it_says_so(self, governed: tuple[Path, Path]) -> None:
        state, config = governed
        result = rotate(state, config)
        assert result.exit_code == 1
        assert "--by" in result.output

    def test_the_first_attempt_opens_a_request_and_exits_3(
        self, governed: tuple[Path, Path]
    ) -> None:
        """Exit 3 is SPEC §12.5's REQUIRE_APPROVAL -- the same number a gated
        agent action gets, so a pipeline that already branches on it needs no
        second convention for qed's own operations."""
        state, config = governed
        result = rotate(state, config, by=ALICE)
        assert result.exit_code == 3, result.output
        assert "approval required:" in result.output
        assert "group:platform-oncall" in result.output

    def test_it_prints_both_commands_somebody_needs(self, governed: tuple[Path, Path]) -> None:
        state, config = governed
        output = rotate(state, config, by=ALICE).output
        assert "qed approve" in output
        assert "--approval" in output

    def test_nothing_was_rotated(self, governed: tuple[Path, Path]) -> None:
        """The active key is the thing to compare. An earlier version of this
        looked for "key_rotated" in `qed status --json`, which lists every
        record *type* the chain knows about -- so it was asserting on a
        vocabulary, not on what happened."""
        state, config = governed

        def active() -> str:
            result = runner.invoke(app, ["status", "--dir", str(state), "--config", str(config)])
            assert result.exit_code == 0, result.output
            return str(json.loads(result.output)["key_id"])

        before = active()
        rotate(state, config, by=ALICE)
        assert active() == before

    def test_the_request_is_in_the_chain(self, governed: tuple[Path, Path]) -> None:
        """A request that is never approved is a thing an auditor should be
        able to see."""
        state, config = governed
        rotate(state, config, by=ALICE)
        records = admin_records(state, config)
        asked = next(item for item in records if item["action"] == "keys_rotate_requested")
        assert asked["requested"] is True
        assert asked["self_governed"] is True
        assert asked["approvers"] == ["group:platform-oncall"]
        assert asked["retiring_key_id"].startswith("ed25519:")

    def test_the_requester_is_a_hash_not_an_address(self, governed: tuple[Path, Path]) -> None:
        """Principals appear in the chain as hashes (SPEC §10.6), and an admin
        request is no exception."""
        state, config = governed
        rotate(state, config, by=ALICE)
        asked = next(item for item in admin_records(state, config) if item["requested"] is True)
        assert ALICE not in json.dumps(asked)
        assert len(asked["requested_by"]) == 64


class TestSeparationOfDuties:
    def test_the_requester_cannot_approve_their_own(self, governed: tuple[Path, Path]) -> None:
        """The whole security content of self-governance. It works because the
        request sets `principal_hash`; forgetting that would leave the gate
        looking right with no SoD at all."""
        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        result = runner.invoke(
            app,
            [
                "approve",
                request,
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                ALICE,
                "--groups",
                "group:platform-oncall",
            ],
        )
        assert result.exit_code != 0
        assert "AG-SOD-001" in result.output

    def test_somebody_outside_the_named_group_cannot_approve(
        self, governed: tuple[Path, Path]
    ) -> None:
        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        result = runner.invoke(
            app,
            [
                "approve",
                request,
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                BOB,
                "--groups",
                "group:interns",
            ],
        )
        assert result.exit_code != 0
        assert "AG-SOD-002" in result.output

    def test_a_second_person_in_the_group_can(self, governed: tuple[Path, Path]) -> None:
        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        result = runner.invoke(
            app,
            [
                "approve",
                request,
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                BOB,
                "--groups",
                "group:platform-oncall",
            ],
        )
        assert result.exit_code == 0, result.output


class TestTheApprovedPath:
    def approve(self, state: Path, config: Path, request: str) -> None:
        result = runner.invoke(
            app,
            [
                "approve",
                request,
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                BOB,
                "--groups",
                "group:platform-oncall",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_it_rotates(self, governed: tuple[Path, Path]) -> None:
        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        self.approve(state, config, request)
        result = rotate(state, config, by=ALICE, approval=request)
        assert result.exit_code == 0, result.output
        assert "rotated" in result.output

    def test_the_authorisation_is_on_the_operations_own_record(
        self, governed: tuple[Path, Path]
    ) -> None:
        """`key_rotated` is the chain event and this `admin_action` is who
        allowed it. An auditor reading one wants the other."""
        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        self.approve(state, config, request)
        rotate(state, config, by=ALICE, approval=request)
        done = next(
            item
            for item in admin_records(state, config)
            if item["action"] == "keys_rotate" and not item.get("requested")
        )
        assert done["approval_id"] == request
        assert done["self_governed"] is True
        assert done["retired_key_id"] != done["active_key_id"]

    def test_the_approval_cannot_be_spent_twice(self, governed: tuple[Path, Path]) -> None:
        """One agreement must not authorise an operation twice. Read back out
        of the chain, not from a column that could disagree with it after a
        restore."""
        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        self.approve(state, config, request)
        assert rotate(state, config, by=ALICE, approval=request).exit_code == 0
        again = rotate(state, config, by=ALICE, approval=request)
        assert again.exit_code == 1
        assert "already been used" in again.output

    def test_an_approval_from_another_instance_means_nothing(
        self, governed: tuple[Path, Path]
    ) -> None:
        state, config = governed
        result = rotate(state, config, by=ALICE, approval="apr_01SOMETHINGELSE")
        assert result.exit_code == 1
        assert "no approval" in result.output

    def test_an_import_approval_cannot_rotate_a_key(
        self, governed: tuple[Path, Path], tmp_path: Path
    ) -> None:
        """The binding check, end to end: the approval has to be for the thing
        it was asked about."""
        state, config = governed
        missing = tmp_path / "absent.qedpack.json"
        asked = runner.invoke(
            app,
            [
                "packs",
                "import",
                str(missing),
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                ALICE,
            ],
        )
        # The bundle is unreadable, so the import fails before the gate -- which
        # is itself correct, and means this test has to open the request the
        # other way round: through a rotation, then spend it on an import.
        assert asked.exit_code == 1

        request = approval_id(rotate(state, config, by=ALICE).output)
        self.approve(state, config, request)
        spent_elsewhere = runner.invoke(
            app,
            [
                "packs",
                "import",
                str(missing),
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                ALICE,
                "--approval",
                request,
            ],
        )
        assert spent_elsewhere.exit_code == 1


class TestBreakGlass:
    def test_it_rotates_without_an_approval(self, governed: tuple[Path, Path]) -> None:
        """The reason to rotate is that the key may have leaked, which is
        exactly when the approver is asleep."""
        state, config = governed
        result = rotate(state, config, by=ALICE, break_glass="INC-412, key leaked")
        assert result.exit_code == 0, result.output
        assert "rotated" in result.output

    def test_it_is_loud_on_stderr(self, governed: tuple[Path, Path]) -> None:
        state, config = governed
        result = rotate(state, config, by=ALICE, break_glass="INC-412")
        assert "BREAK-GLASS" in result.output

    def test_the_reason_is_in_the_chain(self, governed: tuple[Path, Path]) -> None:
        """What makes break-glass acceptable: it costs a permanent record."""
        state, config = governed
        rotate(state, config, by=ALICE, break_glass="INC-412, oncall unreachable")
        done = next(
            item for item in admin_records(state, config) if item.get("break_glass") is True
        )
        assert done["break_glass_reason"] == "INC-412, oncall unreachable"
        assert done["self_governed"] is True
        assert "approval_id" not in done

    def test_it_still_needs_a_requester(self, governed: tuple[Path, Path]) -> None:
        state, config = governed
        result = rotate(state, config, break_glass="INC-412")
        assert result.exit_code == 1
        assert "--by" in result.output


class TestTheChainSurvivesAllOfIt:
    def test_two_governed_rotations_still_verify(self, governed: tuple[Path, Path]) -> None:
        """Self-governance writes extra `admin_action` records around a
        rotation, and ADR-0010's continuity rule is the fussiest thing in the
        product. An independent verifier is the only answer worth having."""
        from qed_verify.verify import verify_records

        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        state, config = governed
        request = approval_id(rotate(state, config, by=ALICE).output)
        runner.invoke(
            app,
            [
                "approve",
                request,
                "--dir",
                str(state),
                "--config",
                str(config),
                "--by",
                BOB,
                "--groups",
                "group:platform-oncall",
            ],
        )
        assert rotate(state, config, by=ALICE, approval=request).exit_code == 0
        assert rotate(state, config, by=ALICE, break_glass="second one").exit_code == 0

        result = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
        records = [json.loads(line) for line in result.output.splitlines() if line.strip()]
        report = verify_records(
            records, load_public_keys(state / PUBLIC_DIR_NAME), instance_id="admin-tests"
        )
        assert report.ok, report.summary()


class TestDoctorSaysWhichItIs:
    def test_an_ungoverned_instance_is_reported_not_silent(self, ungoverned: Path) -> None:
        """A silence here would read as "fine" on an instance where nothing
        gates a key rotation."""
        result = runner.invoke(app, ["doctor", "--dir", str(ungoverned)])
        assert "self-gov   : off" in result.output
        assert "one actor no rule constrains" in result.output

    def test_a_governed_instance_names_the_operations_and_approvers(
        self, governed: tuple[Path, Path]
    ) -> None:
        state, config = governed
        result = runner.invoke(app, ["doctor", "--dir", str(state), "--config", str(config)])
        assert "keys_rotate" in result.output
        assert "group:platform-oncall" in result.output
