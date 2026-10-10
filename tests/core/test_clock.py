"""The clock check (SPEC §17). Pure, plus one end-to-end warning.

SPEC §17: *"Clock: warn if NTP drift > 5 s; `seq` guarantees order regardless of
`ts`."*

Most of this file pins down what the check does **not** claim. It never queries
an NTP server -- the kernel is offline by design (invariant §1.7), and a
governance component that reached for the network to decide whether to trust
itself would be a new dependency in the decision path. What it measures is the
newest record's timestamp against the system clock, which catches the failure
that matters and is a weaker signal than NTP's own. The naming and the
`measured` field exist so that difference is visible in the output rather than
only in a docstring.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from qed.cli import app
from qed.core.clock import TOLERANCE_SECONDS, ClockReport, assess_clock

runner = CliRunner()
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


class TestTheTolerance:
    def test_it_is_the_number_the_spec_names(self) -> None:
        assert TOLERANCE_SECONDS == 5.0


class TestWhatCountsAsSuspect:
    def test_a_record_written_in_the_past_is_ordinary(self) -> None:
        report = assess_clock(NOW - timedelta(minutes=30), now=NOW)
        assert report.ahead_seconds < 0
        assert not report.suspect
        assert report.message() == ""

    def test_an_idle_instance_is_not_a_clock_problem(self) -> None:
        """A record written a week ago looks exactly like a stopped instance.
        Warning about it would make this noise on every laptop that was closed
        overnight."""
        assert not assess_clock(NOW - timedelta(days=7), now=NOW).suspect

    def test_a_record_slightly_ahead_is_within_tolerance(self) -> None:
        """Five seconds is loose enough that a virtual machine coming back from
        a snapshot does not cry wolf."""
        assert not assess_clock(NOW + timedelta(seconds=4), now=NOW).suspect

    def test_a_record_well_ahead_is_suspect(self) -> None:
        report = assess_clock(NOW + timedelta(seconds=90), now=NOW)
        assert report.suspect
        assert report.ahead_seconds == 90

    def test_exactly_at_the_tolerance_is_not_suspect(self) -> None:
        """A boundary worth pinning: `> tolerance`, not `>=`. Otherwise an
        instance whose clock is exactly five seconds out warns forever."""
        assert not assess_clock(NOW + timedelta(seconds=5), now=NOW).suspect

    def test_an_empty_chain_reports_zero_rather_than_nothing(self) -> None:
        """So a caller does not need two code paths for "the clock is fine"."""
        report = assess_clock(None, now=NOW)
        assert report.ahead_seconds == 0.0
        assert not report.suspect


class TestWhatItSays:
    def test_the_message_names_the_consequence_not_just_the_fact(self) -> None:
        message = assess_clock(NOW + timedelta(seconds=90), now=NOW).message()
        assert "90.0s in the future" in message
        assert "seq" in message, "it has to say the chain is unaffected"
        assert "auditor" in message, "and why an operator should care anyway"

    def test_the_report_says_what_it_measured(self) -> None:
        """Rather than letting a reader assume an NTP query happened. The field
        is in the JSON because that is where somebody integrating with
        `qed status` would look."""
        described = assess_clock(NOW, now=NOW).describe()
        assert described["measured"] == "newest record ts vs system clock; no NTP query"

    def test_nothing_in_the_report_claims_ntp(self) -> None:
        rendered = json.dumps(assess_clock(NOW + timedelta(seconds=90), now=NOW).describe())
        assert "no NTP query" in rendered
        assert "ntp_drift" not in rendered

    def test_a_healthy_clock_has_no_message_to_print(self) -> None:
        assert ClockReport(ahead_seconds=-1.0).message() == ""


class TestItReachesTheCommands:
    def test_status_carries_the_clock(self, tmp_path: Path) -> None:
        state = tmp_path / "state"
        assert runner.invoke(app, ["keys", "init", "--dir", str(state)]).exit_code == 0
        result = runner.invoke(app, ["status", "--dir", str(state)])
        assert result.exit_code == 0, result.output
        clock = json.loads(result.output)["clock"]
        assert clock["suspect"] is False
        assert clock["tolerance_seconds"] == TOLERANCE_SECONDS

    def test_doctor_warns_when_the_clock_has_gone_backwards(self, tmp_path: Path) -> None:
        """The end-to-end one, and the only way to know the warning is wired up
        rather than merely computed: rewrite the newest record's timestamp into
        the future, which is what a clock that then jumped back leaves behind.

        The record's hash does not cover the stored `ts` column being edited
        here -- this is a deliberately corrupt chain, made to exercise the
        reporting path, and `qed-verify` would refuse it. That is the point: a
        clock problem is visible *before* an auditor runs the verifier.
        """
        import sqlite3

        state = tmp_path / "state"
        assert runner.invoke(app, ["keys", "init", "--dir", str(state)]).exit_code == 0
        # `keys init` writes the key; the database and its genesis record come
        # from the first session. Without this there is no `evidence` table to
        # edit, which is how the first version of this test failed.
        assert runner.invoke(app, ["status", "--dir", str(state)]).exit_code == 0

        connection = sqlite3.connect(state / "qed.db")
        try:
            future = (datetime.now(UTC) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            connection.execute(
                "UPDATE evidence SET ts = ? WHERE seq = (SELECT MAX(seq) FROM evidence)",
                (future,),
            )
            connection.commit()
        finally:
            connection.close()

        result = runner.invoke(app, ["doctor", "--dir", str(state)])
        assert "clock      :" in result.output
        assert "in the future" in result.output
        assert "seq" in result.output

    def test_doctor_is_quiet_when_the_clock_is_fine(self, tmp_path: Path) -> None:
        state = tmp_path / "state"
        runner.invoke(app, ["keys", "init", "--dir", str(state)])
        result = runner.invoke(app, ["doctor", "--dir", str(state)])
        assert "clock      :" not in result.output
