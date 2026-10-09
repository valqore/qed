"""Retention and purge (SPEC §10.6, week 7's exit criterion).

Two things are being asserted, and the second is the one that makes the first
safe to do at all.

**Purge-then-verify passes.** A record whose payload is gone still verifies:
`hash` recomputes from `payload_hash`, not from the payload, so linkage and
signature are unaffected and `qed-verify` reports the record as purged rather
than broken.

**Some payloads may never be purged.** A `checkpoint`'s payload holds its
Merkle root, a `key_rotated`'s holds the new public key, `genesis` and
`policy_loaded` hold the chain's identity and the rules in force, and
`admin_action` holds the record of the purges themselves. Clearing any of them
destroys something that is not recoverable from anywhere else -- and a
checkpoint that can no longer be checked is worse than no checkpoint, because
it still looks like one. This is a correctness constraint, not a configuration
preference, so no config can override it.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qed.cli import app
from qed.config import RetentionConfig, load_config
from qed.core.evidence.retention import (
    NEVER_PURGE,
    PurgePlan,
    RetentionPolicy,
    parse_retention,
    plan_purge,
    purgeable_types,
)
from qed.core.schemas import Assurance, EvidenceType, utcnow
from qed.infra.storage.sqlite import SqliteStore
from qed.runtime import apply_retention, open_session, plan_retention

runner = CliRunner()

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)


def config_file(path: Path, **retention: object) -> Path:
    path.write_text(yaml.safe_dump({"retention": retention}), encoding="utf-8")
    return path


def session_with(directory: Path, config: Path):  # type: ignore[no-untyped-def]
    return open_session(directory=directory, config_path=config, strict_policy=False)


def write(session, type_: EvidenceType, *, age: timedelta, payload=None):  # type: ignore[no-untyped-def]
    """One record, backdated. `ts` is what retention measures against."""
    return session.writer.append(
        type_=type_,
        assurance=Assurance.kernel,
        payload=payload if payload is not None else {"note": type_.value},
        ts=utcnow() - age,
    )


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


class TestReadingARetentionAge:
    @pytest.mark.parametrize(
        ("text", "seconds"),
        [
            ("30s", 30),
            ("15m", 900),
            ("24h", 86400),
            ("90d", 7776000),
            ("2w", 1209600),
            ("7y", 7 * 365 * 86400),
        ],
    )
    def test_the_units_a_policy_is_written_in(self, text: str, seconds: int) -> None:
        age = parse_retention(text)
        assert age is not None
        assert age.total_seconds() == seconds

    def test_years_are_three_hundred_and_sixty_five_days(self) -> None:
        """Stated rather than implied. Nothing in a retention window turns on
        leap days, and a calendar-aware year would make the purge boundary
        depend on which year the pass happens to run in."""
        age = parse_retention("1y")
        assert age == timedelta(days=365)

    @pytest.mark.parametrize("text", ["forever", "never", "none", "", None])
    def test_forever_is_none(self, text: str | None) -> None:
        assert parse_retention(text) is None

    def test_zero_is_refused_rather_than_obeyed(self) -> None:
        """`payload: 0d` reads like "no retention", means "purge everything
        now", and is almost certainly a typo for `forever`."""
        with pytest.raises(ValueError, match="purge every payload immediately"):
            parse_retention("0d")

    def test_a_negative_age_is_refused(self) -> None:
        with pytest.raises(ValueError, match="purge every payload immediately"):
            parse_retention("-7d")

    def test_nonsense_says_what_is_allowed(self) -> None:
        with pytest.raises(ValueError, match=r"s/m/h/d/w/y"):
            parse_retention("7 years")

    def test_a_missing_unit_is_refused(self) -> None:
        with pytest.raises(ValueError, match=r"s/m/h/d/w/y"):
            parse_retention("90")


class TestTheConfig:
    def test_absent_retention_purges_nothing(self, tmp_path: Path) -> None:
        """A kernel that began deleting evidence because nobody had configured
        retention would be the wrong default by a long way."""
        policy = load_config(None).config.retention.policy()
        assert policy.active is False
        assert policy.payload is None

    def test_a_policy_is_read_from_the_file(self, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="90d")
        policy = load_config(config).config.retention.policy()
        assert policy.payload == timedelta(days=90)
        assert policy.active is True

    def test_per_type_overrides_the_default(self, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="7y", by_type={"proposal": "30d"})
        policy = load_config(config).config.retention.policy()
        assert policy.age_for(EvidenceType.proposal) == timedelta(days=30)
        assert policy.age_for(EvidenceType.verdict) == timedelta(days=7 * 365)

    def test_a_type_can_opt_out_of_a_default(self, tmp_path: Path) -> None:
        config = config_file(
            tmp_path / "qed.yaml", payload="30d", by_type={"execution_result": "forever"}
        )
        policy = load_config(config).config.retention.policy()
        assert policy.age_for(EvidenceType.execution_result) is None

    def test_an_unknown_type_is_refused_at_load(self, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="30d", by_type={"banana": "1d"})
        with pytest.raises(ValueError):
            load_config(config).config.retention.policy()


# --------------------------------------------------------------------------
# The exemptions
# --------------------------------------------------------------------------


class TestWhatIsNeverPurged:
    def test_the_structural_types(self) -> None:
        assert {
            EvidenceType.genesis,
            EvidenceType.checkpoint,
            EvidenceType.key_rotated,
            EvidenceType.policy_loaded,
            EvidenceType.admin_action,
        } == NEVER_PURGE

    @pytest.mark.parametrize("type_", sorted(NEVER_PURGE, key=lambda t: t.value))
    def test_no_config_can_override_one(self, type_: EvidenceType) -> None:
        """Not a preference. Each one holds something unrecoverable: a Merkle
        root, a public key, the chain's identity, the rules in force, or the
        record of what was erased."""
        policy = RetentionPolicy(payload=timedelta(seconds=1), by_type={type_: timedelta(0)})
        assert policy.age_for(type_) is None

    def test_a_checkpoint_in_the_middle_of_an_expired_stretch_survives(self) -> None:
        """Which is why the plan is a set of sequence numbers and not a
        `seq <= N` range. A range would be simpler and would take the
        checkpoint with it."""
        from tests.evidence.helpers import fake_records

        records = fake_records(
            [
                (0, EvidenceType.genesis),
                (1, EvidenceType.proposal),
                (2, EvidenceType.checkpoint),
                (3, EvidenceType.verdict),
            ],
            age=DAY,
        )
        plan = plan_purge(records, policy=RetentionPolicy(payload=HOUR), now=utcnow())
        assert plan.seqs == (1, 3)

    def test_the_overruled_ones_are_counted(self) -> None:
        """So the number means "this policy was overruled here" rather than
        "this chain contains checkpoints"."""
        from tests.evidence.helpers import fake_records

        plan = plan_purge(
            fake_records([(0, EvidenceType.checkpoint), (1, EvidenceType.verdict)], age=DAY),
            policy=RetentionPolicy(payload=HOUR),
            now=utcnow(),
        )
        assert plan.exempt == 1
        assert plan.seqs == (1,)

    def test_purgeable_types_excludes_them(self) -> None:
        assert set(purgeable_types()).isdisjoint({t.value for t in NEVER_PURGE})
        assert "proposal" in purgeable_types()


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


class TestThePlan:
    def test_an_inactive_policy_plans_nothing(self) -> None:
        from tests.evidence.helpers import fake_records

        plan = plan_purge(
            fake_records([(0, EvidenceType.verdict)], age=DAY),
            policy=RetentionPolicy(),
            now=utcnow(),
        )
        assert plan.empty
        assert plan == PurgePlan()

    def test_a_record_younger_than_the_age_is_kept(self) -> None:
        from tests.evidence.helpers import fake_records

        plan = plan_purge(
            fake_records([(0, EvidenceType.verdict)], age=timedelta(minutes=5)),
            policy=RetentionPolicy(payload=HOUR),
            now=utcnow(),
        )
        assert plan.empty

    def test_the_boundary_is_inclusive(self) -> None:
        """`>=`, so "keep for an hour" means a record exactly an hour old has
        had its hour."""
        from tests.evidence.helpers import fake_records

        plan = plan_purge(
            fake_records([(0, EvidenceType.verdict)], age=HOUR),
            policy=RetentionPolicy(payload=HOUR),
            now=utcnow(),
        )
        assert plan.seqs == (0,)

    def test_an_already_purged_record_is_not_reported_again(self) -> None:
        from tests.evidence.helpers import fake_records

        records = fake_records([(0, EvidenceType.verdict)], age=DAY, payload=None)
        plan = plan_purge(records, policy=RetentionPolicy(payload=HOUR), now=utcnow())
        assert plan.empty

    def test_it_is_the_same_plan_for_the_same_instant(self) -> None:
        """Pure, and takes `now` rather than reading a clock -- which is what
        makes a purge reviewable before it happens."""
        from tests.evidence.helpers import fake_records

        now = utcnow()
        records = list(
            fake_records([(0, EvidenceType.proposal), (1, EvidenceType.verdict)], age=DAY)
        )
        policy = RetentionPolicy(payload=HOUR)
        assert plan_purge(records, policy=policy, now=now) == plan_purge(
            records, policy=policy, now=now
        )

    def test_the_summary_says_what_stopped_being_readable(self) -> None:
        from tests.evidence.helpers import fake_records

        plan = plan_purge(
            fake_records(
                [(1, EvidenceType.proposal), (2, EvidenceType.verdict), (3, EvidenceType.verdict)],
                age=DAY,
            ),
            policy=RetentionPolicy(payload=HOUR),
            now=utcnow(),
        )
        summary = plan.summary()
        assert summary["records"] == 3
        assert summary["by_type"] == {"proposal": 1, "verdict": 2}
        assert summary["from_seq"] == 1
        assert summary["to_seq"] == 3
        assert summary["oldest_ts"] is not None


# --------------------------------------------------------------------------
# Applying it, against a real chain
# --------------------------------------------------------------------------


class TestApplyingIt:
    def test_the_chain_still_verifies_afterwards(self, qed_dir: Path, tmp_path: Path) -> None:
        """Week 7's exit criterion. `hash` recomputes from `payload_hash`, so a
        purged record verifies its linkage and its signature; what is lost is
        only the ability to read what the action was."""
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            write(session, EvidenceType.proposal, age=DAY)
            write(session, EvidenceType.verdict, age=DAY)
            write(session, EvidenceType.verdict, age=timedelta(minutes=1))
            result = apply_retention(session)
            assert result.purged == 2
            records = load_jsonl(to_jsonl(session.store.iter_evidence()))
        finally:
            session.close()

        report = verify_records(records, load_public_keys(qed_dir / PUBLIC_DIR_NAME))
        assert report.ok, report.summary()
        assert report.purged == 2

    def test_the_hashes_are_not_touched(self, qed_dir: Path, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            appended = write(session, EvidenceType.proposal, age=DAY)
            assert appended.record is not None
            before = appended.record
            apply_retention(session)
            after = session.store.evidence_at(before.seq)
        finally:
            session.close()

        assert after is not None
        assert after.payload is None
        assert after.payload_hash == before.payload_hash
        assert after.hash == before.hash
        assert after.sig == before.sig
        assert after.prev_hash == before.prev_hash

    def test_it_records_that_it_happened(self, qed_dir: Path, tmp_path: Path) -> None:
        """A NULL payload with nothing saying why is indistinguishable from
        data loss, and "we delete after seven years" is a claim an auditor
        wants evidence of rather than a sentence in a policy document."""
        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            write(session, EvidenceType.proposal, age=DAY)
            result = apply_retention(session)
            assert result.record is not None
            payload = result.record.payload or {}
        finally:
            session.close()

        assert result.record.type is EvidenceType.admin_action
        assert payload["action"] == "retention_purge"
        assert payload["purged"] == 1
        assert payload["by_type"] == {"proposal": 1}
        assert payload["policy"]["payload"] == "1h"
        assert "genesis" in payload["policy"]["never_purged"]

    def test_the_record_of_the_purge_is_itself_never_purged(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """Erasing the record of what was erased is the one thing retention
        must not do."""
        config = config_file(tmp_path / "qed.yaml", payload="1s")
        session = session_with(qed_dir, config)
        try:
            write(session, EvidenceType.proposal, age=DAY)
            first = apply_retention(session)
            assert first.record is not None
            # A second pass, with everything now old enough.
            second = apply_retention(session, now=utcnow() + DAY)
            assert second.purged == 0, "it purged the audit trail"
            still_there = session.store.evidence_at(first.record.seq)
            assert still_there is not None
            assert still_there.payload is not None
        finally:
            session.close()

    def test_a_second_pass_does_nothing(self, qed_dir: Path, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            write(session, EvidenceType.proposal, age=DAY)
            assert apply_retention(session).purged == 1
            again = apply_retention(session)
            assert again.purged == 0
            assert again.record is None, "an empty pass wrote a record"
        finally:
            session.close()

    def test_nothing_happens_without_a_policy(self, qed_dir: Path, tmp_path: Path) -> None:
        config = tmp_path / "qed.yaml"
        config.write_text(yaml.safe_dump({"instance_id": "qed-local"}), encoding="utf-8")
        session = session_with(qed_dir, config)
        try:
            write(session, EvidenceType.proposal, age=timedelta(days=4000))
            result = apply_retention(session)
        finally:
            session.close()
        assert result.purged == 0
        assert result.record is None

    def test_planning_changes_nothing(self, qed_dir: Path, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            appended = write(session, EvidenceType.proposal, age=DAY)
            assert appended.record is not None
            plan = plan_retention(session)
            assert plan.seqs == (appended.record.seq,)
            after = session.store.evidence_at(appended.record.seq)
            assert after is not None
            assert after.payload is not None, "the preview purged"
        finally:
            session.close()


class TestTheStore:
    def test_an_explicit_set_is_purged(self, qed_dir: Path) -> None:
        store = SqliteStore(qed_dir / "qed.db")
        try:
            assert store.purge_payload_seqs([]) == 0
        finally:
            store.close()

    def test_a_long_list_is_batched(self, qed_dir: Path, tmp_path: Path) -> None:
        """A chain with years of history produces a list longer than SQLite's
        999-parameter limit, and a single statement that size is refused rather
        than slow."""
        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            for _ in range(1200):
                write(session, EvidenceType.proposal, age=DAY)
            result = apply_retention(session)
        finally:
            session.close()
        assert result.purged == 1200


# --------------------------------------------------------------------------
# Visibility
# --------------------------------------------------------------------------


class TestWhatAnOperatorSees:
    def test_doctor_previews_the_purge(self, qed_dir: Path, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="1h")
        session = session_with(qed_dir, config)
        try:
            write(session, EvidenceType.proposal, age=DAY)
        finally:
            session.close()

        result = runner.invoke(
            app, ["doctor", "--dir", str(qed_dir), "--config", str(config), "--json"]
        )
        assert result.exit_code == 0, result.output
        report = json.loads(result.output)
        assert report["retention"]["payload"] == "1h"
        assert report["retention"]["would_purge_now"]["records"] == 1

    def test_doctor_says_forever_when_nothing_is_configured(self, qed_dir: Path) -> None:
        result = runner.invoke(app, ["doctor", "--dir", str(qed_dir)])
        assert "payloads forever" in result.output

    def test_status_reports_the_policy(self, qed_dir: Path, tmp_path: Path) -> None:
        config = config_file(tmp_path / "qed.yaml", payload="7y", by_type={"proposal": "30d"})
        result = runner.invoke(app, ["status", "--dir", str(qed_dir), "--config", str(config)])
        assert result.exit_code == 0, result.output
        status = json.loads(result.output)
        assert status["retention"]["payload"] == "7y"
        assert status["retention"]["by_type"] == {"proposal": "30d"}

    def test_an_interrupted_rotation_is_reported(self, qed_dir: Path) -> None:
        from qed.infra.keys.rotation import stage_rotation

        stage_rotation(qed_dir)
        result = runner.invoke(app, ["doctor", "--dir", str(qed_dir)])
        assert "INTERRUPTED" in result.output

    def test_the_duration_text_round_trips(self) -> None:
        """A reported retention age that is not the configured one is a small
        lie in an audit document."""
        for text in ("30d", "24h", "15m", "7y", "2w"):
            described = RetentionConfig(payload=text).policy().describe()
            assert described["payload"] == text, "the reported age is not the configured one"
