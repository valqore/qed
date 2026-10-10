"""Checkpoints, publication and the maintenance pass (SPEC §10.4, §10.6).

`test_publishers.py` covers the targets. This covers the three things around
them, which are where the ordering constraints live:

* **the cadence** -- 1,000 records or 3,600 seconds, whichever comes first,
  and something that actually asks;
* **the receipt carry-forward** -- a receipt describes a record that has
  already been hashed and signed, so it cannot go in that record. Each
  checkpoint carries the previous one's receipts, and the first carries none;
* **the order of a maintenance pass** -- checkpoint, publish, purge. Purging
  before the root is anchored would leave a window in which the payloads were
  gone and nothing outside the instance had attested to the hashes they
  produced.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import yaml
from typer.testing import CliRunner

from qed.cli import app
from qed.core.evidence.merkle import merkle_root
from qed.core.schemas import Assurance, EvidenceType, utcnow
from qed.infra.chain_writer import CHECKPOINT_EVERY_RECORDS, CHECKPOINT_EVERY_SECONDS
from qed.infra.maintenance import maintain, publishers_for
from qed.runtime import open_session

runner = CliRunner()


def config_file(path: Path, **evidence: object) -> Path:
    path.write_text(
        yaml.safe_dump({"instance_id": "qed-local", "evidence": evidence}), encoding="utf-8"
    )
    return path


def anchored(path: Path, anchors: Path, **extra: object) -> Path:
    document: dict[str, object] = {
        "instance_id": "qed-local",
        "evidence": {"checkpoint": {"publishers": [{"type": "file", "path": str(anchors)}]}},
        **extra,
    }
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def fill(session, count: int, *, age: timedelta = timedelta(0)) -> None:  # type: ignore[no-untyped-def]
    for index in range(count):
        session.writer.append(
            type_=EvidenceType.proposal,
            assurance=Assurance.kernel,
            payload={"n": index},
            ts=utcnow() - age,
        )


# --------------------------------------------------------------------------
# The cadence
# --------------------------------------------------------------------------


class TestTheConfiguredThresholdsAreTheOnesUsed:
    """`evidence.checkpoint.every_records` was parsed and never read.

    `ChainWriter.checkpoint` compared against the module constants directly,
    so the config keys were validated, reported by `qed doctor`, and ignored.
    The defaults match SPEC §10.4, so an operator who left them alone saw
    correct behaviour and an operator who tuned them saw none -- the quiet half
    of the same bug that had `observability` in `UNIMPLEMENTED_SECTIONS` while
    the code read it.

    Found by running it: an end-to-end script set `every_records: 1`, wrote
    nine records, and `qed checkpoint` answered "nothing to checkpoint yet".
    """

    def test_a_small_every_records_makes_a_short_chain_due(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            session.writer.every_records = 2
            fill(session, 3)
            assert session.writer.checkpoint() is not None
        finally:
            session.close()

    def test_a_large_every_records_keeps_it_undue(self, qed_dir: Path) -> None:
        """The other direction, so the test would fail if the attribute were
        read and then ignored."""
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            session.writer.every_records = 10_000
            fill(session, 50)
            assert session.writer.checkpoint() is None
        finally:
            session.close()

    def test_a_small_every_seconds_makes_a_young_chain_due(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            session.writer.every_seconds = 1
            fill(session, 2)
            later = utcnow() + timedelta(seconds=5)
            assert session.writer.checkpoint(now=later) is not None
        finally:
            session.close()

    def test_the_session_fills_them_from_the_config(self, qed_dir: Path, tmp_path: Path) -> None:
        """The wiring, not just the attribute. A writer that reads
        `self.every_records` and a session that never sets it is the same bug
        with an extra step."""
        config = tmp_path / "qed.yaml"
        config.write_text(
            "evidence:"
            + chr(10)
            + "  checkpoint:"
            + chr(10)
            + "    every_records: 7"
            + chr(10)
            + "    every_seconds: 11"
            + chr(10),
            encoding="utf-8",
        )
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            assert session.writer.every_records == 7
            assert session.writer.every_seconds == 11
        finally:
            session.close()

    def test_the_defaults_are_the_ones_the_spec_names(self, qed_dir: Path) -> None:
        """And a session with no config gets them, so the constants are still
        the defaults rather than dead code."""
        assert CHECKPOINT_EVERY_RECORDS == 1000
        assert CHECKPOINT_EVERY_SECONDS == 3600
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            assert session.writer.every_records == CHECKPOINT_EVERY_RECORDS
            assert session.writer.every_seconds == CHECKPOINT_EVERY_SECONDS
        finally:
            session.close()


class TestWhenACheckpointIsDue:
    def test_a_young_short_chain_is_not_due(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 3)
            assert session.writer.checkpoint() is None
        finally:
            session.close()

    def test_an_old_chain_is_due_on_time_alone(self, qed_dir: Path) -> None:
        """ "Whichever comes first". Three records an hour old is a chain that
        should be anchored, and waiting for the thousandth would mean a quiet
        instance never anchors at all.

        `now` is passed rather than the records being backdated, because the
        age is measured from the **oldest uncovered record** -- and that is
        `genesis`, which `open_session` writes with its own clock. Backdating
        only the later records leaves the range starting at a fresh genesis and
        the threshold correctly unmet.
        """
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 3)
            assert session.writer.checkpoint() is None, "it was due immediately"
            later = utcnow() + timedelta(seconds=CHECKPOINT_EVERY_SECONDS + 60)
            assert session.writer.checkpoint(now=later) is not None
        finally:
            session.close()

    def test_the_age_is_measured_from_the_oldest_uncovered_record(self, qed_dir: Path) -> None:
        """Not from the newest, and not from the last checkpoint's timestamp.
        A record that has been sitting unanchored for an hour is the thing the
        threshold is about, whatever arrived since."""
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 2)
            first = session.writer.checkpoint(force=True)
            assert first is not None
            # One fresh record, and an hour on the clock. The range starts at
            # the previous checkpoint record, which is now an hour old.
            fill(session, 1)
            later = utcnow() + timedelta(seconds=CHECKPOINT_EVERY_SECONDS + 60)
            assert session.writer.checkpoint(now=later) is not None
        finally:
            session.close()

    def test_force_overrides_both(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 1)
            assert session.writer.checkpoint(force=True) is not None
        finally:
            session.close()

    def test_a_forced_second_checkpoint_covers_the_first(self, qed_dir: Path) -> None:
        """Surprising enough to pin down. A checkpoint is a record, so the
        *next* range starts at it -- which means a second forced checkpoint has
        exactly one record to cover: the first checkpoint.

        That is the design and not an accident: it is what makes "every record
        in the chain, checkpoints included, is covered by exactly one Merkle
        root" true. Without `--force` the thresholds stop it happening, because
        one young record is neither a thousand nor an hour.
        """
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 2)
            first = session.writer.checkpoint(force=True)
            assert first is not None
            second = session.writer.checkpoint(force=True)
            assert second is not None
            payload = second.payload or {}
            assert payload["from_seq"] == first.seq
            assert payload["to_seq"] == first.seq
            assert payload["records"] == 1
            # And a third has nothing new to say either way, so the thresholds
            # are what keep this from being a loop in practice.
            assert session.writer.checkpoint() is None
        finally:
            session.close()


class TestWhatACheckpointCovers:
    def test_the_ranges_are_contiguous_and_do_not_overlap(self, qed_dir: Path) -> None:
        """Every record in the chain, checkpoints included, is covered by
        exactly one Merkle root."""
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 2)
            first = session.writer.checkpoint(force=True)
            fill(session, 2)
            second = session.writer.checkpoint(force=True)
            assert first is not None and second is not None
            one = first.payload or {}
            two = second.payload or {}
        finally:
            session.close()

        assert one["from_seq"] == 0
        assert two["from_seq"] == one["to_seq"] + 1

    def test_a_checkpoint_does_not_cover_itself(self, qed_dir: Path) -> None:
        """Its own hash depends on the root it carries, so it cannot be a leaf
        of that root."""
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 2)
            record = session.writer.checkpoint(force=True)
            assert record is not None
            payload = record.payload or {}
        finally:
            session.close()
        assert payload["to_seq"] < record.seq

    def test_the_root_is_over_the_hashes_in_the_range(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 4)
            record = session.writer.checkpoint(force=True)
            assert record is not None
            payload = record.payload or {}
            covered = list(
                session.store.iter_evidence(int(payload["from_seq"]), int(payload["to_seq"]))
            )
        finally:
            session.close()
        assert payload["merkle_root"] == merkle_root([r.hash for r in covered])
        assert payload["records"] == len(covered)


# --------------------------------------------------------------------------
# Receipts
# --------------------------------------------------------------------------


class TestTheReceiptsGoInTheNextCheckpoint:
    def test_the_first_checkpoint_carries_none(self, qed_dir: Path, tmp_path: Path) -> None:
        config = anchored(tmp_path / "qed.yaml", tmp_path / "anchors")
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
            result = maintain(session, force_checkpoint=True)
            assert result.checkpoint is not None
            assert (result.checkpoint.payload or {})["previous_receipts"] == []
        finally:
            session.close()

    def test_the_second_carries_the_first(self, qed_dir: Path, tmp_path: Path) -> None:
        """A receipt describes a record that has already been hashed and
        signed, so writing it back into that record would change the hash the
        receipt is about. One checkpoint later is the only place it fits."""
        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors)
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
            first = maintain(session, force_checkpoint=True)
            fill(session, 2)
            second = maintain(session, force_checkpoint=True)
            assert second.checkpoint is not None
            carried = (second.checkpoint.payload or {})["previous_receipts"]
        finally:
            session.close()

        assert isinstance(carried, list)
        assert len(carried) == 1
        assert carried[0]["publisher"] == "file"
        assert carried[0]["ok"] is True
        assert carried[0]["target"] == first.receipts[0].target
        assert carried[0]["proof"]["sha256"]

    def test_a_failure_is_carried_forward_too(self, qed_dir: Path, tmp_path: Path) -> None:
        """A failed publication must not disappear. It is the difference
        between "no anchor was asked for" and "the anchor could not be
        written", and only the second is a problem."""
        blocked = tmp_path / "blocked"
        blocked.write_text("not a directory", encoding="utf-8")
        config = anchored(tmp_path / "qed.yaml", blocked)
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
            first = maintain(session, force_checkpoint=True)
            assert first.receipts and not first.receipts[0].ok
            fill(session, 2)
            second = maintain(session, force_checkpoint=True)
            assert second.checkpoint is not None
            carried = (second.checkpoint.payload or {})["previous_receipts"]
        finally:
            session.close()
        assert carried[0]["ok"] is False
        assert carried[0]["error"]

    def test_the_receipts_are_in_the_table_in_the_meantime(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        config = anchored(tmp_path / "qed.yaml", tmp_path / "anchors")
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
            maintain(session, force_checkpoint=True)
            row = session.store.last_checkpoint()
        finally:
            session.close()
        assert row is not None
        assert len(row.published_to) == 1
        assert row.published_to[0]["ok"] is True

    def test_nothing_is_published_when_nothing_is_configured(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            fill(session, 2)
            result = maintain(session, force_checkpoint=True)
            assert result.checkpoint is not None
            assert result.receipts == []
            assert result.errors == []
        finally:
            session.close()


class TestThePublishedAnchorMatchesTheChain:
    def test_byte_for_byte(self, qed_dir: Path, tmp_path: Path) -> None:
        """The comparison an auditor makes. If these two ever differ, one of
        them is not the record that was signed."""
        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors)
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 3)
            result = maintain(session, force_checkpoint=True)
            assert result.checkpoint is not None
            in_chain = session.store.evidence_at(result.checkpoint.seq)
        finally:
            session.close()

        assert in_chain is not None
        published = json.loads(Path(result.receipts[0].target).read_text(encoding="utf-8"))
        assert published == json.loads(in_chain.model_dump_json())


# --------------------------------------------------------------------------
# The pass
# --------------------------------------------------------------------------


class TestTheMaintenancePass:
    def test_it_checkpoints_publishes_and_purges(self, qed_dir: Path, tmp_path: Path) -> None:
        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors, retention={"payload": "1h"})
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 3, age=timedelta(days=1))
            result = maintain(session, force_checkpoint=True)
        finally:
            session.close()

        assert result.checkpoint is not None
        assert result.receipts[0].ok
        assert result.purged >= 3
        assert result.errors == []

    def test_the_purge_happens_after_the_root_is_anchored(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """The ordering constraint. Purging first would leave a window in
        which the payloads were gone and nothing outside the instance had
        attested to the hashes they produced."""
        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors, retention={"payload": "1h"})
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 3, age=timedelta(days=1))
            result = maintain(session, force_checkpoint=True)
            assert result.checkpoint is not None
            payload = result.checkpoint.payload or {}
            # Every record the checkpoint covered is one the purge then
            # cleared, so the root exists for all of them.
            covered = range(int(payload["from_seq"]), int(payload["to_seq"]) + 1)
            purgeable = [
                session.store.evidence_at(seq)
                for seq in covered
                if (record := session.store.evidence_at(seq)) is not None
                and record.type is EvidenceType.proposal
            ]
        finally:
            session.close()
        assert purgeable
        assert all(record is not None and record.payload is None for record in purgeable)

    def test_the_chain_still_verifies(self, qed_dir: Path, tmp_path: Path) -> None:
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors, retention={"payload": "1h"})
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 4, age=timedelta(days=1))
            maintain(session, force_checkpoint=True)
            fill(session, 2)
            maintain(session, force_checkpoint=True)
            records = load_jsonl(to_jsonl(session.store.iter_evidence()))
        finally:
            session.close()

        report = verify_records(records, load_public_keys(qed_dir / PUBLIC_DIR_NAME))
        assert report.ok, report.summary()
        assert report.checkpoints == 2
        assert report.purged >= 4

    def test_a_pass_with_nothing_due_does_nothing(self, qed_dir: Path) -> None:
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            result = maintain(session)
            assert not result.acted
            assert result.errors == []
        finally:
            session.close()

    def test_a_broken_publisher_config_is_reported_not_raised(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """A misconfigured publisher must not take the chain down: the
        instance can still decide, record and checkpoint with no anchor, and
        that is strictly better than refusing to start."""
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump({"evidence": {"checkpoint": {"publishers": [{"type": "nonsense"}]}}}),
            encoding="utf-8",
        )
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
            result = maintain(session, force_checkpoint=True)
        finally:
            session.close()

        assert result.checkpoint is not None, "the chain stopped because of a config error"
        assert any("unknown checkpoint publisher" in problem for problem in result.errors)

    def test_publishers_for_reports_a_bad_config(self, qed_dir: Path, tmp_path: Path) -> None:
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump({"evidence": {"checkpoint": {"publishers": [{"type": "x"}]}}}),
            encoding="utf-8",
        )
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            built, problems = publishers_for(session.config)
        finally:
            session.close()
        assert built == []
        assert problems


# --------------------------------------------------------------------------
# What an operator sees
# --------------------------------------------------------------------------


class TestTheCommand:
    def test_checkpoint_publishes_and_reports(self, qed_dir: Path, tmp_path: Path) -> None:
        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors)
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
        finally:
            session.close()

        result = runner.invoke(
            app,
            ["checkpoint", "--dir", str(qed_dir), "--config", str(config), "--force"],
        )
        assert result.exit_code == 0, result.output
        assert "published: file ->" in result.output
        assert "[ok]" in result.output
        assert len(list(anchors.glob("*.json"))) == 1

    def test_checkpoint_says_when_there_is_nothing_to_do(self, qed_dir: Path) -> None:
        result = runner.invoke(app, ["checkpoint", "--dir", str(qed_dir)])
        assert "nothing to checkpoint yet" in result.output

    def test_doctor_warns_when_nothing_is_anchored(self, qed_dir: Path) -> None:
        """A Merkle root that lives only in the chain it summarises attests to
        nothing an operator who could rewrite the chain could not recompute."""
        result = runner.invoke(app, ["doctor", "--dir", str(qed_dir)])
        assert "anchors    : none" in result.output

    def test_doctor_lists_the_publishers(self, qed_dir: Path, tmp_path: Path) -> None:
        config = anchored(tmp_path / "qed.yaml", tmp_path / "anchors")
        result = runner.invoke(
            app, ["doctor", "--dir", str(qed_dir), "--config", str(config), "--json"]
        )
        report = json.loads(result.output)
        assert report["checkpoints"]["publishers"] == [f"file: {tmp_path / 'anchors'}"]

    def test_doctor_reports_the_last_publication(self, qed_dir: Path, tmp_path: Path) -> None:
        anchors = tmp_path / "anchors"
        config = anchored(tmp_path / "qed.yaml", anchors)
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            fill(session, 2)
            maintain(session, force_checkpoint=True)
        finally:
            session.close()

        result = runner.invoke(
            app, ["doctor", "--dir", str(qed_dir), "--config", str(config), "--json"]
        )
        last = json.loads(result.output)["checkpoints"]["last"]
        assert last["published_to"][0] == {
            "publisher": "file",
            "ok": True,
            "target": last["published_to"][0]["target"],
        }

    def test_doctor_reports_a_broken_publisher_config(self, qed_dir: Path, tmp_path: Path) -> None:
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump({"evidence": {"checkpoint": {"publishers": [{"type": "x"}]}}}),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["doctor", "--dir", str(qed_dir), "--config", str(config)])
        assert "unknown checkpoint publisher" in result.output
