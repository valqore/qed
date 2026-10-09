"""Key rotation (SPEC §10.5, ADR-0010, week 7).

The property is one sentence: **a chain that spans a rotation still verifies,
from genesis, with both public keys and nothing else.** Everything here is
either that or one of the ways it stops being true.

The shape that makes it work is the `key_rotated` record being signed by the
*retiring* key. An auditor holding only the old public key can verify the
record that introduces the new one, and so on forwards; an auditor holding only
the new one cannot verify anything before it, which is why `qed keys
export-public` prints every key rather than the active one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qed.cli import app
from qed.core.schemas import Assurance, EvidenceType, utcnow
from qed.infra.chain_writer import ChainWriter, KeyDiscontinuity
from qed.infra.keys.file import (
    PRIVATE_KEY_NAME,
    PUBLIC_DIR_NAME,
    FileSigner,
    MissingSigningKey,
    load_public_keys,
    load_signer,
    public_key_filename,
)
from qed.infra.keys.rotation import (
    PENDING_SUFFIX,
    finish_rotation,
    pending_rotation,
    stage_rotation,
)
from qed.infra.storage.sqlite import SqliteStore
from qed.runtime import Rotation, open_session, rotate_signing_key

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "proposals" / "github-read.json"


def decide(directory: Path, proposal_id: str) -> None:
    """One real decision, so the chain has something either side of a rotation."""
    import tempfile

    from tests.conftest import BASE_PROPOSAL, deep_merge

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(deep_merge(BASE_PROPOSAL, {"id": proposal_id}), handle)
        path = handle.name
    result = runner.invoke(app, ["check", path, "--dir", str(directory)])
    assert result.exit_code in {0, 2, 3}, result.output


def chain(directory: Path) -> list[tuple[int, str, str]]:
    store = SqliteStore(directory / "qed.db")
    try:
        return [(r.seq, r.type.value, r.key_id) for r in store.iter_evidence()]
    finally:
        store.close()


def rotate(directory: Path) -> Rotation:
    session = open_session(directory=directory, strict_policy=False)
    try:
        return rotate_signing_key(session)
    finally:
        session.close()


# --------------------------------------------------------------------------
# The property
# --------------------------------------------------------------------------


class TestAChainThatSpansARotationVerifies:
    def test_from_genesis_with_both_keys(self, qed_dir: Path) -> None:
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl

        decide(qed_dir, "01JBROTATE0000000000000001")
        first = load_signer(qed_dir).key_id
        rotation = rotate(qed_dir)
        decide(qed_dir, "01JBROTATE0000000000000002")

        store = SqliteStore(qed_dir / "qed.db")
        try:
            records = load_jsonl(to_jsonl(store.iter_evidence()))
        finally:
            store.close()

        report = verify_records(records, load_public_keys(qed_dir / PUBLIC_DIR_NAME))
        assert report.ok, report.summary()
        assert report.keys_used == sorted({first, rotation.new_key_id})

    def test_the_rotation_record_is_signed_by_the_retiring_key(self, qed_dir: Path) -> None:
        """The whole mechanism. Signed by the *new* key, the record introducing
        that key would be unverifiable to anyone who did not already have it --
        which is everyone, before the rotation."""
        decide(qed_dir, "01JBROTATE0000000000000003")
        before = load_signer(qed_dir).key_id
        rotation = rotate(qed_dir)

        assert rotation.record.type is EvidenceType.key_rotated
        assert rotation.record.key_id == before
        assert rotation.record.key_id != rotation.new_key_id

    def test_the_payload_names_both_keys_and_carries_the_new_public_key(
        self, qed_dir: Path
    ) -> None:
        """`new_public_pem` travels in the chain so an auditor given only the
        old key can read the new one out of the record, and check that the key
        they were later handed is the one the rotation introduced."""
        rotation = rotate(qed_dir)
        payload = rotation.record.payload or {}
        assert payload["old_key_id"] == rotation.old_key_id
        assert payload["new_key_id"] == rotation.new_key_id
        assert "BEGIN PUBLIC KEY" in str(payload["new_public_pem"])

        active = load_signer(qed_dir)
        assert payload["new_public_pem"] == active.public_pem

    def test_records_after_the_rotation_use_the_new_key(self, qed_dir: Path) -> None:
        rotation = rotate(qed_dir)
        decide(qed_dir, "01JBROTATE0000000000000004")
        after = [key for _, _, key in chain(qed_dir)][rotation.record.seq + 1 :]
        assert after, "nothing was appended after the rotation"
        assert set(after) == {rotation.new_key_id}

    def test_a_chain_across_two_rotations_verifies(self, qed_dir: Path) -> None:
        """Three keys, two rotation records, one chain."""
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl

        decide(qed_dir, "01JBROTATE0000000000000005")
        first = rotate(qed_dir)
        decide(qed_dir, "01JBROTATE0000000000000006")
        second = rotate(qed_dir)
        decide(qed_dir, "01JBROTATE0000000000000007")

        store = SqliteStore(qed_dir / "qed.db")
        try:
            report = verify_records(
                load_jsonl(to_jsonl(store.iter_evidence())),
                load_public_keys(qed_dir / PUBLIC_DIR_NAME),
            )
        finally:
            store.close()
        assert report.ok, report.summary()
        assert len(report.keys_used) == 3
        assert first.new_key_id == second.old_key_id


# --------------------------------------------------------------------------
# What stops it being true
# --------------------------------------------------------------------------


class TestWithoutTheRetiredKey:
    def test_the_records_before_the_rotation_cannot_be_verified(self, qed_dir: Path) -> None:
        """The reason `qed keys export-public` prints every key. Somebody
        sending one PEM because that is what the command used to print is how
        an auditor ends up unable to check the half of the chain that
        matters."""
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl

        decide(qed_dir, "01JBROTATE0000000000000008")
        rotation = rotate(qed_dir)

        store = SqliteStore(qed_dir / "qed.db")
        try:
            records = load_jsonl(to_jsonl(store.iter_evidence()))
        finally:
            store.close()

        only_active = {
            rotation.new_key_id: load_public_keys(qed_dir / PUBLIC_DIR_NAME)[rotation.new_key_id]
        }
        report = verify_records(records, only_active)
        assert not report.ok
        assert any(problem.code == "unknown_key" for problem in report.problems)


class TestASilentKeyChangeIsRefused:
    """A key swapped in with no `key_rotated` record is indistinguishable from
    a forged chain, and it is silent because nothing in the record format
    requires the writer to notice. One read of the last record closes it."""

    def test_the_writer_refuses_to_continue_the_chain(self, qed_dir: Path) -> None:
        decide(qed_dir, "01JBROTATE0000000000000009")
        stranger = FileSigner.generate()
        stranger.save_private(qed_dir / PRIVATE_KEY_NAME, overwrite=True)
        stranger.save_public(qed_dir / PUBLIC_DIR_NAME)

        with pytest.raises(KeyDiscontinuity, match="last signed by"):
            open_session(directory=qed_dir, strict_policy=False)

    def test_the_message_names_both_keys_and_the_sequence(self, qed_dir: Path) -> None:
        decide(qed_dir, "01JBROTATE000000000000000A")
        was = load_signer(qed_dir).key_id
        stranger = FileSigner.generate()
        stranger.save_private(qed_dir / PRIVATE_KEY_NAME, overwrite=True)

        with pytest.raises(KeyDiscontinuity) as caught:
            open_session(directory=qed_dir, strict_policy=False)
        message = str(caught.value)
        assert was in message
        assert stranger.key_id in message
        assert "seq" in message

    def test_the_cli_says_it_in_a_sentence_and_exits_one(self, qed_dir: Path) -> None:
        """Not a traceback. "This chain was last signed by X" is the whole
        answer; the frames above it are noise."""
        decide(qed_dir, "01JBROTATE000000000000000B")
        FileSigner.generate().save_private(qed_dir / PRIVATE_KEY_NAME, overwrite=True)

        result = runner.invoke(app, ["status", "--dir", str(qed_dir)])
        assert result.exit_code == 1, result.output
        assert "last signed by" in result.output
        assert "Traceback" not in result.output

    def test_a_fresh_chain_accepts_whatever_key_is_active(self, tmp_path: Path) -> None:
        """There is nothing to be continuous with. Genesis is signed by the key
        that exists when it is written."""
        from qed.infra.keys.file import init_keys

        directory = tmp_path / "fresh"
        init_keys(directory)
        session = open_session(directory=directory, strict_policy=False)
        session.close()  # no exception is the assertion

    def test_the_same_key_is_always_fine(self, qed_dir: Path) -> None:
        decide(qed_dir, "01JBROTATE000000000000000C")
        session = open_session(directory=qed_dir, strict_policy=False)
        session.close()


# --------------------------------------------------------------------------
# The ordering, which is the part that can go wrong quietly
# --------------------------------------------------------------------------


class TestTheOrderOfOperations:
    def test_the_new_key_is_on_disk_before_the_record_is_appended(self, qed_dir: Path) -> None:
        """A crash between the two must not lose the key the chain is about to
        say is active."""
        plan = stage_rotation(qed_dir)
        assert plan.pending_path.exists()
        assert plan.pending_path.name.endswith(PENDING_SUFFIX)
        # And the active key has not changed yet.
        assert load_signer(qed_dir).key_id == plan.old.key_id

    def test_the_public_key_is_written_before_the_private_one_is_activated(
        self, qed_dir: Path
    ) -> None:
        """A public key on disk grants nothing; leaving it until after the swap
        would mean a crash in between produced records nobody could verify."""
        plan = stage_rotation(qed_dir)
        assert (qed_dir / PUBLIC_DIR_NAME / public_key_filename(plan.new.key_id)).exists()

    def test_finishing_makes_the_new_key_active(self, qed_dir: Path) -> None:
        plan = stage_rotation(qed_dir)
        finish_rotation(plan)
        assert load_signer(qed_dir).key_id == plan.new.key_id
        assert not plan.pending_path.exists()

    def test_the_old_private_key_is_gone(self, qed_dir: Path) -> None:
        """Rotation exists because a key might have leaked. One left on disk
        has reduced nothing -- and with it an attacker can fabricate a whole
        alternative history that verifies under a key an auditor still trusts
        for the period before the rotation."""
        plan = stage_rotation(qed_dir)
        old_pem = (qed_dir / PRIVATE_KEY_NAME).read_bytes()
        finish_rotation(plan)
        assert (qed_dir / PRIVATE_KEY_NAME).read_bytes() != old_pem
        assert not list(qed_dir.glob("*.pem.old"))
        assert not (qed_dir / "retired").exists()

    def test_an_interrupted_rotation_is_visible(self, qed_dir: Path) -> None:
        plan = stage_rotation(qed_dir)
        assert pending_rotation(qed_dir) == plan.pending_path
        finish_rotation(plan)
        assert pending_rotation(qed_dir) is None

    def test_staging_twice_simply_discards_the_unused_key(self, qed_dir: Path) -> None:
        first = stage_rotation(qed_dir)
        second = stage_rotation(qed_dir)
        assert first.new.key_id != second.new.key_id
        assert load_signer(qed_dir).key_id == first.old.key_id

    def test_there_is_nothing_to_rotate_without_a_key(self, tmp_path: Path) -> None:
        with pytest.raises(MissingSigningKey, match="nothing to rotate"):
            stage_rotation(tmp_path / "empty")


class TestTheStore:
    def test_the_retired_key_is_kept_and_marked(self, qed_dir: Path) -> None:
        """Never deleted: an auditor verifying a record from before the
        rotation needs that public key, and the OSCAL export ships the set."""
        rotation = rotate(qed_dir)
        store = SqliteStore(qed_dir / "qed.db")
        try:
            keys = {key.key_id: key for key in store.signing_keys()}
        finally:
            store.close()

        assert set(keys) == {rotation.old_key_id, rotation.new_key_id}
        assert keys[rotation.old_key_id].retired_at is not None
        assert keys[rotation.new_key_id].retired_at is None

    def test_the_writer_keeps_signing_with_the_new_key_in_the_same_process(
        self, qed_dir: Path
    ) -> None:
        """A caller that kept the session would otherwise go on signing with
        the key the chain has just retired."""
        session = open_session(directory=qed_dir, strict_policy=False)
        try:
            rotation = rotate_signing_key(session)
            appended = session.writer.append(
                type_=EvidenceType.proposal,
                assurance=Assurance.kernel,
                payload={"after": "rotation"},
                ts=utcnow(),
            )
            assert appended.record is not None
            assert appended.record.key_id == rotation.new_key_id
        finally:
            session.close()


# --------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------


class TestTheCommand:
    def test_it_reports_both_keys_and_the_record(self, qed_dir: Path) -> None:
        result = runner.invoke(app, ["keys", "rotate", "--dir", str(qed_dir), "--yes"])
        assert result.exit_code == 0, result.output
        assert "retired" in result.output
        assert "active" in result.output
        assert "key_rotated" in result.output

    def test_it_says_to_keep_the_old_public_key(self, qed_dir: Path) -> None:
        result = runner.invoke(app, ["keys", "rotate", "--dir", str(qed_dir), "--yes"])
        assert "public" in result.output
        assert "cannot be verified from the active key alone" in result.output

    def test_it_asks_first_and_declining_changes_nothing(self, qed_dir: Path) -> None:
        before = (qed_dir / PRIVATE_KEY_NAME).read_bytes()
        result = runner.invoke(app, ["keys", "rotate", "--dir", str(qed_dir)], input="n\n")
        assert result.exit_code == 0, result.output
        assert "nothing was changed" in result.output
        assert (qed_dir / PRIVATE_KEY_NAME).read_bytes() == before

    def test_the_prompt_says_the_old_private_key_is_destroyed(self, qed_dir: Path) -> None:
        result = runner.invoke(app, ["keys", "rotate", "--dir", str(qed_dir)], input="n\n")
        assert "DESTROY" in result.output

    def test_rotating_without_a_key_is_refused(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["keys", "rotate", "--dir", str(tmp_path / "nothing"), "--yes"])
        assert result.exit_code == 1
        assert "no signing key" in result.output

    def test_keys_init_points_at_rotate(self, qed_dir: Path) -> None:
        """`init --overwrite` breaks the chain; rotation is the operation that
        does not."""
        result = runner.invoke(app, ["keys", "init", "--dir", str(qed_dir)])
        assert result.exit_code == 1
        assert "qed keys rotate" in result.output
        assert "week 7" not in result.output, "the pending note outlived the feature"


class TestExportPublic:
    def test_it_prints_every_key_by_default(self, qed_dir: Path) -> None:
        """A chain spanning a rotation cannot be verified from the active key
        alone, so the default has to be all of them."""
        rotation = rotate(qed_dir)
        result = runner.invoke(app, ["keys", "export-public", "--dir", str(qed_dir)])
        assert result.exit_code == 0, result.output
        assert rotation.old_key_id in result.output
        assert rotation.new_key_id in result.output
        assert result.output.count("BEGIN PUBLIC KEY") == 2

    def test_each_key_says_whether_it_is_still_signing(self, qed_dir: Path) -> None:
        rotate(qed_dir)
        output = runner.invoke(app, ["keys", "export-public", "--dir", str(qed_dir)]).output
        assert "active" in output
        assert "retired" in output

    def test_the_output_is_still_usable_as_a_pem_file(self, qed_dir: Path, tmp_path: Path) -> None:
        """`qed keys export-public > public.pem` has to work, so the labels are
        `#` comments rather than prose."""
        rotate(qed_dir)
        output = runner.invoke(app, ["keys", "export-public", "--dir", str(qed_dir)]).output
        for line in output.splitlines():
            if line and not line.startswith("#"):
                assert (
                    line.startswith("-----")
                    or line.replace("+", "").replace("/", "").replace("=", "").isalnum()
                ), line

    def test_active_prints_one_key(self, qed_dir: Path) -> None:
        rotate(qed_dir)
        result = runner.invoke(app, ["keys", "export-public", "--dir", str(qed_dir), "--active"])
        assert result.output.count("BEGIN PUBLIC KEY") == 1
        assert "#" not in result.output


class TestRotationIsDirectEvenWhenWritesAreDeferred:
    def test_the_writer_exposes_a_direct_append(self, qed_dir: Path) -> None:
        """A queued `key_rotated` would be chained after records the new key
        had already signed, so the record introducing the key would sit after
        its first use -- exactly what `qed-verify` reads as a discontinuity."""
        store = SqliteStore(qed_dir / "qed.db")
        try:
            writer = ChainWriter(
                store,
                load_signer(qed_dir),
                instance_id="qed-rotation",
                write_mode="deferred",
            )
            record = writer.append_direct(
                type_=EvidenceType.checkpoint,
                assurance=Assurance.kernel,
                payload={"direct": True},
                ts=utcnow(),
            )
            assert record.seq is not None
            assert store.outbox_depth() == 0, "it was queued"
        finally:
            store.close()
