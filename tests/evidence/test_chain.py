"""Chain behaviour end to end, through the real store and the real verifier.

The tamper tests write the chain, then corrupt the *export* and check that
`qed-verify` notices — which is the position an auditor is actually in.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from qed_verify.verify import load_jsonl, verify_records

from qed.core.evidence.export.jsonl import to_jsonl
from qed.core.schemas import Assurance, EvidenceType
from qed.infra.chain_writer import ChainWriter, InstanceMismatch
from qed.infra.keys.file import FileSigner, load_public_keys
from qed.infra.storage.sqlite import ChainIntegrityError, SqliteStore

INSTANCE = "test-instance"


@pytest.fixture
def chain(tmp_path: Path) -> Iterator[tuple[SqliteStore, ChainWriter, FileSigner]]:
    from qed.infra.keys.file import init_keys, load_signer

    directory = tmp_path / "qed"
    init_keys(directory)
    signer = load_signer(directory)
    store = SqliteStore(directory / "qed.db")
    writer = ChainWriter(store, signer, instance_id=INSTANCE)
    for i in range(5):
        writer.append(
            type_=EvidenceType.proposal,
            assurance=Assurance.kernel,
            payload={"n": i, "note": f"record {i}"},
        )
    try:
        yield store, writer, signer
    finally:
        store.close()


def _verify(store: SqliteStore, directory: Path, *, instance_id: str | None = INSTANCE):
    records = load_jsonl(to_jsonl(store.iter_evidence()))
    return records, verify_records(
        records, load_public_keys(directory / "public"), instance_id=instance_id
    )


def test_a_fresh_chain_verifies(chain, tmp_path: Path) -> None:
    store, _, _ = chain
    records, report = _verify(store, tmp_path / "qed")
    assert report.ok, report.summary()
    assert report.records == 6  # genesis + 5
    assert records[0]["type"] == "genesis"
    assert records[0]["seq"] == 0


def test_genesis_is_written_once(chain) -> None:
    _, writer, _ = chain
    assert writer.ensure_genesis() is None


def test_genesis_prev_hash_is_checked_against_the_instance_id(chain, tmp_path: Path) -> None:
    store, _, _ = chain
    _, report = _verify(store, tmp_path / "qed", instance_id="someone-elses-instance")
    assert not report.ok
    assert any(p.code == "genesis_mismatch" for p in report.problems)


def test_reusing_a_chain_under_a_different_instance_id_is_refused(chain, tmp_path: Path) -> None:
    store, _, signer = chain
    with pytest.raises(InstanceMismatch):
        ChainWriter(store, signer, instance_id="renamed")


def test_out_of_order_append_is_refused(chain) -> None:
    from qed.core.evidence.record import build_record

    store, _, signer = chain
    bogus = build_record(
        seq=99,
        prev_hash=store.last_hash() or "",
        type_=EvidenceType.proposal,
        assurance=Assurance.kernel,
        payload={},
        signer=signer,
    )
    with pytest.raises(ChainIntegrityError):
        store.append_evidence(bogus)


class TestTampering:
    def test_editing_a_payload_is_detected(self, chain, tmp_path: Path) -> None:
        store, _, _ = chain
        records, _ = _verify(store, tmp_path / "qed")
        records[3]["payload"]["note"] = "rewritten after the fact"
        report = verify_records(records, load_public_keys(tmp_path / "qed" / "public"))
        assert not report.ok
        assert any(p.code == "payload_tampered" for p in report.problems)

    def test_editing_a_payload_hash_is_detected(self, chain, tmp_path: Path) -> None:
        store, _, _ = chain
        records, _ = _verify(store, tmp_path / "qed")
        records[2]["payload_hash"] = "0" * 64
        report = verify_records(records, load_public_keys(tmp_path / "qed" / "public"))
        codes = {p.code for p in report.problems}
        assert "hash_mismatch" in codes or "payload_tampered" in codes

    def test_deleting_a_record_is_detected(self, chain, tmp_path: Path) -> None:
        store, _, _ = chain
        records, _ = _verify(store, tmp_path / "qed")
        del records[3]
        report = verify_records(records, load_public_keys(tmp_path / "qed" / "public"))
        assert not report.ok
        codes = {p.code for p in report.problems}
        assert "sequence_gap" in codes
        assert "broken_link" in codes

    def test_reordering_records_is_detected(self, chain, tmp_path: Path) -> None:
        store, _, _ = chain
        records, _ = _verify(store, tmp_path / "qed")
        records[2], records[3] = records[3], records[2]
        report = verify_records(records, load_public_keys(tmp_path / "qed" / "public"))
        assert not report.ok
        assert any(p.code in {"sequence_gap", "broken_link"} for p in report.problems)

    def test_a_forged_signature_is_detected(self, chain, tmp_path: Path) -> None:
        """Re-signing a rewritten record with a different key does not help."""
        store, _, _ = chain
        records, _ = _verify(store, tmp_path / "qed")
        attacker = FileSigner.generate()
        records[4]["payload"] = {"note": "forged"}
        records[4]["payload_hash"] = __import__(
            "qed_verify.jcs", fromlist=["sha256_hex"]
        ).sha256_hex(records[4]["payload"])
        from qed_verify.verify import _record_hash

        records[4]["hash"] = _record_hash(records[4])
        records[4]["sig"] = attacker.sign(bytes.fromhex(records[4]["hash"]))
        report = verify_records(records, load_public_keys(tmp_path / "qed" / "public"))
        assert not report.ok
        # The chain breaks at the next record even before the key is questioned.
        assert any(p.code in {"broken_link", "unknown_key"} for p in report.problems)

    def test_an_unknown_signing_key_is_reported(self, chain, tmp_path: Path) -> None:
        store, _, _ = chain
        records, _ = _verify(store, tmp_path / "qed")
        report = verify_records(records, {})
        assert not report.ok
        assert all(p.code == "unknown_key" for p in report.problems)


def test_purged_payloads_still_verify(chain, tmp_path: Path) -> None:
    """SPEC §10.6: retention removes the payload, never the proof."""
    store, _, _ = chain
    purged = store.purge_payloads(through_seq=3)
    assert purged == 4
    records, report = _verify(store, tmp_path / "qed")
    assert report.ok, report.summary()
    assert report.purged == 4
    assert records[1]["payload"] is None
    assert records[1]["payload_hash"]


def test_checkpoint_merkle_root_verifies(chain, tmp_path: Path) -> None:
    store, writer, _ = chain
    record = writer.checkpoint(force=True)
    assert record is not None
    _, report = _verify(store, tmp_path / "qed")
    assert report.ok, report.summary()
    assert report.checkpoints == 1


def test_a_checkpoint_root_survives_masking(chain, tmp_path: Path) -> None:
    """The flake that made this file go red on about one push in a hundred.

    Masking runs before ``payload_hash``, so a rewritten ``merkle_root`` still
    produced a record that verified against its own hash -- and a checkpoint
    nobody could ever verify again. The digest below is a real one that
    reproduced it: it contains the Luhn-passing run ``2928422540476``.

    Written against the writer rather than against a generated root, because
    whether a run like that turns up is a one-in-four-hundred accident and a
    test that waits for it is not a test.
    """
    _, writer, _ = chain
    poison = "0ed7e112a9844e97c2928422540476bbfda268f8060f061ffdf8d165b7fb5e0b"
    appended = writer.append(
        type_=EvidenceType.checkpoint,
        assurance=Assurance.kernel,
        payload={"from_seq": 0, "to_seq": 4, "merkle_root": poison, "records": 5},
    )
    assert appended.record is not None
    assert appended.record.payload is not None
    assert appended.record.payload["merkle_root"] == poison


def test_a_tampered_checkpoint_root_is_detected(chain, tmp_path: Path) -> None:
    store, writer, _ = chain
    writer.checkpoint(force=True)
    records, _ = _verify(store, tmp_path / "qed")
    records[-1]["payload"]["merkle_root"] = "0" * 64
    report = verify_records(records, load_public_keys(tmp_path / "qed" / "public"))
    assert not report.ok
    assert any(p.code == "checkpoint_mismatch" for p in report.problems)


def test_a_second_checkpoint_continues_where_the_first_stopped(chain) -> None:
    """Every record is covered by exactly one root, checkpoints included."""
    _, writer, _ = chain
    first = writer.checkpoint(force=True)
    assert first is not None and first.payload is not None
    assert first.payload["from_seq"] == 0
    assert first.payload["to_seq"] == first.seq - 1

    writer.append(type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"n": 99})
    second = writer.checkpoint(force=True)
    assert second is not None and second.payload is not None
    # Starts at the first checkpoint's own record: a checkpoint cannot cover
    # itself, so the next one picks it up.
    assert second.payload["from_seq"] == first.seq
    assert second.payload["to_seq"] == second.seq - 1


def test_checkpoint_declines_below_the_threshold(chain) -> None:
    _, writer, _ = chain
    assert writer.checkpoint(force=True) is not None
    # One new record (the checkpoint itself), far below every_records, and
    # nothing like an hour old.
    assert writer.checkpoint() is None


def test_checkpoint_on_an_empty_chain_is_a_no_op(tmp_path: Path) -> None:
    from qed.infra.keys.file import init_keys, load_signer

    directory = tmp_path / "empty"
    init_keys(directory)
    with SqliteStore(directory / "qed.db") as store:
        writer = ChainWriter(store, load_signer(directory), instance_id=INSTANCE)
        assert writer.checkpoint(force=True) is None


def test_rotation_continuity(chain, tmp_path: Path) -> None:
    """ADR-004: a key_rotated record is signed by the retiring key.

    `qed keys rotate` is week 7; the record format and the verifier check
    exist now, so the format is frozen before anything depends on it.
    """
    store, writer, old = chain
    new = FileSigner.generate()
    new.save_public(tmp_path / "qed" / "public")
    writer.append(
        type_=EvidenceType.key_rotated,
        assurance=Assurance.kernel,
        payload={
            "old_key_id": old.key_id,
            "new_key_id": new.key_id,
            "new_public_pem": new.public_pem,
        },
    )
    writer.signer = new
    store.upsert_signing_key(new.info())
    writer.append(
        type_=EvidenceType.proposal, assurance=Assurance.kernel, payload={"after": "rotation"}
    )

    records, report = _verify(store, tmp_path / "qed")
    assert report.ok, report.summary()
    assert len(report.keys_used) == 2
    rotation = next(r for r in records if r["type"] == "key_rotated")
    assert rotation["key_id"] == old.key_id


def test_rotation_signed_by_the_new_key_is_rejected(chain, tmp_path: Path) -> None:
    store, writer, old = chain
    new = FileSigner.generate()
    new.save_public(tmp_path / "qed" / "public")
    writer.signer = new  # the wrong order on purpose
    writer.append(
        type_=EvidenceType.key_rotated,
        assurance=Assurance.kernel,
        payload={"old_key_id": old.key_id, "new_key_id": new.key_id},
    )
    _, report = _verify(store, tmp_path / "qed")
    assert not report.ok
    assert any(p.code == "rotation_discontinuity" for p in report.problems)


def test_jsonl_export_is_one_object_per_line(chain) -> None:
    store, _, _ = chain
    text = to_jsonl(store.iter_evidence())
    lines = text.splitlines()
    assert len(lines) == 6
    assert all(isinstance(json.loads(line), dict) for line in lines)


def test_an_empty_export_is_a_failure_not_a_pass() -> None:
    report = verify_records([], {})
    assert not report.ok
    assert any(p.code == "empty" for p in report.problems)
