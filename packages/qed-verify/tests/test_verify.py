"""The verifier's own tests.

These run against fixture records written in the on-the-wire format by hand,
not produced by the kernel. If the kernel and the verifier ever disagree about
the format, that shows up here rather than cancelling out.

The kernel's own suite covers the other direction (``tests/evidence/test_chain.py``
writes a real chain and verifies it through this package).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from qed_verify import jcs
from qed_verify.cli import main as cli_main
from qed_verify.verify import load_jsonl, verify_records

INSTANCE = "fixture-instance"


def key_id_of(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:16]}"


def record_hash(record: dict[str, Any]) -> str:
    parts = [
        record["schema_version"].encode(),
        str(record["seq"]).encode(),
        record["ts"].encode(),
        record["type"].encode(),
        record["payload_hash"].encode(),
        record["prev_hash"].encode(),
    ]
    return hashlib.sha256(b"\x1f".join(parts)).hexdigest()


def sign(private: Ed25519PrivateKey, digest_hex: str) -> str:
    import base64

    return base64.urlsafe_b64encode(private.sign(bytes.fromhex(digest_hex))).decode().rstrip("=")


def make_chain(private: Ed25519PrivateKey, count: int = 3) -> list[dict[str, Any]]:
    prev = hashlib.sha256(f"evidence-chain/1:genesis:{INSTANCE}".encode()).hexdigest()
    records: list[dict[str, Any]] = []
    for seq in range(count):
        payload: dict[str, Any] = {
            "_assurance": "kernel",
            "_dev": False,
            "_enforcement": None,
            "_key_id": key_id_of(private),
            "_mode": None,
            "n": seq,
        }
        record: dict[str, Any] = {
            "schema_version": "1.0",
            "seq": seq,
            "ts": f"2026-10-07T12:00:0{seq}.000Z",
            "type": "genesis" if seq == 0 else "proposal",
            "assurance": "kernel",
            "mode": None,
            "enforcement": None,
            "dev": False,
            "payload_hash": jcs.sha256_hex(payload),
            "payload": payload,
            "prev_hash": prev,
            "key_id": key_id_of(private),
        }
        record["hash"] = record_hash(record)
        record["sig"] = sign(private, record["hash"])
        prev = record["hash"]
        records.append(record)
    return records


def merkle_root(leaves: list[str]) -> str:
    level = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def make_anchored_chain(private: Ed25519PrivateKey, count: int = 3) -> list[dict[str, Any]]:
    """`count` ordinary records plus the checkpoint that covers them.

    Shaped the way the kernel writes one: the checkpoint sits at seq `count`
    and its payload covers `0..count-1`, so a published copy of it vouches for
    every record before it (through the root) and for itself (through its own
    hash).
    """
    records = make_chain(private, count)
    payload: dict[str, Any] = {
        "from_seq": 0,
        "to_seq": count - 1,
        "merkle_root": merkle_root([r["hash"] for r in records]),
        "records": count,
    }
    checkpoint: dict[str, Any] = {
        "schema_version": "1.0",
        "seq": count,
        "ts": f"2026-10-07T12:01:{count:02d}.000Z",
        "type": "checkpoint",
        "assurance": "kernel",
        "mode": None,
        "enforcement": None,
        "dev": False,
        "payload_hash": jcs.sha256_hex(payload),
        "payload": payload,
        "prev_hash": records[-1]["hash"],
        "key_id": key_id_of(private),
    }
    checkpoint["hash"] = record_hash(checkpoint)
    checkpoint["sig"] = sign(private, checkpoint["hash"])
    return [*records, checkpoint]


def published(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The anchor: a copy of the chain's checkpoint, as a publisher wrote it.

    A copy, not a reference. In real use it comes back from an object-locked
    bucket; here the point is that mutating the export afterwards must not
    mutate this.
    """
    return json.loads(json.dumps(records[-1]))


@pytest.fixture
def private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def keys(private: Ed25519PrivateKey) -> dict[str, Any]:
    return {key_id_of(private): private.public_key()}


def test_a_handwritten_chain_verifies(private, keys) -> None:
    report = verify_records(make_chain(private), keys, instance_id=INSTANCE)
    assert report.ok, report.summary()
    assert report.genesis_bound_to == INSTANCE
    # Not `complete`, and that is the point of check 8: this chain is bound to
    # an instance and internally perfect, and nothing here can tell whether it
    # is the whole chain. `TestTheAnchor` supplies the missing input.
    assert not report.complete
    assert any("completeness" in note for note in report.unchecked)


def test_a_forgery_with_its_own_key_and_id_passes_every_other_check(private, keys) -> None:
    """The reason the genesis binding has to arrive from outside the file.

    This chain is fabricated here, in this test, with a key generated in this
    test, and labelled with whatever instance id the forger liked. Linkage,
    hashes, canonicalisation, signatures: all correct, because the forger
    computed them. The verifier is right to report no problems -- there are
    none *in the file*. What it must not do is let that read as provenance.
    """
    forged = make_chain(private)
    report = verify_records(forged, keys)

    assert report.ok
    assert not report.complete
    assert report.genesis_bound_to is None
    assert "no instance id was supplied" in report.unchecked[0]

    # And the id is sitting in the export, so taking it from there is circular:
    # bound against the id the forger chose, this same forgery passes the
    # binding check too. An anchor is the input that cannot be taken from the
    # file, which is why it is a separate check and not a stricter one.
    circular = verify_records(forged, keys, instance_id=INSTANCE)
    assert circular.ok and circular.genesis_bound_to == INSTANCE, (
        "the tautology verifies, which is exactly the point"
    )
    assert report.records == 3
    assert report.first_seq == 0 and report.last_seq == 2


def test_the_report_round_trips_to_json(private, keys) -> None:
    report = verify_records(make_chain(private), keys)
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["ok"] is True
    assert payload["keys_used"] == [key_id_of(private)]


def test_an_export_that_does_not_start_at_zero_is_reported(private, keys) -> None:
    report = verify_records(make_chain(private)[1:], keys)
    assert any(p.code == "not_from_genesis" for p in report.problems)


def test_a_record_without_a_sequence_number_is_reported(private, keys) -> None:
    records = make_chain(private)
    del records[1]["seq"]
    report = verify_records(records, keys)
    assert any(p.code == "malformed" for p in report.problems)


def test_a_non_object_payload_is_reported(private, keys) -> None:
    records = make_chain(private)
    records[1]["payload"] = ["not", "an", "object"]
    report = verify_records(records, keys)
    assert any(p.code == "malformed" for p in report.problems)


def test_a_purged_record_still_verifies(private, keys) -> None:
    records = make_chain(private)
    records[1]["payload"] = None
    report = verify_records(records, keys)
    assert report.ok, report.summary()
    assert report.purged == 1


def test_a_record_signed_by_an_unsupplied_key_is_reported(private) -> None:
    report = verify_records(make_chain(private), {})
    assert any(p.code == "unknown_key" for p in report.problems)


def test_a_signature_from_the_wrong_key_is_reported(private, keys) -> None:
    other = Ed25519PrivateKey.generate()
    records = make_chain(private)
    records[2]["sig"] = sign(other, records[2]["hash"])
    report = verify_records(records, keys)
    assert any(p.code == "bad_signature" for p in report.problems)


def test_a_malformed_checkpoint_payload_is_reported(private, keys) -> None:
    records = make_chain(private)
    records[2]["type"] = "checkpoint"
    records[2]["payload"] = {"from_seq": 0}
    records[2]["payload_hash"] = jcs.sha256_hex(records[2]["payload"])
    records[2]["hash"] = record_hash(records[2])
    records[2]["sig"] = sign(private, records[2]["hash"])
    report = verify_records(records, keys)
    assert any(p.code == "malformed_checkpoint" for p in report.problems)


def test_a_checkpoint_claiming_records_outside_the_export_is_reported(private, keys) -> None:
    records = make_chain(private)
    records[2]["type"] = "checkpoint"
    records[2]["payload"] = {"from_seq": 0, "to_seq": 99, "merkle_root": "00"}
    records[2]["payload_hash"] = jcs.sha256_hex(records[2]["payload"])
    records[2]["hash"] = record_hash(records[2])
    records[2]["sig"] = sign(private, records[2]["hash"])
    report = verify_records(records, keys)
    assert any(p.code == "checkpoint_range_missing" for p in report.problems)


class TestTheAnchor:
    """Check 8, and the one thing the other seven cannot see.

    Every other check reads the export and asks whether it is self-consistent.
    A chain that stops early is perfectly self-consistent -- that is not a gap
    in the implementation, it is a property of hash chains: the record that
    would say more records followed is the record that was removed. So the only
    way to detect truncation is an input from outside the export, and until
    `--anchor` existed this verifier had nowhere to put one.
    """

    def anchor_args(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {"instance_id": INSTANCE, "anchors": [published(records)]}

    def test_an_anchored_chain_is_the_only_kind_that_can_be_complete(self, private, keys) -> None:
        records = make_anchored_chain(private)
        report = verify_records(records, keys, **self.anchor_args(records))
        assert report.ok, report.summary()
        assert report.complete, report.summary()
        assert report.anchors == 1
        assert report.anchored_through == report.last_seq

    def test_truncation_is_invisible_without_an_anchor_and_caught_with_one(
        self, private, keys
    ) -> None:
        """The finding this check exists for, both halves in one test.

        The first assertion is the uncomfortable one: a chain with its tail cut
        off produces *no problems at all*. It has to be asserted, because a
        reader who only saw the second half would conclude the verifier always
        catches truncation.
        """
        records = make_anchored_chain(private)
        anchor = published(records)
        truncated = records[:-2]  # the checkpoint and the record before it

        blind = verify_records(truncated, keys, instance_id=INSTANCE)
        assert blind.ok, "a truncated chain is self-consistent -- this is the gap"
        assert not blind.problems
        assert not blind.complete, "but it must not read as a complete verification"
        assert any("completeness" in note for note in blind.unchecked)

        caught = verify_records(truncated, keys, instance_id=INSTANCE, anchors=[anchor])
        assert not caught.ok
        problem = next(p for p in caught.problems if p.code == "anchor_not_in_export")
        assert "truncated" in problem.detail
        assert caught.anchors == 0

    def test_a_rewritten_export_disagrees_with_the_published_copy(self, private, keys) -> None:
        """The other thing an anchor is for. A wholesale rewrite -- new
        payloads, re-linked, re-signed with the real key -- passes checks 1
        through 7, because the operator who holds the key can produce a chain
        that is internally perfect. It cannot change the copy already in a
        bucket it does not control."""
        anchor = published(make_anchored_chain(private))
        rewritten = make_anchored_chain(private, count=4)

        report = verify_records(rewritten, keys, instance_id=INSTANCE)
        assert report.ok, "the rewrite is internally flawless, which is the problem"

        caught = verify_records(rewritten, keys, instance_id=INSTANCE, anchors=[anchor])
        assert not caught.ok
        codes = {p.code for p in caught.problems}
        assert "anchor_mismatch" in codes or "anchor_not_in_export" in codes

    def test_a_rewrite_inside_the_anchored_range_names_the_range(self, private, keys) -> None:
        """Both anchor problems at once, which is deliberate: one says the
        export was rewritten, the other says where."""
        records = make_anchored_chain(private)
        anchor = published(records)

        # Same length, same seqs, different content, re-linked and re-signed.
        tampered = make_chain(private, 3)
        tampered[1]["payload"] = {**tampered[1]["payload"], "n": 999}
        tampered[1]["payload_hash"] = jcs.sha256_hex(tampered[1]["payload"])
        tampered[1]["hash"] = record_hash(tampered[1])
        tampered[1]["sig"] = sign(private, tampered[1]["hash"])
        tampered[2]["prev_hash"] = tampered[1]["hash"]
        tampered[2]["hash"] = record_hash(tampered[2])
        tampered[2]["sig"] = sign(private, tampered[2]["hash"])
        payload = {
            "from_seq": 0,
            "to_seq": 2,
            "merkle_root": merkle_root([r["hash"] for r in tampered]),
            "records": 3,
        }
        checkpoint = {**records[-1], "payload": payload}
        checkpoint["payload_hash"] = jcs.sha256_hex(payload)
        checkpoint["prev_hash"] = tampered[-1]["hash"]
        checkpoint["hash"] = record_hash(checkpoint)
        checkpoint["sig"] = sign(private, checkpoint["hash"])
        export = [*tampered, checkpoint]

        assert verify_records(export, keys, instance_id=INSTANCE).ok, "internally consistent"

        caught = verify_records(export, keys, instance_id=INSTANCE, anchors=[anchor])
        codes = {p.code for p in caught.problems}
        assert codes == {"anchor_mismatch", "anchor_root_mismatch"}, codes

    def test_an_anchor_signed_by_the_wrong_key_is_not_evidence(self, private, keys) -> None:
        """An anchor nobody checks is a second file to forge, not a control."""
        records = make_anchored_chain(private)
        anchor = published(records)
        anchor["sig"] = sign(Ed25519PrivateKey.generate(), anchor["hash"])

        report = verify_records(records, keys, instance_id=INSTANCE, anchors=[anchor])
        assert any(p.code == "bad_signature" for p in report.problems)

    def test_an_anchor_whose_hash_does_not_match_its_own_fields(self, private, keys) -> None:
        records = make_anchored_chain(private)
        anchor = published(records)
        anchor["ts"] = "2030-01-01T00:00:00.000Z"

        report = verify_records(records, keys, instance_id=INSTANCE, anchors=[anchor])
        assert any(p.code == "anchor_hash_mismatch" for p in report.problems)

    def test_an_anchor_that_is_not_a_checkpoint_is_reported(self, private, keys) -> None:
        records = make_anchored_chain(private)
        report = verify_records(
            records, keys, instance_id=INSTANCE, anchors=[{"seq": 1, "payload": {"n": 1}}]
        )
        assert any(p.code == "malformed_anchor" for p in report.problems)

    def test_records_after_the_newest_anchor_are_reported_as_unanchored(
        self, private, keys
    ) -> None:
        """An anchor covers the records it names and nothing later. A pass that
        read as unqualified would be the same overstatement the unbound genesis
        check was fixed for."""
        records = make_anchored_chain(private)
        anchor = published(records)

        # Two more records after the checkpoint, linked onto it properly.
        extended = list(records)
        prev = extended[-1]["hash"]
        for seq in (4, 5):
            payload = {"n": seq}
            record = {
                "schema_version": "1.0",
                "seq": seq,
                "ts": f"2026-10-07T12:02:0{seq}.000Z",
                "type": "proposal",
                "assurance": "kernel",
                "mode": None,
                "enforcement": None,
                "dev": False,
                "payload_hash": jcs.sha256_hex(payload),
                "payload": payload,
                "prev_hash": prev,
                "key_id": key_id_of(private),
            }
            record["hash"] = record_hash(record)
            record["sig"] = sign(private, record["hash"])
            prev = record["hash"]
            extended.append(record)

        report = verify_records(extended, keys, instance_id=INSTANCE, anchors=[anchor])
        assert report.ok, report.summary()
        assert report.anchors == 1
        assert report.anchored_through == 3
        assert not report.complete
        note = next(n for n in report.unchecked if "past the newest anchor" in n)
        assert "4..5" in note and "2 record(s)" in note

    def test_the_json_report_carries_the_anchor_fields(self, private, keys) -> None:
        records = make_anchored_chain(private)
        payload = json.loads(
            json.dumps(verify_records(records, keys, **self.anchor_args(records)).to_dict())
        )
        assert payload["anchors"] == 1
        assert payload["anchored_through"] == 3
        assert payload["complete"] is True


def test_load_jsonl_skips_blank_lines() -> None:
    assert load_jsonl('{"a":1}\n\n{"b":2}\n') == [{"a": 1}, {"b": 2}]


def test_load_jsonl_refuses_a_bare_array() -> None:
    with pytest.raises(ValueError, match="must be an object"):
        load_jsonl("[1,2,3]\n")


class TestCommandLine:
    def _write(self, tmp_path: Path, private: Ed25519PrivateKey) -> tuple[Path, Path]:
        records = make_chain(private)
        chain = tmp_path / "chain.jsonl"
        chain.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8"
        )
        keys_dir = tmp_path / "public"
        keys_dir.mkdir()
        (keys_dir / "k.pem").write_bytes(
            private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        return chain, keys_dir

    def _write_anchored(
        self, tmp_path: Path, private: Ed25519PrivateKey
    ) -> tuple[Path, Path, Path]:
        """An export, its keys, and the published checkpoint beside it."""
        records = make_anchored_chain(private)
        chain = tmp_path / "chain.jsonl"
        chain.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8"
        )
        keys_dir = tmp_path / "public"
        keys_dir.mkdir()
        (keys_dir / "k.pem").write_bytes(
            private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        anchors = tmp_path / "anchors"
        anchors.mkdir()
        anchor = anchors / "qed-checkpoint-0000000003.json"
        anchor.write_text(json.dumps(published(records), sort_keys=True), encoding="utf-8")
        return chain, keys_dir, anchor

    def test_exit_zero_on_a_good_chain(self, tmp_path: Path, private) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        assert cli_main([str(chain), "--keys", str(keys_dir)]) == 0

    def test_instance_id_is_checked_when_given(self, tmp_path: Path, private) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        assert cli_main([str(chain), "--keys", str(keys_dir), "--instance-id", INSTANCE]) == 0
        assert cli_main([str(chain), "--keys", str(keys_dir), "--instance-id", "other"]) == 1

    def test_an_unbound_pass_says_so_on_the_result_line(
        self, tmp_path: Path, private, capsys
    ) -> None:
        """The bug this replaces: `OK` printed over a check that never ran.

        Without `--instance-id` the genesis binding is skipped, and for eleven
        weeks the summary said `OK -- chain is contiguous, unmodified and
        signed` anyway while `to_dict()` carried no field recording the
        omission. An auditor reading that line was told more than the verifier
        had checked, by the one tool in this product whose entire job is not
        overstating what it knows.
        """
        chain, keys_dir = self._write(tmp_path, private)
        assert cli_main([str(chain), "--keys", str(keys_dir)]) == 0
        out = capsys.readouterr()
        assert "bound to  : NOTHING" in out.out
        assert "OK SO FAR" in out.out
        assert "did not run" in out.out
        assert "not checked" in out.err

    def test_a_bound_pass_names_the_instance(self, tmp_path: Path, private, capsys) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        assert cli_main([str(chain), "--keys", str(keys_dir), "--instance-id", INSTANCE]) == 0
        out = capsys.readouterr()
        assert f"bound to  : instance {INSTANCE!r}" in out.out
        # Bound, but still not anchored, and the result line says which.
        assert "anchored  : NOTHING -- no anchor supplied" in out.out
        assert "OK SO FAR" in out.out
        assert "not checked" in out.err

    def test_a_supplied_anchor_that_fails_is_not_reported_as_no_anchor(
        self, tmp_path: Path, private, capsys
    ) -> None:
        """The summary counted verified anchors and answered a different
        question with it.

        `report.anchors` is incremented only when an anchor matches, so a
        truncated export checked against a real published checkpoint left it
        at zero -- and the line read `anchored : NOTHING -- no anchor
        supplied` on the exact run where the anchor had just caught the
        truncation. A verifier that understates the evidence it was handed
        invites the reader to go and supply what they already supplied.
        """
        chain, keys_dir, anchor = self._write_anchored(tmp_path, private)
        records = [json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines()]
        # Drop the tail the anchor vouches for: the anchor is now about a
        # record this export does not contain.
        chain.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in records[:-1]),
            encoding="utf-8",
        )
        assert (
            cli_main(
                [
                    str(chain),
                    "--keys",
                    str(keys_dir),
                    "--instance-id",
                    INSTANCE,
                    "--anchor",
                    str(anchor),
                ]
            )
            == 1
        )
        out = capsys.readouterr()
        assert "anchor_not_in_export" in out.out
        assert "no anchor supplied" not in out.out
        assert "1 anchor(s) supplied, none of which verified" in out.out

    def test_a_bound_and_anchored_pass_is_the_unqualified_one(
        self, tmp_path: Path, private, capsys
    ) -> None:
        chain, keys_dir, anchor = self._write_anchored(tmp_path, private)
        assert (
            cli_main(
                [
                    str(chain),
                    "--keys",
                    str(keys_dir),
                    "--instance-id",
                    INSTANCE,
                    "--anchor",
                    str(anchor),
                ]
            )
            == 0
        )
        out = capsys.readouterr()
        assert "anchored  : 1 anchor(s), covering seq 0..3" in out.out
        assert "anchored to its last record" in out.out
        assert out.err == ""

    def test_an_anchor_directory_is_read(self, tmp_path: Path, private) -> None:
        """A bucket synced to disk, rather than each object named."""
        chain, keys_dir, anchor = self._write_anchored(tmp_path, private)
        assert (
            cli_main(
                [
                    str(chain),
                    "--keys",
                    str(keys_dir),
                    "--instance-id",
                    INSTANCE,
                    "--anchor",
                    str(anchor.parent),
                    "--require-complete",
                ]
            )
            == 0
        )

    def test_an_anchor_that_contradicts_the_export_exits_one(
        self, tmp_path: Path, private, capsys
    ) -> None:
        chain, keys_dir, anchor = self._write_anchored(tmp_path, private)
        truncated = [
            json.loads(line) for line in chain.read_text(encoding="utf-8").splitlines() if line
        ][:-1]
        chain.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in truncated), encoding="utf-8"
        )
        assert cli_main([str(chain), "--keys", str(keys_dir), "--anchor", str(anchor)]) == 1
        assert "anchor_not_in_export" in capsys.readouterr().out

    def test_an_unreadable_anchor_is_a_usage_error(self, tmp_path: Path, private) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        bad = tmp_path / "bad.json"
        bad.write_text("[not an object]", encoding="utf-8")
        assert cli_main([str(chain), "--keys", str(keys_dir), "--anchor", str(bad)]) == 2

    def test_require_complete_turns_a_skipped_check_into_a_failure(
        self, tmp_path: Path, private
    ) -> None:
        """What a pipeline needs, because a pipeline reads the exit code only.

        Two inputs have to be present for every check to have run, and
        `--require-complete` now wants both: an instance id, and an anchor. The
        second was added after a real-cloud run found that nine of ten
        tampering mutations were caught and the tenth -- truncation -- had
        nowhere to be caught, because the verifier had no way to accept the
        anchor that would catch it.
        """
        chain, keys_dir, anchor = self._write_anchored(tmp_path, private)
        base = [str(chain), "--keys", str(keys_dir), "--require-complete"]
        assert cli_main(base) == 1, "neither input"
        assert cli_main([*base, "--instance-id", INSTANCE]) == 1, "no anchor"
        assert cli_main([*base, "--anchor", str(anchor)]) == 1, "no instance id"
        assert cli_main([*base, "--instance-id", INSTANCE, "--anchor", str(anchor)]) == 0

    def test_the_json_report_records_the_omission(self, tmp_path: Path, private, capsys) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        cli_main([str(chain), "--keys", str(keys_dir), "--json"])
        report = json.loads(capsys.readouterr().out)
        assert report["ok"] is True
        assert report["complete"] is False
        assert report["genesis_bound_to"] is None
        assert report["anchors"] == 0
        assert report["anchored_through"] is None
        # Two checks did not run: the genesis binding and chain completeness.
        assert len(report["unchecked"]) == 2

    def test_exit_two_when_the_file_is_missing(self, tmp_path: Path) -> None:
        assert cli_main([str(tmp_path / "nope.jsonl"), "--keys", str(tmp_path)]) == 2

    def test_exit_two_when_no_keys_are_usable(self, tmp_path: Path, private) -> None:
        chain, _ = self._write(tmp_path, private)
        empty = tmp_path / "empty"
        empty.mkdir()
        assert cli_main([str(chain), "--keys", str(empty)]) == 2

    def test_a_bad_range_is_a_usage_error(self, tmp_path: Path, private) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        assert cli_main([str(chain), "--keys", str(keys_dir), "--range", "nope"]) == 2

    def test_a_range_narrows_the_export(self, tmp_path: Path, private, capsys) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        # Verifying 1:2 on its own starts above genesis, which is reported.
        assert cli_main([str(chain), "--keys", str(keys_dir), "--range", "1:2"]) == 1
        assert "not_from_genesis" in capsys.readouterr().out

    def test_json_output_is_machine_readable(self, tmp_path: Path, private, capsys) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        cli_main([str(chain), "--keys", str(keys_dir), "--json"])
        assert json.loads(capsys.readouterr().out)["ok"] is True


def test_the_verifier_depends_only_on_cryptography() -> None:
    """SPEC §10.7: an auditor must be able to install this almost anywhere."""
    import ast

    package = Path(__file__).resolve().parents[1] / "qed_verify"
    stdlib_or_allowed = {
        "__future__",
        "argparse",
        "base64",
        "collections",
        "cryptography",
        "dataclasses",
        "decimal",
        "qed_verify",
        "hashlib",
        "json",
        "math",
        "pathlib",
        "sys",
        "typing",
    }
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            roots: set[str] = set()
            if isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots = {node.module.split(".")[0]}
            unexpected = roots - stdlib_or_allowed
            assert not unexpected, f"{path.name} imports {sorted(unexpected)}"
