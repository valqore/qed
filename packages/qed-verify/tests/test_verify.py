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


@pytest.fixture
def private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def keys(private: Ed25519PrivateKey) -> dict[str, Any]:
    return {key_id_of(private): private.public_key()}


def test_a_handwritten_chain_verifies(private, keys) -> None:
    report = verify_records(make_chain(private), keys, instance_id=INSTANCE)
    assert report.ok, report.summary()
    assert report.complete, report.summary()
    assert report.genesis_bound_to == INSTANCE


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
    # bound against the id the forger chose, this same forgery is "complete".
    circular = verify_records(forged, keys, instance_id=INSTANCE)
    assert circular.complete, "the tautology verifies, which is exactly the point"
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
        assert "bound to the instance id supplied" in out.out
        assert out.err == ""

    def test_require_complete_turns_a_skipped_check_into_a_failure(
        self, tmp_path: Path, private
    ) -> None:
        """What a pipeline needs, because a pipeline reads the exit code only."""
        chain, keys_dir = self._write(tmp_path, private)
        assert cli_main([str(chain), "--keys", str(keys_dir), "--require-complete"]) == 1
        assert (
            cli_main(
                [
                    str(chain),
                    "--keys",
                    str(keys_dir),
                    "--instance-id",
                    INSTANCE,
                    "--require-complete",
                ]
            )
            == 0
        )

    def test_the_json_report_records_the_omission(self, tmp_path: Path, private, capsys) -> None:
        chain, keys_dir = self._write(tmp_path, private)
        cli_main([str(chain), "--keys", str(keys_dir), "--json"])
        report = json.loads(capsys.readouterr().out)
        assert report["ok"] is True
        assert report["complete"] is False
        assert report["genesis_bound_to"] is None
        assert len(report["unchecked"]) == 1

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
