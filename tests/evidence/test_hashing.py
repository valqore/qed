"""Record hashing (SPEC §10.2)."""

from __future__ import annotations

import hashlib

import pytest

from qed.core.evidence import hashing
from qed.core.evidence.record import RESERVED_KEYS, build_record, recompute_hash
from qed.core.schemas import Assurance, EvidenceType, Mode
from qed.infra.keys.file import FileSigner


def test_genesis_prev_hash_binds_the_chain_to_one_instance() -> None:
    assert (
        hashing.genesis_prev_hash("acme-prod")
        == hashlib.sha256(b"evidence-chain/1:genesis:acme-prod").hexdigest()
    )
    assert hashing.genesis_prev_hash("acme-prod") != hashing.genesis_prev_hash("acme-dev")


def test_record_hash_is_the_documented_construction() -> None:
    expected = hashlib.sha256(
        b"\x1f".join([b"1.0", b"7", b"2026-10-07T12:00:00.000Z", b"verdict", b"aa", b"bb"])
    ).hexdigest()
    assert (
        hashing.record_hash(
            schema_version="1.0",
            seq=7,
            ts="2026-10-07T12:00:00.000Z",
            type_="verdict",
            payload_hash_hex="aa",
            prev_hash="bb",
        )
        == expected
    )


@pytest.mark.parametrize(
    "changed",
    [
        {"seq": 8},
        {"ts": "2026-10-07T12:00:00.001Z"},
        {"type_": "proposal"},
        {"payload_hash_hex": "ab"},
        {"prev_hash": "bc"},
        {"schema_version": "1.1"},
    ],
)
def test_every_hashed_field_changes_the_hash(changed: dict[str, object]) -> None:
    base = {
        "schema_version": "1.0",
        "seq": 7,
        "ts": "2026-10-07T12:00:00.000Z",
        "type_": "verdict",
        "payload_hash_hex": "aa",
        "prev_hash": "bb",
    }
    assert hashing.record_hash(**base) != hashing.record_hash(**{**base, **changed})  # type: ignore[arg-type]


def test_no_hashed_field_can_contain_the_separator() -> None:
    """0x1F joining is only unambiguous because no field can contain 0x1F.

    ``schema_version`` is a literal, ``type`` is a closed enum, ``seq`` is an
    int and the two hashes are hex. ``ts`` is machine-formatted. This test
    pins that property so that widening any of those types fails here first.
    """
    from qed.core.schemas import SCHEMA_VERSION, EvidenceType, rfc3339_ms, utcnow

    fields = [SCHEMA_VERSION, rfc3339_ms(utcnow()), *(t.value for t in EvidenceType)]
    assert all("\x1f" not in field for field in fields)


class TestBuildRecord:
    def test_reserved_keys_are_refused(self, signer: FileSigner) -> None:
        for key in sorted(RESERVED_KEYS):
            with pytest.raises(ValueError, match="reserved"):
                build_record(
                    seq=1,
                    prev_hash="00",
                    type_=EvidenceType.proposal,
                    assurance=Assurance.kernel,
                    payload={key: "spoofed"},
                    signer=signer,
                )

    def test_metadata_is_inside_the_payload_so_it_is_hashed(self, signer: FileSigner) -> None:
        record = build_record(
            seq=1,
            prev_hash="00",
            type_=EvidenceType.verdict,
            assurance=Assurance.kernel,
            payload={"x": 1},
            signer=signer,
            mode=Mode.shadow,
        )
        assert record.payload is not None
        assert record.payload["_assurance"] == "kernel"
        assert record.payload["_mode"] == "shadow"
        assert record.payload["_key_id"] == signer.key_id
        assert record.payload["_dev"] is False
        assert hashing.payload_hash(record.payload) == record.payload_hash

    def test_hash_recomputes_from_the_record_alone(self, signer: FileSigner) -> None:
        record = build_record(
            seq=0,
            prev_hash=hashing.genesis_prev_hash("t"),
            type_=EvidenceType.genesis,
            assurance=Assurance.kernel,
            payload={"instance_id": "t"},
            signer=signer,
        )
        assert recompute_hash(record) == record.hash

    def test_signature_covers_the_hash_bytes(self, signer: FileSigner) -> None:
        from qed.core.evidence.signing import verify_signature

        record = build_record(
            seq=3,
            prev_hash="ff",
            type_=EvidenceType.proposal,
            assurance=Assurance.adapter,
            payload={"a": "b"},
            signer=signer,
        )
        assert verify_signature(signer.public_key, bytes.fromhex(record.hash), record.sig)

    def test_secrets_are_masked_before_hashing(self, signer: FileSigner) -> None:
        record = build_record(
            seq=1,
            prev_hash="00",
            type_=EvidenceType.proposal,
            assurance=Assurance.kernel,
            payload={"note": "token is ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
            signer=signer,
        )
        assert record.payload is not None
        assert "ghp_" not in str(record.payload["note"])
        assert "[masked:github_token]" in str(record.payload["note"])
