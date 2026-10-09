"""Mandate signing, storage and revocation (SPEC §6.5)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from qed.core.mandates import (
    MANDATE_ALG,
    MandateError,
    canonical_mandate,
    is_active,
    signing_payload,
    verify_mandate,
)
from qed.core.schemas import Mandate, MandateSignature
from qed.infra.keys.file import FileSigner
from qed.infra.storage.sqlite import SqliteStore

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
EXAMPLE = Path(__file__).parents[2] / "examples/mandates/sre-agent.json"


@pytest.fixture
def unsigned() -> Mandate:
    return Mandate.model_validate_json(EXAMPLE.read_text(encoding="utf-8"))


@pytest.fixture
def signer() -> FileSigner:
    return FileSigner.generate()


@pytest.fixture
def public(signer: FileSigner) -> dict[str, object]:
    return {signer.key_id: load_pem_public_key(signer.public_pem.encode())}


def sign(mandate: Mandate, signer: FileSigner) -> Mandate:
    return mandate.model_copy(
        update={
            "signature": MandateSignature(
                key_id=signer.key_id, alg=MANDATE_ALG, sig=signer.sign(signing_payload(mandate))
            )
        }
    )


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SqliteStore]:
    with SqliteStore(tmp_path / "qed.db") as opened:
        yield opened


class TestWhatIsSigned:
    def test_the_signature_field_is_not_part_of_its_own_input(
        self, unsigned: Mandate, signer: FileSigner
    ) -> None:
        signed = sign(unsigned, signer)
        assert canonical_mandate(signed) == canonical_mandate(unsigned)

    def test_revocation_is_not_part_of_the_signed_input(
        self, unsigned: Mandate, signer: FileSigner
    ) -> None:
        """The whole point: revoking a mandate must not destroy the proof of
        who granted the authority."""
        revoked = unsigned.model_copy(update={"revoked_at": NOW})
        assert canonical_mandate(revoked) == canonical_mandate(unsigned)

    def test_the_payload_is_domain_separated(self, unsigned: Mandate) -> None:
        assert signing_payload(unsigned).startswith(b"evidence-chain/1:mandate:")

    def test_every_other_field_is_covered(
        self, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        signed = sign(unsigned, signer)
        for field, value in (
            ("purpose", "something else"),
            ("for_agent", "svc:someone-else"),
            ("issued_by_hash", "b" * 64),
        ):
            tampered = signed.model_copy(update={field: value})
            with pytest.raises(MandateError, match="does not match"):
                verify_mandate(tampered, public)

    def test_narrowing_the_allowed_envelope_breaks_the_signature(
        self, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        """Even a change that looks like a tightening is still a change to a
        document somebody signed."""
        signed = sign(unsigned, signer)
        widened = signed.model_copy(
            update={"allowed": signed.allowed.model_copy(update={"environments": ["prod", "dev"]})}
        )
        with pytest.raises(MandateError):
            verify_mandate(widened, public)


class TestVerification:
    def test_a_signed_mandate_verifies(
        self, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        verify_mandate(sign(unsigned, signer), public)

    def test_an_unsigned_mandate_is_refused(
        self, unsigned: Mandate, public: dict[str, object]
    ) -> None:
        with pytest.raises(MandateError, match="no signature"):
            verify_mandate(unsigned, public)

    def test_an_unknown_signing_key_is_a_failure_not_a_skip(
        self, unsigned: Mandate, signer: FileSigner
    ) -> None:
        """Treating "I don't have that key" as "probably fine" is how an
        unsigned document gets accepted."""
        with pytest.raises(MandateError, match="does not hold"):
            verify_mandate(sign(unsigned, signer), {})

    def test_another_partys_key_does_not_verify(
        self, unsigned: Mandate, signer: FileSigner
    ) -> None:
        other = FileSigner.generate()
        public = {signer.key_id: load_pem_public_key(other.public_pem.encode())}
        with pytest.raises(MandateError, match="does not match"):
            verify_mandate(sign(unsigned, signer), public)

    def test_an_unexpected_algorithm_is_refused(
        self, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        signed = sign(unsigned, signer)
        assert signed.signature is not None
        swapped = signed.model_copy(
            update={"signature": signed.signature.model_copy(update={"alg": "HS256"})}
        )
        with pytest.raises(MandateError, match="only Ed25519"):
            verify_mandate(swapped, public)

    def test_a_revoked_mandate_still_verifies(
        self, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        signed = sign(unsigned, signer)
        verify_mandate(signed.model_copy(update={"revoked_at": NOW}), public)


class TestIsActive:
    def test_inside_the_window(self, unsigned: Mandate) -> None:
        assert is_active(unsigned, now=NOW) is True

    def test_before_it_starts(self, unsigned: Mandate) -> None:
        assert is_active(unsigned, now=unsigned.valid.from_ - timedelta(days=1)) is False

    def test_after_it_ends(self, unsigned: Mandate) -> None:
        assert is_active(unsigned, now=unsigned.valid.until + timedelta(days=1)) is False

    def test_revoked_in_the_past(self, unsigned: Mandate) -> None:
        assert is_active(unsigned.model_copy(update={"revoked_at": NOW}), now=NOW) is False

    def test_a_future_revocation_has_not_taken_effect_yet(self, unsigned: Mandate) -> None:
        later = unsigned.model_copy(update={"revoked_at": NOW + timedelta(days=1)})
        assert is_active(later, now=NOW) is True


class TestStore:
    def test_a_stored_mandate_round_trips_byte_identically(
        self, store: SqliteStore, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        """If storage changed a single byte the signature would stop verifying,
        and a signature that no longer verifies is indistinguishable from a
        forged one."""
        signed = sign(unsigned, signer)
        store.record_mandate(signed, created_at=NOW)
        loaded = store.load_mandate(signed.id)
        assert loaded is not None
        verify_mandate(loaded, public)

    def test_an_unknown_id_is_none(self, store: SqliteStore) -> None:
        assert store.load_mandate("md_nope") is None

    def test_listing_filters_by_agent(
        self, store: SqliteStore, unsigned: Mandate, signer: FileSigner
    ) -> None:
        store.record_mandate(sign(unsigned, signer), created_at=NOW)
        assert len(store.list_mandates(for_agent="svc:sre-agent")) == 1
        assert store.list_mandates(for_agent="svc:other") == []

    def test_revocation_does_not_touch_the_signed_document(
        self, store: SqliteStore, unsigned: Mandate, signer: FileSigner, public: dict[str, object]
    ) -> None:
        signed = sign(unsigned, signer)
        store.record_mandate(signed, created_at=NOW)
        assert store.revoke_mandate(signed.id, at=NOW, by_hash="a" * 64, reason="done") is True
        loaded = store.load_mandate(signed.id)
        assert loaded is not None
        assert loaded.revoked_at is not None
        verify_mandate(loaded, public)

    def test_revoking_twice_reports_that_it_was_already_revoked(
        self, store: SqliteStore, unsigned: Mandate, signer: FileSigner
    ) -> None:
        signed = sign(unsigned, signer)
        store.record_mandate(signed, created_at=NOW)
        store.revoke_mandate(signed.id, at=NOW, by_hash=None, reason="first")
        assert store.revoke_mandate(signed.id, at=NOW, by_hash=None, reason="again") is False

    def test_the_revocation_time_comes_back_as_a_datetime(
        self, store: SqliteStore, unsigned: Mandate, signer: FileSigner
    ) -> None:
        """`model_copy` does not validate, so an earlier version handed back a
        raw string here and every comparison against it raised TypeError."""
        signed = sign(unsigned, signer)
        store.record_mandate(signed, created_at=NOW)
        store.revoke_mandate(signed.id, at=NOW, by_hash=None, reason="x")
        loaded = store.load_mandate(signed.id)
        assert loaded is not None
        assert isinstance(loaded.revoked_at, datetime)
        assert is_active(loaded, now=NOW) is False
