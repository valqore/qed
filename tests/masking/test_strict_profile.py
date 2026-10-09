"""The `strict` masking profile, and what it must not touch (SPEC §10.9, week 7).

`strict` adds two patterns to the default set: any hex run of 32 characters or
more, and any base64 run of 40 or more. They exist for the payload nobody
anticipated — a dumped token, an inlined certificate, a blob of credentials
with no recognisable shape — and they are deliberately blunt.

Blunt enough to be dangerous, which is what most of this file is about.
**Masking runs before `payload_hash`**, so a false positive does not redact a
secret: it rewrites a value the kernel itself produced, the record still
verifies against its own hash, and nothing reports a problem. The chain stays
internally consistent while having quietly lost the thing it was written to
say.

Two such values exist, both added in week 7, and both would have been eaten:

* a `key_rotated`'s `new_public_pem`, which is how an auditor holding only the
  old public key follows the chain across a rotation. Under `strict` the PEM's
  body is a base64 run.
* a checkpoint receipt's `sha256`, which is what makes a published anchor
  checkable rather than merely claimed. Under `strict` it is a hex run.

The fix is `STRUCTURAL_TYPES`: the record types whose payloads the kernel
writes are not masked at all. The same set retention may not purge, for the
same reason — they are how the chain is read, not data it happens to carry.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from qed.core.evidence.masking import mask_payload, mask_text
from qed.core.evidence.record import build_record
from qed.core.evidence.retention import NEVER_PURGE
from qed.core.schemas import STRUCTURAL_TYPES, Assurance, EvidenceType
from qed.infra.keys.file import FileSigner
from qed.runtime import open_session, rotate_signing_key

PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAx7BqA0NTsXSKl1K1Jz9kQWx3eLm5pQ8vZ2nR4tYuIoA=\n"
    "-----END PUBLIC KEY-----\n"
)
DIGEST = "a3f1" * 16


def given(built) -> dict[str, object]:  # type: ignore[no-untyped-def]
    """The payload as it was passed in, without the fields `build_record` adds.

    `_assurance`, `_mode`, `_enforcement`, `_dev` and `_key_id` are hashed with
    the payload but are not part of it.
    """
    return {key: value for key, value in (built.payload or {}).items() if not key.startswith("_")}


def record(type_: EvidenceType, payload: dict[str, object], profile: str = "strict"):  # type: ignore[no-untyped-def]
    return build_record(
        seq=1,
        prev_hash="0" * 64,
        type_=type_,
        assurance=Assurance.kernel,
        payload=payload,
        signer=FileSigner.generate(),
        masking=profile,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------
# What strict adds
# --------------------------------------------------------------------------


class TestTheBluntPatterns:
    def test_a_hex_blob_is_masked(self) -> None:
        assert "[masked:hex_blob]" in mask_text(f"blob={DIGEST}", "strict")

    def test_a_base64_blob_is_masked(self) -> None:
        text = "data=" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
        assert "[masked:base64_blob]" in mask_text(text, "strict")

    def test_the_default_profile_leaves_both_alone(self) -> None:
        """They are too blunt to be the default. A chain full of
        `[masked:hex_blob]` would be a chain nobody could read."""
        assert DIGEST in mask_text(f"blob={DIGEST}", "default")

    def test_strict_still_masks_everything_the_default_does(self) -> None:
        text = "contact alice@example.com password=hunter2"
        strict = mask_text(text, "strict")
        assert "[masked:email]" in strict
        assert "[masked:secret]" in strict

    def test_a_short_hex_run_survives(self) -> None:
        """A commit sha, a request id, a correlation id. The threshold is 32
        because that is where a value stops looking like an identifier
        somebody chose and starts looking like a dumped blob."""
        assert "abc123def4567890" in mask_text("commit=abc123def4567890", "strict")


# --------------------------------------------------------------------------
# What it must not touch
# --------------------------------------------------------------------------


class TestStructuralRecordsAreNotMaskedAtAll:
    def test_the_set_is_the_one_retention_protects(self) -> None:
        """Deliberately the same list. Two would be two to keep in step, and
        the reason is identical: these payloads are how the chain is read."""
        assert NEVER_PURGE == STRUCTURAL_TYPES

    def test_a_rotation_keeps_its_public_key(self) -> None:
        """The value the record exists to carry. Masked, an auditor holding
        only the first public key loses the thread at the rotation -- and the
        record still verifies against its own hash, so nothing says so."""
        built = record(EvidenceType.key_rotated, {"new_public_pem": PEM})
        assert (built.payload or {})["new_public_pem"] == PEM

    def test_a_checkpoint_keeps_its_receipt_proofs(self) -> None:
        """The sha256 is what makes a published anchor checkable rather than
        merely claimed."""
        payload = {
            "merkle_root": "b4" * 32,
            "previous_receipts": [{"publisher": "file", "proof": {"sha256": DIGEST}}],
        }
        built = record(EvidenceType.checkpoint, payload)
        receipts = (built.payload or {})["previous_receipts"]
        assert receipts[0]["proof"]["sha256"] == DIGEST  # type: ignore[index]

    def test_a_checkpoint_keeps_its_merkle_root(self) -> None:
        built = record(EvidenceType.checkpoint, {"merkle_root": "b4" * 32})
        assert (built.payload or {})["merkle_root"] == "b4" * 32

    def test_an_admin_action_keeps_its_report(self) -> None:
        payload = {"action": "retention_purge", "purged": 4, "to_seq": 19}
        built = record(EvidenceType.admin_action, dict(payload))
        assert given(built) == payload

    @pytest.mark.parametrize("type_", sorted(STRUCTURAL_TYPES, key=lambda t: t.value))
    def test_none_of_them_is_touched(self, type_: EvidenceType) -> None:
        payload = {"blob": DIGEST, "pem": PEM, "note": "alice@example.com"}
        built = record(type_, dict(payload))
        assert given(built) == payload

    def test_everything_else_still_is(
        self,
    ) -> None:
        """The exemption is by record type, not a general escape. A proposal is
        an agent's description of an action and gets the full treatment."""
        built = record(EvidenceType.proposal, {"blob": DIGEST, "who": "alice@example.com"})
        payload = built.payload or {}
        assert payload["blob"] == "[masked:hex_blob]"
        assert payload["who"] == "[masked:email]"

    def test_a_verdict_is_masked_too(self) -> None:
        built = record(EvidenceType.verdict, {"reason": f"saw {DIGEST}"})
        assert "[masked:hex_blob]" in str((built.payload or {})["reason"])


class TestTheStructuralKeyExemptionStillWorks:
    """`mask_payload` has a second, narrower exemption: a kernel identifier
    under a kernel-owned key. It predates this one (it was added after masking
    rewrote a sha256 digest and broke a checkpoint) and still matters, because
    a non-structural record can carry a `policy_hash`."""

    def test_a_hash_under_a_kernel_key_survives_strict(self) -> None:
        masked = mask_payload({"policy_hash": DIGEST}, "strict")
        assert masked == {"policy_hash": DIGEST}

    def test_the_same_value_under_an_ordinary_key_does_not(self) -> None:
        masked = mask_payload({"whatever": DIGEST}, "strict")
        assert masked == {"whatever": "[masked:hex_blob]"}

    def test_a_pure_digit_run_is_never_exempted(self) -> None:
        """So a card number cannot be hidden from the redactor by putting it
        under a key called `params_hash`."""
        masked = mask_payload({"params_hash": "4111111111111111"}, "strict")
        assert masked == {"params_hash": "[masked:card]"}


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------


class TestAStrictInstance:
    def test_a_rotation_under_strict_is_still_followable(
        self, qed_dir: Path, tmp_path: Path
    ) -> None:
        """The whole bug, end to end: rotate on a strict instance, export, and
        check an auditor can read the incoming key out of the chain."""
        config = tmp_path / "qed.yaml"
        config.write_text(yaml.safe_dump({"evidence": {"masking": "strict"}}), encoding="utf-8")
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            rotation = rotate_signing_key(session)
            payload = rotation.record.payload or {}
            active = session.signer.public_pem
        finally:
            session.close()

        assert payload["new_public_pem"] == active
        assert "masked" not in str(payload["new_public_pem"])

    def test_the_chain_verifies_under_strict(self, qed_dir: Path, tmp_path: Path) -> None:
        from qed_verify.verify import load_jsonl, verify_records

        from qed.core.evidence.export.jsonl import to_jsonl
        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys
        from qed.infra.maintenance import maintain

        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "evidence": {
                        "masking": "strict",
                        "checkpoint": {
                            "publishers": [{"type": "file", "path": str(tmp_path / "anchors")}]
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        session = open_session(directory=qed_dir, config_path=config, strict_policy=False)
        try:
            session.writer.append(
                type_=EvidenceType.proposal,
                assurance=Assurance.kernel,
                payload={"blob": DIGEST},
            )
            maintain(session, force_checkpoint=True)
            rotate_signing_key(session)
            maintain(session, force_checkpoint=True)
            records = load_jsonl(to_jsonl(session.store.iter_evidence()))
        finally:
            session.close()

        report = verify_records(records, load_public_keys(qed_dir / PUBLIC_DIR_NAME))
        assert report.ok, report.summary()
        assert report.checkpoints == 2
        assert len(report.keys_used) == 2
