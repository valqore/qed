"""Mandate signing and verification (SPEC §6.5, §3.4). Pure.

A mandate is the answer to "who authorised this agent to act while nobody was
watching". It is the only thing standing between an unattended service identity
and QED refusing it outright (§6.1 step 5, AG-IDN-007), so it has to be
something an auditor can check without trusting the instance that stored it —
which means signed, with the signature covering the whole document.

What is signed
--------------

The RFC 8785 canonical form of the mandate **without** its ``signature`` field
and **without** ``revoked_at``.

Leaving ``signature`` out is obvious: a signature cannot cover itself.
Leaving ``revoked_at`` out is the less obvious half. Revocation is an act of
QED, recorded in the evidence chain, not an edit the original signer
authorised — so a revoked mandate must still verify against the signature the
issuer produced. Including it would mean revoking a mandate destroyed the proof
of who granted it, which is exactly the record an investigation needs.
"""

from __future__ import annotations

from datetime import datetime

from qed.core import jcs
from qed.core.evidence.format import CHAIN_FORMAT
from qed.core.evidence.signing import b64u_decode
from qed.core.schemas import Mandate, MandateSignature

__all__ = [
    "MANDATE_DOMAIN",
    "MandateError",
    "canonical_mandate",
    "is_active",
    "signing_payload",
    "verify_mandate",
]

#: Domain separator. Without one, a mandate's signing payload and some other
#: canonical JSON of the same shape would be interchangeable.
MANDATE_DOMAIN = f"{CHAIN_FORMAT}:mandate:"

#: Only Ed25519, matching the evidence chain. There is no algorithm field to
#: read from the document, for the same reason there is none in the token path.
MANDATE_ALG = "Ed25519"

_UNSIGNED_FIELDS = ("signature", "revoked_at")


class MandateError(Exception):
    """A mandate is unsigned, signed by an unknown key, or tampered with."""

    rule_id = "AG-IDN-006"


def canonical_mandate(mandate: Mandate) -> str:
    """The RFC 8785 canonical JSON of everything the signature covers."""
    document = mandate.model_dump(mode="json", by_alias=True)
    for field in _UNSIGNED_FIELDS:
        document.pop(field, None)
    return jcs.dumps(document)


def signing_payload(mandate: Mandate) -> bytes:
    """The exact bytes a signer signs and a verifier checks."""
    return (MANDATE_DOMAIN + canonical_mandate(mandate)).encode("utf-8")


def verify_mandate(mandate: Mandate, public_keys: dict[str, object]) -> None:
    """Raise :class:`MandateError` unless the signature is present and valid.

    ``public_keys`` maps ``key_id`` to an Ed25519 public key. An unknown
    ``key_id`` is a failure rather than a skip: a mandate signed by a key this
    instance does not hold is a mandate it cannot vouch for, and treating that
    as "probably fine" is how an unsigned document gets accepted.
    """
    signature: MandateSignature | None = mandate.signature
    if signature is None:
        raise MandateError(
            f"mandate {mandate.id} carries no signature; an unattended agent's "
            "authority has to be something an auditor can check"
        )
    if signature.alg != MANDATE_ALG:
        raise MandateError(
            f"mandate {mandate.id} is signed with {signature.alg!r}; only {MANDATE_ALG} is accepted"
        )
    key = public_keys.get(signature.key_id)
    if key is None:
        raise MandateError(
            f"mandate {mandate.id} is signed by {signature.key_id}, which this "
            "instance does not hold; export the signer's public key to the "
            "`public/` directory before using it"
        )
    try:
        # base64url without padding, the same encoding every other signature in
        # this codebase uses. One encoding everywhere is one fewer thing for a
        # verifier written by somebody else to get wrong.
        key.verify(b64u_decode(signature.sig), signing_payload(mandate))  # type: ignore[attr-defined]
    except Exception as exc:
        raise MandateError(f"mandate {mandate.id} does not match its signature: {exc}") from exc


def is_active(mandate: Mandate, *, now: datetime) -> bool:
    """Inside its window and not revoked. Signature validity is separate."""
    if mandate.revoked_at is not None and mandate.revoked_at <= now:
        return False
    return mandate.valid.from_ <= now <= mandate.valid.until
