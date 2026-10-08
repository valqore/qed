"""The evidence format is pinned, and it does not carry the product name.

ADR-0006. Two separate things are checked here.

**Known answers.** The digests below were computed once, outside the package,
and written down. They are not recomputed from the constants, because a test
that recomputes proves nothing: it would pass after a rename and the chains
written yesterday would stop verifying. If one of these fails, the evidence
format changed. That is allowed, but it is a format version bump with a
migration note, never a side effect of a rename.

**No product name.** SPEC §24.1 closed on 2026-10-08 — the product is "Valqore
Gate" — and that changes nothing here. A brand inside a hash domain separator
would make a rename an evidence-compatibility decision instead of a packaging
one, whether or not the brand is settled today. The constants stay
format-scoped and brand-free, and this file is what keeps them that way.
"""

from __future__ import annotations

import hashlib

import pytest
from gate_verify import verify as verifier

from gate.core.evidence import format as fmt
from gate.core.evidence import hashing

# Computed independently and recorded. Do not regenerate from the code.
GENESIS_ACME_PROD = "a4aa4287e70eb8c942c5234b7366120ba2c6e3780ceaf90f08cf6c3915767f99"
PRINCIPAL_ALI = "ff215dac5c51c6dda65b7238c4a26a87e9f0f82643867a2f8117de85227268d3"
PRINCIPAL_NO_ISSUER = "261d2ca718a9f1640f14a9a344b2b0de86e6aeb4eb482c747ab4b813d225779d"


def test_constants_are_the_recorded_byte_strings() -> None:
    assert fmt.CHAIN_FORMAT == "evidence-chain/1"
    assert fmt.GENESIS_DOMAIN == "evidence-chain/1:genesis:"
    assert fmt.PRINCIPAL_DOMAIN == "evidence-chain/1:principal:"


def test_genesis_prev_hash_matches_the_recorded_answer() -> None:
    assert hashing.genesis_prev_hash("acme-prod") == GENESIS_ACME_PROD


def test_principal_hash_matches_the_recorded_answer() -> None:
    assert hashing.principal_hash("ali@acme.com", issuer="https://idp.example") == PRINCIPAL_ALI
    assert hashing.principal_hash("operator") == PRINCIPAL_NO_ISSUER


def test_verifier_carries_the_same_constants() -> None:
    """The verifier reimplements the format; the two copies must not drift.

    `gate_verify` imports nothing from `gate` on purpose (SPEC §10.7), so the
    strings exist twice. This is the check that they are the same strings.
    """
    assert verifier.CHAIN_FORMAT == fmt.CHAIN_FORMAT
    assert verifier.GENESIS_DOMAIN == fmt.GENESIS_DOMAIN
    assert verifier._genesis_prev_hash("acme-prod") == GENESIS_ACME_PROD


@pytest.mark.parametrize(
    "constant",
    [fmt.CHAIN_FORMAT, fmt.GENESIS_DOMAIN, fmt.PRINCIPAL_DOMAIN, verifier.GENESIS_DOMAIN],
)
def test_no_product_name_inside_a_hash_input(constant: str) -> None:
    """Guards the reason these constants were moved out of `hashing.py`.

    The names checked are the settled name's two words plus the candidate that
    lost (SPEC §24.1). A rename must stay a packaging change; if one of these
    words lands in a hash input, it stops being one.
    """
    for name in ("gate", "valqore", "lictor"):
        assert name not in constant.lower()


def test_genesis_still_separates_two_instances() -> None:
    assert hashing.genesis_prev_hash("acme-prod") != hashing.genesis_prev_hash("acme-dev")


def test_principal_domain_separates_from_a_bare_digest() -> None:
    """Without the domain separator, a principal hash would be a plain sha256."""
    assert hashing.principal_hash("ali@acme.com") != hashlib.sha256(b"ali@acme.com").hexdigest()
