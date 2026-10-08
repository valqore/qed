"""Masking fixtures (SPEC §10.6, ADR-005).

Every case asserts both halves: the secret is gone, and the surrounding text
survives. A redactor that replaces the whole payload passes the first half and
makes the evidence useless.
"""

from __future__ import annotations

import pytest

from gate.core.evidence.masking import mask_payload, mask_text

CASES = [
    ("email", "ping ali.celik@acme.com now", "ali.celik@acme.com", "[masked:email]"),
    (
        "aws_key_id",
        "key AKIAIOSFODNN7EXAMPLE used",
        "AKIAIOSFODNN7EXAMPLE",
        "[masked:aws_key_id]",
    ),
    (
        "github_token",
        "auth ghp_abcdefghijklmnopqrstuvwxyz0123456789 end",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "[masked:github_token]",
    ),
    (
        "github_pat",
        "auth github_pat_11ABCDEFG0abcdefghij_KLMNOP end",
        "github_pat_11ABCDEFG0abcdefghij_KLMNOP",
        "[masked:github_token]",
    ),
    (
        "slack_token",
        "bot xoxb-1234567890-abcdefghij end",
        "xoxb-1234567890-abcdefghij",
        "[masked:slack_token]",
    ),
    (
        "jwt",
        "bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM end",
        "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM",
        "[masked:jwt]",
    ),
    (
        "private_key",
        "cert -----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJB-----END RSA PRIVATE KEY----- end",
        "MIIBOgIBAAJB",
        "[masked:private_key]",
    ),
    (
        "password_assignment",
        "psql password=hunter2 --host db",
        "hunter2",
        "[masked:secret]",
    ),
    (
        "api_key_assignment",
        'config api_key: "sk-live-abcdef" done',
        "sk-live-abcdef",
        "[masked:secret]",
    ),
    ("iban", "pay DE89 3704 0044 0532 0130 00 now", "3704", "[masked:iban]"),
    ("phone_e164", "call +905321234567 now", "+905321234567", "[masked:phone]"),
    ("phone_dashed", "call 415-555-0132 now", "415-555-0132", "[masked:phone]"),
    ("credit_card", "card 4111 1111 1111 1111 charged", "4111", "[masked:card]"),
]


@pytest.mark.parametrize(("name", "text", "secret", "marker"), CASES, ids=[c[0] for c in CASES])
def test_secret_is_removed_and_context_survives(
    name: str, text: str, secret: str, marker: str
) -> None:
    masked = mask_text(text)
    assert secret not in masked, f"{name}: secret survived"
    assert marker in masked, f"{name}: expected {marker}, got {masked!r}"
    assert masked.split()[0] == text.split()[0], f"{name}: lost leading context"
    assert masked.endswith(text.rsplit(" ", 1)[-1]), f"{name}: lost trailing context"


def test_a_number_that_fails_luhn_is_not_a_card() -> None:
    assert "[masked:card]" not in mask_text("order 1234567890123456 shipped")


class TestLuhnAloneIsNotEnough:
    """Luhn is a checksum, not an identifier: one run in ten passes by chance.

    Over-masking is not the harmless direction it sounds like. The chain is
    masked *before* it is hashed, so a false positive does not redact a secret,
    it rewrites a value gate itself generated -- and the record then attests to
    something nothing else in the system has.
    """

    def test_a_run_of_zeros_is_not_a_card(self) -> None:
        """Eighteen zeros pass Luhn exactly: the sum is 0, and 0 % 10 == 0."""
        assert "[masked:card]" not in mask_text("id 000000000000000000 ok")

    @pytest.mark.parametrize("digit", list("0123456789"))
    def test_no_run_of_one_repeated_digit_is_a_card(self, digit: str) -> None:
        assert "[masked:card]" not in mask_text(f"id {digit * 16} ok")

    def test_a_ulid_shaped_token_id_survives(self) -> None:
        """The exact value that was being corrupted in every proposal record."""
        token = "01JB000000000000000000JTI0"
        assert mask_text(f"token_jti {token}") == f"token_jti {token}"

    @pytest.mark.parametrize(
        "number",
        [
            "4111111111111111",  # Visa
            "5500005555555559",  # Mastercard
            "2221000000000009",  # Mastercard 2-series
            "378282246310005",  # Amex
            "6011111111111117",  # Discover
        ],
    )
    def test_real_card_ranges_are_still_masked(self, number: str) -> None:
        assert mask_text(f"card {number} charged") == "card [masked:card] charged"

    def test_a_luhn_valid_number_outside_every_card_range_is_not_masked(self) -> None:
        """No issued card starts with 0, 1, 7, 8 or 9."""
        assert "[masked:card]" not in mask_text("ref 0000000000000018 ok")
        assert "[masked:card]" not in mask_text("ref 1234567812345670 ok")


def test_ordinary_text_is_untouched() -> None:
    text = "restart the worker pool in staging, then re-run the migration"
    assert mask_text(text) == text


def test_masking_is_idempotent() -> None:
    once = mask_text("mail ali@acme.com")
    assert mask_text(once) == once


def test_strict_profile_also_masks_opaque_blobs() -> None:
    text = "state " + "a1" * 24
    assert "[masked:hex_blob]" not in mask_text(text)
    assert "[masked:hex_blob]" in mask_text(text, "strict")


def test_payload_is_masked_recursively_including_keys() -> None:
    payload = {
        "ali@acme.com": {"items": ["key AKIAIOSFODNN7EXAMPLE", 42, True, None]},
        "safe": "value",
    }
    masked = mask_payload(payload)
    rendered = repr(masked)
    assert "ali@acme.com" not in rendered
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
    assert "value" in rendered
    assert "42" in rendered


def test_non_string_scalars_pass_through_unchanged() -> None:
    assert mask_payload({"n": 7, "b": False, "z": None}) == {"n": 7, "b": False, "z": None}


def test_absurdly_nested_payloads_are_refused() -> None:
    value: object = "x"
    for _ in range(120):
        value = {"k": value}
    with pytest.raises(ValueError, match="nested"):
        mask_payload(value)
