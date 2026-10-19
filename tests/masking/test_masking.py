"""Masking fixtures (SPEC §10.6, ADR-005).

Every case asserts both halves: the secret is gone, and the surrounding text
survives. A redactor that replaces the whole payload passes the first half and
makes the evidence useless.
"""

from __future__ import annotations

import time

import pytest

from qed.core.evidence.masking import mask_payload, mask_text

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
    it rewrites a value qed itself generated -- and the record then attests to
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


class TestADigestIsNotContent:
    """A redactor must not rewrite a value the kernel generated.

    This cost a red CI run before it was understood, and the shape of the
    failure is the reason it is worth this many tests: about one sha256 digest
    in four hundred contains a 13-to-19 digit run that starts with 2-6 and
    passes Luhn. Masking happens *before* ``payload_hash``, so the record
    still verified against its own hash and nothing reported a problem -- the
    checkpoint simply became impossible for anyone to verify, for ever.

    ``params_hash`` and ``policy_hash`` were exposed at the same rate.
    """

    #: A real digest that reproduces it. The run is `2928422540476`.
    POISON = "0ed7e112a9844e97c2928422540476bbfda268f8060f061ffdf8d165b7fb5e0b"

    def test_the_digest_that_broke_a_checkpoint_survives(self) -> None:
        assert mask_text(self.POISON) == self.POISON

    def test_it_survives_as_a_merkle_root_in_a_payload(self) -> None:
        payload = {"from_seq": 0, "to_seq": 5, "merkle_root": self.POISON, "records": 6}
        assert mask_payload(payload)["merkle_root"] == self.POISON

    @pytest.mark.parametrize(
        "key", ["params_hash", "policy_hash", "prev_hash", "payload_hash", "hash"]
    )
    def test_every_digest_field_survives(self, key: str) -> None:
        assert mask_payload({key: self.POISON})[key] == self.POISON

    def test_a_digit_run_glued_to_hex_letters_is_never_a_card(self) -> None:
        """The general fix, independent of which key it sits under: a card
        number in a payload is delimited by whitespace, a quote, a comma or a
        colon, never by a hex letter."""
        assert mask_text("a4111111111111111b") == "a4111111111111111b"

    def test_no_randomly_generated_digest_is_altered(self) -> None:
        """A property test, because the bug was a 1-in-400 accident and a
        fixed example would have been chosen to pass."""
        import secrets

        altered = [
            digest
            for digest in (secrets.token_hex(32) for _ in range(20000))
            if mask_text(digest) != digest
        ]
        assert not altered, altered[:3]

    def test_a_card_number_under_a_digest_key_is_still_masked(self) -> None:
        """The exemption is not a hole. A card number is pure digits, and an
        exempt value has to contain a letter, so no amount of putting one
        under a key called `params_hash` gets it into the chain."""
        assert mask_payload({"params_hash": "4111111111111111"}) == {"params_hash": "[masked:card]"}

    def test_an_email_under_a_digest_key_is_still_masked(self) -> None:
        assert mask_payload({"human_hash": "ali@acme.com"}) == {"human_hash": "[masked:email]"}

    def test_a_key_the_kernel_does_not_own_is_not_exempt(self) -> None:
        """`params_redacted` carries whatever the adapter sent, and the
        exemption is by key name, so the names have to stay kernel-owned."""
        assert mask_payload({"note": "ali@acme.com"}) == {"note": "[masked:email]"}

    def test_a_sequence_number_passes_through(self) -> None:
        assert mask_payload({"seq": 7, "from_seq": 0}) == {"seq": 7, "from_seq": 0}

    def test_a_key_id_keeps_its_prefix(self) -> None:
        assert mask_payload({"key_id": "ed25519:7fbb6319282f9912"}) == {
            "key_id": "ed25519:7fbb6319282f9912"
        }


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


class TestTheBudgetIsNotAClock:
    """The masking budget, asserted as a number rather than left to a comment.

    `REGEX_TIMEOUT` on the predicate side was raised from 100 ms to 1 s in
    ADR-0016, because the `regex` module's budget is wall clock: a loaded
    runner spends it by descheduling the matching thread, so a pattern that
    matches in microseconds times out anyway. Masking was left on the old
    100 ms and failed the same way four days later, on the same runner --
    `mcp-proxy/0.1.0`, fifteen characters, came back `[masked:timeout]`.

    The two budgets guard the same hazard on the same machine, so they are
    pinned to each other here. Changing one alone is the bug this file exists
    to stop happening a third time.
    """

    def test_the_masking_budget_is_wide_enough_to_survive_a_busy_machine(self) -> None:
        from qed.core.evidence.masking import _TIMEOUT

        assert _TIMEOUT >= 1.0

    def test_masking_and_predicates_share_one_budget(self) -> None:
        from qed.core.evidence.masking import _TIMEOUT
        from qed.core.policy.predicates import REGEX_TIMEOUT

        assert _TIMEOUT == REGEX_TIMEOUT, (
            "the evidence redactor and the policy engine bound the same hazard -- a "
            "pattern that will not finish -- under the same wall clock on the same "
            "host. Two numbers that are meant to be one is how masking kept the "
            "100 ms that ADR-0016 had already found too narrow to survive CI."
        )

    def test_the_redactor_asks_twice_before_eating_a_payload(self) -> None:
        """Masking must go through the shared budget, not call `regex` itself.

        The deadline, the per-attempt grant and the retry all live in
        `qed.core.regex_budget` and are tested in `tests/core`. What belongs
        here is that this module uses them: a direct `timeout=_TIMEOUT` would
        pass every test in that file and still corrupt a record on a busy
        host, which is how the two callers drifted apart the first time.
        """
        import inspect

        import qed.core.evidence.masking as m

        source = inspect.getsource(m.mask_text)
        assert "under_budget" in source, (
            "mask_text does not go through the shared budget, so a timeout is believed "
            "the first time it happens and a host stall becomes a permanent "
            "`[masked:timeout]` in the chain"
        )
        assert "timeout=_TIMEOUT" not in source, (
            "mask_text hands a pattern the raw budget, which skips both the retry and "
            "the one-deadline-per-call rule"
        )
