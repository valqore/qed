"""Masking at write (SPEC §10.6, ADR-005).

Applied to every payload before it is hashed, so the chain never contains the
raw value and no later purge is needed to remove it. Because masking happens
*before* ``payload_hash``, changing this module changes record hashes — treat
the pattern set as part of the evidence format.

Patterns run through the ``regex`` module with an evaluation timeout (SPEC §17).
If a pattern times out the whole string is replaced rather than passed through:
failing closed is the only safe direction for a redactor.
"""

from __future__ import annotations

from typing import Literal

import regex

__all__ = ["MaskingProfile", "mask_payload", "mask_text"]

MaskingProfile = Literal["default", "strict"]

_TIMEOUT = 0.1


def _p(pattern: str) -> regex.Pattern[str]:
    return regex.compile(pattern)


# Ordered. Structured forms first so that a labelled secret is caught by its
# label before a generic token pattern gets a chance to half-match it.
_RULES: list[tuple[regex.Pattern[str], str]] = [
    (
        _p(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[masked:private_key]",
    ),
    (
        _p(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"client[_-]?secret|authorization)\b(\s*[=:]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1\2[masked:secret]",
    ),
    (_p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), "[masked:aws_key_id]"),
    (_p(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[masked:github_token]"),
    (_p(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[masked:github_token]"),
    (_p(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[masked:slack_token]"),
    (
        _p(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
        "[masked:jwt]",
    ),
    (_p(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4}\b"), "[masked:iban]"),
    (_p(r"[\w.+-]+@[\w-]+\.[\w.-]*\w"), "[masked:email]"),
    (_p(r"(?<![\w.])\+\d{8,15}(?![\w.])"), "[masked:phone]"),
    (_p(r"(?<!\d)\d{3}[-.]\d{3}[-.]\d{4}(?!\d)"), "[masked:phone]"),
]

_STRICT_RULES: list[tuple[regex.Pattern[str], str]] = [
    (_p(r"\b[0-9a-fA-F]{32,}\b"), "[masked:hex_blob]"),
    (_p(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "[masked:base64_blob]"),
]

_CARD = _p(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

#: First digit of every live card range: Mastercard's 2221-2720, Amex 34/37,
#: Visa 4, Mastercard 51-55, Discover/JCB/UnionPay/Maestro 6x.
_CARD_PREFIXES = frozenset("23456")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _looks_like_a_card(digits: str) -> bool:
    """Luhn alone is not enough to call a digit run a card number.

    Luhn is a checksum, not an identifier: one run in ten passes it by chance,
    and a run of eighteen zeros passes it exactly (the sum is zero, and zero is
    divisible by ten). That is not hypothetical. The ULID-shaped
    ``token_jti`` ``01JB000000000000000000JTI0`` contains such a run, so before
    this check every proposal carrying one had its token id rewritten to
    ``01JB[masked:card]JTI0`` *inside the chain* -- after which the recorded
    token no longer matched the token the budget ledger and the API's
    ``GET /v1/proposals/{id}`` know about, and a corrupted identifier looked
    exactly like a redacted one.

    Two cheap conditions fix it without weakening the real check: no issued card
    has every digit the same, and none starts outside :data:`_CARD_PREFIXES`.
    """
    if len(set(digits)) == 1:
        return False
    if digits[0] not in _CARD_PREFIXES:
        return False
    return _luhn_ok(digits)


def _mask_cards(text: str) -> str:
    def repl(m: regex.Match[str]) -> str:
        # str() throughout: the `regex` module ships no type information, so
        # without it every return here is Any and mypy --strict stops checking.
        digits = str(regex.sub(r"\D", "", str(m.group(0))))
        if 13 <= len(digits) <= 19 and _looks_like_a_card(digits):
            return "[masked:card]"
        return str(m.group(0))

    return str(_CARD.sub(repl, text, timeout=_TIMEOUT))


def mask_text(text: str, profile: MaskingProfile = "default") -> str:
    """Mask secrets and personal data in a single string."""
    rules = _RULES + _STRICT_RULES if profile == "strict" else _RULES
    try:
        out = text
        for pattern, replacement in rules:
            out = pattern.sub(replacement, out, timeout=_TIMEOUT)
        return _mask_cards(out)
    except TimeoutError:
        return "[masked:timeout]"


def mask_payload(value: object, profile: MaskingProfile = "default", _depth: int = 0) -> object:
    """Recursively mask a payload. Keys are masked too — they can carry values."""
    if _depth > 100:
        raise ValueError("payload nested deeper than 100 levels")
    if isinstance(value, str):
        return mask_text(value, profile)
    if isinstance(value, dict):
        return {
            mask_text(str(k), profile): mask_payload(v, profile, _depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [mask_payload(v, profile, _depth + 1) for v in value]
    return value
