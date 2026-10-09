"""RFC 8785 canonical JSON — verifier-side implementation.

Deliberately a second implementation rather than an import from `qed.core`.
If the producer and the verifier shared this code, a canonicalisation bug would
produce a chain that verifies perfectly against itself and against nothing else,
which is the one failure mode an independent verifier exists to catch.

``tests/core/test_jcs_agreement.py`` in the kernel repository runs both
implementations over the same corpus and fails the build if they ever disagree.
"""

from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

__all__ = ["canonicalize", "dumps", "sha256_hex"]

_SHORT = {
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


def _string(text: str) -> str:
    pieces = ['"']
    for ch in text:
        if ch in _SHORT:
            pieces.append(_SHORT[ch])
        elif ord(ch) < 0x20:
            pieces.append(f"\\u{ord(ch):04x}")
        else:
            pieces.append(ch)
    pieces.append('"')
    return "".join(pieces)


def _number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("integer outside the safe double range")
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not JSON numbers")
    if value == 0.0:
        return "0"
    dec = Decimal(repr(value))
    exponent = dec.adjusted()
    if -7 < exponent < 21:
        text = format(dec, "f")
        return text.rstrip("0").rstrip(".") if "." in text else text
    sign, digits, _ = dec.as_tuple()
    mantissa = "".join(map(str, digits)).rstrip("0") or "0"
    if len(mantissa) > 1:
        mantissa = mantissa[0] + "." + mantissa[1:]
    prefix = "-" if sign else ""
    marker = "+" if exponent >= 0 else "-"
    return f"{prefix}{mantissa}e{marker}{abs(exponent)}"


def dumps(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int | float):
        return _number(value)
    if isinstance(value, list | tuple):
        return "[" + ",".join(dumps(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: str(k).encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(f"{_string(str(k))}:{dumps(value[k])}" for k in keys) + "}"
    raise TypeError(f"cannot canonicalise {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    return dumps(value).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()
