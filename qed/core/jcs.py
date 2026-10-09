"""RFC 8785 JSON Canonicalization Scheme (JCS).

Every hash in qed is taken over JCS bytes (SPEC §10.1). The canonical form has
to be reproducible by `qed-verify`, which depends on nothing but the standard
library and `cryptography`, so this module is self-contained and must stay that
way: no Pydantic, no third-party JSON.

Two properties matter and are tested:

* **Key order** is by UTF-16 code unit, not by Unicode code point. Those differ
  for astral characters, so keys are compared on their UTF-16BE encoding.
* **Numbers** follow ECMAScript ``Number::toString``, which is not Python's
  ``repr``. Thresholds for exponential notation differ (ES6 switches at 1e21 and
  1e-7; Python at 1e16 and 1e-5), so the conversion is explicit.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Final

__all__ = ["canonicalize", "dumps", "sha256_hex"]

_ESCAPES: Final[dict[int, str]] = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

_MAX_SAFE_INTEGER: Final = 2**53 - 1


def _ser_string(value: str) -> str:
    out = ['"']
    for ch in value:
        cp = ord(ch)
        esc = _ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ser_int(value: int) -> str:
    if abs(value) > _MAX_SAFE_INTEGER:
        raise ValueError(
            f"integer {value} is outside the IEEE-754 double safe range; "
            "JCS cannot represent it unambiguously — use a string"
        )
    return str(value)


def _ser_float(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if value == 0.0:
        return "0"  # also collapses -0.0, as ES6 does
    dec = Decimal(repr(value))
    exponent = dec.adjusted()  # power of ten of the leading digit
    if -7 < exponent < 21:
        text = format(dec, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text
    sign, digits, _ = dec.as_tuple()
    mantissa = "".join(str(d) for d in digits).rstrip("0") or "0"
    if len(mantissa) > 1:
        mantissa = f"{mantissa[0]}.{mantissa[1:]}"
    prefix = "-" if sign else ""
    return f"{prefix}{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"


def _ser_number(value: int | float) -> str:
    return _ser_int(value) if isinstance(value, int) else _ser_float(value)


def _utf16_sort_key(key: str) -> bytes:
    """RFC 8785 §3.2.3: members are sorted on their UTF-16 code units."""
    return key.encode("utf-16-be", errors="surrogatepass")


def _ser(value: object, out: list[str], depth: int) -> None:
    if depth > 100:
        raise ValueError("JCS input nested deeper than 100 levels")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_ser_string(value))
    elif isinstance(value, int | float):
        out.append(_ser_number(value))
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _ser(item, out, depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        keys = list(value.keys())
        if not all(isinstance(k, str) for k in keys):
            raise TypeError("JCS object keys must be strings")
        out.append("{")
        for i, key in enumerate(sorted(keys, key=_utf16_sort_key)):
            if i:
                out.append(",")
            out.append(_ser_string(key))
            out.append(":")
            _ser(value[key], out, depth + 1)
        out.append("}")
    else:
        raise TypeError(f"{type(value).__name__} is not JSON-serialisable under JCS")


def dumps(value: object) -> str:
    """Return the canonical JSON text for ``value``."""
    out: list[str] = []
    _ser(value, out, 0)
    return "".join(out)


def canonicalize(value: object) -> bytes:
    """Return the canonical JSON bytes (UTF-8) for ``value``."""
    return dumps(value).encode("utf-8")


def sha256_hex(value: object) -> str:
    """Return ``sha256(JCS(value))`` as lowercase hex."""
    import hashlib

    return hashlib.sha256(canonicalize(value)).hexdigest()
