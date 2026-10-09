"""The vendored NIST OSCAL schema and the validator that can read it.

``oscal_assessment-results_schema.json`` is the published file from the NIST
OSCAL v1.1.2 release, byte for byte. ``tests/evidence/test_oscal_schema.py``
checks its sha256 before using it: an export that validates against a schema
somebody adjusted proves nothing about OSCAL.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import regex
from jsonschema import Draft7Validator, validators
from jsonschema.exceptions import ValidationError

__all__ = ["build_validator"]


def _pattern(validator: Any, patrn: str, instance: Any, schema: Any) -> Iterator[ValidationError]:
    """``pattern``, evaluated with the ``regex`` module instead of ``re``.

    JSON Schema says patterns are ECMA-262 regexes, and the NIST schema uses
    Unicode property escapes (``\\p{L}``) from ES2018 -- for instance in
    ``TokenDatatype``, which constrains every ``target-id`` qed emits. CPython's
    ``re`` raises ``bad escape \\p`` on those, so a stock ``jsonschema`` run
    cannot evaluate the real schema at all.

    ``regex`` supports them. Swapping the engine makes the check *stricter* than
    skipping those patterns would be, which is the point: the NCName constraint
    on control ids is exactly the one qed has to satisfy.
    """
    if not validator.is_type(instance, "string"):
        return
    if regex.search(patrn, instance) is None:
        yield ValidationError(f"{instance!r} does not match {patrn!r}")


_Validator = validators.extend(Draft7Validator, {"pattern": _pattern})


def build_validator(schema: dict[str, Any]) -> Any:
    """A draft-07 validator for the OSCAL schema.

    ``format`` is deliberately not checked. Draft-07 makes format annotation
    only, enabling it would add another dependency, and every OSCAL datatype
    that carries a ``format`` also carries a ``pattern`` that is stricter --
    ``DateTimeWithTimezoneDatatype`` pins the offsets it accepts, which
    ``format: date-time`` does not.
    """
    return _Validator(schema)
