"""Predicate evaluation (SPEC §4.4).

A predicate is a tree. Leaves are ``{field: <dotted path>, <op>: <value>}``;
interior nodes are ``{any: [...]}``, ``{all: [...]}`` or ``{not: {...}}``.

**Missing fields are falsy for every operator except ``exists``.** A rule that
asks ``action.method not_equals GET`` does not fire when the proposal carries no
method at all. The alternative — treating absence as "not equal" — makes a
rule's blast radius depend on which optional fields an adapter happened to fill
in, which is the opposite of determinism. Authors who want absence to count
write it explicitly with ``exists`` or wrap the leaf in ``not``.
See ``docs/adr/0002-predicate-semantics.md``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

import regex

from qed.core.policy.fields import is_known_path

__all__ = [
    "COMPOSITE_KEYS",
    "MISSING",
    "OPERATORS",
    "PredicateError",
    "evaluate_predicate",
    "resolve_field",
    "validate_predicate",
]

REGEX_TIMEOUT: Final = 0.1


class _Missing:
    """Sentinel for "the proposal has no such field"."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING: Final = _Missing()

OPERATORS: Final = frozenset(
    {
        "equals",
        "not_equals",
        "in",
        "not_in",
        "glob",
        "regex",
        "gt",
        "gte",
        "lt",
        "lte",
        "exists",
        "contains",
    }
)
COMPOSITE_KEYS: Final = frozenset({"any", "all", "not"})


class PredicateError(ValueError):
    """Raised for a structurally invalid predicate. Surfaced as a lint error."""


# --------------------------------------------------------------------------
# Field resolution
# --------------------------------------------------------------------------


def resolve_field(path: str, proposal: dict[str, object], derived: dict[str, object]) -> object:
    """Resolve a dotted path. Returns :data:`MISSING` if any segment is absent.

    List indexing is not supported: a rule matches on a list with ``contains``,
    never on ``tags.0``, so that reordering a list cannot change a decision.
    """
    if path.startswith("derived."):
        current: object = derived
        segments = path.split(".")[1:]
    else:
        current = proposal
        segments = path.split(".")
    for segment in segments:
        if not isinstance(current, dict):
            return MISSING
        if segment not in current:
            return MISSING
        current = current[segment]
    return current


# --------------------------------------------------------------------------
# Operators
# --------------------------------------------------------------------------


def _as_number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _glob(value: object, operand: object) -> bool:
    from fnmatch import fnmatchcase

    patterns = operand if isinstance(operand, list) else [operand]
    text = str(value)
    return any(isinstance(p, str) and fnmatchcase(text, p) for p in patterns)


def _regex(value: object, operand: object) -> bool:
    if not isinstance(operand, str):
        raise PredicateError("regex operand must be a string")
    try:
        return regex.search(operand, str(value), timeout=REGEX_TIMEOUT) is not None
    except TimeoutError:
        # A pattern that cannot be evaluated in budget must not silently pass.
        raise PredicateError(f"regex evaluation timed out: {operand!r}") from None


def _contains(value: object, operand: object) -> bool:
    if isinstance(value, str):
        return isinstance(operand, str) and operand in value
    if isinstance(value, list | tuple):
        return operand in value
    return False


def _compare(op: str, value: object, operand: object) -> bool:
    left, right = _as_number(value), _as_number(operand)
    if left is None or right is None:
        return False
    if op == "gt":
        return left > right
    if op == "gte":
        return left >= right
    if op == "lt":
        return left < right
    return left <= right


def _apply(op: str, value: object, operand: object) -> bool:
    if op == "exists":
        present = value is not MISSING and value is not None
        return present is bool(operand)
    if value is MISSING:
        return False
    if op == "equals":
        return value == operand
    if op == "not_equals":
        return value != operand
    if op == "in":
        return isinstance(operand, list) and value in operand
    if op == "not_in":
        return isinstance(operand, list) and value not in operand
    if op == "glob":
        return _glob(value, operand)
    if op == "regex":
        return _regex(value, operand)
    if op == "contains":
        return _contains(value, operand)
    return _compare(op, value, operand)


# --------------------------------------------------------------------------
# Tree walking
# --------------------------------------------------------------------------


def _leaf_op(node: dict[str, object]) -> str:
    ops = sorted(set(node) & OPERATORS)
    unknown = sorted(set(node) - OPERATORS - {"field"})
    # Report the misspelling before the arity, because a typo'd operator shows
    # up as "no operator" and that message sends the author looking in the
    # wrong place.
    if unknown:
        raise PredicateError(
            f"unknown predicate keys: {unknown}; operators are {sorted(OPERATORS)}"
        )
    if len(ops) != 1:
        raise PredicateError(f"a leaf predicate needs exactly one operator, got {ops or 'none'}")
    return ops[0]


def evaluate_predicate(
    node: dict[str, object], proposal: dict[str, object], derived: dict[str, object], depth: int = 0
) -> bool:
    if depth > 20:
        raise PredicateError("predicate nested deeper than 20 levels")
    if "any" in node or "all" in node:
        key = "any" if "any" in node else "all"
        children = node[key]
        if not isinstance(children, Sequence) or isinstance(children, str):
            raise PredicateError(f"'{key}' takes a list of predicates")
        results = (
            evaluate_predicate(_as_node(child), proposal, derived, depth + 1) for child in children
        )
        return any(results) if key == "any" else all(results)
    if "not" in node:
        return not evaluate_predicate(_as_node(node["not"]), proposal, derived, depth + 1)
    op = _leaf_op(node)
    field = node.get("field")
    if not isinstance(field, str):
        raise PredicateError("a leaf predicate needs a string 'field'")
    return _apply(op, resolve_field(field, proposal, derived), node[op])


def _as_node(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PredicateError("expected a predicate object")
    return {str(k): v for k, v in value.items()}


def validate_predicate(node: object, path: str = "when", depth: int = 0) -> list[tuple[str, str]]:
    """Static check. Returns ``(lint_code, message)`` pairs; empty means valid."""
    errors: list[tuple[str, str]] = []
    if depth > 20:
        return [("invalid_predicate", f"{path}: nested deeper than 20 levels")]
    if not isinstance(node, dict):
        return [("invalid_predicate", f"{path}: expected an object")]
    keys = set(node)
    composite = keys & COMPOSITE_KEYS
    if composite:
        if len(keys) != 1:
            return [
                (
                    "invalid_predicate",
                    f"{path}: '{sorted(composite)[0]}' must be the only key",
                )
            ]
        key = next(iter(composite))
        child = node[key]
        if key == "not":
            return validate_predicate(child, f"{path}.not", depth + 1)
        if not isinstance(child, list) or not child:
            return [("invalid_predicate", f"{path}.{key}: expected a non-empty list")]
        for i, sub in enumerate(child):
            errors += validate_predicate(sub, f"{path}.{key}[{i}]", depth + 1)
        return errors
    try:
        op = _leaf_op(node)
    except PredicateError as exc:
        return [("invalid_predicate", f"{path}: {exc}")]
    field = node.get("field")
    if not isinstance(field, str):
        return [("invalid_predicate", f"{path}: missing string 'field'")]
    if not is_known_path(field):
        errors.append(("unknown_field_path", f"{path}: unknown field path {field!r}"))
    if op == "regex":
        operand = node[op]
        if not isinstance(operand, str):
            errors.append(("invalid_regex", f"{path}: regex operand must be a string"))
        else:
            try:
                regex.compile(operand)
            except regex.error as exc:
                errors.append(("invalid_regex", f"{path}: invalid regex {operand!r}: {exc}"))
    if op == "glob":
        errors += _lint_glob(node[op], path)
    if op in {"in", "not_in"} and not isinstance(node[op], list):
        errors.append(("invalid_predicate", f"{path}: '{op}' operand must be a list"))
    if op == "exists" and not isinstance(node[op], bool):
        errors.append(("invalid_predicate", f"{path}: 'exists' operand must be true or false"))
    return errors


def _lint_glob(operand: object, path: str) -> list[tuple[str, str]]:
    """An unescaped ``[`` in a glob is almost always a mistake.

    ``fnmatch`` reads ``[`` as the start of a character class, so the pattern
    ``*://[fd00:ec2::254]*`` does not look for that IPv6 literal -- it matches
    any target whose host begins with one of ``f d 0 2 4 5 c e :``, which is
    most of the internet. A rule written that way fires on traffic nobody
    meant it to, in the direction that blocks real work, and it reads correct.

    This is not hypothetical: the first live run of ``qed proxy`` was refused
    a CONNECT to ``example.com`` by the instance-metadata rule, because ``e``
    was in that accidental class.

    A literal bracket is still expressible, as ``[[]`` and ``[]]``, so the
    finding names the escape rather than forbidding the character. ``contains``
    is usually what the author actually wanted.
    """
    patterns = operand if isinstance(operand, list) else [operand]
    errors: list[tuple[str, str]] = []
    for pattern in patterns:
        if not isinstance(pattern, str):
            errors.append(("invalid_predicate", f"{path}: a glob operand must be a string"))
            continue
        if "[" in pattern and "[[]" not in pattern:
            errors.append(
                (
                    "suspicious_glob",
                    f"{path}: the glob {pattern!r} contains '[', which fnmatch reads as a "
                    "character class rather than a literal bracket. Use `contains` for a "
                    "substring, or write the bracket as '[[]'.",
                )
            )
    return errors
