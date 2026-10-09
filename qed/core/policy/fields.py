"""The set of field paths a rule is allowed to reference.

Derived from the Pydantic models rather than written by hand, so a schema change
cannot leave the linter accepting a path the engine will never resolve (SPEC
§4.3, "unknown field path").

Some subtrees are free-form: ``action.params_redacted`` is adapter-supplied JSON
and ``context.tags`` is a list. Paths under those prefixes are accepted without
further checking.
"""

from __future__ import annotations

import types
import typing
from collections.abc import Iterable

from pydantic import BaseModel

from qed.core.schemas import ActionProposal, Derived

__all__ = ["FREE_FORM_PREFIXES", "is_known_path", "known_paths"]

#: Anything at or below these prefixes is accepted by the linter.
FREE_FORM_PREFIXES: tuple[str, ...] = (
    "action.params_redacted",
    "context.tags",
)


def _unwrap(annotation: object) -> Iterable[object]:
    """Yield the candidate concrete types inside Optional/Union/list/Annotated."""
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        yield from _unwrap(typing.get_args(annotation)[0])
    elif origin in (types.UnionType, typing.Union):
        for arg in typing.get_args(annotation):
            if arg is not type(None):
                yield from _unwrap(arg)
    elif origin in (list, set, tuple):
        for arg in typing.get_args(annotation):
            yield from _unwrap(arg)
    else:
        yield annotation


def _walk(model: type[BaseModel], prefix: str, out: set[str], depth: int = 0) -> None:
    if depth > 10:  # pragma: no cover - models are shallow
        return
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        out.add(path)
        for candidate in _unwrap(field.annotation):
            if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                _walk(candidate, f"{path}.", out, depth + 1)


def known_paths() -> frozenset[str]:
    """Every dotted path resolvable against a proposal or its derived context."""
    out: set[str] = set()
    _walk(ActionProposal, "", out)
    _walk(Derived, "derived.", out)
    return frozenset(out)


_KNOWN = known_paths()


def is_known_path(path: str) -> bool:
    if path in _KNOWN:
        return True
    return any(path == p or path.startswith(f"{p}.") for p in FREE_FORM_PREFIXES)
