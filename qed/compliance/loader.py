"""Framework id normalisation (SPEC §11).

This module is the registry and the normaliser. The control catalogues
themselves are :mod:`qed.compliance.packs`.

SPEC §4.6 anticipated importing each rule's ``compliance`` mappings from an
existing rule set. That is not possible and was not done: a mapping is keyed to
the rule it belongs to and this project shares no rules with anything, so every
imported mapping would dangle. Control *titles* transfer; links do not. Every
rule-to-control link in this repository was written here by hand, per rule,
which is also why ``docs/compliance.md`` reports coverage as a fraction rather
than as a claim.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import Field

from qed.core.schemas import Frozen

__all__ = ["Framework", "canonical_framework", "frameworks", "is_known_framework"]

_PATH = Path(__file__).with_name("frameworks.yaml")


class Framework(Frozen):
    id: str
    title: str
    depth: str
    aliases: list[str] = Field(default_factory=list)


@lru_cache(maxsize=1)
def frameworks() -> tuple[Framework, ...]:
    data = yaml.safe_load(_PATH.read_text(encoding="utf-8"))
    return tuple(Framework.model_validate(item) for item in data["frameworks"])


@lru_cache(maxsize=1)
def _index() -> dict[str, str]:
    out: dict[str, str] = {}
    for fw in frameworks():
        out[fw.id.lower()] = fw.id
        for alias in fw.aliases:
            out[alias.lower()] = fw.id
    return out


def canonical_framework(name: str) -> str | None:
    """Canonical id for ``name``, or ``None`` when unrecognised."""
    return _index().get(name.strip().lower())


def is_known_framework(name: str) -> bool:
    return canonical_framework(name) is not None
