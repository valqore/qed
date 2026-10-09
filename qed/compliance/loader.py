"""Framework id normalisation (SPEC §11).

Week 1 scope is deliberately only the registry and the normaliser. Control
*packs* are week 8.

A note for whoever does week 8: SPEC §4.6 says each rule's ``compliance``
mappings are "imported from Valqore's AIG rules (mapping data only)". They
cannot be. Valqore's ``compliance/packs.py`` keys its ~3,000 mapping lines to
210 Valqore rule IDs, and qed ports zero rules, so every mapping dangles. What
transfers is the 169 control titles. The rule→control links in this repository
are written here, by hand, per rule.
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
