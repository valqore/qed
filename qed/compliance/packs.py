"""Control catalogues, and honest coverage over them (SPEC §11, week 8).

A rule says `compliance: [{framework: eu_ai_act, control: "Art. 14"}]`. Until
now nothing said what `Art. 14` *is*, so an OSCAL export handed an auditor a
list of identifiers with no titles and no way to tell whether the mapping was
thorough or decorative. These catalogues close that.

Three decisions shape the module, and all three are about not overclaiming.

**A label is not a quotation.** Each control carries a short description
written for this catalogue plus the standard's `source` URL. Transcribing legal
or standards text by hand into a file that goes in front of an auditor invites
a misquotation that is worse than no quotation, so nothing here claims to be
verbatim and every entry says where the real words are.

**Coverage is only a fraction when the catalogue is complete.** A pack declares
`catalogue: complete | partial`. For a partial one -- SOC 2's sixty-odd
criteria, the AI RMF's seventy subcategories -- "5 of 5 covered" would read as
complete while meaning "every control we chose to list". So a percentage is
computed only for a complete catalogue, and :class:`Coverage` says which it is
rather than leaving the caller to notice.

**A framework with no mapping gets a catalogue anyway.** `iso_42001` has no
rule pointing at it. Omitting the pack would make it look like a framework
nobody had considered; including it makes the zero visible, and a visible gap
is one somebody can close.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal, Protocol

import yaml
from pydantic import Field

from qed.compliance.loader import canonical_framework, frameworks
from qed.core.schemas import Frozen

__all__ = [
    "Control",
    "Coverage",
    "Pack",
    "control",
    "coverage",
    "pack",
    "packs",
    "unknown_controls",
]

_DIR = Path(__file__).with_name("packs")

Completeness = Literal["complete", "partial"]


class _Ref(Protocol):
    @property
    def framework(self) -> str: ...
    @property
    def control(self) -> str: ...


class Mappable(Protocol):
    """What these functions need of a rule, and nothing more.

    A protocol rather than importing `Rule`: the policy loader calls
    `unknown_controls` to lint, so a real import here would be a cycle. It also
    says plainly that this module cares about two attributes and has no opinion
    about rules.

    Read-only properties, not plain attributes. A protocol's mutable attribute
    is invariant, so `compliance: Sequence[_Ref]` would reject a `Rule` whose
    own annotation is `list[ComplianceRef]` -- correct of mypy, and not what is
    meant here: nothing in this module writes to either.
    """

    @property
    def rule_id(self) -> str: ...
    @property
    def compliance(self) -> Sequence[_Ref]: ...


class Control(Frozen):
    id: str
    #: A short description written for this catalogue, **not** a quotation.
    #: Follow the pack's `source` for the standard's own words.
    label: str
    #: Why no rule maps here, for a control that is deliberately unmapped.
    #:
    #: A **claim about this kernel**, never a reading of the standard: "nothing
    #: here records X" is checkable, "this control does not apply to us" is a
    #: legal opinion and does not belong in a YAML file. An unmapped control
    #: with no note is simply not mapped yet, and the distinction is the point
    #: -- an auditor can argue with a stated reason and can only guess at a
    #: silence.
    note: str = ""


class Pack(Frozen):
    framework: str
    source: str
    catalogue: Completeness
    scope: str = ""
    #: The edition, where the identifiers depend on it. `nist_csf` is 1.1,
    #: whose `PR.AC-*` family does not exist in 2.0 -- the sort of thing that
    #: makes a mapping unfollowable if it is not written down.
    version: str = ""
    controls: list[Control] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.catalogue == "complete"

    def has(self, control_id: str) -> bool:
        return any(item.id == control_id for item in self.controls)


@dataclass(frozen=True)
class Coverage:
    """What a rule set maps, against one framework's catalogue."""

    framework: str
    title: str
    #: `article`, `category` or `pack`, from the framework registry. SPEC §11's
    #: honesty flag: it says how deep the mapping goes, not how good it is.
    depth: str
    catalogue: Completeness
    controls: int
    mapped: int
    #: Controls in the catalogue that no rule points at.
    unmapped: tuple[str, ...]
    #: Rules that map to this framework, by rule id.
    rules: tuple[str, ...]
    #: Of the unmapped controls, the ones that say why, as `{control: note}`. A
    #: stated reason is something an auditor can disagree with; a bare absence
    #: is not.
    unmapped_notes: Mapping[str, str] = field(default_factory=dict)
    #: What the catalogue covers, from the pack. It belongs in the coverage
    #: report and not only in the YAML file, because `eu_ai_act 44.4%` reads as
    #: a share of the whole Regulation and is a share of Chapter III Section 2
    #: plus two articles. A complete catalogue is complete *for a scope*.
    scope: str = ""

    @property
    def percentage(self) -> float | None:
        """Mapped share, or **None** for a partial catalogue.

        None rather than a number, because a percentage over a catalogue that
        lists only what somebody chose to list is a figure that reads as
        complete and is not. The caller has to handle the None, which is the
        point.
        """
        if self.catalogue != "complete" or not self.controls:
            return None
        return round(100.0 * self.mapped / self.controls, 1)

    def describe(self) -> dict[str, object]:
        return {
            "framework": self.framework,
            "title": self.title,
            "depth": self.depth,
            "catalogue": self.catalogue,
            "controls": self.controls,
            "mapped": self.mapped,
            "percentage": self.percentage,
            "unmapped": list(self.unmapped),
            "unmapped_notes": dict(self.unmapped_notes),
            "rules": len(self.rules),
            "scope": self.scope,
        }


@lru_cache(maxsize=1)
def packs() -> tuple[Pack, ...]:
    """Every catalogue on disk, ordered by framework id."""
    found = []
    for path in sorted(_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        loaded = Pack.model_validate(data)
        if canonical_framework(loaded.framework) != loaded.framework:
            raise ValueError(
                f"{path.name} declares framework {loaded.framework!r}, which is not a "
                "canonical id in frameworks.yaml. A pack for a framework the normaliser "
                "does not know is a catalogue nothing can look up."
            )
        found.append(loaded)
    return tuple(found)


def pack(framework: str) -> Pack | None:
    """The catalogue for a framework, by canonical id or alias."""
    canonical = canonical_framework(framework)
    if canonical is None:
        return None
    return next((item for item in packs() if item.framework == canonical), None)


def control(framework: str, control_id: str) -> Control | None:
    """One control, or None when the framework or the id is unknown."""
    found = pack(framework)
    if found is None:
        return None
    return next((item for item in found.controls if item.id == control_id), None)


def unknown_controls(rules: Iterable[Mappable]) -> list[tuple[str, str, str]]:
    """``(rule_id, framework, control)`` for every mapping with no catalogue entry.

    A typo'd control id is worse than a missing one: it reaches the OSCAL
    export looking exactly like a real mapping, and the first person to notice
    is the auditor who goes looking for the control. The loader turns this into
    an error rather than a warning for that reason.
    """
    missing = []
    for rule in rules:
        for ref in rule.compliance or ():
            if control(ref.framework, ref.control) is None:
                missing.append((rule.rule_id, ref.framework, ref.control))
    return missing


def coverage(rules: Iterable[Mappable]) -> list[Coverage]:
    """Coverage for every catalogued framework, including the ones at zero."""
    mapped: dict[str, dict[str, list[str]]] = {}
    for rule in rules:
        for ref in rule.compliance or ():
            canonical = canonical_framework(ref.framework) or ref.framework
            mapped.setdefault(canonical, {}).setdefault(ref.control, []).append(rule.rule_id)

    titles = {fw.id: fw for fw in frameworks()}
    out = []
    for item in packs():
        hits = mapped.get(item.framework, {})
        registry = titles.get(item.framework)
        out.append(
            Coverage(
                framework=item.framework,
                title=registry.title if registry else item.framework,
                depth=registry.depth if registry else "pack",
                catalogue=item.catalogue,
                controls=len(item.controls),
                mapped=sum(1 for entry in item.controls if entry.id in hits),
                unmapped=tuple(entry.id for entry in item.controls if entry.id not in hits),
                unmapped_notes={
                    entry.id: entry.note
                    for entry in item.controls
                    if entry.id not in hits and entry.note
                },
                rules=tuple(sorted({rid for ids in hits.values() for rid in ids})),
                scope=item.scope,
            )
        )
    return out
