"""Rule and bundle models (SPEC §4.2–4.3).

``Rule.verdict`` is typed as the full :class:`Decision` enum even though ADR-002.3
forbids ALLOW rules. Rejecting it in the model would surface as a Pydantic
validation error pointing at a line number; rejecting it in the linter produces
the sentence a policy author needs ("narrow ``applies_to`` instead"). The engine
never sees an unlinted bundle, so the guarantee holds either way.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import ConfigDict, Field

from qed.core.schemas import (
    ActionKind,
    ComplianceRef,
    Decision,
    Environment,
    Frozen,
    Mode,
    Severity,
)

__all__ = [
    "DURATION_PATTERN",
    "RULE_ID_PATTERN",
    "AppliesTo",
    "ApprovalSpec",
    "PolicyBundle",
    "Rule",
    "RuleOverride",
]

RULE_ID_PATTERN: Final = r"^[A-Z]{2,6}(-[A-Z0-9]{2,8})+$"
DURATION_PATTERN: Final = r"^\d+(ms|s|m|h|d)$"


class ApprovalSpec(Frozen):
    approvers: list[str] = Field(default_factory=list)
    timeout: str | None = Field(default=None, pattern=DURATION_PATTERN)
    window_max: str | None = Field(default=None, pattern=DURATION_PATTERN)
    escalate_to: list[str] | None = None
    escalate_after: str | None = Field(default=None, pattern=DURATION_PATTERN)


class AppliesTo(Frozen):
    """All present constraints must hold (AND). Absent means "any"."""

    kinds: list[ActionKind] | None = None
    name_globs: list[str] | None = None
    target_globs: list[str] | None = None
    environments: list[Environment] | None = None
    adapters: list[str] | None = None

    def narrows(self, other: AppliesTo) -> bool:
        """True when ``self`` is at most as broad as ``other`` on every axis."""
        for name in type(self).model_fields:
            mine = getattr(self, name)
            theirs = getattr(other, name)
            if mine is None and theirs is not None:
                return False  # dropping a constraint widens the rule
            if mine is not None and theirs is not None and not set(mine) <= set(theirs):
                return False
        return True


class Rule(Frozen):
    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    name: str
    message: str
    verdict: Decision
    severity: Severity = Severity.MEDIUM
    mode: Mode = Mode.enforce
    applies_to: AppliesTo = AppliesTo()
    when: dict[str, object] | None = None
    approval: ApprovalSpec | None = None
    fix: str | None = None
    compliance: list[ComplianceRef] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    disabled: bool = False
    reason: str | None = None
    disabled_by: str | None = None
    #: File the rule or its last modification came from. Reporting only;
    #: excluded from the bundle hash so moving a rule between files is a no-op.
    source: str | None = None


class RuleOverride(Frozen):
    """May only soften or narrow an existing rule (ADR-002.4)."""

    verdict: Decision | None = None
    mode: Mode | None = None
    applies_to: AppliesTo | None = None
    approval: ApprovalSpec | None = None
    severity: Severity | None = None


class PolicyBundle(Frozen):
    """Resolved rules, sorted by ``rule_id``, including disabled ones."""

    rules: list[Rule]
    hash: str
    default_verdict: Decision = Decision.ALLOW
    version: str | None = None
    sources: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, extra="forbid")

    def active_rules(self) -> list[Rule]:
        return [r for r in self.rules if not r.disabled]

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)


#: Fields that take part in ``policy_hash``. ``source`` is excluded on purpose.
HASHED_RULE_FIELDS: Final[tuple[str, ...]] = (
    "rule_id",
    "name",
    "message",
    "verdict",
    "severity",
    "mode",
    "applies_to",
    "when",
    "approval",
    "fix",
    "compliance",
    "disabled",
    "reason",
)

LintSeverity = Literal["error", "warning"]


class LintFinding(Frozen):
    code: str
    message: str
    severity: LintSeverity = "error"
    rule_id: str | None = None
    source: str | None = None

    def format(self) -> str:
        where = " ".join(filter(None, [self.source, self.rule_id]))
        prefix = f"{where}: " if where else ""
        return f"{self.severity.upper()} [{self.code}] {prefix}{self.message}"
