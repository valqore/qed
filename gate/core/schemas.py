"""Domain model (SPEC §3).

Every model is frozen and rejects unknown fields. Two choices here exist purely
to make hashing reproducible:

* ``Timestamp`` always serialises as RFC 3339 UTC with exactly three fractional
  digits, in both Python and JSON dump modes, so a record's bytes do not depend
  on which dump mode the caller used.
* No field anywhere is typed ``Any``. Free-form payloads are ``dict[str, object]``
  so that the predicate evaluator and the canonicaliser have to narrow types
  explicitly instead of trusting them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
)

SCHEMA_VERSION = "1.0"
ENGINE_VERSION = "0.1.0"

# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------


def rfc3339_ms(value: datetime) -> str:
    """Format as RFC 3339 UTC with millisecond precision."""
    aware = value.astimezone(UTC)
    return f"{aware.strftime('%Y-%m-%dT%H:%M:%S')}.{aware.microsecond // 1000:03d}Z"


def _parse(value: object) -> object:
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def _normalise(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    aware = value.astimezone(UTC)
    return aware.replace(microsecond=(aware.microsecond // 1000) * 1000)


Timestamp = Annotated[
    datetime,
    BeforeValidator(_parse),
    AfterValidator(_normalise),
    PlainSerializer(rfc3339_ms, return_type=str, when_used="always"),
]


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=(datetime.now(UTC).microsecond // 1000) * 1000)


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class ActionKind(StrEnum):
    mcp_tool = "mcp_tool"
    http = "http"
    shell = "shell"
    skill = "skill"
    custom = "custom"


class Enforcement(StrEnum):
    advisory = "advisory"
    enforcing = "enforcing"


class Mode(StrEnum):
    shadow = "shadow"
    enforce = "enforce"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Assurance(StrEnum):
    """Who vouches for a record (ADR-007.1)."""

    kernel = "kernel"
    broker = "broker"
    adapter = "adapter"
    self_ = "self"


class EvidenceType(StrEnum):
    genesis = "genesis"
    proposal = "proposal"
    verdict = "verdict"
    approval_requested = "approval_requested"
    approval_decided = "approval_decided"
    approval_expired = "approval_expired"
    executed = "executed"
    execution_result = "execution_result"
    budget_update = "budget_update"
    budget_exhausted = "budget_exhausted"
    policy_loaded = "policy_loaded"
    key_rotated = "key_rotated"
    mandate_issued = "mandate_issued"
    mandate_revoked = "mandate_revoked"
    ungated_window = "ungated_window"
    correction = "correction"
    checkpoint = "checkpoint"
    admin_action = "admin_action"


Scope = Literal["single_resource", "multi_resource", "account", "global"]
Environment = Literal["dev", "staging", "prod"]


# --------------------------------------------------------------------------
# ActionProposal (SPEC §3.1)
# --------------------------------------------------------------------------


class Principal(Frozen):
    token_jti: str
    human_hash: str | None = None
    agent_chain: list[str] = Field(default_factory=list)
    mandate_id: str | None = None
    #: Adapter-supplied. ADVISORY and spoofable — never used for enforcement.
    client_fingerprint: str | None = None


class Action(Frozen):
    kind: ActionKind
    name: str
    target: str
    params_hash: str
    params_redacted: dict[str, object] | None = None
    method: str | None = None


class BlastHints(Frozen):
    writes: bool = False
    deletes: bool = False
    scope: Scope = "single_resource"


class CostEstimate(Frozen):
    tokens: int = 0
    money_cents: int = 0
    currency: str = "USD"
    #: False when the adapter could not estimate; drives AG-BUD-004.
    known: bool = True


class Context(Frozen):
    environment: Environment
    adapter: str
    adapter_id: str
    enforcement: Enforcement
    mode: Mode
    tags: list[str] = Field(default_factory=list)
    cost_estimate: CostEstimate = CostEstimate()
    blast_radius_hints: BlastHints = BlastHints()
    intent: str | None = None
    summary: str = ""


class ActionProposal(Frozen):
    id: str
    ts: Timestamp
    principal: Principal
    action: Action
    context: Context
    schema_version: Literal["1.0"] = "1.0"


# --------------------------------------------------------------------------
# Verdict (SPEC §3.2)
# --------------------------------------------------------------------------


class ComplianceRef(Frozen):
    framework: str
    control: str


class RuleHit(Frozen):
    rule_id: str
    verdict: Decision
    severity: Severity
    mode: Mode
    message: str
    fix: str | None = None
    compliance: list[ComplianceRef] = Field(default_factory=list)


class Verdict(Frozen):
    proposal_id: str
    decision: Decision
    would_decision: Decision
    hits: list[RuleHit]
    blast_radius: int = Field(ge=0, le=100)
    policy_hash: str
    engine_version: str = ENGINE_VERSION
    default_applied: bool = False
    approval_id: str | None = None
    via_approval: str | None = None


# --------------------------------------------------------------------------
# Budgets (SPEC §8)
# --------------------------------------------------------------------------


class Budget(Frozen):
    """Caps carried by a delegation token. ``0`` means no cap on that axis."""

    steps: int = 0
    tokens: int = 0
    seconds: int = 0
    money_cents: int = 0
    currency: str = "USD"


class BudgetState(Frozen):
    token_jti: str
    budget: Budget = Budget()
    steps_used: int = 0
    tokens_used: int = 0
    money_used_cents: int = 0
    first_seen: Timestamp | None = None

    def exhausted(self, now: datetime | None = None) -> bool:
        b = self.budget
        if b.steps and self.steps_used >= b.steps:
            return True
        if b.tokens and self.tokens_used >= b.tokens:
            return True
        if b.money_cents and self.money_used_cents >= b.money_cents:
            return True
        if b.seconds and self.first_seen is not None and now is not None:
            return (now - self.first_seen).total_seconds() > b.seconds
        return False


# --------------------------------------------------------------------------
# Mandate (SPEC §3.4)
# --------------------------------------------------------------------------


class MandateAllowed(Frozen):
    kinds: list[ActionKind] | None = None
    name_globs: list[str] | None = None
    target_globs: list[str] | None = None
    environments: list[Environment] | None = None


class MandateValidity(Frozen):
    from_: Timestamp = Field(alias="from")
    until: Timestamp

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class MandateOversight(Frozen):
    approvers: list[str] = Field(default_factory=list)
    require_approval_when: list[str] = Field(default_factory=list)


class MandateSignature(Frozen):
    key_id: str
    alg: str
    sig: str


class Mandate(Frozen):
    id: str
    issued_by_hash: str
    for_agent: str
    purpose: str
    allowed: MandateAllowed
    valid: MandateValidity
    budget: Budget = Budget()
    oversight: MandateOversight = MandateOversight()
    signature: MandateSignature | None = None
    revoked_at: Timestamp | None = None
    schema_version: Literal["1.0"] = "1.0"


# --------------------------------------------------------------------------
# Derived context (SPEC §4.4)
# --------------------------------------------------------------------------


class BudgetDerived(Frozen):
    """Remaining budget. ``None`` on any axis means that axis is uncapped.

    The ``*_pct_used`` fields exist so a rule can say "80 percent consumed"
    without the predicate language needing arithmetic. They are integers,
    truncated toward zero, and capped at 100.
    """

    steps_remaining: int | None = None
    tokens_remaining: int | None = None
    seconds_remaining: int | None = None
    money_remaining_cents: int | None = None
    steps_pct_used: int | None = None
    tokens_pct_used: int | None = None
    money_pct_used: int | None = None
    seconds_pct_used: int | None = None
    #: True when this action's estimated cost exceeds what the token has left.
    #: ``None`` when there is no money cap. The predicate language has no
    #: arithmetic, so the comparison between two fields is made here.
    money_overrun: bool | None = None


class MandateDerived(Frozen):
    present: bool = False
    within: bool = True


class HistoryDerived(Frozen):
    calls_24h: int = 0
    blocks_24h: int = 0


class Derived(Frozen):
    blast_radius: int = Field(ge=0, le=100)
    budget: BudgetDerived = BudgetDerived()
    mandate: MandateDerived = MandateDerived()
    chain_depth: int = 0
    history: HistoryDerived = HistoryDerived()


class EvalContext(Frozen):
    """Everything the engine needs that it is not allowed to fetch itself.

    The API layer collects this before calling ``evaluate`` so that the engine
    performs no I/O (SPEC §5).
    """

    now: Timestamp
    mandate: Mandate | None = None
    history: HistoryDerived = HistoryDerived()


# --------------------------------------------------------------------------
# Evidence (SPEC §3.5)
# --------------------------------------------------------------------------


class EvidenceRecord(Frozen):
    seq: int = Field(ge=0)
    ts: Timestamp
    type: EvidenceType
    assurance: Assurance
    payload_hash: str
    payload: dict[str, object] | None
    prev_hash: str
    hash: str
    key_id: str
    sig: str
    mode: Mode | None = None
    enforcement: Enforcement | None = None
    dev: bool = False
    schema_version: Literal["1.0"] = "1.0"


class SigningKeyInfo(Frozen):
    key_id: str
    public_pem: str
    alg: str = "Ed25519"
    source: Literal["file", "kms", "vault"] = "file"
    created_at: Timestamp | None = None
    retired_at: Timestamp | None = None


class Checkpoint(Frozen):
    from_seq: int
    to_seq: int
    merkle_root: str
    previous_receipts: list[dict[str, object]] = Field(default_factory=list)
