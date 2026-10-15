"""Re-deriving a recorded decision and saying exactly what that proves (SPEC §14).

An auditor's question is not "is this record authentic" -- `qed verify` answers
that, and a chain rewritten wholesale and re-signed would pass it. The question
is **does this verdict follow from the policy it says it was decided under**.
That needs the decision run again, and it needs honesty about which inputs
could be recovered and which could not.

**What the chain holds, and what it does not.** The `proposal` record carries
the whole `ActionProposal`; the `verdict` record carries the whole `Verdict`;
both carry the timestamp that was `ctx.now`, so the clock is exact rather than
approximated. The `policy_loaded` record carries the bundle's **hash** and its
counts -- not its rules. So the chain cannot reconstruct the policy, and a
replay against a bundle whose hash does not match is not a replay of anything:
it answers "what would today's policy decide", which is a different and much
weaker question. This module refuses to conflate the two.

Two inputs are not in the chain at all:

* the **budget ledger** state for the token, which the ledger has since moved;
* the **mandate** object -- `mandate_issued` records its id and window, not the
  signed document `evaluate` is given.

They can be supplied, and otherwise they are defaulted and *named* as assumed.
Naming them is the whole point: a difference in a rule that reads
`derived.budget.*` when the budget was assumed is not evidence of anything,
while the same difference in a rule that reads only the proposal is evidence of
non-determinism, a changed engine, or an edited record.

So every difference is classified. :attr:`ReplayReport.unexplained` is the set
that no assumed input accounts for, and it is the only set that should worry
anybody.

**The 24-hour history counters are not assumed, and that is a statement about
the product rather than about replay.** `HistoryDerived` is threaded all the
way through `check_proposal` into `EvalContext`, and nothing in `qed` ever
passes it: every decision this product has ever made saw `calls_24h = 0` and
`blocks_24h = 0`. Replaying with zeros therefore reproduces the real input
exactly. `tests/core/test_replay.py` pins that, so the day something starts
supplying real counters the test fails and says to revisit this -- because on
that day zeros would silently become an assumption nobody declared.

An input is also only named when it could have mattered. `derived.budget.*` and
`derived.mandate.*` reach synthetic gates the engine checks before any rule, so
they always can; a bundle with no rule reading an input gets no caveat about
it, because a caveat that is always printed is one nobody reads.

**Approvals are an overlay, not a decision.** `check_proposal` runs `evaluate`
and *then*, for a REQUIRE_APPROVAL, consults the approval store: an open window
becomes ALLOW with `via_approval`, a recent denial becomes BLOCK with
`approval_id`. The recorded `decision` is therefore not always the engine's
verdict, and comparing them directly would report a mismatch for every
correctly approved action in the chain. The engine's own decision is recovered
first, and the overlay is then checked as its own claim -- an ALLOW carrying
`via_approval` must have been a REQUIRE_APPROVAL from the policy, and if it was
not, that is a finding of its own.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from qed.core.policy.engine import evaluate
from qed.core.policy.model import PolicyBundle
from qed.core.schemas import (
    ENGINE_VERSION,
    ActionProposal,
    BudgetState,
    Decision,
    EvalContext,
    Verdict,
)

__all__ = [
    "ASSUMED_PREFIXES",
    "Difference",
    "ReplayReport",
    "predicate_fields",
    "replay_verdict",
    "rules_reading_assumed_inputs",
]

#: Derived paths a rule may read that this module cannot recover from the
#: chain. `derived.blast_radius` and `derived.chain_depth` are deliberately
#: absent: both are computed from the proposal, which *is* recorded, so a
#: difference in a rule reading them is a real difference.
ASSUMED_PREFIXES: Final = ("derived.budget", "derived.history", "derived.mandate")

#: Synthetic rules the engine raises before any policy rule is consulted, and
#: the input each one depends on. A replay that assumed that input cannot
#: distinguish "the budget was exhausted then" from "the ledger has moved
#: since", so a difference here is attributed rather than reported.
SYNTHETIC_DEPENDS_ON: Final = {
    "AG-BUD-001": "budget",
    "AG-IDN-006": "mandate",
    "AG-IDN-007": "mandate",
}


@dataclass(frozen=True)
class Difference:
    """One field of the verdict that came out differently, and whether that
    difference is accounted for by an input the replay had to assume."""

    field: str
    recorded: object
    replayed: object
    #: The assumed input that explains it, or "" when nothing does. Empty is
    #: the one that matters.
    attributed_to: str = ""

    def format(self) -> str:
        where = f" (explained by the assumed {self.attributed_to})" if self.attributed_to else ""
        return f"{self.field}: recorded {self.recorded!r}, replayed {self.replayed!r}{where}"


@dataclass(frozen=True)
class ReplayReport:
    proposal_id: str
    recorded_policy_hash: str
    replayed_policy_hash: str
    recorded_engine_version: str
    replayed_engine_version: str = ENGINE_VERSION
    #: How the recorded decision was reached if an approval changed it, in
    #: words, or "" for the ordinary case.
    approval_overlay: str = ""
    #: Inputs that were not recovered from the chain, by name.
    assumed_inputs: tuple[str, ...] = ()
    differences: tuple[Difference, ...] = ()

    @property
    def policy_matches(self) -> bool:
        return self.recorded_policy_hash == self.replayed_policy_hash

    @property
    def engine_matches(self) -> bool:
        return self.recorded_engine_version == self.replayed_engine_version

    @property
    def unexplained(self) -> tuple[Difference, ...]:
        """Differences no assumed input accounts for. The ones that matter."""
        return tuple(d for d in self.differences if not d.attributed_to)

    @property
    def reproduced(self) -> bool:
        """The record follows from its policy, with nothing left over."""
        return self.policy_matches and not self.differences

    @property
    def inconclusive(self) -> bool:
        """Differences, but every one of them explained by an assumed input.

        Not a pass and not a failure. Supplying `--budget` or `--mandate`
        turns this into one or the other, and saying so is more use than
        picking whichever reads better.
        """
        return bool(self.differences) and not self.unexplained

    def summary(self) -> str:
        if not self.policy_matches:
            return (
                f"cannot replay {self.proposal_id}: decided under policy "
                f"{self.recorded_policy_hash[:16]}..., replayed against "
                f"{self.replayed_policy_hash[:16]}..."
            )
        if self.reproduced:
            return f"reproduced {self.proposal_id} exactly"
        if self.inconclusive:
            return (
                f"inconclusive for {self.proposal_id}: "
                f"{len(self.differences)} difference(s), each explained by an assumed input"
            )
        return (
            f"DIFFERS for {self.proposal_id}: "
            f"{len(self.unexplained)} difference(s) nothing accounts for"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "reproduced": self.reproduced,
            "inconclusive": self.inconclusive,
            "policy_matches": self.policy_matches,
            "recorded_policy_hash": self.recorded_policy_hash,
            "replayed_policy_hash": self.replayed_policy_hash,
            "recorded_engine_version": self.recorded_engine_version,
            "replayed_engine_version": self.replayed_engine_version,
            "approval_overlay": self.approval_overlay,
            "assumed_inputs": list(self.assumed_inputs),
            "differences": [
                {
                    "field": d.field,
                    "recorded": d.recorded,
                    "replayed": d.replayed,
                    "attributed_to": d.attributed_to,
                }
                for d in self.differences
            ],
        }


# --------------------------------------------------------------- predicates


def predicate_fields(node: object, depth: int = 0) -> set[str]:
    """Every `field` path a predicate reads, however deeply nested.

    Walked rather than pattern-matched on the rule's source text: a rule's
    `when` is a tree of `any`/`all`/`not`, and a `derived.budget.*` reference
    three levels down counts exactly as much as one at the top.
    """
    if depth > 20 or not isinstance(node, dict):
        return set()
    found: set[str] = set()
    for key in ("any", "all"):
        children = node.get(key)
        if isinstance(children, Sequence) and not isinstance(children, str):
            for child in children:
                found |= predicate_fields(child, depth + 1)
    if "not" in node:
        found |= predicate_fields(node["not"], depth + 1)
    path = node.get("field")
    if isinstance(path, str):
        found.add(path)
    return found


def rules_reading_assumed_inputs(bundle: PolicyBundle) -> dict[str, str]:
    """``{rule_id: which assumed input it reads}`` for every rule in `bundle`.

    A rule that reads `derived.budget.remaining_cents` cannot be replayed
    faithfully without the ledger state it was decided against, so a
    difference involving it is attributed rather than reported as a finding.
    """
    out: dict[str, str] = {}
    for rule in bundle.rules:
        if rule.when is None:
            continue
        for path in sorted(predicate_fields(rule.when)):
            for prefix in ASSUMED_PREFIXES:
                if path == prefix or path.startswith(prefix + "."):
                    out[rule.rule_id] = prefix.removeprefix("derived.")
                    break
            if rule.rule_id in out:
                break
    return out


# ------------------------------------------------------------------- replay


def _engine_decision(recorded: Verdict) -> tuple[Decision, str]:
    """The decision `evaluate` returned, before approvals were consulted.

    `_resolve_approval` is reached only for a REQUIRE_APPROVAL, so any
    approval marker on the record means the engine said REQUIRE_APPROVAL and
    something else changed it afterwards.
    """
    if recorded.via_approval:
        return Decision.REQUIRE_APPROVAL, (
            f"recorded as {recorded.decision.value} through an open approval window "
            f"({recorded.via_approval})"
        )
    if recorded.approval_id and recorded.decision is Decision.BLOCK:
        return Decision.REQUIRE_APPROVAL, (
            f"recorded as BLOCK by a recent denial on approval {recorded.approval_id}"
        )
    if recorded.approval_id:
        return recorded.decision, f"linked to pending approval {recorded.approval_id}"
    return recorded.decision, ""


def _hit_view(verdict: Verdict) -> list[dict[str, str]]:
    return [
        {"rule_id": hit.rule_id, "mode": hit.mode.value}
        for hit in sorted(verdict.hits, key=lambda h: h.rule_id)
    ]


def _attribution(rule_ids: Sequence[str], assumed: Sequence[str], reading: dict[str, str]) -> str:
    """Which assumed input explains a difference involving `rule_ids`."""
    for rule_id in rule_ids:
        depends = SYNTHETIC_DEPENDS_ON.get(rule_id) or reading.get(rule_id)
        if depends and depends in assumed:
            return depends
    return ""


def replay_verdict(
    proposal: ActionProposal,
    recorded: Verdict,
    bundle: PolicyBundle,
    budget: BudgetState,
    ctx: EvalContext,
    *,
    assumed_inputs: Sequence[str] = (),
) -> ReplayReport:
    """Decide `proposal` again and report how the result compares. Pure.

    `assumed_inputs` names the inputs the caller could not recover -- any of
    ``"budget"``, ``"mandate"``, ``"history"``. They are not inferred here: a
    caller that *did* recover the ledger state should pass nothing, and get a
    report in which no difference is excused.
    """
    assumed = tuple(assumed_inputs)
    if recorded.policy_hash != bundle.hash:
        # Deliberately short. Re-deciding under a different policy produces a
        # verdict about today, and a field-by-field diff against the record
        # would read as a replay that disagreed -- which is the one thing this
        # must not imply.
        return ReplayReport(
            proposal_id=proposal.id,
            recorded_policy_hash=recorded.policy_hash,
            replayed_policy_hash=bundle.hash,
            recorded_engine_version=recorded.engine_version,
            assumed_inputs=assumed,
        )

    replayed = evaluate(proposal, bundle, budget, ctx)
    expected_decision, overlay = _engine_decision(recorded)
    reading = rules_reading_assumed_inputs(bundle)
    # Only report an assumption that could have changed this bundle's answer.
    # `budget` and `mandate` always can -- the engine checks AG-BUD-001,
    # AG-IDN-006 and AG-IDN-007 before it looks at a single rule -- so they
    # survive this filter whatever the pack contains.
    always_matters = {"budget", "mandate"}
    relevant = set(reading.values()) | always_matters
    assumed = tuple(name for name in assumed if name in relevant)

    # Every rule named by either side, so a hit that appeared and one that
    # vanished are both attributable.
    touched = sorted({h.rule_id for h in recorded.hits} | {h.rule_id for h in replayed.hits})

    differences: list[Difference] = []

    if replayed.decision is not expected_decision:
        differences.append(
            Difference(
                "decision",
                expected_decision.value,
                replayed.decision.value,
                _attribution(touched, assumed, reading),
            )
        )
    if replayed.would_decision is not recorded.would_decision:
        differences.append(
            Difference(
                "would_decision",
                recorded.would_decision.value,
                replayed.would_decision.value,
                _attribution(touched, assumed, reading),
            )
        )
    if _hit_view(replayed) != _hit_view(recorded):
        differences.append(
            Difference(
                "hits",
                _hit_view(recorded),
                _hit_view(replayed),
                _attribution(touched, assumed, reading),
            )
        )
    if replayed.blast_radius != recorded.blast_radius:
        # Computed from the proposal alone, so nothing can excuse this one.
        differences.append(Difference("blast_radius", recorded.blast_radius, replayed.blast_radius))
    if replayed.default_applied != recorded.default_applied:
        differences.append(
            Difference(
                "default_applied",
                recorded.default_applied,
                replayed.default_applied,
                _attribution(touched, assumed, reading),
            )
        )

    return ReplayReport(
        proposal_id=proposal.id,
        recorded_policy_hash=recorded.policy_hash,
        replayed_policy_hash=bundle.hash,
        recorded_engine_version=recorded.engine_version,
        approval_overlay=overlay,
        assumed_inputs=assumed,
        differences=tuple(differences),
    )
