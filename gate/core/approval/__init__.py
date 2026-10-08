"""Approvals: the state machine, the dedupe key, and separation of duties.

SPEC §9, ADR-006. Pure — no store, no channel, no clock of its own.

The point of this module is that a human said yes, and that the fact is
checkable later. Everything here exists to make one of two sentences true:

* nobody approved their own action, and
* an approval covers exactly what was approved, for exactly as long as was
  agreed.

The second is why a window is keyed on the dedupe key rather than on a
principal or a rule. "Ali approved restarting nginx on web-01 for fifteen
minutes" is a sentence an auditor can check. "Ali is approved" is not.
"""

from __future__ import annotations

from gate.core.approval.model import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    DecisionKind,
    SoDViolation,
    check_separation_of_duties,
    decide,
    dedupe_key,
    is_expired,
    parse_duration,
    window_until,
)

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "DecisionKind",
    "SoDViolation",
    "check_separation_of_duties",
    "decide",
    "dedupe_key",
    "is_expired",
    "parse_duration",
    "window_until",
]
