"""Self-governance: qed's own admin operations go through qed (SPEC §17).

Every rule in the baseline pack constrains an agent. The operator is the one
actor that has been exempt, and the operator is the one who can rotate the
signing key, replace the control catalogues, or change the policy an agent is
judged by. An auditor's first question about a governance product is who
governs the thing doing the governing, and until this module the answer was
"nobody".

SPEC §17: *"Admin operations (`policies:reload`, `keys:rotate`, upstream
changes, adapter add) go through the approval service with SoD and produce
`admin_action` evidence -- qed governs itself."*

**This reuses the approval machinery rather than reimplementing it.** The same
:class:`~qed.core.approval.model.ApprovalRequest`, the same
:func:`~qed.core.approval.model.check_separation_of_duties`, the same
``qed approve``. Two approval systems would be two places for the SoD check to
be subtly different, and the one that matters would be the one nobody tested.

Four decisions, each with a wrong answer that looks reasonable.

**Off by default.** Self-governance needs somebody to approve, and the common
case is one person on a laptop with no second operator. On by default would mean
`qed keys rotate` stops working on first use, which teaches people that the
feature is an obstacle. Off by default and loudly reportable by `qed doctor` is
the honest trade -- and `assurance` already exists to say what an instance can
actually enforce.

**Break-glass exists, and is loud.** The reason to rotate a key is that it may
have leaked, and that is exactly when an approver is asleep. A gate with no
break-glass would be worked around by editing the config, which records
nothing. So `--break-glass "<reason>"` proceeds, and costs: the reason is
required, the `admin_action` carries ``break_glass: true``, and it is counted
where an operator will see it. A gate that cannot be bypassed in an incident is
a gate that gets turned off before the incident.

**An approval is bound to one operation and spent once.** An approval granted
for importing a catalogue must not be spendable on rotating a key, and must not
be spendable twice. Both would be surprising in the direction that matters, and
the chain is where it is checked: an `admin_action` carrying an approval id is
the receipt that it has been used.

**The requester is self-asserted on the CLI, and this module does not pretend
otherwise.** `qed approve --by you@example.com` has always taken the approver's
word for it, because the CLI runs on the operator's own machine. What
self-governance buys there is that *two separate invocations naming two separate
subjects* are needed, which is a real obstacle to a careless action and no
obstacle at all to a determined operator lying about who they are. The identity
is proven only on the API path, where a delegation token says who is asking.
``THREAT_MODEL.md`` says this where an auditor will read it rather than leaving
it to be discovered.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = [
    "AdminOperation",
    "AdminRefusal",
    "GateDecision",
    "decide_admin",
]


class AdminOperation(StrEnum):
    """The operations SPEC §17 puts behind an approval.

    Named rather than free text so a config typo is a validation error instead
    of an operation that silently governs nothing. `policy_reload` is here with
    no command behind it yet: it is in the spec's list, and a name that exists
    in the config but not in the enum would be the quiet failure this avoids.
    """

    keys_rotate = "keys_rotate"
    packs_import = "packs_import"
    policy_reload = "policy_reload"


#: What an `admin_action` payload calls the approval it spent. One constant,
#: because the gate writes it and the gate reads it back to refuse reuse, and
#: two spellings would make every approval look unspent.
APPROVAL_FIELD: Final = "approval_id"


class AdminRefusal(Exception):
    """An admin operation that will not proceed, and why.

    The message is for an operator at a terminal: what is missing, and the one
    command that would supply it.
    """


@dataclass(frozen=True)
class GateDecision:
    """Whether an admin operation may proceed, and what to record."""

    allowed: bool
    #: True when self-governance is on for this operation. False means the
    #: instance is not self-governed and the action is ungated -- which is a
    #: fact worth recording either way, so `qed doctor` and an auditor can see
    #: that an unapproved rotation was unapproved *by configuration* and not by
    #: evasion.
    governed: bool
    break_glass: bool = False
    reason: str = ""
    approval_id: str | None = None

    def payload(self) -> dict[str, object]:
        """The fields an `admin_action` carries about its own authorisation."""
        document: dict[str, object] = {"self_governed": self.governed}
        if self.approval_id:
            document[APPROVAL_FIELD] = self.approval_id
        if self.break_glass:
            document["break_glass"] = True
            document["break_glass_reason"] = self.reason
        return document


def decide_admin(
    operation: AdminOperation,
    *,
    governed_operations: frozenset[AdminOperation],
    approval_id: str | None,
    approval_status: str | None,
    approval_operation: AdminOperation | None,
    approval_already_spent: bool,
    break_glass_reason: str,
    requester: str,
) -> GateDecision:
    """May this admin operation proceed?

    Pure: every fact it needs is an argument, so the ordering of the checks --
    which is the part with security content -- is testable without a chain, a
    store or a clock.

    The order matters. `break_glass` is checked **after** the governed check so
    that passing it on an ungoverned instance is not silently recorded as an
    emergency, and **before** the approval checks so that an operator in an
    incident is not told to go and find an approval id first.
    """
    if operation not in governed_operations:
        if break_glass_reason:
            # Not an error: a script may always pass it. But recording an
            # emergency override on an instance that has no gate would put a
            # false alarm in the chain, which is worse than ignoring the flag.
            return GateDecision(
                allowed=True,
                governed=False,
                reason="break-glass ignored: this operation is not self-governed",
            )
        return GateDecision(allowed=True, governed=False)

    if not requester:
        raise AdminRefusal(
            f"{operation.value} is self-governed on this instance, so it needs to know who "
            "is asking: pass `--by you@example.com`. The approver may not be the same "
            "subject, which is the whole point."
        )

    if break_glass_reason:
        return GateDecision(
            allowed=True,
            governed=True,
            break_glass=True,
            reason=break_glass_reason,
        )

    if approval_id is None:
        raise AdminRefusal(
            f"{operation.value} needs an approval on this instance. Nothing has been "
            "requested yet -- run this command again and it will open a request, or pass "
            "`--approval <id>` if you already have one. In an incident, "
            '`--break-glass "<why>"` proceeds and records that it did.'
        )

    if approval_status != "approved":
        raise AdminRefusal(
            f"approval {approval_id} is {approval_status or 'unknown'}, not approved. "
            f"Somebody other than {requester} has to run `qed approve {approval_id} "
            "--by them@example.com`."
        )

    if approval_operation is not operation:
        # An approval for one operation spent on another is the sort of thing
        # that reads as an administrative slip and works as a privilege
        # escalation: "approve the catalogue import" is a smaller ask than
        # "approve rotating the signing key".
        raise AdminRefusal(
            f"approval {approval_id} was granted for "
            f"{approval_operation.value if approval_operation else 'an unknown operation'}, "
            f"not for {operation.value}. An approval is for the thing it was asked about."
        )

    if approval_already_spent:
        raise AdminRefusal(
            f"approval {approval_id} has already been used -- the chain carries the "
            "`admin_action` that spent it. Approvals are single use, so that one "
            "agreement cannot authorise an operation twice."
        )

    return GateDecision(allowed=True, governed=True, approval_id=approval_id)
