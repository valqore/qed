"""OCSF events for a SIEM (SPEC §18, §13).

The evidence chain is the record of what happened; this is the same facts in
the shape a SIEM already understands, so an authorization decision from `qed`
lands in the same dashboard as one from an identity provider or a cloud
audit log.

**It is a copy, not the record.** The chain is the authority and `qed-verify`
checks it; a SIEM event is a derived view, unsigned, and designed to be dropped
when a webhook is down. Nothing here is on the decision path, nothing is
retried into the chain, and a SIEM that never receives an event changes nothing
about what was decided or recorded.

Which OCSF class a record maps to is the one substantive decision, and it is
made by *what the record says*, not by a guess:

* a verdict is **Authorization (3003)** — the class that exists for "a request
  was allowed or denied", with `activity_id` saying which and `authorizations`
  carrying the rules that decided it;
* everything else is **API Activity (6003)** — a call that happened, with the
  operation named. A proposal, an execution result, a budget update and a key
  rotation are all of this shape.

Approvals are deliberately *not* mapped to an Account Change or an Entity
Management class. An approval is an authorization decision made by a person
rather than by a rule, so it is Authorization too, with the approver as the
actor. Putting it elsewhere would split one question — "who allowed this?" —
across two dashboards.

Pure: no network, no clock, no store. `qed/infra/siem.py` does the sending.
"""

from __future__ import annotations

from typing import Final

from qed.core.schemas import EvidenceRecord, EvidenceType, rfc3339_ms

__all__ = [
    "ACTIVITY_ALLOW",
    "ACTIVITY_DENY",
    "CLASS_API_ACTIVITY",
    "CLASS_AUTHORIZATION",
    "SCHEMA_VERSION",
    "to_ocsf",
]

#: OCSF schema this maps to. Named in every event, because a consumer's parser
#: is written against a version and a silent change of shape is the thing that
#: breaks an ingestion pipeline a month later.
SCHEMA_VERSION: Final = "1.3.0"

CLASS_AUTHORIZATION: Final = 3003
CLASS_API_ACTIVITY: Final = 6003

#: `activity_id` within Authorization. OCSF numbers these: 1 is Assign
#: Privileges (allowed), 2 is Revoke Privileges (denied).
ACTIVITY_UNKNOWN: Final = 0
ACTIVITY_ALLOW: Final = 1
ACTIVITY_DENY: Final = 2

#: `severity_id`. Mapped from what the decision *did*, not from a rule's own
#: severity: a CRITICAL rule that fired in shadow mode stopped nothing, and
#: paging on it would train people to ignore the channel.
SEVERITY_INFORMATIONAL: Final = 1
SEVERITY_LOW: Final = 2
SEVERITY_MEDIUM: Final = 3
SEVERITY_HIGH: Final = 4

#: `status_id`: 1 Success, 2 Failure.
STATUS_SUCCESS: Final = 1
STATUS_FAILURE: Final = 2

_AUTHORIZATION_TYPES: Final = frozenset({EvidenceType.verdict, EvidenceType.approval_decided})


def to_ocsf(
    record: EvidenceRecord,
    *,
    instance_id: str,
    principal_hash: str | None = None,
) -> dict[str, object]:
    """One evidence record as one OCSF event.

    `instance_id` is passed rather than read from the record, because an
    `EvidenceRecord` does not carry it -- it is a property of the chain, and
    the SIEM needs it to tell two instances apart.

    `principal_hash` is for the records that reference a principal without
    carrying one. A `verdict`'s payload holds the verdict and a `proposal_id`,
    so without this the Authorization event -- the one a SIEM cares about most
    -- would have `actor: unknown`, and an authorization feed that cannot say
    who was authorized is not much of a feed.
    """
    if record.type in _AUTHORIZATION_TYPES:
        return _authorization(record, instance_id=instance_id, principal_hash=principal_hash)
    return _api_activity(record, instance_id=instance_id, principal_hash=principal_hash)


# --------------------------------------------------------------------------
# Authorization (3003)
# --------------------------------------------------------------------------


def _authorization(
    record: EvidenceRecord, *, instance_id: str, principal_hash: str | None = None
) -> dict[str, object]:
    payload = record.payload or {}
    verdict = payload.get("verdict")
    verdict = verdict if isinstance(verdict, dict) else {}
    decision = str(verdict.get("decision") or payload.get("decision") or "")

    event: dict[str, object] = {
        **_common(record, instance_id=instance_id, principal_hash=principal_hash),
        "class_uid": CLASS_AUTHORIZATION,
        "class_name": "Authorization",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": _activity_for(decision),
        "activity_name": _activity_name(decision),
        "type_uid": CLASS_AUTHORIZATION * 100 + _activity_for(decision),
        "severity_id": _severity_for(record, decision),
        "status_id": STATUS_SUCCESS,
        # The decision string as qed wrote it. OCSF's three-way activity_id
        # cannot express REQUIRE_APPROVAL, which is the verdict that matters
        # most to a reviewer, so it travels verbatim as well.
        "action": decision or "UNKNOWN",
    }

    rules = verdict.get("hits")
    if isinstance(rules, list) and rules:
        event["authorizations"] = [
            {
                "decision": decision,
                "policy": {
                    "uid": str(hit.get("rule_id", "")),
                    "name": str(hit.get("message", ""))[:256],
                    "desc": str(hit.get("severity", "")),
                },
            }
            for hit in rules
            if isinstance(hit, dict)
        ]
    if verdict.get("policy_hash"):
        event["metadata"] = {
            **_metadata(),
            "labels": [f"policy_hash:{verdict['policy_hash']}"],
        }
    if payload.get("approval_id") or verdict.get("approval_id"):
        event["actor"] = {
            **_actor(record, principal_hash=principal_hash),
            "invoked_by": str(payload.get("approval_id") or verdict.get("approval_id")),
        }
    return event


def _activity_for(decision: str) -> int:
    if decision == "ALLOW":
        return ACTIVITY_ALLOW
    if decision in {"BLOCK", "deny"}:
        return ACTIVITY_DENY
    # REQUIRE_APPROVAL, approve_once, approve_window: neither granted nor
    # refused yet, and OCSF has no third value. `Unknown` with the real
    # decision in `action` is honest; forcing it to Allow would report a grant
    # that has not happened.
    return ACTIVITY_UNKNOWN


def _activity_name(decision: str) -> str:
    return {
        ACTIVITY_ALLOW: "Assign Privileges",
        ACTIVITY_DENY: "Revoke Privileges",
    }.get(_activity_for(decision), "Unknown")


def _severity_for(record: EvidenceRecord, decision: str) -> int:
    """From what the decision *did*.

    A CRITICAL rule that fired in shadow mode stopped nothing, so it is not a
    high-severity event -- paging on it would train people to ignore the
    channel. `mode` is on the record, so this can tell the two apart.
    """
    shadow = record.mode is not None and record.mode.value == "shadow"
    if decision == "BLOCK":
        return SEVERITY_MEDIUM if shadow else SEVERITY_HIGH
    if decision == "REQUIRE_APPROVAL":
        return SEVERITY_LOW if shadow else SEVERITY_MEDIUM
    return SEVERITY_INFORMATIONAL


# --------------------------------------------------------------------------
# API Activity (6003)
# --------------------------------------------------------------------------


def _api_activity(
    record: EvidenceRecord, *, instance_id: str, principal_hash: str | None = None
) -> dict[str, object]:
    payload = record.payload or {}
    failed = str(payload.get("status", "")) in {"error", "failed", "refused"}
    event: dict[str, object] = {
        **_common(record, instance_id=instance_id, principal_hash=principal_hash),
        "class_uid": CLASS_API_ACTIVITY,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        # 0 Unknown: the record type is the operation, and mapping fifteen
        # types onto OCSF's four CRUD verbs would invent a distinction the
        # chain does not make.
        "activity_id": ACTIVITY_UNKNOWN,
        "activity_name": record.type.value,
        "type_uid": CLASS_API_ACTIVITY * 100,
        "severity_id": SEVERITY_HIGH
        if record.type is EvidenceType.ungated_window
        else SEVERITY_INFORMATIONAL,
        "status_id": STATUS_FAILURE if failed else STATUS_SUCCESS,
        "api": {
            "operation": record.type.value,
            "service": {"name": "qed"},
        },
    }
    nested = payload.get("proposal")
    nested = nested if isinstance(nested, dict) else {}
    action = nested.get("action") or payload.get("action")
    if isinstance(action, dict) and action.get("name"):
        # The verb, never the target. A SIEM event leaves the instance, and a
        # target is the half of an action that names somebody's data.
        event["api"] = {
            **(event["api"] if isinstance(event["api"], dict) else {}),
            "operation": str(action["name"])[:128],
        }
    elif isinstance(action, str):
        event["api"] = {
            **(event["api"] if isinstance(event["api"], dict) else {}),
            "operation": action[:128],
        }
    return event


# --------------------------------------------------------------------------
# Shared
# --------------------------------------------------------------------------


def _common(
    record: EvidenceRecord, *, instance_id: str, principal_hash: str | None = None
) -> dict[str, object]:
    payload = record.payload or {}
    verdict = payload.get("verdict")
    verdict = verdict if isinstance(verdict, dict) else {}
    nested = payload.get("proposal")
    nested = nested if isinstance(nested, dict) else {}
    proposal_id = nested.get("id") or verdict.get("proposal_id") or payload.get("proposal_id")
    return {
        "time": rfc3339_ms(record.ts),
        "metadata": _metadata(),
        "actor": _actor(record, principal_hash=principal_hash),
        "observables": _observables(record, instance_id=instance_id),
        # Not `message`: OCSF reserves that for a human-readable summary and
        # this is a reference an operator can resolve.
        "raw_data": f"qed:{instance_id}:{record.seq}",
        "unmapped": {
            "qed_seq": record.seq,
            "qed_type": record.type.value,
            "qed_assurance": record.assurance.value,
            "qed_instance_id": instance_id,
            "qed_record_hash": record.hash,
            "qed_key_id": record.key_id,
            # The reason this event is a copy and not the record: an auditor
            # verifies the chain, and this points at the entry to verify.
            "qed_verify_with": "qed export | qed-verify --keys <public dir>",
            # The join key. A verdict event carries no action name -- the
            # proposal event has it -- and this is how a SIEM puts the two
            # together, which is what a SIEM is good at.
            **({"qed_proposal_id": str(proposal_id)} if proposal_id else {}),
        },
    }


def _metadata() -> dict[str, object]:
    return {
        "version": SCHEMA_VERSION,
        "product": {
            "name": "Valqore QED",
            "vendor_name": "Valqore",
            "feature": {"name": "policy-kernel"},
        },
    }


def _actor(record: EvidenceRecord, *, principal_hash: str | None = None) -> dict[str, object]:
    """Who did it, as far as the chain knows.

    A principal appears only as a hash (SPEC §10.9), so `uid` is that hash and
    there is no name, email or ip. Resolving it is the operator's job, inside
    their own systems, with data `qed` never held.
    """
    payload = record.payload or {}
    # The principal sits one level down in a `proposal` record -- the whole
    # proposal document is the payload -- and at the top level in the records
    # that mention a principal directly, like an approval decision. Both,
    # because the actor is the most useful field in a SIEM event and an
    # `unknown` here makes the whole feed much less so.
    nested = payload.get("proposal")
    nested = nested if isinstance(nested, dict) else {}
    principal = nested.get("principal") or payload.get("principal")
    principal = principal if isinstance(principal, dict) else {}
    human = (
        principal.get("human_hash")
        or payload.get("principal_hash")
        or payload.get("approver_hash")
        or principal_hash
    )
    actor: dict[str, object] = {"user": {"uid": str(human) if human else "unknown"}}
    chain = principal.get("agent_chain")
    agent = (
        chain[0]
        if isinstance(chain, list) and chain
        else principal.get("agent_id") or principal.get("token_jti")
    )
    if agent:
        # The first link of the agent chain: who is acting, as opposed to on
        # whose behalf. SPEC §4's delegation chain can be four deep, and a
        # SIEM pivot wants the nearest actor.
        actor["process"] = {"name": str(agent)[:128]}
    return actor


def _observables(record: EvidenceRecord, *, instance_id: str) -> list[dict[str, object]]:
    """The fields a SIEM can pivot on.

    `type_id: 10` is Fingerprint, which is what a record hash is: an opaque
    identifier that two systems can compare. Correlating on it is how somebody
    gets from an alert back to the evidence entry.
    """
    return [
        {"name": "record.hash", "type_id": 10, "value": record.hash},
        {"name": "instance.uid", "type_id": 10, "value": instance_id},
    ]
