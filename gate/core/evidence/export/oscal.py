"""OSCAL 1.1.2 ``assessment-results`` export (SPEC §10.8).

What an auditor gets: one ``result`` per export, one ``observation`` per evidence
record, and one ``finding`` per (rule hit, control) pair, targeted at the control
the rule claims to serve. The public keys and the checkpoint receipts travel in
``back-matter``, so the document an auditor receives contains everything needed
to verify the chain it describes.

Week 2 maps only the control references that the baseline rules carry in their
own ``compliance`` blocks. The compliance *packs* -- control titles, the full
EU AI Act and NIST AI RMF mapping -- are week 8. Until then this export says
exactly as much as the rules do and no more, and ``mapping-depth`` on every
finding says how deep that is (SPEC §11, honesty flags).

Determinism
-----------

Every UUID is a version 5 UUID derived from the thing it names: an observation
from the record hash, a finding from the record hash plus the rule and control.
Exporting the same range twice produces byte-identical output, and two auditors
working from two copies of the chain get the same document identifiers. OSCAL
requires v4 or v5, and v4 would have made each export unreproducible.

The only input that is not derived from the chain is ``generated_at``, which the
caller passes so that it, too, can be pinned.

Shape rules worth knowing when editing this file
------------------------------------------------

* Every array in the schema is ``minItems: 1``. An empty list is a validation
  error, not an empty section, so lists are added only when non-empty.
* ``target-id`` is an NCName. ``"Art. 14"`` is not one, so controls are
  tokenised and the verbatim framework and control also travel as props.
* ``uuid`` must have version nibble 4 or 5 and an RFC 4122 variant.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Final

import regex

from gate.core.schemas import (
    ENGINE_VERSION,
    Assurance,
    Decision,
    EvidenceRecord,
    EvidenceType,
    SigningKeyInfo,
    rfc3339_ms,
)

__all__ = ["OSCAL_VERSION", "PROP_NS", "control_token", "to_oscal"]

OSCAL_VERSION: Final = "1.1.2"

#: Namespace for gate's own properties. OSCAL requires custom props to be
#: namespaced so a consumer can tell them from the standard vocabulary.
PROP_NS: Final = "https://valqore.io/ns/oscal/gate"

#: Root for the derived UUIDs. A fixed v5 UUID under the DNS namespace, so the
#: value itself is reproducible from this string and not a magic constant.
_NS: Final = uuid.uuid5(uuid.NAMESPACE_DNS, "oscal.gate.valqore.io")

#: Characters that may not appear in an NCName.
_NOT_NCNAME: Final = regex.compile(r"[^\p{L}\p{N}.\-_]+")
_NCNAME_HEAD: Final = regex.compile(r"^(?:\p{L}|_)")
#: Two or more separators in a row, left behind when a control id has both
#: punctuation and a space ("Art. 14").
_SEPARATOR_RUN: Final = regex.compile(r"[.\-_]{2,}")

_OBSERVATION_METHOD: Final = "TEST"

#: How each record type reads in an observation description.
_DESCRIPTIONS: Final[dict[EvidenceType, str]] = {
    EvidenceType.genesis: "The evidence chain was opened.",
    EvidenceType.proposal: "An agent proposed an action and it was submitted for a decision.",
    EvidenceType.verdict: "The policy kernel decided a proposed action.",
    EvidenceType.approval_requested: "A human approval was requested for a proposed action.",
    EvidenceType.approval_decided: "A human decided an approval request.",
    EvidenceType.approval_expired: "An approval request expired without a decision.",
    EvidenceType.executed: "An allowed action was executed through gate.",
    EvidenceType.execution_result: "An adapter reported the result of an executed action.",
    EvidenceType.budget_update: "A delegation token's budget was updated.",
    EvidenceType.budget_exhausted: "A delegation token's budget was exhausted.",
    EvidenceType.policy_loaded: "A policy bundle was loaded and its hash recorded.",
    EvidenceType.key_rotated: "The evidence signing key was rotated.",
    EvidenceType.mandate_issued: "A mandate was issued to an agent.",
    EvidenceType.mandate_revoked: "A mandate was revoked.",
    EvidenceType.ungated_window: "Actions ran while the kernel was unreachable.",
    EvidenceType.correction: "A correction was appended for an earlier record.",
    EvidenceType.checkpoint: "A Merkle checkpoint was appended over a range of records.",
    EvidenceType.admin_action: "An administrative change to gate itself was recorded.",
}


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def to_oscal(
    records: Iterable[EvidenceRecord],
    *,
    instance_id: str,
    generated_at: datetime,
    signing_keys: Sequence[SigningKeyInfo] = (),
    policy_hash: str | None = None,
    title: str | None = None,
) -> dict[str, object]:
    """Build one ``assessment-results`` document over ``records``.

    Pure: no clock, no I/O, no store access. The caller supplies the records,
    the keys and the timestamp, which is what lets the CLI, the API and the
    tests all produce the same bytes for the same range.
    """
    ordered = sorted(records, key=lambda r: r.seq)
    if not ordered:
        raise ValueError("an OSCAL export needs at least one evidence record")

    first, last = ordered[0], ordered[-1]
    scope = f"{instance_id}:{first.seq}-{last.seq}:{last.hash}"

    observations = [_observation(record) for record in ordered]
    findings, controls, skipped = _findings(ordered)

    no_plan = _no_plan_resource(scope)
    resources: list[dict[str, object]] = [dict(no_plan)]
    resources.extend(_key_resource(key) for key in signing_keys)
    resources.extend(_checkpoint_resource(r) for r in ordered if r.type is EvidenceType.checkpoint)

    result: dict[str, object] = {
        "uuid": _uuid(f"result:{scope}"),
        "title": f"gate continuous monitoring, records {first.seq}-{last.seq}",
        "description": (
            f"Decisions and evidence recorded by gate instance {instance_id} for evidence "
            f"records {first.seq} through {last.seq}. Each observation is one signed, "
            "hash-chained evidence record; each finding is one policy rule that matched an "
            "action, targeted at a control that rule claims to serve."
        ),
        "start": rfc3339_ms(first.ts),
        "end": rfc3339_ms(last.ts),
        "props": _props(
            {
                "instance-id": instance_id,
                "chain-format": "gate-evidence/1.0",
                "engine-version": ENGINE_VERSION,
                "policy-hash": policy_hash,
                "first-seq": str(first.seq),
                "last-seq": str(last.seq),
                "chain-tip-hash": last.hash,
                "records": str(len(ordered)),
                "rule-hits-without-control": str(skipped) if skipped else None,
            }
        ),
        "reviewed-controls": _reviewed_controls(controls),
        "observations": observations,
    }
    if findings:
        result["findings"] = findings
    if skipped:
        result["remarks"] = (
            f"{skipped} rule hit(s) in this range carry no compliance block, so they have no "
            "control to target and appear as observation properties rather than findings. "
            "Adding a control reference is a policy change, not an export change."
        )

    return {
        "assessment-results": {
            "uuid": _uuid(f"document:{scope}"),
            "metadata": {
                "title": title or f"gate assessment results, instance {instance_id}",
                "last-modified": rfc3339_ms(generated_at),
                "version": ENGINE_VERSION,
                "oscal-version": OSCAL_VERSION,
                "props": _props(
                    {
                        "instance-id": instance_id,
                        "generator": "valqore-gate",
                        "generator-version": ENGINE_VERSION,
                        "mapping-scope": "baseline-rule-control-references-only",
                    }
                ),
            },
            "import-ap": {
                "href": f"#{no_plan['uuid']}",
                "remarks": (
                    "gate monitors continuously rather than running a planned assessment, so "
                    "there is no assessment plan to import. The reference resolves to a "
                    "back-matter resource that says so."
                ),
            },
            "results": [result],
            "back-matter": {"resources": resources},
        }
    }


# --------------------------------------------------------------------------
# Observations
# --------------------------------------------------------------------------


def _observation(record: EvidenceRecord) -> dict[str, object]:
    """One evidence record as an observation.

    ``methods: [TEST]`` because every record here is the output of an automated
    check rather than an interview or a document review. The assurance class
    (ADR-007.1) is the observation ``type``, which is what SPEC §10.8 asks for
    and what lets an auditor filter the testimony out of the attested facts.
    """
    payload = record.payload or {}
    description = _DESCRIPTIONS.get(record.type, f"A {record.type.value} record was appended.")
    extra = _payload_summary(record)
    if extra:
        description = f"{description} {extra}"
    if record.payload is None:
        description += (
            " The payload has been purged under the retention policy; the hashes and the "
            "signature are intact, so the record still verifies."
        )

    observation: dict[str, object] = {
        "uuid": _uuid(f"observation:{record.hash}"),
        "title": f"evidence record {record.seq}: {record.type.value}",
        "description": description,
        "methods": [_OBSERVATION_METHOD],
        "types": [f"assurance-{_assurance_token(record.assurance)}"],
        "collected": rfc3339_ms(record.ts),
    }
    # ``props`` is ``minItems: 1``: attach it only when something survived.
    props = _props(_observation_props(record, payload))
    if props:
        observation["props"] = props
    return observation


def _observation_props(record: EvidenceRecord, payload: dict[str, object]) -> dict[str, str | None]:
    props: dict[str, str | None] = {
        "evidence-seq": str(record.seq),
        "evidence-type": record.type.value,
        "assurance": record.assurance.value,
        "record-hash": record.hash,
        "previous-hash": record.prev_hash,
        "payload-hash": record.payload_hash,
        "signing-key-id": record.key_id,
        "signature": record.sig,
        "mode": None if record.mode is None else record.mode.value,
        "enforcement": None if record.enforcement is None else record.enforcement.value,
        "dev-key": "true" if record.dev else None,
        "payload-purged": "true" if record.payload is None else None,
    }
    verdict = payload.get("verdict")
    if isinstance(verdict, dict):
        props["proposal-id"] = _as_str(verdict.get("proposal_id"))
        props["decision"] = _as_str(verdict.get("decision"))
        props["would-decision"] = _as_str(verdict.get("would_decision"))
        props["blast-radius"] = _as_str(verdict.get("blast_radius"))
        props["policy-hash"] = _as_str(verdict.get("policy_hash"))
        hits = verdict.get("hits")
        if isinstance(hits, list):
            uncovered = [
                _as_str(hit.get("rule_id"))
                for hit in hits
                if isinstance(hit, dict) and not hit.get("compliance")
            ]
            joined = " ".join(h for h in uncovered if h)
            props["rule-hits-without-control"] = joined or None
    proposal = payload.get("proposal")
    if isinstance(proposal, dict):
        props["proposal-id"] = _as_str(proposal.get("id"))
        action = proposal.get("action")
        if isinstance(action, dict):
            props["action-kind"] = _as_str(action.get("kind"))
            props["action-name"] = _as_str(action.get("name"))
            props["action-target"] = _as_str(action.get("target"))
            props["params-hash"] = _as_str(action.get("params_hash"))
        context = proposal.get("context")
        if isinstance(context, dict):
            props["environment"] = _as_str(context.get("environment"))
            props["adapter"] = _as_str(context.get("adapter"))
            props["adapter-id"] = _as_str(context.get("adapter_id"))
    if record.type is EvidenceType.checkpoint:
        props["merkle-root"] = _as_str(payload.get("merkle_root"))
        props["checkpoint-from-seq"] = _as_str(payload.get("from_seq"))
        props["checkpoint-to-seq"] = _as_str(payload.get("to_seq"))
    return props


def _payload_summary(record: EvidenceRecord) -> str:
    """A sentence about this particular record, for someone reading the prose."""
    payload = record.payload or {}
    verdict = payload.get("verdict")
    if isinstance(verdict, dict):
        decision = _as_str(verdict.get("decision")) or "?"
        would = _as_str(verdict.get("would_decision")) or decision
        blast = _as_str(verdict.get("blast_radius")) or "?"
        text = f"Decision {decision} (blast radius {blast}/100)."
        if would != decision:
            text += f" With shadow rules counted as well it would have been {would}."
        return text
    proposal = payload.get("proposal")
    if isinstance(proposal, dict):
        context = proposal.get("context")
        summary = _as_str(context.get("summary")) if isinstance(context, dict) else None
        return summary or ""
    if record.type is EvidenceType.policy_loaded:
        total = _as_str(payload.get("rules_total")) or "?"
        active = _as_str(payload.get("rules_active")) or "?"
        return f"{active} of {total} rules active."
    if record.type is EvidenceType.checkpoint:
        return (
            f"Covers records {_as_str(payload.get('from_seq'))} to "
            f"{_as_str(payload.get('to_seq'))}."
        )
    if record.type is EvidenceType.ungated_window:
        calls = _as_str(payload.get("calls")) or "?"
        reason = _as_str(payload.get("reason")) or "no reason recorded"
        return f"{calls} call(s) were not decided: {reason}."
    if record.type is EvidenceType.execution_result:
        return f"Reported status {_as_str(payload.get('status')) or 'unknown'}."
    return ""


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def _findings(
    records: Sequence[EvidenceRecord],
) -> tuple[list[dict[str, object]], list[str], int]:
    """One finding per (rule hit, control reference). Returns also the skipped count."""
    findings: list[dict[str, object]] = []
    controls: dict[str, None] = {}
    skipped = 0

    for record in records:
        if record.type is not EvidenceType.verdict or record.payload is None:
            continue
        verdict = record.payload.get("verdict")
        if not isinstance(verdict, dict):
            continue
        hits = verdict.get("hits")
        if not isinstance(hits, list):
            continue
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            refs = hit.get("compliance")
            if not isinstance(refs, list) or not refs:
                skipped += 1
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                framework = _as_str(ref.get("framework"))
                control = _as_str(ref.get("control"))
                if framework is None or control is None:
                    skipped += 1
                    continue
                target_id = control_token(framework, control)
                controls[target_id] = None
                findings.append(_finding(record, verdict, hit, framework, control, target_id))

    return findings, sorted(controls), skipped


def _finding(
    record: EvidenceRecord,
    verdict: dict[str, object],
    hit: dict[str, object],
    framework: str,
    control: str,
    target_id: str,
) -> dict[str, object]:
    """One rule hit against one control.

    The status is about the *action*, not about gate: a rule that matched means
    the action the agent proposed did not satisfy the control objective. Whether
    gate then stopped it is a separate fact, carried in the ``enforced`` and
    ``mode`` props, because in shadow mode the objective was equally unsatisfied
    and nothing was prevented.
    """
    rule_id = _as_str(hit.get("rule_id")) or "unknown"
    decision = _as_str(hit.get("verdict")) or "unknown"
    satisfied = decision == Decision.ALLOW.value
    mode = _as_str(hit.get("mode")) or "enforce"
    enforced = mode == "enforce" and _as_str(record.mode) != "shadow"

    return {
        "uuid": _uuid(f"finding:{record.hash}:{rule_id}:{framework}:{control}"),
        "title": f"{rule_id} against {framework} {control}",
        "description": (
            f"{_as_str(hit.get('message')) or rule_id} "
            f"Rule {rule_id} matched evidence record {record.seq} and asked for {decision}."
            + (
                ""
                if enforced
                else " The rule was in shadow mode, so the action was recorded and not stopped."
            )
        ),
        "target": {
            "type": "objective-id",
            "target-id": target_id,
            "title": f"{framework} {control}",
            "status": {
                "state": "satisfied" if satisfied else "not-satisfied",
                "reason": "pass" if satisfied else "fail",
            },
            "props": _props(
                {
                    "framework": framework,
                    "control": control,
                    "mapping-scope": "rule-declared",
                }
            ),
        },
        "props": _props(
            {
                "rule-id": rule_id,
                "severity": _as_str(hit.get("severity")),
                "rule-mode": mode,
                "rule-verdict": decision,
                "enforced": "true" if enforced else "false",
                "evidence-seq": str(record.seq),
                "record-hash": record.hash,
                "policy-hash": _as_str(verdict.get("policy_hash")),
                "fix": _as_str(hit.get("fix")),
            }
        ),
        "related-observations": [{"observation-uuid": _uuid(f"observation:{record.hash}")}],
    }


def _reviewed_controls(controls: Sequence[str]) -> dict[str, object]:
    """Which controls this result speaks to.

    When no rule in the range carried a control reference there is nothing to
    list, and ``include-controls`` is ``minItems: 1``; ``include-all`` is the
    schema's own way of saying "everything in scope", with a description that
    makes the emptiness explicit rather than implied.
    """
    selection: dict[str, object] = {
        "description": (
            "Controls referenced by the policy rules that matched in this range. gate maps "
            "only what its rules declare; the full control catalogues are not imported."
        )
    }
    if controls:
        selection["include-controls"] = [{"control-id": control} for control in controls]
    else:
        selection["include-all"] = {}
        selection["description"] = (
            "No policy rule that matched in this range carries a control reference, so no "
            "specific control is in scope for this result."
        )
    return {
        "description": "Control references declared by the gate policy bundle.",
        "control-selections": [selection],
    }


# --------------------------------------------------------------------------
# Back matter
# --------------------------------------------------------------------------


def _no_plan_resource(scope: str) -> dict[str, str]:
    return {
        "uuid": _uuid(f"no-assessment-plan:{scope}"),
        "title": "No assessment plan",
        "description": (
            "gate produces assessment results from continuous monitoring of agent actions. "
            "There is no assessment plan document; OSCAL requires import-ap, so it resolves "
            "here."
        ),
    }


def _key_resource(key: SigningKeyInfo) -> dict[str, object]:
    """A public key, embedded, so the document can verify the chain it reports."""
    resource: dict[str, object] = {
        "uuid": _uuid(f"signing-key:{key.key_id}"),
        "title": f"Evidence signing public key {key.key_id}",
        "description": (
            f"The {key.alg} public key for records signed with key_id {key.key_id}. "
            "Verify the chain with `gate-verify --keys <dir>`."
        ),
        "props": _props(
            {
                "key-id": key.key_id,
                "algorithm": key.alg,
                "key-source": key.source,
                "created-at": None if key.created_at is None else rfc3339_ms(key.created_at),
                "retired-at": None if key.retired_at is None else rfc3339_ms(key.retired_at),
            }
        ),
        "base64": {
            "filename": f"{_filename_token(key.key_id)}.pem",
            "media-type": "application/x-pem-file",
            "value": base64.b64encode(key.public_pem.encode("utf-8")).decode("ascii"),
        },
    }
    return resource


def _checkpoint_resource(record: EvidenceRecord) -> dict[str, object]:
    """A checkpoint and whatever receipts the previous one collected."""
    payload = record.payload or {}
    receipts = payload.get("previous_receipts")
    count = len(receipts) if isinstance(receipts, list) else 0
    return {
        "uuid": _uuid(f"checkpoint:{record.hash}"),
        "title": f"Merkle checkpoint at record {record.seq}",
        "description": (
            f"Merkle root over records {_as_str(payload.get('from_seq'))} to "
            f"{_as_str(payload.get('to_seq'))}. "
            + (
                f"Carries {count} publication receipt(s) for the previous checkpoint."
                if count
                else "No publication receipts were attached."
            )
        ),
        "props": _props(
            {
                "evidence-seq": str(record.seq),
                "merkle-root": _as_str(payload.get("merkle_root")),
                "checkpoint-from-seq": _as_str(payload.get("from_seq")),
                "checkpoint-to-seq": _as_str(payload.get("to_seq")),
                "previous-receipts": str(count),
            }
        ),
    }


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def control_token(framework: str, control: str) -> str:
    """``("eu_ai_act", "Art. 14")`` -> ``"eu_ai_act.art-14"``.

    OSCAL's ``target-id`` is an NCName: no spaces, no colons, and it may not
    start with a digit. Real control ids break all three rules ("Art. 14",
    "A.5.34", "6.2.4"), so they are tokenised. The verbatim framework and
    control stay on the target as props, which is what an auditor reads; the
    token only has to be stable, unique and legal.

    Runs of separators are collapsed so that ``"Art. 14"`` -- a dot *and* a
    space -- does not come out as ``art.-14``. Single separators survive, so
    ``"CC8.1"`` stays recognisable as ``soc2.cc8.1`` rather than becoming
    ``soc2-cc8-1``; an auditor has to be able to find the control they asked
    about.
    """
    return _token(f"{_slug(framework)}.{_slug(control)}")


def _slug(value: str) -> str:
    cleaned = _NOT_NCNAME.sub("-", value.strip().lower())
    return str(_SEPARATOR_RUN.sub("-", cleaned)).strip(".-_")


def _token(base: str) -> str:
    # An NCName may not start with a digit, and "6.2.4" does.
    return base if _NCNAME_HEAD.match(base) else f"_{base}"


def _assurance_token(assurance: Assurance) -> str:
    # ``Assurance.self_`` serialises as "self"; the enum member name has the
    # trailing underscore only because `self` is a keyword.
    return assurance.value


def _props(values: dict[str, str | None]) -> list[dict[str, str]]:
    """Drop the empty entries and namespace the rest.

    Returns a list that the caller must only attach when it is non-empty --
    ``props`` is ``minItems: 1`` everywhere in the schema.
    """
    return [
        {"name": name, "value": value, "ns": PROP_NS}
        for name, value in values.items()
        if value is not None and value != ""
    ]


def _uuid(name: str) -> str:
    return str(uuid.uuid5(_NS, name))


def _as_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return None


def _filename_token(value: str) -> str:
    """A key_id contains a colon, which is not legal in a filename on Windows."""
    return str(regex.sub(r"[^A-Za-z0-9._-]+", "_", value))
