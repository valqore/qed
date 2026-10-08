"""The OSCAL export validates against the NIST schema (SPEC §10.8, "MUST pass").

The schema in ``tests/oscal/`` is the published
``oscal_assessment-results_schema.json`` from the NIST OSCAL v1.1.2 release,
vendored byte for byte and checked by hash below. SPEC §10.8 allows JSON Schema
in place of ``oscal-cli``, which would put a JVM in CI for one check.

Schema validation is necessary and not sufficient, so the rest of this file
asserts the things a draft-07 validator cannot see: that the identifiers are
derived rather than random, that a purged payload still exports, and that no
rule hit is silently dropped on the way out.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gate.core.evidence.export.oscal import OSCAL_VERSION, control_token, to_oscal
from gate.core.policy.engine import evaluate
from gate.core.policy.model import PolicyBundle
from gate.core.schemas import (
    Assurance,
    BudgetState,
    EvalContext,
    EvidenceRecord,
    EvidenceType,
    Mode,
    SigningKeyInfo,
)
from gate.infra.chain_writer import ChainWriter
from gate.infra.keys.file import FileSigner
from gate.infra.storage.sqlite import SqliteStore
from tests.conftest import NOW, make_proposal
from tests.oscal import build_validator

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "oscal" / "oscal_assessment-results_schema.json"

#: sha256 of the file as published by NIST. If this fails, the vendored schema
#: was edited or replaced; an export that only validates against a schema
#: somebody adjusted proves nothing about OSCAL.
SCHEMA_SHA256 = "d033da70154cf6625ae46a746199e88e58f2928b1387dfac051d381b92f41b0d"

GENERATED_AT = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)

#: Proposals chosen to produce findings across several frameworks, a BLOCK and a
#: REQUIRE_APPROVAL, a shadow-mode hit, and a hit with no compliance block.
CASES: list[dict[str, Any]] = [
    {
        "id": "01JB0000000000000000000001",
        "action": {
            "name": "postgres.execute_sql",
            "target": "db:prod/orders",
            "params_redacted": {"sql": "DROP TABLE orders_archive;"},
        },
        "context": {
            "environment": "prod",
            "blast_radius_hints": {"writes": True, "deletes": True, "scope": "multi_resource"},
        },
    },
    {
        "id": "01JB0000000000000000000002",
        "action": {"name": "aws.put_role_policy", "target": "aws:iam:roles/deploy"},
        "context": {
            "environment": "prod",
            "blast_radius_hints": {"writes": True, "deletes": False, "scope": "account"},
        },
    },
    {
        "id": "01JB0000000000000000000003",
        "action": {"name": "github.list_issues", "target": "repo:acme/payments"},
    },
]


@pytest.fixture(scope="module")
def validator() -> Any:
    raw = SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256, (
        "the vendored NIST schema has changed; update SCHEMA_SHA256 only together with a "
        "deliberate OSCAL version bump"
    )
    return build_validator(json.loads(raw.decode("utf-8")))


@pytest.fixture
def chain(tmp_path: Path, baseline_bundle: PolicyBundle) -> list[EvidenceRecord]:
    """A real chain: genesis, proposals, verdicts, a result and a checkpoint."""
    store = SqliteStore(tmp_path / "gate.db")
    signer = FileSigner.generate()
    writer = ChainWriter(store, signer, instance_id="gate-test")
    records: list[EvidenceRecord] = []

    for patch in CASES:
        proposal = make_proposal(patch)
        records.append(
            writer.append(
                type_=EvidenceType.proposal,
                assurance=Assurance.kernel,
                payload={"proposal": proposal.model_dump(mode="json")},
                mode=Mode.shadow,
                enforcement=proposal.context.enforcement,
                proposal_id=proposal.id,
                principal_hash=proposal.principal.human_hash,
            )
        )
        verdict = evaluate(
            proposal,
            baseline_bundle,
            BudgetState(token_jti=proposal.principal.token_jti),
            EvalContext(now=NOW),
        )
        records.append(
            writer.append(
                type_=EvidenceType.verdict,
                assurance=Assurance.kernel,
                payload={"verdict": verdict.model_dump(mode="json")},
                mode=Mode.shadow,
                enforcement=proposal.context.enforcement,
                proposal_id=proposal.id,
                principal_hash=proposal.principal.human_hash,
            )
        )

    records.append(
        writer.append(
            type_=EvidenceType.execution_result,
            assurance=Assurance.adapter,
            payload={"proposal_id": CASES[0]["id"], "status": "ok", "duration_ms": 12.5},
            mode=Mode.shadow,
        )
    )
    checkpoint = writer.checkpoint(force=True)
    assert checkpoint is not None
    records.append(checkpoint)

    everything = list(store.iter_evidence())
    store.close()
    return everything


@pytest.fixture
def keys() -> list[SigningKeyInfo]:
    signer = FileSigner.generate()
    return [
        SigningKeyInfo(
            key_id=signer.key_id,
            public_pem=signer.public_pem,
            created_at=GENERATED_AT,
        )
    ]


def export(records: list[EvidenceRecord], keys: list[SigningKeyInfo]) -> dict[str, Any]:
    return to_oscal(
        records,
        instance_id="gate-test",
        generated_at=GENERATED_AT,
        signing_keys=keys,
        policy_hash="a" * 64,
    )


# --------------------------------------------------------------------- schema


def test_the_export_validates_against_the_nist_schema(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    errors = sorted(validator.iter_errors(export(chain, keys)), key=lambda e: list(e.path))
    assert not errors, "\n".join(
        f"{'/'.join(str(p) for p in error.path)}: {error.message}" for error in errors[:20]
    )


def test_a_single_record_export_validates(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    """The genesis record alone: no findings, no controls, no checkpoints.

    Every array in the schema is ``minItems: 1``, so the degenerate export is
    where an empty list would be caught.
    """
    errors = list(validator.iter_errors(export(chain[:1], keys)))
    assert not errors, [error.message for error in errors[:5]]


def test_an_export_without_keys_validates(chain: list[EvidenceRecord], validator: Any) -> None:
    errors = list(validator.iter_errors(export(chain, [])))
    assert not errors, [error.message for error in errors[:5]]


def test_a_purged_payload_still_exports_and_validates(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    """Retention (SPEC §10.6) nulls payloads; the chain still verifies forever."""
    purged = [record.model_copy(update={"payload": None}) for record in chain]
    document = export(purged, keys)
    assert not list(validator.iter_errors(document))
    observations = document["assessment-results"]["results"][0]["observations"]
    assert any("purged" in obs["description"] for obs in observations)


def test_an_empty_range_is_refused(keys: list[SigningKeyInfo]) -> None:
    with pytest.raises(ValueError, match="at least one evidence record"):
        export([], keys)


# --------------------------------------------------------- the schema bites


def test_the_validator_rejects_a_random_uuid_version(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    """Negative control.

    A validator that accepts everything is worse than no validator, and this
    suite's whole claim rests on one. OSCAL requires a v4 or v5 UUID; a v1 is
    a plausible mistake that only the ``pattern`` keyword catches -- and
    ``pattern`` is the keyword this suite had to swap the regex engine for.
    """
    document = export(chain, keys)
    document["assessment-results"]["uuid"] = "c232fd54-a4b9-11ee-be56-0242ac120002"
    errors = list(validator.iter_errors(document))
    assert errors, "the validator accepted a version 1 UUID"
    assert any("does not match" in error.message for error in errors)


def test_the_validator_rejects_a_control_id_that_is_not_an_ncname(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    """The constraint ``control_token`` exists to satisfy is really enforced."""
    document = export(chain, keys)
    result = document["assessment-results"]["results"][0]
    result["findings"][0]["target"]["target-id"] = "EU AI Act Art. 14"
    assert list(validator.iter_errors(document)), (
        "the validator accepted a target-id with spaces; the \\p{L} patterns in the NIST "
        "schema are not being evaluated"
    )


def test_the_validator_rejects_a_missing_required_field(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    document = export(chain, keys)
    del document["assessment-results"]["results"][0]["reviewed-controls"]
    assert list(validator.iter_errors(document))


def test_the_validator_rejects_an_empty_array(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo], validator: Any
) -> None:
    """Every array in the schema is ``minItems: 1``; this is why props are guarded."""
    document = export(chain, keys)
    document["assessment-results"]["results"][0]["observations"][0]["props"] = []
    assert list(validator.iter_errors(document))


# ----------------------------------------------------------------- semantics


def test_every_record_becomes_exactly_one_observation(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    result = export(chain, keys)["assessment-results"]["results"][0]
    assert len(result["observations"]) == len(chain)
    uuids = {obs["uuid"] for obs in result["observations"]}
    assert len(uuids) == len(chain), "two records produced the same observation uuid"


def test_the_assurance_class_is_the_observation_type(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    result = export(chain, keys)["assessment-results"]["results"][0]
    by_seq = {int(_prop(obs, "evidence-seq")): obs["types"][0] for obs in result["observations"]}
    adapter_seq = next(r.seq for r in chain if r.assurance is Assurance.adapter)
    assert by_seq[adapter_seq] == "assurance-adapter"
    assert by_seq[0] == "assurance-kernel"


def test_every_rule_hit_is_either_a_finding_or_a_counted_omission(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    """Nothing is dropped quietly.

    A hit with a compliance block becomes one finding per control reference. A
    hit without one has no control to target, so it is counted in the result
    props and named on the observation instead.
    """
    result = export(chain, keys)["assessment-results"]["results"][0]
    expected_findings = 0
    uncovered = 0
    for record in chain:
        if record.type is not EvidenceType.verdict or record.payload is None:
            continue
        verdict = record.payload["verdict"]
        assert isinstance(verdict, dict)
        hits = verdict["hits"]
        assert isinstance(hits, list)
        for hit in hits:
            refs = hit.get("compliance") or []
            if refs:
                expected_findings += len(refs)
            else:
                uncovered += 1

    assert len(result.get("findings", [])) == expected_findings
    assert int(_prop(result, "rule-hits-without-control") or 0) == uncovered
    if uncovered:
        assert "no compliance block" in result["remarks"]


def test_findings_target_the_controls_listed_in_reviewed_controls(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    result = export(chain, keys)["assessment-results"]["results"][0]
    selection = result["reviewed-controls"]["control-selections"][0]
    listed = {entry["control-id"] for entry in selection["include-controls"]}
    targeted = {finding["target"]["target-id"] for finding in result["findings"]}
    assert targeted == listed


def test_a_blocked_action_is_a_not_satisfied_objective(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    result = export(chain, keys)["assessment-results"]["results"][0]
    states = {
        _prop(finding, "rule-id"): finding["target"]["status"]["state"]
        for finding in result["findings"]
    }
    # AG-BLR-003 asks for approval on the prod DROP; the objective was not met.
    assert states["AG-BLR-003"] == "not-satisfied"


def test_a_shadow_rule_hit_says_it_was_not_enforced(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    result = export(chain, keys)["assessment-results"]["results"][0]
    for finding in result["findings"]:
        assert _prop(finding, "enforced") == "false", (
            "the whole fixture chain was written in shadow mode, so no finding may "
            "claim it was enforced"
        )
        assert "recorded and not stopped" in finding["description"]


def test_the_public_key_travels_in_back_matter(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    """An auditor must be able to verify the chain the document describes."""
    import base64

    back = export(chain, keys)["assessment-results"]["back-matter"]["resources"]
    embedded = [r for r in back if "base64" in r]
    assert len(embedded) == 1
    decoded = base64.b64decode(embedded[0]["base64"]["value"]).decode("utf-8")
    assert decoded == keys[0].public_pem
    assert ":" not in embedded[0]["base64"]["filename"], "a key_id colon is not a legal filename"


def test_import_ap_resolves_to_a_back_matter_resource(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    document = export(chain, keys)["assessment-results"]
    href = document["import-ap"]["href"]
    assert href.startswith("#")
    uuids = {resource["uuid"] for resource in document["back-matter"]["resources"]}
    assert href[1:] in uuids


def test_the_checkpoint_merkle_root_is_in_back_matter(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    back = export(chain, keys)["assessment-results"]["back-matter"]["resources"]
    checkpoint = next(r for r in back if r["title"].startswith("Merkle checkpoint"))
    assert _prop(checkpoint, "merkle-root")


def test_the_document_declares_the_oscal_version_it_targets(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    metadata = export(chain, keys)["assessment-results"]["metadata"]
    assert metadata["oscal-version"] == OSCAL_VERSION == "1.1.2"


def test_the_mapping_scope_is_stated_rather_than_implied(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    """Week 2 maps rule-declared controls only; an auditor must see that."""
    document = export(chain, keys)["assessment-results"]
    assert _prop(document["metadata"], "mapping-scope") == ("baseline-rule-control-references-only")
    for finding in document["results"][0]["findings"]:
        assert _prop(finding["target"], "mapping-scope") == "rule-declared"


# ---------------------------------------------------------------- determinism


def test_the_same_range_exports_identically_twice(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    first = json.dumps(export(chain, keys), sort_keys=True)
    second = json.dumps(export(chain, keys), sort_keys=True)
    assert first == second


def test_identifiers_are_derived_from_the_records(
    chain: list[EvidenceRecord], keys: list[SigningKeyInfo]
) -> None:
    """Change one record's hash and only that observation's uuid moves."""
    before = export(chain, keys)["assessment-results"]["results"][0]["observations"]
    altered = list(chain)
    altered[1] = altered[1].model_copy(update={"hash": "f" * 64})
    after = export(altered, keys)["assessment-results"]["results"][0]["observations"]

    moved = [
        (one["uuid"], two["uuid"])
        for one, two in zip(before, after, strict=True)
        if one["uuid"] != two["uuid"]
    ]
    assert len(moved) == 1


# ------------------------------------------------------------ control tokens


@pytest.mark.parametrize(
    ("framework", "control", "expected"),
    [
        ("eu_ai_act", "Art. 14", "eu_ai_act.art-14"),
        ("soc2", "CC8.1", "soc2.cc8.1"),
        ("iso_27001", "A.5.34", "iso_27001.a.5.34"),
        ("nist_ai_rmf", "MANAGE-2.2", "nist_ai_rmf.manage-2.2"),
        ("owasp_agentic", "ASI04", "owasp_agentic.asi04"),
    ],
)
def test_control_ids_become_ncnames(framework: str, control: str, expected: str) -> None:
    """OSCAL's ``target-id`` is an NCName: no spaces, no colons, no leading digit."""
    import regex

    token = control_token(framework, control)
    assert token == expected
    assert regex.fullmatch(r"(?:\p{L}|_)(?:\p{L}|\p{N}|[.\-_])*", token)


def test_a_control_id_starting_with_a_digit_is_still_an_ncname() -> None:
    assert control_token("9lives", "2.3").startswith("_")


def _prop(node: dict[str, Any], name: str) -> str | None:
    for prop in node.get("props", []):
        if prop["name"] == name:
            return str(prop["value"])
    return None
