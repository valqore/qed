"""``/v1/proposals`` (SPEC §13, SPEC §22 week 2).

The first test is the week 2 exit criterion: ``POST /v1/proposals`` returns the
same verdict ``gate check`` would, for the same input. It is asserted by running
both against the same proposal and comparing the verdict JSON field by field,
rather than by trusting that both call ``check_proposal`` -- which is true today
and is exactly the kind of thing a refactor breaks quietly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from gate.cli import app as cli_app
from tests.api.conftest import Signer
from tests.conftest import BASE_PROPOSAL, deep_merge

runner = CliRunner()

PROD_DROP: dict[str, object] = {
    "id": "01JB0000000000000000000001",
    "action": {
        "name": "postgres.execute_sql",
        "target": "db:prod/orders",
        "params_redacted": {"sql": "DROP TABLE orders_archive;"},
    },
    "context": {
        "environment": "prod",
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "single_resource"},
    },
}


def proposal(patch: dict[str, object] | None = None) -> dict[str, object]:
    return deep_merge(BASE_PROPOSAL, patch or {})


# --------------------------------------------------------------------------
# The exit criterion: one decision path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "patch",
    [
        {},
        PROD_DROP,
        {"id": "01JB000000000000000000000B", "principal": {"token_jti": ""}},
        {
            "id": "01JB000000000000000000000C",
            "action": {"params_redacted": {"body": "AKIAIOSFODNN7EXAMPLE"}},
        },
        {
            "id": "01JB000000000000000000000D",
            "context": {"environment": "prod", "blast_radius_hints": {"scope": "global"}},
        },
    ],
    ids=["plain-read", "prod-drop", "empty-token", "secret-in-params", "global-scope"],
)
def test_the_api_and_the_cli_agree(
    patch: dict[str, object],
    signed: Signer,
    api_dir: Path,
    gate_config: Path,
    tmp_path: Path,
) -> None:
    """SPEC §22: the same input must give the same verdict either way.

    Two separate state directories, so neither sees the other's chain and the
    duplicate-id check cannot interfere. The verdict is compared whole, with
    ``policy_hash`` included: a difference there would mean the two loaded
    different bundles.
    """
    body = proposal(patch)
    api = signed.post("/v1/proposals", body)
    assert api.status_code in {200, 202}, api.text
    from_api = api.json()["verdict"]

    cli_dir = tmp_path / "cli-gate"
    from gate.infra.keys.file import init_keys

    init_keys(cli_dir)
    proposal_file = tmp_path / "p.json"
    proposal_file.write_text(json.dumps(body), encoding="utf-8")
    result = runner.invoke(
        cli_app,
        [
            "check",
            str(proposal_file),
            "--dir",
            str(cli_dir),
            "--config",
            str(gate_config),
            "--json",
        ],
    )
    assert result.exit_code in {0, 2, 3}, result.output
    from_cli = json.loads(result.output)["verdict"]

    # `approval_id` is per-request state: a REQUIRE_APPROVAL opens a request
    # in whichever store it ran against, and two independent stores mint two
    # ids. Everything the decision rests on still has to match byte for byte,
    # which is what this test exists for.
    assert (from_api.get("approval_id") is None) == (from_cli.get("approval_id") is None)
    assert {k: v for k, v in from_api.items() if k != "approval_id"} == {
        k: v for k, v in from_cli.items() if k != "approval_id"
    }


# --------------------------------------------------------------------------
# POST /v1/proposals
# --------------------------------------------------------------------------


def test_a_verdict_carries_an_evidence_reference(signed: Signer) -> None:
    response = signed.post("/v1/proposals", proposal())
    payload = response.json()
    assert payload["evidence_seq"] == [2, 3], "genesis, policy_loaded, proposal, verdict"
    assert payload["evidence_ref"] == "3"
    assert payload["approval"] is None


def test_shadow_mode_reports_the_decision_and_allows_anyway(signed: Signer) -> None:
    response = signed.post("/v1/proposals", proposal(PROD_DROP))
    assert response.status_code == 200, "nothing is pending in shadow mode"
    payload = response.json()
    assert payload["verdict"]["decision"] == "REQUIRE_APPROVAL"
    assert payload["enforced"] is False
    assert payload["effective_decision"] == "ALLOW"


def test_enforce_mode_answers_202_for_an_approval(
    api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SPEC §13: 202 when REQUIRE_APPROVAL is actually being enforced."""
    import yaml
    from fastapi.testclient import TestClient as Client

    from gate.api.app import create_app
    from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV

    monkeypatch.setenv(SECRET_ENV, SECRET)
    config = tmp_path / "enforce.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "mode": "enforce",
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}],
            }
        ),
        encoding="utf-8",
    )
    with Client(create_app(directory=api_dir, config_path=config)) as client:
        response = Signer(client).post("/v1/proposals", proposal(PROD_DROP))
    assert response.status_code == 202
    assert response.json()["enforced"] is True
    assert response.json()["effective_decision"] == "REQUIRE_APPROVAL"


def test_a_replayed_proposal_id_is_a_conflict(signed: Signer) -> None:
    """SPEC §17: ids are single-use, and the second attempt writes nothing."""
    first = signed.post("/v1/proposals", proposal())
    assert first.status_code == 200

    second = signed.post("/v1/proposals", proposal())
    assert second.status_code == 409
    assert second.headers["content-type"].startswith("application/problem+json")
    problem = second.json()
    assert problem["title"] == "That proposal id has already been decided"
    assert problem["proposal_id"] == BASE_PROPOSAL["id"]

    after = signed.get("/v1/evidence?from=0")
    assert len(after.text.strip().splitlines()) == 4, "the replay must not add a record"


def test_an_envelope_may_carry_a_budget(signed: Signer) -> None:
    """The same shape `gate check --budget` takes."""
    response = signed.post(
        "/v1/proposals",
        {
            "proposal": proposal(),
            "budget": {
                "token_jti": BASE_PROPOSAL["principal"]["token_jti"],  # type: ignore[index]
                "budget": {"steps": 10},
                "steps_used": 10,
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["verdict"]["decision"] == "BLOCK"
    assert [h["rule_id"] for h in response.json()["verdict"]["hits"]] == ["AG-BUD-001"]


def test_an_unknown_field_is_refused_rather_than_ignored(signed: Signer) -> None:
    """A field gate does not understand is a field no rule can match."""
    response = signed.post("/v1/proposals", proposal({"severity": "critical"}))
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["type"].endswith("/invalid-proposal")


def test_an_error_never_echoes_the_rejected_input(signed: Signer) -> None:
    """A rejected body can hold the secret AG-DAT-001 exists to stop.

    The error response is not part of the chain and is not masked on the way
    out, so the value must not be in it at all.
    """
    secret = "AKIAIOSFODNN7EXAMPLE"
    response = signed.post(
        "/v1/proposals",
        proposal({"action": {"params_redacted": {"body": secret}, "kind": "not-a-kind"}}),
    )
    assert response.status_code == 422
    assert secret not in response.text
    assert "kind" in response.text, "the field name is still reported"


def test_a_body_over_the_limit_is_refused(signed: Signer) -> None:
    """SPEC §17: proposals are capped at 64 KB."""
    response = signed.post("/v1/proposals", proposal({"context": {"summary": "x" * 70_000}}))
    assert response.status_code == 413
    assert "SPEC 17" in response.json()["detail"]


def test_a_body_that_is_not_json_is_a_400(signed: Signer, client: TestClient) -> None:
    headers = signed.headers("POST", "/v1/proposals", b"not json")
    response = client.post("/v1/proposals", content=b"not json", headers=headers)
    assert response.status_code == 400
    assert response.json()["type"].endswith("/bad-request")


# --------------------------------------------------------------------------
# GET /v1/proposals/{id}
# --------------------------------------------------------------------------


def test_a_decided_proposal_can_be_fetched_back(signed: Signer) -> None:
    signed.post("/v1/proposals", proposal(PROD_DROP))
    response = signed.get(f"/v1/proposals/{PROD_DROP['id']}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["proposal"]["id"] == PROD_DROP["id"]
    assert payload["verdict"]["proposal_id"] == PROD_DROP["id"]
    assert payload["verdict"]["decision"] == "REQUIRE_APPROVAL"


def test_what_comes_back_is_what_went_into_the_chain(signed: Signer) -> None:
    """The proposal the API returns must be the one the chain attests to.

    Not a tautology: the chain payload is masked before it is hashed
    (``gate/core/evidence/record.py``), and the ``proposals`` table is not. Any
    pattern in the masking set that fires on a value gate itself generated --
    an id, a token id, a hash -- makes these two disagree, and the record then
    attests to a value nothing else in the system has. That is how the
    ``token_jti`` / card-number collision in ``_mask_cards`` was found.

    ``payload_hash`` is asserted over the *whole* stored payload, including the
    five reserved ``_`` keys SPEC §10.2 puts inside it.
    """
    signed.post("/v1/proposals", proposal(PROD_DROP))
    fetched = signed.get(f"/v1/proposals/{PROD_DROP['id']}").json()["proposal"]

    from gate.core import jcs
    from gate.core.evidence.hashing import payload_hash

    records = [
        json.loads(line) for line in signed.get("/v1/evidence?from=0").text.strip().splitlines()
    ]
    record = next(r for r in records if r["type"] == "proposal")

    assert jcs.dumps(fetched) == jcs.dumps(record["payload"]["proposal"])
    assert payload_hash(record["payload"]) == record["payload_hash"]
    assert set(record["payload"]) == {
        "proposal",
        "_assurance",
        "_mode",
        "_enforcement",
        "_dev",
        "_key_id",
    }


def test_an_identifier_gate_generated_is_never_masked_in_the_chain(signed: Signer) -> None:
    """Regression for the ``token_jti`` / card-number collision.

    ``01JB000000000000000000JTI0`` holds eighteen zeros, which pass the Luhn
    checksum exactly, so the card masker used to rewrite it to
    ``01JB[masked:card]JTI0``. A corrupted identifier is indistinguishable from
    a redacted one, and the budget ledger in week 3 keys on this field.
    """
    body = proposal({"id": "01JB00000000000000000000ZZ"})
    signed.post("/v1/proposals", body)
    records = [
        json.loads(line) for line in signed.get("/v1/evidence?from=0").text.strip().splitlines()
    ]
    stored = next(r for r in records if r["type"] == "proposal")["payload"]["proposal"]
    assert stored["principal"]["token_jti"] == BASE_PROPOSAL["principal"]["token_jti"]  # type: ignore[index]
    assert "masked" not in json.dumps(stored["principal"])
    assert stored["id"] == body["id"]


def test_an_unknown_proposal_is_a_404(signed: Signer) -> None:
    response = signed.get("/v1/proposals/01JB000000000000000000NOPE")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")


# --------------------------------------------------------------------------
# POST /v1/proposals/{id}/result
# --------------------------------------------------------------------------


def test_an_execution_result_is_recorded_with_adapter_assurance(signed: Signer) -> None:
    signed.post("/v1/proposals", proposal())
    response = signed.post(
        f"/v1/proposals/{BASE_PROPOSAL['id']}/result",
        {"status": "ok", "http_status": 200, "cost_actual": {"tokens": 120}},
    )
    assert response.status_code == 201
    assert response.json()["assurance"] == "adapter"

    records = [
        json.loads(line) for line in signed.get("/v1/evidence?from=0").text.strip().splitlines()
    ]
    result = next(r for r in records if r["type"] == "execution_result")
    assert result["assurance"] == "adapter"
    assert result["payload"]["status"] == "ok"
    assert result["payload"]["reported_by"] == "adp_test"
    assert result["payload"]["cost_actual"] == {"tokens": 120}


def test_an_advisory_adapters_result_is_only_testimony(signed: Signer) -> None:
    """ADR-007.1: an adapter the agent could bypass gives `self` evidence."""
    body = proposal({"id": "01JB00000000000000000000AD", "context": {"enforcement": "advisory"}})
    signed.post("/v1/proposals", body)
    response = signed.post(f"/v1/proposals/{body['id']}/result", {"status": "ok"})
    assert response.json()["assurance"] == "self"


def test_a_result_for_an_unknown_proposal_is_a_404(signed: Signer) -> None:
    response = signed.post("/v1/proposals/01JB000000000000000000NOPE/result", {"status": "ok"})
    assert response.status_code == 404


def test_an_unknown_status_is_refused(signed: Signer) -> None:
    signed.post("/v1/proposals", proposal())
    response = signed.post(
        f"/v1/proposals/{BASE_PROPOSAL['id']}/result", {"status": "probably-fine"}
    )
    assert response.status_code == 422
    assert "status" in response.json()["detail"]


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------


def test_concurrent_submissions_keep_the_sequence_contiguous(client: TestClient) -> None:
    """The chain is only verifiable if `seq` has no gaps and no repeats.

    All handlers are ``async def`` so they share the event loop thread, and
    ``check_proposal`` has no ``await`` inside it. If someone makes a handler
    ``def``, Starlette will run it in a threadpool, the SQLite connection will
    be used from the wrong thread, and this test is what notices.
    """
    from concurrent.futures import ThreadPoolExecutor

    signer = Signer(client)
    bodies = [proposal({"id": f"01JB00000000000000000{i:05d}"}) for i in range(24)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda body: signer.post("/v1/proposals", body), bodies))

    assert all(r.status_code in {200, 202} for r in responses), [r.status_code for r in responses]
    records = [
        json.loads(line) for line in signer.get("/v1/evidence?from=0").text.strip().splitlines()
    ]
    seqs = [record["seq"] for record in records]
    assert seqs == list(range(len(seqs))), "the sequence has a gap or a repeat"
    assert len([r for r in records if r["type"] == "verdict"]) == len(bodies)
