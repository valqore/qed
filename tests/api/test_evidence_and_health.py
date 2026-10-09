"""``/v1/evidence``, ``/healthz`` and ``/readyz`` (SPEC §13, §10.8, §17).

The readiness tests are the SPEC §17 MUST: "service refuses to start without
evidence signing key (``readyz=false``)". The evidence tests are mostly about
one thing -- a filtered export is not a verifiable export, and the response has
to say so rather than hand back something that will fail ``qed-verify`` later
with no explanation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from qed.api.app import create_app
from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV, Signer
from tests.conftest import BASE_PROPOSAL, deep_merge


def submit(signed: Signer, count: int) -> None:
    for i in range(count):
        body = deep_merge(BASE_PROPOSAL, {"id": f"01JB00000000000000000{i:05d}"})
        assert signed.post("/v1/proposals", body).status_code in {200, 202}


# --------------------------------------------------------------------------
# Readiness
# --------------------------------------------------------------------------


class TestReadiness:
    def test_no_signing_key_means_not_ready(self, tmp_path: Path) -> None:
        """SPEC §17. An unsigned decision is not evidence."""
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump({"adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}]}),
            encoding="utf-8",
        )
        app = create_app(directory=tmp_path / "no-keys", config_path=config)
        with TestClient(app) as client:
            ready = client.get("/readyz")
            assert ready.status_code == 503
            assert ready.json()["ready"] is False
            assert ready.json()["checks"]["signing_key"] is False
            assert any("signing key" in b for b in ready.json()["blockers"])

    def test_the_process_is_still_alive_without_a_key(self, tmp_path: Path) -> None:
        """Liveness and readiness answer different questions.

        Restarting the container will not conjure up a signing key, so a
        missing key must not fail the liveness probe into a crash loop.
        """
        app = create_app(directory=tmp_path / "no-keys")
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/readyz").status_code == 503

    def test_v1_is_refused_while_not_ready(self, tmp_path: Path) -> None:
        app = create_app(directory=tmp_path / "no-keys")
        with TestClient(app) as client:
            response = client.post("/v1/proposals", json=BASE_PROPOSAL)
            assert response.status_code == 503
            assert response.headers["content-type"].startswith("application/problem+json")

    def test_a_broken_policy_bundle_means_not_ready(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deciding against a bundle with errors would apply rules nobody wrote."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        broken = tmp_path / "policies"
        broken.mkdir()
        (broken / "bad.yaml").write_text(
            yaml.safe_dump(
                [
                    {
                        "rule_id": "XX-BAD-001",
                        "name": "unclosed regex",
                        "message": "m",
                        "verdict": "BLOCK",
                        "when": {"field": "action.name", "regex": "([unclosed"},
                    }
                ]
            ),
            encoding="utf-8",
        )
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "policies": [str(broken)],
                    "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}],
                }
            ),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            ready = client.get("/readyz")
            assert ready.status_code == 503
            assert any("broken bundle" in b for b in ready.json()["blockers"])

    def test_a_ready_instance_reports_its_posture(self, client: TestClient) -> None:
        ready = client.get("/readyz").json()
        assert ready["ready"] is True
        assert ready["key_id"].startswith("ed25519:")
        assert len(ready["policy_hash"]) == 64
        assert ready["mode"] == "shadow"
        assert ready["instance_id"] == "qed-local"
        assert ready["checks"]["adapter_auth"] == "signed"


# --------------------------------------------------------------------------
# GET /v1/evidence
# --------------------------------------------------------------------------


class TestEvidenceExport:
    def test_jsonl_is_what_qed_verify_reads(self, signed: Signer, api_dir: Path) -> None:
        submit(signed, 2)
        response = signed.get("/v1/evidence")
        assert response.headers["content-type"].startswith("application/x-ndjson")
        assert response.headers["X-QED-Verifiable"] == "true"

        from qed_verify.verify import load_jsonl, verify_records

        from qed.infra.keys.file import PUBLIC_DIR_NAME, load_public_keys

        report = verify_records(
            load_jsonl(response.text),
            load_public_keys(api_dir / PUBLIC_DIR_NAME),
            instance_id="qed-local",
        )
        assert report.ok, report.summary()

    def test_csv_has_a_header(self, signed: Signer) -> None:
        submit(signed, 1)
        response = signed.get("/v1/evidence?format=csv")
        assert response.headers["content-type"].startswith("text/csv")
        assert response.text.splitlines()[0].startswith("seq,ts,type")

    def test_a_range_is_honoured(self, signed: Signer) -> None:
        submit(signed, 3)
        rows = signed.get("/v1/evidence?from=2&to=4").text.strip().splitlines()
        seqs = [json.loads(row)["seq"] for row in rows]
        assert seqs == [2, 3, 4]

    def test_a_type_filter_is_marked_unverifiable(self, signed: Signer) -> None:
        """``qed-verify`` needs contiguous sequence numbers to check linkage."""
        submit(signed, 2)
        response = signed.get("/v1/evidence?type=verdict")
        assert response.headers["X-QED-Verifiable"] == "false"
        assert "not contiguous" in response.headers["X-QED-Not-Verifiable-Reason"]
        types = {json.loads(row)["type"] for row in response.text.strip().splitlines()}
        assert types == {"verdict"}

    def test_an_unknown_type_is_refused(self, signed: Signer) -> None:
        response = signed.get("/v1/evidence?type=banana")
        assert response.status_code == 400
        assert "verdict" in response.json()["known_types"]

    def test_an_unknown_format_is_refused(self, signed: Signer) -> None:
        assert signed.get("/v1/evidence?format=sarif").status_code == 400

    def test_oscal_validates_against_the_nist_schema(self, signed: Signer) -> None:
        """The same check as the CLI export, over the API (SPEC §10.8)."""
        import hashlib

        from tests.evidence.test_oscal_schema import SCHEMA_PATH, SCHEMA_SHA256
        from tests.oscal import build_validator

        submit(signed, 2)
        response = signed.get("/v1/evidence?format=oscal")
        assert response.status_code == 200
        raw = SCHEMA_PATH.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256
        validator = build_validator(json.loads(raw.decode("utf-8")))
        errors = list(validator.iter_errors(response.json()))
        assert not errors, [error.message for error in errors[:5]]

    def test_a_filtered_oscal_export_is_refused_outright(self, signed: Signer) -> None:
        """An assessment-results document states what was observed in a period.

        Built from a subset, it would omit observations without saying so, and
        this one goes to an auditor.
        """
        submit(signed, 1)
        response = signed.get("/v1/evidence?format=oscal&type=verdict")
        assert response.status_code == 400
        assert response.json()["type"].endswith("/filtered-oscal-export")

    def test_an_empty_oscal_range_is_a_404(self, signed: Signer) -> None:
        response = signed.get("/v1/evidence?format=oscal&from=9000")
        assert response.status_code == 404
        assert response.json()["type"].endswith("/empty-range")

    def test_the_record_count_is_in_a_header(self, signed: Signer) -> None:
        submit(signed, 1)
        assert signed.get("/v1/evidence").headers["X-QED-Records"] == "4"


# --------------------------------------------------------------------------
# GET /v1/evidence/by-ref/{ref}
# --------------------------------------------------------------------------


class TestEvidenceByRef:
    def test_the_ref_from_a_verdict_resolves(self, signed: Signer) -> None:
        ref = signed.post("/v1/proposals", BASE_PROPOSAL).json()["evidence_ref"]
        response = signed.get(f"/v1/evidence/by-ref/{ref}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["seq"] == int(ref)
        assert payload["record"]["type"] == "verdict"

    def test_an_unknown_ref_is_a_404(self, signed: Signer) -> None:
        assert signed.get("/v1/evidence/by-ref/9000").status_code == 404

    def test_a_ref_that_is_not_a_number_is_a_400(self, signed: Signer) -> None:
        response = signed.get("/v1/evidence/by-ref/outbox-abc")
        assert response.status_code == 400
        assert "sequence number" in response.json()["detail"]


# --------------------------------------------------------------------------
# Error shape
# --------------------------------------------------------------------------


class TestProblemJson:
    def test_a_missing_route_is_problem_json(self, client: TestClient) -> None:
        """SPEC §13 fixes the error shape; 404s are where a default leaks."""
        response = client.get("/v1/nothing-here")
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/problem+json")
        body = response.json()
        assert set(body) >= {"type", "title", "status", "detail"}
        assert "detail" in body and isinstance(body["detail"], str)

    def test_a_wrong_method_is_problem_json(self, client: TestClient) -> None:
        response = client.request("DELETE", "/v1/proposals")
        assert response.status_code == 405
        assert response.headers["content-type"].startswith("application/problem+json")

    def test_the_type_is_a_uri(self, client: TestClient) -> None:
        body = client.get("/v1/nothing-here").json()
        assert body["type"].startswith("https://")
