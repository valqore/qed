"""Adapter authentication (SPEC §13 auth, SPEC §17).

SPEC §17 requires adapter authentication to be mandatory and unknown adapters to
be rejected. The test that matters most is the sweep at the bottom: it walks the
app's own route table and asserts that every ``/v1`` path refuses an unsigned
request. A new router added in week 3 without auth fails it without anyone
having to remember to write a test.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from qed.api.app import create_app
from qed.api.auth import (
    HEADER_ADAPTER,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    AdapterAuth,
    canonical_string,
    sign,
)
from qed.config import load_config
from qed.core.schemas import rfc3339_ms, utcnow
from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV, Signer
from tests.conftest import BASE_PROPOSAL


def config_file(path: Path, **extra: object) -> Path:
    path.write_text(
        yaml.safe_dump(
            {
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}],
                **extra,
            }
        ),
        encoding="utf-8",
    )
    return path


class TestRejection:
    def test_an_unsigned_request_is_401(self, client: TestClient) -> None:
        response = client.post("/v1/proposals", json=BASE_PROPOSAL)
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["rule_id"] == "AG-IDN-005"

    def test_an_unknown_adapter_is_401(self, client: TestClient) -> None:
        response = Signer(client, adapter_id="adp_someone_else").post(
            "/v1/proposals", BASE_PROPOSAL
        )
        assert response.status_code == 401

    def test_the_error_does_not_say_which_adapters_exist(self, client: TestClient) -> None:
        """An unauthenticated caller does not get to enumerate adapter ids."""
        unknown = Signer(client, adapter_id="adp_someone_else").post("/v1/proposals", BASE_PROPOSAL)
        bad_signature = client.post(
            "/v1/proposals",
            json=BASE_PROPOSAL,
            headers={
                HEADER_ADAPTER: ADAPTER_ID,
                HEADER_TIMESTAMP: rfc3339_ms(utcnow()),
                HEADER_SIGNATURE: "not-the-right-mac",
            },
        )
        assert unknown.json()["detail"] == bad_signature.json()["detail"]
        assert ADAPTER_ID not in unknown.text

    def test_a_tampered_body_is_401(self, client: TestClient) -> None:
        """The MAC covers the body, so a captured signature does not transfer."""
        signer = Signer(client)
        original = json.dumps(BASE_PROPOSAL).encode("utf-8")
        headers = signer.headers("POST", "/v1/proposals", original)
        tampered = json.dumps({**BASE_PROPOSAL, "id": "01JB0000000000000000009999"}).encode()
        response = client.post("/v1/proposals", content=tampered, headers=headers)
        assert response.status_code == 401

    def test_a_signature_for_another_path_is_401(self, client: TestClient) -> None:
        signer = Signer(client)
        body = json.dumps(BASE_PROPOSAL).encode("utf-8")
        headers = signer.headers("POST", "/v1/evidence", body)
        response = client.post("/v1/proposals", content=body, headers=headers)
        assert response.status_code == 401

    def test_a_signature_for_another_method_is_401(self, client: TestClient) -> None:
        signer = Signer(client)
        headers = signer.headers("GET", "/v1/proposals", b"")
        response = client.post("/v1/proposals", content=b"", headers=headers)
        assert response.status_code == 401

    def test_a_stale_timestamp_is_401(self, client: TestClient) -> None:
        body = json.dumps(BASE_PROPOSAL).encode("utf-8")
        stale = rfc3339_ms(utcnow() - timedelta(hours=2))
        canonical = canonical_string(
            method="POST", path="/v1/proposals", timestamp=stale, nonce="", body=body
        )
        response = client.post(
            "/v1/proposals",
            content=body,
            headers={
                HEADER_ADAPTER: ADAPTER_ID,
                HEADER_TIMESTAMP: stale,
                HEADER_SIGNATURE: sign(SECRET, canonical),
            },
        )
        assert response.status_code == 401
        assert "away from this server's clock" in response.json()["detail"]

    @pytest.mark.parametrize("timestamp", ["", "not-a-date", "2026-10-07T12:00:00"])
    def test_a_bad_timestamp_is_401(self, client: TestClient, timestamp: str) -> None:
        """The last one has no timezone, so "now" is unknowable."""
        body = json.dumps(BASE_PROPOSAL).encode("utf-8")
        canonical = canonical_string(
            method="POST", path="/v1/proposals", timestamp=timestamp, nonce="", body=body
        )
        response = client.post(
            "/v1/proposals",
            content=body,
            headers={
                HEADER_ADAPTER: ADAPTER_ID,
                HEADER_TIMESTAMP: timestamp,
                HEADER_SIGNATURE: sign(SECRET, canonical),
            },
        )
        assert response.status_code == 401


class TestConfiguration:
    def test_an_instance_with_no_adapters_is_not_ready(self, api_dir: Path, tmp_path: Path) -> None:
        """SPEC §17 says reject unknown adapters; an instance that cannot tell
        them apart cannot do that, so it must not pretend to be ready."""
        plain = tmp_path / "plain.yaml"
        plain.write_text(yaml.safe_dump({"mode": "shadow"}), encoding="utf-8")
        with TestClient(create_app(directory=api_dir, config_path=plain)) as client:
            ready = client.get("/readyz")
            assert ready.status_code == 503
            assert any("adapter" in blocker for blocker in ready.json()["blockers"])
            assert client.post("/v1/proposals", json=BASE_PROPOSAL).status_code == 503

    def test_a_secret_that_is_not_set_is_reported_not_ignored(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(SECRET_ENV, raising=False)
        config = config_file(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            blockers = client.get("/readyz").json()["blockers"]
            assert any(SECRET_ENV in blocker for blocker in blockers)

    def test_a_short_secret_is_refused(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A shared secret somebody typed is a password, not a key."""
        monkeypatch.setenv(SECRET_ENV, "hunter2")
        config = config_file(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            blockers = client.get("/readyz").json()["blockers"]
            assert any("shorter than" in blocker for blocker in blockers)

    def test_dev_mode_skips_the_check_and_says_so(self, api_dir: Path, tmp_path: Path) -> None:
        plain = tmp_path / "plain.yaml"
        plain.write_text(yaml.safe_dump({"mode": "shadow"}), encoding="utf-8")
        with TestClient(create_app(directory=api_dir, config_path=plain, dev=True)) as client:
            ready = client.get("/readyz")
            assert ready.status_code == 200
            assert ready.json()["checks"]["adapter_auth"] == "dev"
            assert ready.json()["dev"] is True
            assert client.post("/v1/proposals", json=BASE_PROPOSAL).status_code == 200

    def test_dev_mode_records_that_nobody_was_authenticated(
        self, api_dir: Path, tmp_path: Path
    ) -> None:
        """A dev chain must be honest about never having checked the caller."""
        plain = tmp_path / "plain.yaml"
        plain.write_text(yaml.safe_dump({"mode": "shadow"}), encoding="utf-8")
        with TestClient(create_app(directory=api_dir, config_path=plain, dev=True)) as client:
            client.post("/v1/proposals", json=BASE_PROPOSAL)
            client.post(f"/v1/proposals/{BASE_PROPOSAL['id']}/result", json={"status": "ok"})
            records = [
                json.loads(line) for line in client.get("/v1/evidence").text.strip().splitlines()
            ]
        result = next(r for r in records if r["type"] == "execution_result")
        assert result["payload"]["reported_by"] == "dev-unauthenticated"
        assert all(record["dev"] is True for record in records)

    def test_both_config_spellings_are_accepted(self, tmp_path: Path) -> None:
        """SPEC §16 puts adapters at the top level; SPEC §13 reads them as API
        config. An operator should not have to guess which this build wants."""
        top = tmp_path / "top.yaml"
        top.write_text(
            yaml.safe_dump({"adapters": [{"adapter_id": "a", "secret_env": "E"}]}),
            encoding="utf-8",
        )
        nested = tmp_path / "nested.yaml"
        nested.write_text(
            yaml.safe_dump({"api": {"adapters": [{"adapter_id": "a", "secret_env": "E"}]}}),
            encoding="utf-8",
        )
        assert [a.adapter_id for a in load_config(top).config.registered_adapters] == ["a"]
        assert [a.adapter_id for a in load_config(nested).config.registered_adapters] == ["a"]


class TestARotationInFlight:
    """Both secrets verify until `qed adapters rotate --finish`.

    A shared secret cannot be replaced on the instance and on every adapter at
    the same instant. Without an overlap, every request signed with the old
    one during the rollout is refused as `AG-IDN-005` -- an unknown adapter --
    and under `fail: closed` a refused request is a blocked action. So the
    rotation window is the feature, and these are the tests that say it works:
    without them `previous_secret_env` is a config key that parses.
    """

    PREVIOUS_ENV = "QED_TEST_PREVIOUS_SECRET"
    PREVIOUS_SECRET = "p" * 44

    @pytest.fixture(autouse=True)
    def _current_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """These tests build their own app, so the `qed_config` fixture that
        normally sets the current secret is not in play."""
        monkeypatch.setenv(SECRET_ENV, SECRET)

    def rotating_config(self, path: Path) -> Path:
        path.write_text(
            yaml.safe_dump(
                {
                    "adapters": [
                        {
                            "adapter_id": ADAPTER_ID,
                            "secret_env": SECRET_ENV,
                            "previous_secret_env": self.PREVIOUS_ENV,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_the_new_secret_is_accepted(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(self.PREVIOUS_ENV, self.PREVIOUS_SECRET)
        config = self.rotating_config(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            assert Signer(client).post("/v1/proposals", BASE_PROPOSAL).status_code == 200

    def test_the_previous_secret_is_also_accepted(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The adapter that has not been restarted yet. This passing is the
        difference between a rotation and an outage."""
        monkeypatch.setenv(self.PREVIOUS_ENV, self.PREVIOUS_SECRET)
        config = self.rotating_config(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            signer = Signer(client, secret=self.PREVIOUS_SECRET)
            assert signer.post("/v1/proposals", BASE_PROPOSAL).status_code == 200

    def test_a_third_secret_is_still_refused(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An overlap that accepted anything would be worse than no rotation
        at all."""
        monkeypatch.setenv(self.PREVIOUS_ENV, self.PREVIOUS_SECRET)
        config = self.rotating_config(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            signer = Signer(client, secret="z" * 44)
            assert signer.post("/v1/proposals", BASE_PROPOSAL).status_code == 401

    def test_finishing_the_rotation_stops_accepting_the_old_one(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--finish` removes `previous_secret_env` from the config, and the
        old secret must stop working -- otherwise the rotation never actually
        retired anything."""
        monkeypatch.setenv(self.PREVIOUS_ENV, self.PREVIOUS_SECRET)
        finished = tmp_path / "finished.yaml"
        finished.write_text(
            yaml.safe_dump({"adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}]}),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=api_dir, config_path=finished)) as client:
            signer = Signer(client, secret=self.PREVIOUS_SECRET)
            assert signer.post("/v1/proposals", BASE_PROPOSAL).status_code == 401

    def test_an_unset_previous_variable_is_not_a_startup_problem(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ordinary end of a rotation: the operator has removed the old
        variable and not yet run `--finish`. Treating that as a configuration
        error would make `/readyz` fail for a correctly rotated instance."""
        monkeypatch.delenv(self.PREVIOUS_ENV, raising=False)
        config = self.rotating_config(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            assert client.get("/readyz").status_code == 200
            assert Signer(client).post("/v1/proposals", BASE_PROPOSAL).status_code == 200

    def test_an_unusable_previous_secret_does_not_take_the_instance_down(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale rotation variable must not stop the kernel serving.

        The current secret is fine, so the instance can authenticate every
        adapter that has been restarted; what is missing is only the grace
        for the ones that have not. Failing `/readyz` here would turn a
        half-finished rotation into an outage -- which is the exact thing the
        overlap exists to prevent, arriving by a different route.

        It is not silent either: `qed adapters list` reports the overlap as
        unusable, which is where an operator mid-rotation is looking.
        """
        monkeypatch.setenv(self.PREVIOUS_ENV, "short")
        config = self.rotating_config(tmp_path / "qed.yaml")
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            assert client.get("/readyz").status_code == 200
            assert Signer(client).post("/v1/proposals", BASE_PROPOSAL).status_code == 200
            stale = Signer(client, secret="short")
            assert stale.post("/v1/proposals", BASE_PROPOSAL).status_code == 401


class TestTheCanonicalString:
    def test_both_sides_build_the_same_bytes(self) -> None:
        canonical = canonical_string(
            method="post", path="/v1/proposals", timestamp="T", nonce="N", body=b"{}"
        )
        assert canonical.startswith(b"POST\n/v1/proposals\nT\nN\n")
        assert canonical.decode().count("\n") == 4

    def test_the_method_is_upper_cased(self) -> None:
        lower = canonical_string(method="get", path="/p", timestamp="T", nonce="", body=b"")
        upper = canonical_string(method="GET", path="/p", timestamp="T", nonce="", body=b"")
        assert lower == upper

    def test_the_signature_is_url_safe_and_unpadded(self) -> None:
        signature = sign("k" * 48, b"anything")
        assert "=" not in signature
        assert "+" not in signature and "/" not in signature

    def test_verification_is_constant_time(self) -> None:
        """``hmac.compare_digest``, not ``==``."""
        import inspect

        source = inspect.getsource(AdapterAuth.verify)
        assert "compare_digest" in source


def v1_operations(app: object) -> list[tuple[str, str]]:
    """Every ``/v1`` method and path, read from the app's own OpenAPI document.

    The published contract rather than the internal route tree: FastAPI wraps
    included routers in a private type whose shape has changed between
    versions, and a sweep that silently found nothing would be the worst kind
    of passing test.
    """
    spec = app.openapi()  # type: ignore[attr-defined]
    return sorted(
        (method.upper(), path)
        for path, operations in spec["paths"].items()
        for method in operations
        if path.startswith("/v1")
    )


def test_the_sweep_can_see_the_routes(client: TestClient) -> None:
    """Guards the test below against passing because it found nothing."""
    operations = v1_operations(client.app)
    assert len(operations) >= 5, operations
    assert ("POST", "/v1/proposals") in operations


def test_every_v1_route_refuses_an_unsigned_request(client: TestClient) -> None:
    """A router added in week 3 without auth fails here, unprompted.

    401 or 503 are both refusals -- 503 when the instance has no usable adapter
    auth at all. What must never happen is a 2xx.
    """
    for method, path in v1_operations(client.app):
        concrete = path.replace("{proposal_id}", "x").replace("{ref}", "1")
        response = client.request(method, concrete, json={} if method == "POST" else None)
        assert response.status_code in {401, 503}, (
            f"{method} {concrete} answered {response.status_code} without a signature"
        )


def test_healthz_and_readyz_are_deliberately_open(client: TestClient) -> None:
    """A probe has no credentials, and a liveness check that 401s is useless."""
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
