"""``POST /v1/token`` end to end (SPEC §6.2), against a stand-in identity provider.

The IdP here is a real RSA key and a real JWKS document served over a mock
transport, so the token travels the whole path: signed by someone else,
verified against a fetched key set, narrowed, minted, recorded. What is faked
is the network, not the cryptography.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from qed.api.app import create_app
from qed.core.schemas import EvidenceType, utcnow
from qed.infra.keys.file import init_keys
from qed.infra.storage.sqlite import SqliteStore
from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV, Signer

IDP = "https://idp.example"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt"

IDP_KEY = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})


def idp_token(**claims: Any) -> str:
    now = utcnow()
    payload: dict[str, Any] = {
        "iss": IDP,
        "sub": "ali@example.com",
        "aud": "qed",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "jti": "01JB000000000000000000IDP0",
        "groups": ["platform"],
    }
    payload.update(claims)
    return jwt.encode({"alg": "RS256", "kid": "idp-1"}, payload, IDP_KEY)


@pytest.fixture
def delegation_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    # Seed the JWKS cache on disk so the app never needs the network. This is
    # the air-gapped path, exercised by default rather than as a special case.
    cache = directory / "jwks"
    cache.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() else "_" for c in IDP)
    (cache / f"{safe}.json").write_text(
        json.dumps({"keys": [IDP_KEY.as_dict(private=False)]}), encoding="utf-8"
    )
    return directory


@pytest.fixture
def delegation_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(SECRET_ENV, SECRET)
    path = tmp_path / "qed.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "instance_id": "qed-local",
                "mode": "shadow",
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}],
                "delegation": {
                    "self_issuer": "https://qed.test",
                    "offline": True,
                    "token_ttl_default_seconds": 900,
                    "issuers": [
                        {
                            "issuer": IDP,
                            "jwks_uri": f"{IDP}/jwks",
                            "algorithms": ["RS256"],
                            "scopes_by_group": {"platform": ["read", "write"]},
                        }
                    ],
                    "budget_caps": {"platform": {"steps": 20, "money_cents": 500}},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def app(delegation_dir: Path, delegation_config: Path) -> FastAPI:
    return create_app(directory=delegation_dir, config_path=delegation_config)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as started:
        yield started


@pytest.fixture
def signed(client: TestClient) -> Signer:
    return Signer(client)


def ledger(directory: Path) -> Iterator[SqliteStore]:
    """A connection of our own.

    The app's connection belongs to the event-loop thread (see the note at the
    top of `qed/api/routers/proposals.py`); reaching into it from the test
    thread is what sqlite3 refuses, and rightly.
    """
    with SqliteStore(directory / "qed.db") as store:
        yield store


def claims_of(token: str) -> dict[str, Any]:
    import base64

    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def exchange(signed: Signer, **body: Any) -> httpx.Response:
    payload: dict[str, Any] = {
        "grant_type": GRANT,
        "subject_token": idp_token(),
        "subject_token_type": JWT_TYPE,
        "requested_token_type": JWT_TYPE,
    }
    payload.update(body)
    return signed.post("/v1/token", payload)


class TestHappyPath:
    def test_an_idp_token_is_exchanged_for_a_qed_token(self, signed: Signer) -> None:
        response = exchange(signed)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["issued_token_type"] == JWT_TYPE
        assert body["access_token"].count(".") == 2

    def test_the_minted_token_verifies_against_the_published_jwks(
        self, signed: Signer, client: TestClient
    ) -> None:
        """The whole point of publishing the key: a third party can check a
        token this qed issued without asking QED."""
        from joserfc.jwk import KeySet, OKPKey

        token = exchange(signed).json()["access_token"]
        published = client.get("/.well-known/jwks.json").json()
        keyset = KeySet([OKPKey.import_key(published["keys"][0])])
        decoded = jwt.decode(token, keyset, algorithms=["Ed25519"])
        assert decoded.claims["sub"] == "ali@example.com"
        assert decoded.claims["iss"] == "https://qed.test"

    def test_the_jwks_endpoint_needs_no_credential(self, client: TestClient) -> None:
        assert client.get("/.well-known/jwks.json").status_code == 200


class TestNarrowing:
    def test_only_scopes_the_group_holds_are_granted(self, signed: Signer) -> None:
        body = exchange(signed, scope="read admin").json()
        assert body["scope"] == "read"
        assert body["refused_scope"] == "admin"

    def test_a_budget_is_capped_at_the_group_ceiling(self, signed: Signer) -> None:
        """Asking for more than the group allows must not grant more."""
        claims = claims_of(exchange(signed, budget={"steps": 1000}).json()["access_token"])
        assert claims["budget"]["steps"] == 20

    def test_an_unrequested_budget_takes_the_ceiling(self, signed: Signer) -> None:
        claims = claims_of(exchange(signed).json()["access_token"])
        assert claims["budget"]["steps"] == 20
        assert claims["budget"]["money_cents"] == 500

    def test_lifetime_is_capped_at_an_hour(self, signed: Signer) -> None:
        body = exchange(signed, expires_in=86400).json()
        assert body["expires_in"] <= 3600


class TestLedgerAndEvidence:
    def test_the_caps_reach_the_budget_ledger(self, signed: Signer, delegation_dir: Path) -> None:
        """A token whose budget was never recorded would be treated as
        uncapped by the first action that used it (SPEC §8)."""
        jti = claims_of(exchange(signed).json()["access_token"])["jti"]
        for store in ledger(delegation_dir):
            state = store.load_budget(jti)
            assert state is not None
            assert state.budget.steps == 20

    def test_issuance_writes_a_budget_update_record(
        self, signed: Signer, delegation_dir: Path
    ) -> None:
        """SPEC §6.2: `budget_update{type: token_issued}`. This is the only
        place that record type is written -- a charge does not write one."""
        exchange(signed)
        for store in ledger(delegation_dir):
            issued = [r for r in store.iter_evidence() if r.type is EvidenceType.budget_update]
            assert len(issued) == 1
            assert issued[0].payload is not None
            assert issued[0].payload["type"] == "token_issued"

    def test_the_record_carries_no_token_and_no_subject_in_clear(
        self, signed: Signer, delegation_dir: Path
    ) -> None:
        """Evidence names a principal by hash. A chain that held the token
        itself would be a chain that hands out credentials."""
        exchange(signed)
        for store in ledger(delegation_dir):
            blob = json.dumps([r.payload for r in store.iter_evidence() if r.payload])
        assert "ali@example.com" not in blob
        assert "eyJ" not in blob, "a JWT leaked into the evidence payload"


class TestRefusals:
    def test_an_unsigned_request_is_refused(self, client: TestClient) -> None:
        response = client.post("/v1/token", json={"grant_type": GRANT})
        assert response.status_code in {401, 503}

    def test_a_wrong_grant_type_is_refused(self, signed: Signer) -> None:
        response = exchange(signed, grant_type="password")
        assert response.status_code == 400
        assert response.json()["error"] == "unsupported_grant_type"

    def test_a_missing_subject_token_is_refused(self, signed: Signer) -> None:
        response = signed.post("/v1/token", {"grant_type": GRANT})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_a_token_from_an_unconfigured_issuer_is_refused(self, signed: Signer) -> None:
        response = exchange(signed, subject_token=idp_token(iss="https://attacker.example"))
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_grant"

    def test_an_expired_subject_token_is_refused(self, signed: Signer) -> None:
        past = int((utcnow() - timedelta(hours=2)).timestamp())
        response = exchange(signed, subject_token=idp_token(exp=past))
        assert response.status_code == 401

    def test_a_token_signed_by_the_wrong_key_is_refused(self, signed: Signer) -> None:
        forged = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})
        now = utcnow()
        token = jwt.encode(
            {"alg": "RS256", "kid": "idp-1"},
            {
                "iss": IDP,
                "sub": "attacker@example.com",
                "aud": "qed",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=5)).timestamp()),
                "jti": "01JB000000000000000000IDPX",
            },
            forged,
        )
        assert exchange(signed, subject_token=token).status_code == 401

    def test_a_service_subject_without_a_mandate_is_refused(self, signed: Signer) -> None:
        """SPEC §6.1 step 5: an unattended agent must say who authorised it."""
        response = exchange(signed, subject_token=idp_token(sub="svc:nightly"))
        assert response.status_code == 401

    def test_a_service_subject_with_a_mandate_is_accepted(self, signed: Signer) -> None:
        response = exchange(signed, subject_token=idp_token(sub="svc:nightly", mandate_id="mdt_1"))
        assert response.status_code == 200, response.text

    def test_an_oversized_body_is_refused_before_parsing(self, signed: Signer) -> None:
        response = signed.post("/v1/token", {"grant_type": GRANT, "pad": "x" * 20_000})
        assert response.status_code == 413


class TestNotConfigured:
    def test_without_issuers_the_endpoint_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """501, not a 500 and not a silent mint. A deployment that never
        exchanges tokens should not be made to hold a token key."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        directory = tmp_path / "plain"
        init_keys(directory)
        config = tmp_path / "plain.yaml"
        config.write_text(
            yaml.safe_dump(
                {"adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}]}
            ),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=directory, config_path=config)) as plain:
            response = Signer(plain).post(
                "/v1/token", {"grant_type": GRANT, "subject_token": idp_token()}
            )
            assert response.status_code == 501
            assert plain.get("/.well-known/jwks.json").json() == {"keys": []}
