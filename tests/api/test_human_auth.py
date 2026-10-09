"""Human authentication on ``/v1`` (SPEC §13 auth, SPEC §19 SSO).

The web approval page is the reason this exists, but the page is not what these
tests are about. The substance is that the approver's identity stops being an
assertion.

Until now it arrived in ``X-QED-Approver``, a header the *adapter* writes. The
router was honest about that, and separation of duties checked against a
header is separation of duties the caller gets to choose — a smaller version of
declaring the control in an OSCAL export while enforcing nothing, which is the
one outcome worse than not claiming it at all. With a verified bearer the
subject comes from the identity provider, so ``AG-SOD-001`` and ``AG-SOD-002``
are decided on evidence, and the chain records which of the two it was.

The identity provider here is a real RSA key and a real JWKS document on disk,
as in ``test_token.py``: what is faked is the network, not the cryptography.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from qed.api.app import create_app
from qed.core.approval.model import ApprovalRequest, ApprovalStatus, dedupe_key
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import utcnow
from qed.infra.keys.file import init_keys
from qed.infra.storage.sqlite import SqliteStore
from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV, Signer
from tests.conftest import make_proposal

IDP = "https://idp.example"
OTHER_IDP = "https://not-configured.example"

IDP_KEY = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})
IMPOSTOR_KEY = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})

UI_CLIENT = "qed-ui"
APPROVER = "dana@example.com"
REQUESTER = "ali@example.com"
SUMMARY = "db.drop_table wants to delete db:prod/orders"


def token_for(
    subject: str = APPROVER,
    *,
    key: RSAKey = IDP_KEY,
    issuer: str = IDP,
    **claims: Any,
) -> str:
    now = utcnow()
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": "qed",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "jti": "01JB00000000000000000HUMAN",
        "email": subject,
        "groups": ["db-oncall"],
    }
    payload.update(claims)
    return jwt.encode({"alg": "RS256", "kid": "idp-1"}, payload, key)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    cache = directory / "jwks"
    cache.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() else "_" for c in IDP)
    (cache / f"{safe}.json").write_text(
        json.dumps({"keys": [IDP_KEY.as_dict(private=False)]}), encoding="utf-8"
    )
    return directory


def write_config(path: Path, *, issuers: bool = True, **approvals: object) -> Path:
    body: dict[str, Any] = {
        "instance_id": "qed-local",
        "mode": "enforce",
        "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}],
        "approvals": approvals,
    }
    if issuers:
        body["delegation"] = {
            "self_issuer": "https://qed.test",
            "offline": True,
            "issuers": [
                {
                    "issuer": IDP,
                    "jwks_uri": f"{IDP}/jwks",
                    "algorithms": ["RS256"],
                    "ui_client_id": UI_CLIENT,
                }
            ],
        }
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return path


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(SECRET_ENV, SECRET)
    return write_config(tmp_path / "qed.yaml")


@pytest.fixture
def app(qed_dir: Path, config: Path) -> FastAPI:
    return create_app(directory=qed_dir, config_path=config)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as started:
        yield started


def pending(
    client: TestClient, qed_dir: Path, *, principal: str | None = REQUESTER
) -> ApprovalRequest:
    """One pending approval in the store, with the approver view beside it.

    Going through `POST /v1/proposals` would work and would also make every
    test here depend on the baseline pack keeping a rule that asks for
    approval on this particular action.
    """
    now = utcnow()
    human = None if principal is None else principal_hash(principal, issuer=IDP)
    proposal = make_proposal(
        {
            "principal": {"human_hash": human},
            "action": {"name": "db.drop_table", "target": "db:prod/orders"},
            "context": {"environment": "prod", "summary": SUMMARY},
        }
    )
    request = ApprovalRequest(
        id="ap_01JB0000000000000000000001",
        proposal_id=proposal.id,
        dedupe_key=dedupe_key(proposal),
        status=ApprovalStatus.pending,
        approvers=["db-oncall"],
        principal_hash=human,
        created_at=now,
        expires_at=now + timedelta(minutes=30),
        window_max=timedelta(minutes=15),
    )
    view = {
        "approval_id": request.id,
        "summary": SUMMARY,
        "environment": "prod",
        "action": {"kind": "mcp_tool", "name": "db.drop_table", "target": "db:prod/orders"},
        "blast_radius": 72,
        "hits": [{"rule_id": "AG-BLR-003", "message": "Destructive change in production."}],
        "expires_at": request.expires_at.isoformat(),
        "window_max_seconds": 900,
    }
    with SqliteStore(qed_dir / "qed.db") as store:
        store.record_approval(request, request_json=json.dumps(view))
    return request


def decided_records(qed_dir: Path) -> list[dict[str, Any]]:
    with SqliteStore(qed_dir / "qed.db") as store:
        return [
            record.payload or {}
            for record in store.iter_evidence()
            if record.type.value == "approval_decided"
        ]


# --------------------------------------------------------------------------
# The credential itself
# --------------------------------------------------------------------------


class TestWhatIsAccepted:
    def test_a_verified_bearer_can_read_the_queue(self, client: TestClient) -> None:
        response = client.get("/v1/approvals?status=pending", headers=bearer(token_for()))
        assert response.status_code == 200

    def test_no_credential_is_still_refused(self, client: TestClient) -> None:
        """The invariant the sweep in test_auth.py asserts for every route: a
        bearer is a credential, not the absence of one."""
        assert client.get("/v1/approvals").status_code == 401

    def test_a_token_signed_by_the_wrong_key_is_refused(self, client: TestClient) -> None:
        """Same `kid`, different key. The `kid` selects among a configured
        issuer's keys; it never names where to fetch one."""
        response = client.get("/v1/approvals", headers=bearer(token_for(key=IMPOSTOR_KEY)))
        assert response.status_code == 401

    def test_a_token_from_an_unconfigured_issuer_is_refused(self, client: TestClient) -> None:
        response = client.get("/v1/approvals", headers=bearer(token_for(issuer=OTHER_IDP)))
        assert response.status_code == 401

    def test_an_expired_token_is_refused(self, client: TestClient) -> None:
        past = int((utcnow() - timedelta(hours=2)).timestamp())
        response = client.get("/v1/approvals", headers=bearer(token_for(exp=past)))
        assert response.status_code == 401

    def test_a_refusal_does_not_enumerate_the_issuers(self, client: TestClient) -> None:
        """An unauthenticated caller does not get to learn the configuration,
        the same rule the adapter refusal follows (AG-IDN-005)."""
        response = client.get("/v1/approvals", headers=bearer(token_for(issuer=OTHER_IDP)))
        assert IDP not in response.text
        assert response.json()["rule_id"] == "AG-IDN-005"

    def test_a_non_bearer_authorization_header_falls_through_to_adapter_auth(
        self, client: TestClient
    ) -> None:
        """`Basic` is not a bearer, so it is not reinterpreted as a person --
        it is simply not an adapter signature either, and is refused as one."""
        response = client.get("/v1/approvals", headers={"Authorization": "Basic Zm9vOmJhcg=="})
        assert response.status_code == 401

    def test_an_adapter_signature_still_works(self, client: TestClient) -> None:
        assert Signer(client).get("/v1/approvals").status_code == 200

    def test_a_bearer_without_any_configured_issuer_says_so(
        self, qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """501 and not 401: nothing is wrong with the caller, the deployment
        has no identity provider to verify anybody against."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        path = write_config(tmp_path / "no-idp.yaml", issuers=False)
        with TestClient(create_app(directory=qed_dir, config_path=path)) as bare:
            response = bare.get("/v1/approvals", headers=bearer(token_for()))
        assert response.status_code == 501
        assert "delegation.issuers" in response.json()["detail"]


# --------------------------------------------------------------------------
# Who the approver is
# --------------------------------------------------------------------------


class TestTheApproverComesFromTheToken:
    def test_the_recorded_approver_is_the_tokens_subject(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        """Hashed with the issuer, as every other principal is, so the hash is
        comparable with the one that recorded the proposal."""
        request = pending(client, qed_dir)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for()),
        )
        assert response.status_code == 200, response.text
        payload = decided_records(qed_dir)[-1]
        assert payload["approver_hash"] == principal_hash(APPROVER, issuer=IDP)

    def test_the_record_says_the_identity_was_verified(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        """ADR-001's distinction applied to identity: an auditor reading one
        row should not have to know which channel wrote it."""
        request = pending(client, qed_dir)
        client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for()),
        )
        assert decided_records(qed_dir)[-1]["identity"] == f"oidc:{IDP}"

    def test_an_adapter_decision_is_recorded_as_asserted(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        request = pending(client, qed_dir)
        response = Signer(client).post(
            f"/v1/approvals/{request.id}",
            {"decision": "approve_once"},
            headers={"X-QED-Approver": APPROVER, "X-QED-Approver-Groups": "db-oncall"},
        )
        assert response.status_code == 200, response.text
        assert decided_records(qed_dir)[-1]["identity"] == f"adapter-asserted:{ADAPTER_ID}"

    def test_a_header_disagreeing_with_the_token_is_refused(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        """Refused rather than resolved. Reading the token and ignoring the
        header would be safe but silent, and a request presenting two different
        approvers is either a bug worth finding or an attempt worth recording.
        """
        request = pending(client, qed_dir)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers={**bearer(token_for()), "X-QED-Approver": "someone.else@example.com"},
        )
        assert response.status_code == 400
        assert response.json()["type"].endswith("approver-mismatch")

    def test_a_header_agreeing_with_the_token_is_allowed(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        """A client that sends both is redundant, not wrong."""
        request = pending(client, qed_dir)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers={**bearer(token_for()), "X-QED-Approver": APPROVER},
        )
        assert response.status_code == 200, response.text

    def test_a_service_subject_cannot_approve(self, client: TestClient, qed_dir: Path) -> None:
        """AG-SOD-002 would refuse it too, but a service account presenting a
        token to the approval UI is a misconfiguration, not a policy decision,
        and it is worth saying so in those words."""
        request = pending(client, qed_dir)
        # With a mandate, so the token is otherwise valid: a `svc:` subject
        # without one is already refused at claim validation (AG-IDN-007), and
        # the point here is the one that gets past that.
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for("svc:deployer", mandate_id="md_01JB000000000000000001")),
        )
        assert response.status_code == 403
        assert response.json()["type"].endswith("service-identity")

    def test_a_service_subject_without_a_mandate_never_gets_that_far(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        """Refused at claim validation, which is the earlier and stricter of
        the two gates. Worth pinning so that a change to either one does not
        quietly leave service accounts able to approve."""
        request = pending(client, qed_dir)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for("svc:deployer")),
        )
        assert response.status_code == 401


# --------------------------------------------------------------------------
# Separation of duties, now decided on evidence
# --------------------------------------------------------------------------


class TestSeparationOfDuties:
    def test_the_requester_cannot_approve_their_own_action(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        """The point of the whole exercise. The proposal's principal_hash was
        built from the same subject and issuer, so AG-SOD-001 fires on the
        identity provider's word rather than on a header."""
        request = pending(client, qed_dir, principal=REQUESTER)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for(REQUESTER)),
        )
        assert response.status_code == 403
        assert response.json()["rule_id"] == "AG-SOD-001"

    def test_the_refusal_is_written_to_the_chain(self, client: TestClient, qed_dir: Path) -> None:
        """A refusal nobody recorded is indistinguishable from an attempt
        nobody made."""
        request = pending(client, qed_dir, principal=REQUESTER)
        client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for(REQUESTER)),
        )
        payload = decided_records(qed_dir)[-1]
        assert payload["refused"] == "AG-SOD-001"
        assert payload["identity"] == f"oidc:{IDP}"

    def test_an_approver_outside_the_named_group_is_refused(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        request = pending(client, qed_dir)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for(groups=["frontend"])),
        )
        assert response.status_code == 403
        assert response.json()["rule_id"] == "AG-SOD-002"

    def test_groups_come_from_the_token_claim(self, client: TestClient, qed_dir: Path) -> None:
        request = pending(client, qed_dir)
        response = client.post(
            f"/v1/approvals/{request.id}",
            json={"decision": "approve_once"},
            headers=bearer(token_for(groups=["db-oncall", "frontend"])),
        )
        assert response.status_code == 200, response.text

    def test_the_config_map_can_still_grant_a_group(
        self, qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An installation whose identity provider has no group mapper yet is
        the state every installation starts in, so the operator's own map is
        still a grant. Both sources are deliberate; week 6 makes the claim the
        only one."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        path = write_config(tmp_path / "mapped.yaml", groups_by_email={APPROVER: ["db-oncall"]})
        with TestClient(create_app(directory=qed_dir, config_path=path)) as mapped:
            request = pending(mapped, qed_dir)
            response = mapped.post(
                f"/v1/approvals/{request.id}",
                json={"decision": "approve_once"},
                headers=bearer(token_for(groups=[])),
            )
        assert response.status_code == 200, response.text


# --------------------------------------------------------------------------
# Reading the queue, which is what the page does first
# --------------------------------------------------------------------------


class TestTheQueue:
    def test_a_pending_approval_is_listed_with_what_an_approver_needs(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        request = pending(client, qed_dir)
        listed = client.get("/v1/approvals?status=pending", headers=bearer(token_for())).json()
        ids = [row["id"] for row in listed["approvals"]]
        assert request.id in ids
        row = next(row for row in listed["approvals"] if row["id"] == request.id)
        assert row["approvers"] == ["db-oncall"]
        assert row["status"] == "pending"

    def test_the_detail_view_carries_the_stored_request(
        self, client: TestClient, qed_dir: Path
    ) -> None:
        request = pending(client, qed_dir)
        detail = client.get(f"/v1/approvals/{request.id}", headers=bearer(token_for()))
        assert detail.status_code == 200
        payload = detail.json()
        assert payload["id"] == request.id
        # The stored approver view, which is what the page renders: it reflects
        # the proposal as it was when the question was asked.
        assert payload["request"]["summary"] == SUMMARY
        assert payload["request"]["blast_radius"] == 72
        assert payload["request"]["hits"][0]["rule_id"] == "AG-BLR-003"
        assert payload["request"]["window_max_seconds"] == 900

    def test_an_unknown_status_filter_is_refused(self, client: TestClient) -> None:
        response = client.get("/v1/approvals?status=maybe", headers=bearer(token_for()))
        assert response.status_code == 400


# --------------------------------------------------------------------------
# The audience, which is where this nearly shipped broken
# --------------------------------------------------------------------------


class TestTheAudience:
    """An **id_token's `aud` is the client id**, by OIDC definition.

    The week-3 audience check expected `aud` to include `qed`, the service.
    That is right for an access token or an exchange subject token, and it can
    never be true of an id_token: the pages log in as a public PKCE client, so
    their token carries that client's id. Pointing the page at a real Keycloak
    is what found it -- the realm answered `aud: qed-cli` and every request was
    refused with "a token minted for another service must not be usable here".

    The fix is a closed set built from configuration: `qed` plus every
    `ui_client_id` the operator declared. These tests hold both halves -- the
    client id is accepted, and anything nobody declared still is not.
    """

    def test_the_service_audience_is_accepted(self, client: TestClient) -> None:
        response = client.get("/v1/approvals", headers=bearer(token_for(aud="qed")))
        assert response.status_code == 200

    def test_the_configured_ui_client_is_accepted(self, client: TestClient) -> None:
        """What a real id_token actually carries."""
        response = client.get("/v1/approvals", headers=bearer(token_for(aud=UI_CLIENT)))
        assert response.status_code == 200

    def test_a_token_carrying_both_is_accepted(self, client: TestClient) -> None:
        response = client.get(
            "/v1/approvals", headers=bearer(token_for(aud=[UI_CLIENT, "something-else"]))
        )
        assert response.status_code == 200

    def test_an_audience_nobody_declared_is_still_refused(self, client: TestClient) -> None:
        """The control this check exists for. Widening it to "any audience"
        would have made a token minted for an unrelated service replayable
        here, which is the whole thing it is meant to stop."""
        response = client.get("/v1/approvals", headers=bearer(token_for(aud="some-other-service")))
        assert response.status_code == 401
        assert "includes none of" in response.json()["detail"]

    def test_the_refusal_names_what_was_expected(self, client: TestClient) -> None:
        response = client.get("/v1/approvals", headers=bearer(token_for(aud="nope")))
        detail = response.json()["detail"]
        assert "qed" in detail
        assert UI_CLIENT in detail

    def test_an_issuer_without_a_ui_client_accepts_only_the_service(
        self, qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No `ui_client_id` means no browser login against that issuer, so
        the set does not grow by accident."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        path = tmp_path / "no-client.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "instance_id": "qed-local",
                    "mode": "enforce",
                    "adapters": [
                        {"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}
                    ],
                    "delegation": {
                        "self_issuer": "https://qed.test",
                        "offline": True,
                        "issuers": [
                            {"issuer": IDP, "jwks_uri": f"{IDP}/jwks", "algorithms": ["RS256"]}
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=qed_dir, config_path=path)) as bare:
            assert (
                bare.get("/v1/approvals", headers=bearer(token_for(aud="qed"))).status_code == 200
            )
            refused = bare.get("/v1/approvals", headers=bearer(token_for(aud=UI_CLIENT)))
        assert refused.status_code == 401


class TestTheBrowserConfiguration:
    """``/.well-known/qed-configuration``, which is how a page starts a login."""

    def test_it_is_public(self, client: TestClient) -> None:
        """A login page cannot authenticate before it has logged in. Nothing
        here is a secret: an issuer URL and a public client id are what every
        single-page app ships in plain JavaScript."""
        assert client.get("/.well-known/qed-configuration").status_code == 200

    def test_it_names_the_issuer_and_the_client(self, client: TestClient) -> None:
        payload = client.get("/.well-known/qed-configuration").json()
        row = payload["issuers"][0]
        assert row["issuer"] == IDP
        assert row["client_id"] == UI_CLIENT

    def test_it_points_at_discovery_rather_than_a_guessed_endpoint(
        self, client: TestClient
    ) -> None:
        """`/protocol/openid-connect/auth` is Keycloak's path and nobody
        else's. The browser reads `authorization_endpoint` out of the
        discovery document, which is what discovery is for."""
        row = client.get("/.well-known/qed-configuration").json()["issuers"][0]
        assert row["discovery"] == f"{IDP}/.well-known/openid-configuration"
        assert "authorization_endpoint" not in row

    def test_it_carries_no_secret(self, client: TestClient) -> None:
        body = client.get("/.well-known/qed-configuration").text
        assert SECRET not in body
        assert "secret" not in body.lower()

    def test_an_issuer_without_a_client_is_listed_as_null_not_omitted(
        self, qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """So the page can say "configured, but not for browser login", which
        is a fixable state an operator should see, rather than behave as
        though the issuer did not exist."""
        monkeypatch.setenv(SECRET_ENV, SECRET)
        path = tmp_path / "no-client2.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "instance_id": "qed-local",
                    "delegation": {
                        "offline": True,
                        "issuers": [
                            {"issuer": IDP, "jwks_uri": f"{IDP}/jwks", "algorithms": ["RS256"]}
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=qed_dir, config_path=path)) as bare:
            payload = bare.get("/.well-known/qed-configuration").json()
        assert len(payload["issuers"]) == 1
        assert payload["issuers"][0]["client_id"] is None
