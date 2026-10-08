"""Attended login — RFC 8628 device authorization grant (SPEC §6.3).

Chosen over the authorization-code flow because the thing logging in is a
terminal. A code flow needs a loopback listener and a browser that can reach
it; over SSH, inside a container, or on a machine with no browser at all, that
is a series of workarounds. The device flow asks the person to open a URL
somewhere they already have a browser and type a short code, and it works the
same everywhere.

The refresh token this produces is the only long-lived secret the CLI holds.
It is stored by :mod:`gate.infra.credentials`, never in the gate directory
beside the evidence, and never in the evidence itself.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from gate.core.delegation.claims import DelegationError

__all__ = [
    "AuthorizationPending",
    "DeviceAuthorization",
    "DeviceFlowError",
    "TokenResponse",
    "discover_endpoints",
    "poll_for_token",
    "refresh_access_token",
    "start_device_authorization",
]

HTTP_TIMEOUT = 10.0

#: RFC 8628 §3.5. The server tells us how often to poll and may tell us to slow
#: down; this is only the floor used when it says nothing.
DEFAULT_INTERVAL = 5

#: A login nobody completes should not poll an identity provider forever.
DEFAULT_EXPIRY = 600


class DeviceFlowError(DelegationError):
    """The identity provider refused, or answered something unusable."""


class AuthorizationPending(DeviceFlowError):
    """Not an error: the person has not finished approving yet."""


@dataclass(frozen=True)
class DeviceAuthorization:
    device_code: str
    user_code: str
    verification_uri: str
    #: Present on most providers: the URI with the code already in it, so the
    #: person can follow one link instead of typing anything.
    verification_uri_complete: str | None
    expires_in: int
    interval: int


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    refresh_token: str | None
    expires_in: int
    id_token: str | None = None


def _post(url: str, data: dict[str, str], *, client: httpx.Client | None = None) -> dict[str, Any]:
    owned = client is None
    http = client or httpx.Client(timeout=HTTP_TIMEOUT)
    try:
        response = http.post(url, data=data)
    except httpx.HTTPError as exc:
        raise DeviceFlowError(f"could not reach {url}: {exc}") from exc
    finally:
        if owned:
            http.close()
    try:
        body = response.json()
    except ValueError as exc:
        raise DeviceFlowError(f"{url} did not answer JSON ({response.status_code})") from exc
    if not isinstance(body, dict):
        raise DeviceFlowError(f"{url} did not answer a JSON object")
    return body


def discover_endpoints(issuer: str, *, client: httpx.Client | None = None) -> dict[str, str]:
    """``device_authorization_endpoint`` and ``token_endpoint`` for an issuer."""
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    owned = client is None
    http = client or httpx.Client(timeout=HTTP_TIMEOUT)
    try:
        response = http.get(url)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise DeviceFlowError(f"could not discover {issuer}: {exc}") from exc
    finally:
        if owned:
            http.close()

    endpoints = {
        key: document.get(key) for key in ("device_authorization_endpoint", "token_endpoint")
    }
    missing = [key for key, value in endpoints.items() if not isinstance(value, str)]
    if missing:
        raise DeviceFlowError(
            f"{issuer} does not advertise {', '.join(missing)}; "
            "the device flow is not available on this provider"
        )
    return {key: str(value) for key, value in endpoints.items()}


def start_device_authorization(
    endpoint: str,
    *,
    client_id: str,
    scope: str = "openid profile email offline_access",
    http: httpx.Client | None = None,
) -> DeviceAuthorization:
    """RFC 8628 §3.1–3.2. Returns the code to show the person."""
    body = _post(endpoint, {"client_id": client_id, "scope": scope}, client=http)
    if "error" in body:
        raise DeviceFlowError(f"{body['error']}: {body.get('error_description', 'no description')}")
    try:
        return DeviceAuthorization(
            device_code=str(body["device_code"]),
            user_code=str(body["user_code"]),
            verification_uri=str(body["verification_uri"]),
            verification_uri_complete=(
                str(body["verification_uri_complete"])
                if body.get("verification_uri_complete")
                else None
            ),
            expires_in=int(body.get("expires_in", DEFAULT_EXPIRY)),
            interval=max(int(body.get("interval", DEFAULT_INTERVAL)), 1),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DeviceFlowError(f"device authorization response is not usable: {exc}") from exc


def _token_request(
    endpoint: str, data: dict[str, str], *, http: httpx.Client | None = None
) -> TokenResponse:
    body = _post(endpoint, data, client=http)
    error = body.get("error")
    if error == "authorization_pending":
        raise AuthorizationPending("waiting for the person to approve")
    if error == "slow_down":
        raise AuthorizationPending("slow_down")
    if error:
        raise DeviceFlowError(f"{error}: {body.get('error_description', 'no description')}")
    token = body.get("access_token")
    if not isinstance(token, str):
        raise DeviceFlowError("the token response carries no access_token")
    return TokenResponse(
        access_token=token,
        refresh_token=body.get("refresh_token")
        if isinstance(body.get("refresh_token"), str)
        else None,
        expires_in=int(body.get("expires_in", 300)),
        id_token=body.get("id_token") if isinstance(body.get("id_token"), str) else None,
    )


def poll_for_token(
    endpoint: str,
    authorization: DeviceAuthorization,
    *,
    client_id: str,
    http: httpx.Client | None = None,
    sleep: Any = time.sleep,
    now: Any = time.monotonic,
) -> TokenResponse:
    """RFC 8628 §3.4–3.5. Polls until the person approves, or gives up.

    ``slow_down`` increases the interval permanently rather than for one round:
    §3.5 says the client MUST increase it, and a client that backed off once
    and then resumed its old rate would be told to slow down again on the next
    poll, forever.
    """
    interval = authorization.interval
    deadline = now() + authorization.expires_in
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": authorization.device_code,
        "client_id": client_id,
    }
    while True:
        if now() >= deadline:
            raise DeviceFlowError(
                "the login was not approved before the code expired; run `gate login` again"
            )
        sleep(interval)
        try:
            return _token_request(endpoint, data, http=http)
        except AuthorizationPending as pending:
            if str(pending) == "slow_down":
                interval += 5


def refresh_access_token(
    endpoint: str,
    refresh_token: str,
    *,
    client_id: str,
    http: httpx.Client | None = None,
) -> TokenResponse:
    """Exchange a stored refresh token for a fresh access token."""
    return _token_request(
        endpoint,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
        http=http,
    )
