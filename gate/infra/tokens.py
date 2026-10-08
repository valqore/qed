"""Minting and verifying delegation tokens (SPEC §6.1–§6.2).

This is the I/O half of delegation: it resolves a ``kid`` to a key, checks a
signature, and hands the resulting claims to :mod:`gate.core.delegation`, which
decides whether they are acceptable. The split is not decorative — the core
half has to stay importable with no socket in reach, and an air-gapped install
has to make the same decisions a connected one does.

Two kinds of token arrive here:

* **gate-issued**, signed by this instance's token key. The `kid` resolves
  locally and no network is involved, ever.
* **IdP-issued**, signed by an identity provider. The `kid` resolves through a
  JWKS set, which :mod:`gate.infra.jwks` fetches and caches on disk.

The token key is deliberately **not** the evidence key. An evidence key signs
history and must outlive every token; a token key is online, used constantly,
and should be rotatable without invalidating a single past record.
"""

from __future__ import annotations

import contextlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, OKPKey

from gate.core.delegation.claims import (
    AUDIENCE,
    DEFAULT_SKEW,
    MAX_CHAIN_DEPTH,
    TokenClaims,
    TokenVerificationError,
)
from gate.core.delegation.claims import (
    verify as verify_claims,
)
from gate.core.schemas import Budget, Principal

__all__ = [
    "GATE_ALG",
    "IDP_ALGS",
    "TOKEN_KEY_NAME",
    "TokenIssuer",
    "decode_unverified_header",
    "load_or_create_token_key",
    "verify_token",
]

#: RFC 9864 deprecates the generic `EdDSA` identifier in favour of the curve
#: name, and `joserfc` raises SecurityWarning on `EdDSA`. Settled before the
#: first token is minted, because the identifier ends up inside every one.
GATE_ALG = "Ed25519"

#: What an identity provider may sign with. `none` is absent and there is no
#: code path that reads `alg` from the token to pick a verifier — algorithm
#: agility is where JWT implementations historically go wrong.
IDP_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "Ed25519")

TOKEN_KEY_NAME = "token-key.json"

#: SPEC §6.2: a gate token lives at most an hour, whatever was requested.
MAX_TOKEN_LIFETIME = timedelta(minutes=60)


def _numeric_date(value: datetime) -> int:
    """RFC 7519 §2 NumericDate: whole seconds since 1970-01-01T00:00:00Z."""
    return int(value.timestamp())


def load_or_create_token_key(directory: Path, *, kid: str | None = None) -> OKPKey:
    """The instance's token-signing key, created on first use.

    Stored as a JWK rather than a PEM so that the ``kid`` travels with the key.
    A PEM would mean deriving the id from the key material every time, and two
    derivations that disagree produce tokens nobody can verify.
    """
    path = directory / TOKEN_KEY_NAME
    if path.exists():
        # A dict, not the raw text: `import_key` treats a string as PEM.
        return OKPKey.import_key(json.loads(path.read_text(encoding="utf-8")))
    directory.mkdir(parents=True, exist_ok=True)
    key = OKPKey.generate_key("Ed25519", parameters={"kid": kid or "gate-token-1"})
    path.write_text(json.dumps(key.as_dict(private=True)), encoding="utf-8")
    # Best effort: Windows and some mounts do not carry POSIX modes, and a
    # key the OS will not restrict is still better than no key at all. The
    # posture check in `gate doctor` is what reports it (SPEC §5 week 5).
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    return key


def decode_unverified_header(token: str) -> dict[str, Any]:
    """The JOSE header, before any signature is checked.

    Needed only to read ``kid`` so the right key can be fetched. Nothing from
    this header is trusted for a decision: the claims that matter are read back
    out of the *verified* token.
    """
    from joserfc import jws

    try:
        return dict(jws.extract_compact(token.encode("ascii")).protected)
    except (JoseError, ValueError, UnicodeEncodeError) as exc:
        raise TokenVerificationError(f"token is not a well-formed JWS: {exc}") from exc


def verify_token(
    token: str,
    *,
    keys: KeySet | OKPKey,
    now: datetime,
    issuers: frozenset[str] | set[str] | list[str],
    algorithms: tuple[str, ...] = (GATE_ALG,),
    parent: TokenClaims | None = None,
    skew: timedelta = DEFAULT_SKEW,
    max_depth: int = MAX_CHAIN_DEPTH,
    audience: str = AUDIENCE,
) -> tuple[TokenClaims, Principal]:
    """Check the signature, then run every §6.1 check against the claims.

    ``algorithms`` is passed explicitly on every call and never derived from
    the token. Letting the token choose its own verifier is the root of both
    the ``alg: none`` family and RSA/HMAC confusion.
    """
    try:
        decoded = jwt.decode(token, keys, algorithms=list(algorithms))
    except JoseError as exc:
        raise TokenVerificationError(f"token signature is not valid: {exc}") from exc

    try:
        claims = TokenClaims.model_validate(decoded.claims)
    except ValueError as exc:
        raise TokenVerificationError(f"token is missing a required claim: {exc}") from exc

    principal = verify_claims(
        claims,
        now=now,
        issuers=issuers,
        parent=parent,
        skew=skew,
        max_depth=max_depth,
        audience=audience,
    )
    return claims, principal


class TokenIssuer:
    """Mints gate tokens (SPEC §6.2).

    Every cap applied here is a *minimum* of what was asked for and what the
    caller is allowed, never the request on its own. A token exchange that
    granted what it was asked for would be a way to escalate by asking.
    """

    def __init__(self, key: OKPKey, *, issuer: str) -> None:
        self.key = key
        self.issuer = issuer

    @property
    def kid(self) -> str:
        return str(self.key.kid)

    def public_jwk(self) -> dict[str, Any]:
        """The public half, for anyone verifying a token this gate issued."""
        return dict(self.key.as_dict(private=False))

    def mint(
        self,
        *,
        subject: str,
        jti: str,
        now: datetime,
        lifetime: timedelta,
        scope: list[str] | None = None,
        budget: Budget | None = None,
        environments: list[str] | None = None,
        agent_id: str | None = None,
        mandate_id: str | None = None,
        parent: TokenClaims | None = None,
        actor: str | None = None,
    ) -> tuple[str, TokenClaims]:
        """Return ``(compact_jwt, claims)``.

        Lifetime is capped at :data:`MAX_TOKEN_LIFETIME` and, when there is a
        parent, at the parent's expiry — a child that outlived its parent would
        survive the revocation of the thing that authorised it.
        """
        capped = min(lifetime, MAX_TOKEN_LIFETIME)
        exp = now + capped
        if parent is not None and parent.exp < exp:
            exp = parent.exp

        payload: dict[str, Any] = {
            "iss": self.issuer,
            "sub": subject,
            "aud": AUDIENCE,
            # NumericDate (RFC 7519 §2): seconds since the epoch, as a number.
            # The evidence chain uses RFC 3339 strings, but a token is read by
            # other people's JWT libraries and they expect a number here.
            "iat": _numeric_date(now),
            "exp": _numeric_date(exp),
            "jti": jti,
            "scope": list(scope or []),
            "budget": (budget or Budget()).model_dump(mode="json"),
            "environments": list(environments or []),
        }
        if agent_id is not None:
            payload["agent_id"] = agent_id
        if mandate_id is not None:
            payload["mandate_id"] = mandate_id
        if parent is not None:
            payload["parent_jti"] = parent.jti
        if actor is not None:
            payload["act"] = {"sub": actor}

        claims = TokenClaims.model_validate(payload)
        if parent is not None:
            from gate.core.delegation.claims import narrows_from

            narrows_from(claims, parent)

        token = jwt.encode(
            {"alg": GATE_ALG, "kid": self.kid, "typ": "JWT"},
            payload,
            self.key,
            algorithms=[GATE_ALG],
        )
        return token, claims
