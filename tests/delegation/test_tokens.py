"""Minting and verifying tokens (SPEC §6.1–§6.2), including the attacks that
JWT implementations historically fall to."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey, RSAKey

from qed.core.delegation.claims import NarrowingViolation, TokenClaims, TokenVerificationError
from qed.core.schemas import Budget
from qed.infra.tokens import (
    MAX_TOKEN_LIFETIME,
    QED_ALG,
    TOKEN_KEY_NAME,
    TokenIssuer,
    decode_unverified_header,
    load_or_create_token_key,
    verify_token,
)

NOW = datetime.fromisoformat("2026-10-08T12:00:00+00:00")
ISSUER = "https://qed.internal"
ISSUERS = frozenset({ISSUER})


@pytest.fixture
def issuer(tmp_path: Path) -> TokenIssuer:
    return TokenIssuer(load_or_create_token_key(tmp_path), issuer=ISSUER)


def mint(issuer: TokenIssuer, **kwargs: object) -> tuple[str, TokenClaims]:
    params: dict[str, object] = {
        "subject": "ali@example.com",
        "jti": "01JB000000000000000000JTI0",
        "now": NOW,
        "lifetime": timedelta(minutes=15),
    }
    params.update(kwargs)
    return issuer.mint(**params)  # type: ignore[arg-type]


class TestTokenKey:
    def test_the_key_is_created_once_and_reused(self, tmp_path: Path) -> None:
        first = load_or_create_token_key(tmp_path)
        second = load_or_create_token_key(tmp_path)
        assert first.kid == second.kid
        assert (tmp_path / TOKEN_KEY_NAME).exists()

    def test_the_token_key_is_not_the_evidence_key(self, tmp_path: Path) -> None:
        """An evidence key signs history and must outlive every token; a token
        key is online, used constantly, and has to be rotatable without
        invalidating a single past record."""
        from qed.infra.keys.file import PRIVATE_KEY_NAME, init_keys

        init_keys(tmp_path)
        load_or_create_token_key(tmp_path)
        assert (tmp_path / PRIVATE_KEY_NAME).read_text(encoding="utf-8") != (
            tmp_path / TOKEN_KEY_NAME
        ).read_text(encoding="utf-8")

    def test_only_the_public_half_is_published(self, issuer: TokenIssuer) -> None:
        public = issuer.public_jwk()
        assert "d" not in public, "the private scalar must never leave the instance"
        assert public["kty"] == "OKP"


class TestMint:
    def test_a_minted_token_verifies(self, issuer: TokenIssuer) -> None:
        token, claims = mint(issuer)
        back, principal = verify_token(token, keys=issuer.key, now=NOW, issuers=ISSUERS)
        assert back.jti == claims.jti
        assert principal.human_hash is not None

    def test_the_algorithm_is_the_rfc_9864_curve_name(self, issuer: TokenIssuer) -> None:
        """`EdDSA` is deprecated by RFC 9864 and the identifier is baked into
        every token, so it is settled before the first one is issued."""
        token, _ = mint(issuer)
        assert decode_unverified_header(token)["alg"] == QED_ALG == "Ed25519"

    def test_times_are_numeric_dates(self, issuer: TokenIssuer) -> None:
        """RFC 7519 §2. The evidence chain uses RFC 3339 strings; a token is
        read by other people's libraries and they expect a number."""
        token, _ = mint(issuer)
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==").decode("utf-8"))
        assert isinstance(payload["exp"], int)
        assert isinstance(payload["iat"], int)

    def test_lifetime_is_capped_at_an_hour(self, issuer: TokenIssuer) -> None:
        _, claims = mint(issuer, lifetime=timedelta(days=7))
        assert claims.exp == NOW + MAX_TOKEN_LIFETIME

    def test_a_child_cannot_outlive_its_parent(self, issuer: TokenIssuer) -> None:
        """Otherwise a child survives the revocation of what authorised it."""
        _, parent = mint(issuer, lifetime=timedelta(minutes=5))
        _, child = mint(
            issuer,
            jti="01JB000000000000000000JTI1",
            lifetime=timedelta(minutes=50),
            parent=parent,
        )
        assert child.exp == parent.exp

    def test_minting_a_wider_child_is_refused(self, issuer: TokenIssuer) -> None:
        _, parent = mint(issuer, scope=["read"])
        with pytest.raises(NarrowingViolation):
            mint(
                issuer,
                jti="01JB000000000000000000JTI2",
                scope=["read", "admin"],
                parent=parent,
            )

    def test_the_actor_becomes_the_agent_chain(self, issuer: TokenIssuer) -> None:
        token, _ = mint(issuer, actor="claude-code@laptop")
        _, principal = verify_token(token, keys=issuer.key, now=NOW, issuers=ISSUERS)
        assert principal.agent_chain == ["claude-code@laptop"]

    def test_a_budget_survives_the_round_trip(self, issuer: TokenIssuer) -> None:
        token, _ = mint(issuer, budget=Budget(steps=5, money_cents=250))
        back, _ = verify_token(token, keys=issuer.key, now=NOW, issuers=ISSUERS)
        assert back.budget.steps == 5
        assert back.budget.money_cents == 250


class TestVerifyRejects:
    def test_a_tampered_payload_is_refused(self, issuer: TokenIssuer) -> None:
        token, _ = mint(issuer)
        head, payload, sig = token.split(".")
        body = json.loads(base64.urlsafe_b64decode(payload + "==").decode("utf-8"))
        body["sub"] = "someone-else@example.com"
        swapped = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")
        with pytest.raises(TokenVerificationError, match="signature"):
            verify_token(f"{head}.{swapped}.{sig}", keys=issuer.key, now=NOW, issuers=ISSUERS)

    def test_a_token_signed_by_another_key_is_refused(
        self, issuer: TokenIssuer, tmp_path: Path
    ) -> None:
        other = TokenIssuer(load_or_create_token_key(tmp_path / "other"), issuer=ISSUER)
        token, _ = mint(other)
        with pytest.raises(TokenVerificationError):
            verify_token(token, keys=issuer.key, now=NOW, issuers=ISSUERS)

    def test_alg_none_is_refused(self, issuer: TokenIssuer) -> None:
        """The classic. `none` is not in any accepted list, and the accepted
        list is passed in by the caller rather than read from the token."""
        _, claims = mint(issuer)
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        payload = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "iss": ISSUER,
                        "sub": "x",
                        "aud": "qed",
                        "exp": 9999999999,
                        "iat": 1,
                        "jti": claims.jti,
                    }
                ).encode()
            )
            .decode()
            .rstrip("=")
        )
        with pytest.raises(TokenVerificationError):
            verify_token(f"{header}.{payload}.", keys=issuer.key, now=NOW, issuers=ISSUERS)

    def test_a_symmetric_token_cannot_impersonate_an_asymmetric_one(
        self, issuer: TokenIssuer
    ) -> None:
        """Algorithm confusion: sign with HMAC using the public key as the
        secret and hope the verifier dispatches on the token's own `alg`."""
        secret = OctKey.import_key(json.dumps(issuer.public_jwk()).encode())
        forged = jwt.encode(
            {"alg": "HS256", "kid": issuer.kid},
            {
                "iss": ISSUER,
                "sub": "attacker",
                "aud": "qed",
                "exp": 9999999999,
                "iat": 1,
                "jti": "01JB000000000000000000JTIX",
            },
            secret,
        )
        with pytest.raises(TokenVerificationError):
            verify_token(forged, keys=issuer.key, now=NOW, issuers=ISSUERS)

    def test_an_expired_token_is_refused_after_the_signature_checks_out(
        self, issuer: TokenIssuer
    ) -> None:
        token, _ = mint(issuer, lifetime=timedelta(minutes=1))
        with pytest.raises(TokenVerificationError, match="expired"):
            verify_token(token, keys=issuer.key, now=NOW + timedelta(hours=1), issuers=ISSUERS)

    def test_a_token_from_an_unconfigured_issuer_is_refused(self, issuer: TokenIssuer) -> None:
        token, _ = mint(issuer)
        with pytest.raises(TokenVerificationError, match="not configured"):
            verify_token(token, keys=issuer.key, now=NOW, issuers=frozenset({"https://other"}))

    def test_garbage_is_refused_without_an_unhandled_exception(self, issuer: TokenIssuer) -> None:
        for junk in ("", "not-a-jwt", "a.b", "a.b.c.d", "...."):
            with pytest.raises(TokenVerificationError):
                verify_token(junk, keys=issuer.key, now=NOW, issuers=ISSUERS)


class TestIdpTokens:
    def test_an_rs256_token_from_a_key_set_verifies(self) -> None:
        """What an IdP actually sends. The key arrives through a JWKS set."""
        private = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})
        keyset = KeySet([RSAKey.import_key(private.as_dict(private=False))])
        token = jwt.encode(
            {"alg": "RS256", "kid": "idp-1"},
            {
                "iss": "https://idp.example",
                "sub": "ali@example.com",
                "aud": "qed",
                "exp": int((NOW + timedelta(minutes=10)).timestamp()),
                "iat": int(NOW.timestamp()),
                "jti": "01JB000000000000000000JTI9",
            },
            private,
        )
        claims, principal = verify_token(
            token,
            keys=keyset,
            now=NOW,
            issuers=frozenset({"https://idp.example"}),
            algorithms=("RS256",),
        )
        assert claims.sub == "ali@example.com"
        assert principal.human_hash is not None

    def test_an_idp_token_is_not_accepted_under_the_qed_algorithm(self) -> None:
        """The accepted algorithms are named by the caller for each key source,
        so an IdP token cannot be presented as a qed-issued one."""
        private = RSAKey.generate_key(2048, parameters={"kid": "idp-1"})
        keyset = KeySet([RSAKey.import_key(private.as_dict(private=False))])
        token = jwt.encode(
            {"alg": "RS256", "kid": "idp-1"},
            {
                "iss": "https://idp.example",
                "sub": "x",
                "aud": "qed",
                "exp": 9999999999,
                "iat": 1,
                "jti": "01JB000000000000000000JTI8",
            },
            private,
        )
        with pytest.raises(TokenVerificationError):
            verify_token(
                token,
                keys=keyset,
                now=NOW,
                issuers=frozenset({"https://idp.example"}),
                algorithms=(QED_ALG,),
            )
