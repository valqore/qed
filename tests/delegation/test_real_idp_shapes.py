"""Regressions for what a real identity provider actually sends.

Every case here was found by running the week-3 demo against a real Keycloak 26
rather than a fixture, and every one of them was invisible to the synthetic
tests because those built claims the way the gate itself writes them.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from gate.core.delegation.claims import TokenClaims, TokenVerificationError
from gate.infra.tokens import verify_token

NOW = datetime.fromisoformat("2026-10-08T12:00:00+00:00")
IDP = "https://idp.example"

BASE = {
    "iss": IDP,
    "sub": "c952ac57-6ece-44a2-a385-a09eb6eb40c4",
    "aud": "gate",
    "exp": NOW + timedelta(minutes=30),
    "iat": NOW,
    "jti": "01JB000000000000000000IDP0",
}


class TestScopeIsASpaceDelimitedString:
    """RFC 6749 §3.3. Keycloak, Okta and Entra all send the string form."""

    def test_a_string_scope_is_split(self) -> None:
        claims = TokenClaims.model_validate({**BASE, "scope": "openid email profile"})
        assert claims.scope == ["openid", "email", "profile"]

    def test_a_list_scope_still_works(self) -> None:
        """The gate's own tokens carry a list, because that is what the rest of
        the code works with. Both forms have to be accepted."""
        claims = TokenClaims.model_validate({**BASE, "scope": ["read", "write"]})
        assert claims.scope == ["read", "write"]

    def test_repeated_whitespace_does_not_produce_empty_scopes(self) -> None:
        claims = TokenClaims.model_validate({**BASE, "scope": "  read   write  "})
        assert claims.scope == ["read", "write"]

    def test_an_absent_scope_is_empty(self) -> None:
        assert TokenClaims.model_validate(BASE).scope == []


class TestAKeycloakShapedToken:
    def test_the_claim_set_keycloak_sends_is_accepted(self) -> None:
        """Captured from a real realm: a UUID subject, a string scope, groups,
        and a pile of claims the gate has never heard of."""
        key = RSAKey.generate_key(2048, parameters={"kid": "kc-1"})
        token = jwt.encode(
            {"alg": "RS256", "kid": "kc-1"},
            {
                "iss": IDP,
                "sub": "c952ac57-6ece-44a2-a385-a09eb6eb40c4",
                "aud": "gate",
                "exp": int((NOW + timedelta(minutes=30)).timestamp()),
                "iat": int(NOW.timestamp()),
                "jti": "64377988-f004-4b9f-b3e7-9a66abb8fcc8",
                "scope": "openid profile email",
                "groups": ["platform"],
                "acr": "1",
                "azp": "gate-cli",
                "email": "ali@example.com",
                "email_verified": True,
                "preferred_username": "ali",
                "sid": "5471de47-8206-4399-8b99-c8e0a54752bf",
                "typ": "Bearer",
                "name": "Ali Demo",
            },
            key,
        )
        keyset = KeySet([RSAKey.import_key(key.as_dict(private=False))])
        claims, principal = verify_token(
            token,
            keys=keyset,
            now=NOW,
            issuers=frozenset({IDP}),
            algorithms=("RS256",),
        )
        assert claims.scope == ["openid", "profile", "email"]
        assert principal.human_hash is not None

    def test_a_token_with_no_subject_is_refused_not_silently_accepted(self) -> None:
        """Keycloak 26 omits `sub` unless the client has the `basic` scope.
        The principal hash is built from the subject, so a token without one
        cannot name anybody and must not produce a principal."""
        with pytest.raises(ValueError, match="sub"):
            TokenClaims.model_validate({k: v for k, v in BASE.items() if k != "sub"})


class TestATokenCannotDeclareItsOwnKind:
    def test_a_token_type_claim_is_ignored(self) -> None:
        """`TokenClaims` carried a `token_type` field with a default of "gate",
        so an IdP token -- which has no such claim -- arrived looking
        gate-issued and was handed to the narrowing check as its own parent.
        Whether a token is gate-issued is now decided by which key verified it.
        """
        import inspect

        from gate.api import app_state
        from gate.api.routers import token as token_router
        from gate.core.delegation import claims as claims_module

        # Extra claims are kept, as any unknown claim is -- but no field by
        # that name exists, so nothing can read it off the model.
        claims = TokenClaims.model_validate({**BASE, "token_type": "gate"})
        assert "token_type" not in type(claims).model_fields

        # And no module on the verification path mentions it either.
        for module in (claims_module, app_state, token_router):
            source = inspect.getsource(module)
            # Reads of the *claim* only. `"token_type": "Bearer"` in the
            # response body is RFC 6749 §5.1 and has nothing to do with this.
            offenders = [
                line.strip()
                for line in source.splitlines()
                if "claims.token_type" in line or 'get("token_type")' in line
            ]
            assert not offenders, (
                f"{module.__name__} reads a token_type claim again: {offenders}. "
                "Whether a token is gate-issued is decided by which key "
                "verified it, not by what the token says about itself."
            )


class TestNarrowingAgainstAnIdpToken:
    def test_an_idp_token_is_not_its_own_parent(self) -> None:
        """The bug this guards: an IdP token with no `scope` was treated as a
        parent, so asking for any scope at all failed narrowing with
        "child token asks for scope [...] that its parent does not hold"."""
        key = RSAKey.generate_key(2048, parameters={"kid": "kc-2"})
        token = jwt.encode(
            {"alg": "RS256", "kid": "kc-2"},
            {
                **{k: v for k, v in BASE.items() if k not in {"exp", "iat"}},
                "exp": int((NOW + timedelta(minutes=30)).timestamp()),
                "iat": int(NOW.timestamp()),
                "scope": "openid email profile",
            },
            key,
        )
        keyset = KeySet([RSAKey.import_key(key.as_dict(private=False))])
        # No `parent=` is passed, which is what the router now does for a
        # token that its own key did not verify.
        claims, _ = verify_token(
            token, keys=keyset, now=NOW, issuers=frozenset({IDP}), algorithms=("RS256",)
        )
        assert claims.scope == ["openid", "email", "profile"]

    def test_verification_still_fails_loudly_for_an_unknown_issuer(self) -> None:
        key = RSAKey.generate_key(2048, parameters={"kid": "kc-3"})
        token = jwt.encode(
            {"alg": "RS256", "kid": "kc-3"},
            {
                **{k: v for k, v in BASE.items() if k not in {"exp", "iat"}},
                "exp": int((NOW + timedelta(minutes=30)).timestamp()),
                "iat": int(NOW.timestamp()),
            },
            key,
        )
        keyset = KeySet([RSAKey.import_key(key.as_dict(private=False))])
        with pytest.raises(TokenVerificationError):
            verify_token(
                token,
                keys=keyset,
                now=NOW,
                issuers=frozenset({"https://somewhere-else"}),
                algorithms=("RS256",),
            )
