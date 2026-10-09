"""Token claim checks (SPEC §6.1). Pure — no key, no clock, no network."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from qed.core.delegation.claims import (
    ChainTooDeep,
    NarrowingViolation,
    TokenClaims,
    TokenVerificationError,
    flatten_actor_chain,
    narrows_from,
    principal_from,
    require_mandate,
    validate_claims,
    verify,
)
from qed.core.schemas import Budget

NOW = datetime.fromisoformat("2026-10-08T12:00:00+00:00")
ISSUERS = frozenset({"https://idp.example"})

BASE: dict[str, Any] = {
    "iss": "https://idp.example",
    "sub": "ali@example.com",
    "aud": "qed",
    "exp": NOW + timedelta(minutes=30),
    "iat": NOW,
    "jti": "01JB000000000000000000JTI0",
}


def claims(**patch: Any) -> TokenClaims:
    return TokenClaims.model_validate({**BASE, **patch})


class TestValidateClaims:
    def test_a_well_formed_token_passes(self) -> None:
        validate_claims(claims(), now=NOW, issuers=ISSUERS)

    def test_an_unknown_issuer_is_refused(self) -> None:
        with pytest.raises(TokenVerificationError, match="not configured"):
            validate_claims(claims(iss="https://attacker.example"), now=NOW, issuers=ISSUERS)

    def test_a_token_minted_for_another_service_is_refused(self) -> None:
        """Without the audience check, any token the IdP ever issued to any
        client would be usable here."""
        with pytest.raises(TokenVerificationError, match="audience"):
            validate_claims(claims(aud="some-other-api"), now=NOW, issuers=ISSUERS)

    def test_an_audience_list_containing_qed_is_accepted(self) -> None:
        validate_claims(claims(aud=["other", "qed"]), now=NOW, issuers=ISSUERS)

    def test_an_expired_token_is_refused(self) -> None:
        with pytest.raises(TokenVerificationError, match="expired"):
            validate_claims(claims(exp=NOW - timedelta(minutes=5)), now=NOW, issuers=ISSUERS)

    def test_expiry_gets_no_benefit_of_the_doubt_beyond_the_skew(self) -> None:
        just_inside = claims(exp=NOW - timedelta(seconds=30))
        validate_claims(just_inside, now=NOW, issuers=ISSUERS)
        with pytest.raises(TokenVerificationError):
            validate_claims(claims(exp=NOW - timedelta(seconds=90)), now=NOW, issuers=ISSUERS)

    def test_a_not_yet_valid_token_is_refused(self) -> None:
        with pytest.raises(TokenVerificationError, match="not valid before"):
            validate_claims(claims(nbf=NOW + timedelta(minutes=10)), now=NOW, issuers=ISSUERS)

    def test_a_clock_slightly_ahead_is_tolerated(self) -> None:
        """A fleet whose clocks differ by seconds must not fail to delegate."""
        validate_claims(claims(iat=NOW + timedelta(seconds=30)), now=NOW, issuers=ISSUERS)

    def test_a_token_issued_far_in_the_future_is_refused(self) -> None:
        with pytest.raises(TokenVerificationError, match="clock skew"):
            validate_claims(claims(iat=NOW + timedelta(hours=1)), now=NOW, issuers=ISSUERS)


class TestActorChain:
    def test_a_token_with_no_actor_is_one_link(self) -> None:
        assert flatten_actor_chain(claims()) == ["ali@example.com"]

    def test_the_subject_comes_first_then_each_actor(self) -> None:
        """Outermost first: who the action is *for*, then who is acting."""
        chain = flatten_actor_chain(
            claims(act={"sub": "claude-code@laptop", "act": {"sub": "sub:planner"}})
        )
        assert chain == ["ali@example.com", "claude-code@laptop", "sub:planner"]

    def test_a_chain_at_the_limit_is_allowed(self) -> None:
        nested = {"sub": "a", "act": {"sub": "b", "act": {"sub": "c"}}}
        assert len(flatten_actor_chain(claims(act=nested))) == 4

    def test_a_chain_past_the_limit_is_refused(self) -> None:
        nested = {"sub": "a", "act": {"sub": "b", "act": {"sub": "c", "act": {"sub": "d"}}}}
        with pytest.raises(ChainTooDeep):
            flatten_actor_chain(claims(act=nested))

    def test_a_looping_chain_is_caught_by_the_depth_bound(self) -> None:
        """No seen-set is needed: at four links a cycle has nowhere to hide."""
        nested = {"sub": "a", "act": {"sub": "a", "act": {"sub": "a", "act": {"sub": "a"}}}}
        with pytest.raises(ChainTooDeep):
            flatten_actor_chain(claims(act=nested))


class TestNarrowing:
    def parent(self, **patch: Any) -> TokenClaims:
        return claims(
            scope=["read", "write"],
            budget=Budget(steps=10, money_cents=500),
            environments=["dev", "staging"],
            **patch,
        )

    def test_an_equal_token_narrows(self) -> None:
        narrows_from(self.parent(), self.parent())

    def test_a_strictly_smaller_token_narrows(self) -> None:
        child = claims(
            scope=["read"],
            budget=Budget(steps=5, money_cents=100),
            environments=["dev"],
            exp=NOW + timedelta(minutes=10),
        )
        narrows_from(child, self.parent())

    def test_extra_scope_is_refused(self) -> None:
        with pytest.raises(NarrowingViolation, match="scope"):
            narrows_from(claims(scope=["read", "admin"]), self.parent())

    def test_a_larger_budget_is_refused(self) -> None:
        with pytest.raises(NarrowingViolation, match="steps"):
            narrows_from(claims(budget=Budget(steps=50)), self.parent())

    def test_an_uncapped_child_under_a_capped_parent_is_refused(self) -> None:
        """A cap of 0 means uncapped, so the obvious numeric comparison gives
        the wrong answer here: 0 is an *increase*, not a decrease."""
        with pytest.raises(NarrowingViolation, match="steps"):
            narrows_from(claims(budget=Budget(steps=0, money_cents=100)), self.parent())

    def test_an_uncapped_parent_permits_any_child_budget(self) -> None:
        narrows_from(claims(budget=Budget(steps=99)), claims(budget=Budget()))

    def test_a_child_outliving_its_parent_is_refused(self) -> None:
        # The budget has to be inside the parent's, or the budget check fires
        # first and this test passes for the wrong reason.
        child = claims(
            scope=["read"],
            budget=Budget(steps=5, money_cents=100),
            environments=["dev"],
            exp=NOW + timedelta(hours=2),
        )
        with pytest.raises(NarrowingViolation, match="outlives"):
            narrows_from(child, self.parent())

    def test_an_extra_environment_is_refused(self) -> None:
        child = claims(
            scope=["read"],
            budget=Budget(steps=5, money_cents=100),
            environments=["prod"],
        )
        with pytest.raises(NarrowingViolation, match="environments"):
            narrows_from(child, self.parent())

    def test_a_parent_with_no_constraint_does_not_constrain(self) -> None:
        """An absent list means "any", matching how `applies_to` reads, so a
        reader does not have to hold two different rules in their head."""
        narrows_from(claims(scope=["anything"], environments=["prod"]), claims())


class TestMandateRequirement:
    def test_a_human_token_needs_no_mandate(self) -> None:
        require_mandate(claims())

    def test_a_service_token_without_a_mandate_is_refused(self) -> None:
        with pytest.raises(TokenVerificationError, match="unattended"):
            require_mandate(claims(sub="svc:nightly-sre"))

    def test_a_service_token_with_a_mandate_passes(self) -> None:
        require_mandate(claims(sub="svc:nightly-sre", mandate_id="mdt_1"))


class TestPrincipal:
    def test_a_human_subject_is_hashed(self) -> None:
        principal = principal_from(claims())
        assert principal.human_hash is not None
        assert len(principal.human_hash) == 64
        assert "ali@example.com" not in principal.human_hash

    def test_the_same_subject_at_two_issuers_is_two_principals(self) -> None:
        """Two people can share a local username across identity providers."""
        a = principal_from(claims())
        b = principal_from(claims(iss="https://other.example"))
        # Only one issuer is configured, so this never reaches `validate_claims`;
        # the point is the hash input, not the issuer allow-list.
        assert a.human_hash != b.human_hash

    def test_a_service_subject_has_no_human_hash(self) -> None:
        """There is no person to attribute the action to — which is exactly why
        a mandate is required, and why AG-IDN-007 blocks it if one is absent."""
        principal = principal_from(claims(sub="svc:nightly-sre", mandate_id="mdt_1"))
        assert principal.human_hash is None

    def test_the_agent_chain_excludes_the_subject(self) -> None:
        principal = principal_from(claims(act={"sub": "claude-code@laptop"}))
        assert principal.agent_chain == ["claude-code@laptop"]

    def test_the_jti_becomes_the_token_jti(self) -> None:
        assert principal_from(claims()).token_jti == BASE["jti"]


class TestVerify:
    def test_the_happy_path_returns_a_principal(self) -> None:
        principal = verify(claims(), now=NOW, issuers=ISSUERS)
        assert principal.token_jti == BASE["jti"]

    def test_the_issuer_is_checked_before_anything_else(self) -> None:
        """Cheapest and most damning first: an unknown issuer is refused before
        any effort goes into a chain that is also too deep."""
        nested = {"sub": "a", "act": {"sub": "b", "act": {"sub": "c", "act": {"sub": "d"}}}}
        with pytest.raises(TokenVerificationError, match="not configured"):
            verify(claims(iss="https://attacker.example", act=nested), now=NOW, issuers=ISSUERS)

    def test_narrowing_is_enforced_when_a_parent_is_given(self) -> None:
        parent = claims(scope=["read"])
        with pytest.raises(NarrowingViolation):
            verify(claims(scope=["read", "write"]), now=NOW, issuers=ISSUERS, parent=parent)

    def test_an_unattended_token_without_a_mandate_never_yields_a_principal(self) -> None:
        with pytest.raises(TokenVerificationError):
            verify(claims(sub="svc:nightly-sre"), now=NOW, issuers=ISSUERS)


class TestUnknownClaims:
    def test_an_unknown_claim_is_kept_not_rejected(self) -> None:
        """An IdP adds claims for its own reasons. A token it considers valid
        must not be refused because this software has not heard of a field."""
        token = claims(groups=["platform"], email_verified=True)
        validate_claims(token, now=NOW, issuers=ISSUERS)
        assert token.groups == ["platform"]  # type: ignore[attr-defined]

    def test_a_missing_required_claim_is_an_error(self) -> None:
        payload = {k: v for k, v in BASE.items() if k != "jti"}
        with pytest.raises(ValueError, match="jti"):
            TokenClaims.model_validate(payload)
