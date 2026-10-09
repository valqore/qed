"""What a token exchange grants (SPEC §6.2). Pure arithmetic, no HTTP."""

from __future__ import annotations

from datetime import timedelta

from qed.core.delegation.exchange import (
    MAX_LIFETIME,
    cap_budget,
    grant_for,
    scopes_for_groups,
)
from qed.core.schemas import Budget

HOUR = timedelta(hours=1)
QUARTER = timedelta(minutes=15)

SCOPES = {"platform": ["read", "write"], "sre": ["read", "restart"]}


def grant(**kwargs: object):  # type: ignore[no-untyped-def]
    params: dict[str, object] = {
        "requested_scope": [],
        "groups": [],
        "scopes_by_group": SCOPES,
        "requested_budget": Budget(),
        "ceiling": Budget(),
        "requested_lifetime": QUARTER,
        "default_lifetime": QUARTER,
    }
    params.update(kwargs)
    return grant_for(**params)  # type: ignore[arg-type]


class TestScopes:
    def test_groups_union_their_scopes(self) -> None:
        assert scopes_for_groups(["platform", "sre"], SCOPES) == frozenset(
            {"read", "write", "restart"}
        )

    def test_an_unknown_group_contributes_nothing(self) -> None:
        assert scopes_for_groups(["nobody"], SCOPES) == frozenset()

    def test_only_the_intersection_is_granted(self) -> None:
        result = grant(requested_scope=["read", "admin"], groups=["platform"])
        assert result.scope == ["read"]

    def test_a_refused_scope_is_reported_back(self) -> None:
        """A misconfigured agent should fail loudly here, not silently at the
        first action it cannot take."""
        result = grant(requested_scope=["read", "admin"], groups=["platform"])
        assert result.refused_scope == ["admin"]

    def test_with_no_mapping_configured_scope_restricts_nothing(self) -> None:
        """Honest about what is actually enforced before an operator writes a
        mapping: nothing. Refusing everything would make the endpoint unusable
        on day one."""
        result = grant(requested_scope=["anything"], groups=[], scopes_by_group={})
        assert result.scope == ["anything"]
        assert result.refused_scope == []


class TestBudgetCeiling:
    def test_two_caps_take_the_smaller(self) -> None:
        assert cap_budget(Budget(steps=50), Budget(steps=10)).steps == 10

    def test_an_uncapped_ceiling_grants_what_was_asked(self) -> None:
        assert cap_budget(Budget(steps=50), Budget()).steps == 50

    def test_an_uncapped_request_takes_the_ceiling(self) -> None:
        """The case the obvious arithmetic gets wrong: 0 means uncapped, so
        `min(0, 10)` would hand back an unlimited token."""
        assert cap_budget(Budget(steps=0), Budget(steps=10)).steps == 10

    def test_a_smaller_request_is_left_alone(self) -> None:
        assert cap_budget(Budget(steps=3), Budget(steps=10)).steps == 3

    def test_every_axis_is_capped_independently(self) -> None:
        capped = cap_budget(
            Budget(steps=99, tokens=1, seconds=99, money_cents=0),
            Budget(steps=10, tokens=100, seconds=0, money_cents=250),
        )
        assert (capped.steps, capped.tokens, capped.seconds, capped.money_cents) == (
            10,
            1,
            99,
            250,
        )

    def test_the_ceiling_currency_wins(self) -> None:
        capped = cap_budget(Budget(money_cents=10, currency="USD"), Budget(currency="EUR"))
        assert capped.currency == "EUR"


class TestLifetime:
    def test_the_request_is_honoured_when_it_is_modest(self) -> None:
        assert grant(requested_lifetime=timedelta(minutes=5)).lifetime == timedelta(minutes=5)

    def test_an_hour_is_the_ceiling(self) -> None:
        assert grant(requested_lifetime=timedelta(days=1)).lifetime == MAX_LIFETIME

    def test_an_absent_request_takes_the_default(self) -> None:
        result = grant(requested_lifetime=timedelta(0), default_lifetime=timedelta(minutes=7))
        assert result.lifetime == timedelta(minutes=7)

    def test_a_child_cannot_outlive_its_parent(self) -> None:
        result = grant(requested_lifetime=HOUR, parent_expires_in=timedelta(minutes=4))
        assert result.lifetime == timedelta(minutes=4)

    def test_a_token_cannot_outlive_its_mandate(self) -> None:
        result = grant(requested_lifetime=HOUR, mandate_expires_in=timedelta(minutes=2))
        assert result.lifetime == timedelta(minutes=2)

    def test_the_tightest_bound_wins(self) -> None:
        result = grant(
            requested_lifetime=HOUR,
            parent_expires_in=timedelta(minutes=9),
            mandate_expires_in=timedelta(minutes=3),
        )
        assert result.lifetime == timedelta(minutes=3)

    def test_an_already_expired_parent_yields_no_lifetime_not_a_negative_one(self) -> None:
        result = grant(requested_lifetime=HOUR, parent_expires_in=timedelta(seconds=-30))
        assert result.lifetime == timedelta(0)
