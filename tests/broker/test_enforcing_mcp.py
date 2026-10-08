"""Enforcement is derived, not asserted (SPEC §7.2).

Before the broker, an adapter was *told* it was enforcing by a command-line
flag, and that claim went into `context.enforcement` and from there into the
evidence. If the credential was missing the claim was simply wrong and
nothing in the chain said so.

These tests are about the replacement: the gate is enforcing for a call if
and only if it is holding the credential for that call.
"""

from __future__ import annotations

from typing import Any

import pytest

from gate.adapters.mcp.proxy import ProxyOptions, UpstreamSpec, build_tool_proposal
from gate.core.broker.injection import (
    STRIPPED_HEADERS,
    plan_injection,
    strip_agent_credentials,
)
from gate.core.broker.model import Secret, Upstream, UpstreamSet
from gate.core.evidence.hashing import principal_hash
from gate.core.schemas import Enforcement, Mode
from gate.infra.secrets.broker import CredentialBroker
from gate.infra.secrets.resolver import CredentialResolver

UPSTREAM = UpstreamSpec(name="orders-db", command="python", args=["-c", "pass"])
OPTIONS = ProxyOptions(
    environment="prod",
    human_hash=principal_hash("ali@example.com"),
    enforcement=Enforcement.enforcing,
)


def proposal(tool: str = "execute_sql", **arguments: Any):  # type: ignore[no-untyped-def]
    built, _ = build_tool_proposal(
        upstream=UPSTREAM,
        tool=tool,
        arguments=arguments or {"sql": "SELECT 1"},
        options=OPTIONS,
        mode=Mode.enforce,
    )
    return built


def broker_with(upstreams: list[dict[str, Any]], environ: dict[str, str]) -> CredentialBroker:
    return CredentialBroker(
        upstreams=UpstreamSet(upstreams=[Upstream.model_validate(u) for u in upstreams]),
        resolver=CredentialResolver(environ=environ),
    )


CONFIGURED = {
    "id": "orders-db",
    "kind": "mcp",
    "match": {"mcp_server": "orders-db"},
    "credential": {
        "source": "env",
        "ref": "ORDERS_DB_URL",
        "inject": {"type": "env", "name": "DATABASE_URL"},
    },
}


class TestEnforcementIsDerived:
    def test_a_held_credential_means_enforcing(self) -> None:
        broker = broker_with([CONFIGURED], {"ORDERS_DB_URL": "postgres://real"})
        result = broker.for_action(proposal())
        assert result.enforcement is Enforcement.enforcing
        assert result.injection is not None

    def test_a_missing_credential_means_advisory_with_a_reason(self) -> None:
        """The flag said enforcing. The environment disagrees, and the
        environment is the one that decides what actually happens."""
        broker = broker_with([CONFIGURED], {})
        result = broker.for_action(proposal())
        assert result.enforcement is Enforcement.advisory
        assert "ORDERS_DB_URL" in result.reason

    def test_an_unmatched_action_is_advisory(self) -> None:
        broker = broker_with([CONFIGURED], {"ORDERS_DB_URL": "x"})
        other, _ = build_tool_proposal(
            upstream=UpstreamSpec(name="github", command="python", args=["-c", "pass"]),
            tool="list_issues",
            arguments={},
            options=OPTIONS,
            mode=Mode.enforce,
        )
        result = broker.for_action(other)
        assert result.enforcement is Enforcement.advisory
        assert "no upstream matches" in result.reason

    def test_an_upstream_with_no_credential_is_advisory(self) -> None:
        bare = {"id": "orders-db", "kind": "mcp", "match": {"mcp_server": "orders-db"}}
        result = broker_with([bare], {}).for_action(proposal())
        assert result.enforcement is Enforcement.advisory
        assert "no credential configured" in result.reason

    def test_the_reason_never_carries_the_credential(self) -> None:
        secret = "postgres://user:hunter2@db/orders"
        broker = broker_with([CONFIGURED], {"ORDERS_DB_URL": secret})
        result = broker.for_action(proposal())
        assert secret not in result.reason
        assert secret not in repr(result)

    def test_the_proposal_records_what_the_broker_decided(self) -> None:
        """The whole point: `context.enforcement` in the evidence is the
        derived answer, not the flag."""
        built, _ = build_tool_proposal(
            upstream=UPSTREAM,
            tool="execute_sql",
            arguments={"sql": "SELECT 1"},
            options=OPTIONS,
            mode=Mode.enforce,
            enforcement=Enforcement.advisory,
        )
        assert built.context.enforcement is Enforcement.advisory

    def test_without_an_override_the_option_still_applies(self) -> None:
        """A deployment with no upstreams configured behaves as it did
        before the broker existed, rather than silently going advisory."""
        assert proposal().context.enforcement is Enforcement.enforcing


class TestStripping:
    def test_an_agent_supplied_authorization_is_removed(self) -> None:
        """An adapter that added the broker's header while leaving the
        agent's in place would be an adapter where the agent still chooses
        which credential is used."""
        kept, removed = strip_agent_credentials(
            {"Authorization": "Bearer agent-token", "Content-Type": "application/json"}
        )
        assert "Authorization" not in kept
        assert removed == ["Authorization"]
        assert kept == {"Content-Type": "application/json"}

    def test_case_does_not_help(self) -> None:
        """HTTP header names are case-insensitive, so an agent capitalising
        the header would otherwise sail straight through."""
        kept, removed = strip_agent_credentials({"AUTHORIZATION": "Bearer x"})
        assert kept == {}
        assert removed == ["AUTHORIZATION"]

    @pytest.mark.parametrize("header", sorted(STRIPPED_HEADERS))
    def test_every_listed_header_is_stripped(self, header: str) -> None:
        kept, _ = strip_agent_credentials({header: "value"})
        assert kept == {}

    def test_ordinary_headers_survive(self) -> None:
        kept, removed = strip_agent_credentials(
            {"User-Agent": "claude-code", "Accept": "application/json"}
        )
        assert len(kept) == 2
        assert removed == []


class TestInjectionPlans:
    def plan(self, inject: dict[str, Any]):  # type: ignore[no-untyped-def]
        upstream = Upstream.model_validate(
            {
                "id": "u",
                "kind": "http",
                "credential": {"source": "env", "ref": "X", "inject": inject},
            }
        )
        return plan_injection(upstream, Secret("s3cret"))

    def test_an_env_injection_names_the_variable(self) -> None:
        plan = self.plan({"type": "env", "name": "DATABASE_URL"})
        assert plan.env_values() == {"DATABASE_URL": "s3cret"}

    def test_a_header_injection_applies_the_format(self) -> None:
        plan = self.plan({"type": "header", "name": "Authorization", "format": "Bearer {value}"})
        assert plan.header_values() == {"Authorization": "Bearer s3cret"}

    def test_sigv4_says_it_needs_signing_rather_than_faking_a_header(self) -> None:
        """Signing depends on the request body, so it cannot be planned here.
        The adapter refuses rather than forwarding unsigned -- forwarding
        unsigned would mean the agent's own credentials get used after all."""
        plan = self.plan({"type": "sigv4"})
        assert plan.needs_signing is True
        assert plan.headers == {}

    def test_a_plan_can_be_printed_without_leaking(self) -> None:
        plan = self.plan({"type": "header", "name": "Authorization"})
        assert "s3cret" not in repr(plan)
        assert "s3cret" not in str(plan.headers)

    def test_an_injection_without_a_name_is_refused(self) -> None:
        with pytest.raises(ValueError, match="needs a `name`"):
            self.plan({"type": "header"})
