"""Which upstream an action belongs to, and resolving its credential."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gate.core.broker.model import (
    CredentialSpec,
    Enforcement,
    Upstream,
    UpstreamSet,
    describe,
    match_upstream,
)
from gate.infra.secrets.resolver import (
    CredentialResolver,
    SecretNotAvailable,
    SecretResolutionError,
)
from tests.conftest import make_proposal


def upstream(**kwargs: Any) -> Upstream:
    base: dict[str, Any] = {"id": "u1", "kind": "mcp"}
    base.update(kwargs)
    return Upstream.model_validate(base)


GITHUB = upstream(
    id="github",
    match={"mcp_server": "github"},
    credential={
        "source": "env",
        "ref": "GITHUB_TOKEN",
        "inject": {"type": "header", "name": "Authorization", "format": "Bearer {value}"},
    },
)
POSTGRES_PROD = upstream(
    id="postgres-prod",
    match={"mcp_server": "postgres", "environments": ["prod"]},
    credential={
        "source": "env",
        "ref": "DATABASE_URL",
        "inject": {"type": "env", "name": "DATABASE_URL"},
    },
)
AWS = upstream(
    id="aws-prod",
    kind="http",
    match={"host_globs": ["*.amazonaws.com"], "environments": ["prod"]},
    credential={"source": "env", "ref": "AWS_CREDS", "inject": {"type": "sigv4"}},
)


class TestMatching:
    def test_an_mcp_server_matches_by_tool_prefix(self) -> None:
        proposal = make_proposal({"action": {"name": "github.list_issues"}})
        assert match_upstream(proposal, UpstreamSet(upstreams=[GITHUB])) is GITHUB

    def test_a_different_server_does_not_match(self) -> None:
        proposal = make_proposal({"action": {"name": "gitlab.list_issues"}})
        assert match_upstream(proposal, UpstreamSet(upstreams=[GITHUB])) is None

    def test_a_tool_name_with_no_server_matches_nothing(self) -> None:
        proposal = make_proposal({"action": {"name": "list_issues"}})
        assert match_upstream(proposal, UpstreamSet(upstreams=[GITHUB])) is None

    def test_the_environment_constraint_applies(self) -> None:
        dev = make_proposal({"action": {"name": "postgres.execute_sql"}})
        prod = make_proposal(
            {
                "action": {"name": "postgres.execute_sql"},
                "context": {"environment": "prod"},
            }
        )
        pool = UpstreamSet(upstreams=[POSTGRES_PROD])
        assert match_upstream(dev, pool) is None
        assert match_upstream(prod, pool) is POSTGRES_PROD

    def test_a_host_glob_matches_a_url_target(self) -> None:
        proposal = make_proposal(
            {
                "action": {"kind": "http", "target": "https://ec2.eu-west-1.amazonaws.com/"},
                "context": {"environment": "prod"},
            }
        )
        assert match_upstream(proposal, UpstreamSet(upstreams=[AWS])) is AWS

    def test_a_host_glob_does_not_match_a_lookalike(self) -> None:
        """`amazonaws.com.evil.test` is the whole reason host matching is on
        the host and not on the string."""
        proposal = make_proposal(
            {
                "action": {"kind": "http", "target": "https://ec2.amazonaws.com.evil.test/"},
                "context": {"environment": "prod"},
            }
        )
        assert match_upstream(proposal, UpstreamSet(upstreams=[AWS])) is None

    def test_first_match_wins_in_file_order(self) -> None:
        """Not "most specific": specificity between a host glob and an
        environment list is not something anyone can rank, and an order
        nobody can predict is worse than one they can read top to bottom."""
        broad = upstream(id="broad", match={"mcp_server": "postgres"})
        pool = UpstreamSet(upstreams=[broad, POSTGRES_PROD])
        proposal = make_proposal(
            {
                "action": {"name": "postgres.execute_sql"},
                "context": {"environment": "prod"},
            }
        )
        assert match_upstream(proposal, pool) is broad

    def test_an_upstream_with_no_constraints_matches_everything(self) -> None:
        catchall = upstream(id="catchall")
        assert match_upstream(make_proposal(), UpstreamSet(upstreams=[catchall])) is catchall


class TestEnforcementHonesty:
    def test_an_upstream_with_a_credential_can_enforce(self) -> None:
        assert GITHUB.effective_enforcement is Enforcement.enforcing

    def test_an_upstream_without_one_is_advisory_whatever_it_claims(self) -> None:
        """Config that claims more than it can deliver is worse than config
        that admits the gap, because the claim ends up in the evidence."""
        claiming = upstream(id="x", enforcement="enforcing", credential=None)
        assert claiming.effective_enforcement is Enforcement.advisory

    def test_the_posture_description_carries_no_secret(self) -> None:
        rendered = describe(GITHUB)
        assert rendered["ref"] == "GITHUB_TOKEN"
        assert rendered["enforcement"] == "enforcing"
        assert "value" not in rendered


class TestResolution:
    def spec(self, source: str, ref: str) -> CredentialSpec:
        return CredentialSpec.model_validate(
            {"source": source, "ref": ref, "inject": {"type": "env", "name": "X"}}
        )

    def test_an_env_variable_resolves(self) -> None:
        resolver = CredentialResolver(environ={"TOKEN": "abc123"})
        assert resolver.resolve(self.spec("env", "TOKEN")).reveal() == "abc123"

    def test_an_unset_variable_says_which_one(self) -> None:
        resolver = CredentialResolver(environ={})
        with pytest.raises(SecretNotAvailable, match="TOKEN"):
            resolver.resolve(self.spec("env", "TOKEN"))

    def test_an_empty_variable_is_treated_as_a_mistake(self) -> None:
        """Almost always a deployment slip rather than an intentionally empty
        credential, and failing loudly beats injecting nothing."""
        resolver = CredentialResolver(environ={"TOKEN": ""})
        with pytest.raises(SecretNotAvailable, match="empty"):
            resolver.resolve(self.spec("env", "TOKEN"))

    def test_a_file_resolves_and_loses_its_trailing_newline(self, tmp_path: Path) -> None:
        """`echo secret > file` is how every one of these is created, and the
        newline is what the following hour of debugging is about."""
        path = tmp_path / "token"
        path.write_text("abc123\n", encoding="utf-8")
        resolver = CredentialResolver()
        assert resolver.resolve(self.spec("file", str(path))).reveal() == "abc123"

    def test_a_missing_file_names_the_path(self, tmp_path: Path) -> None:
        resolver = CredentialResolver()
        with pytest.raises(SecretNotAvailable, match="nope"):
            resolver.resolve(self.spec("file", str(tmp_path / "nope")))

    def test_a_vault_reference_without_a_client_says_what_to_install(self) -> None:
        resolver = CredentialResolver()
        with pytest.raises(SecretResolutionError, match=r"valqore-gate\[vault\]"):
            resolver.resolve(self.spec("vault", "secret/data/gate/pg#DATABASE_URL"))

    def test_an_error_never_carries_the_value(self, tmp_path: Path) -> None:
        path = tmp_path / "token"
        path.write_text("", encoding="utf-8")
        resolver = CredentialResolver()
        with pytest.raises(SecretNotAvailable) as caught:
            resolver.resolve(self.spec("file", str(path)))
        assert "empty" in str(caught.value)


class TestCache:
    def spec(self) -> CredentialSpec:
        return CredentialSpec.model_validate(
            {"source": "env", "ref": "TOKEN", "inject": {"type": "env", "name": "X"}}
        )

    def test_a_second_read_inside_the_ttl_is_cached(self) -> None:
        environ = {"TOKEN": "first"}
        resolver = CredentialResolver(environ=environ, ttl_seconds=60)
        first = resolver.resolve(self.spec(), now=0.0)
        environ["TOKEN"] = "second"
        assert resolver.resolve(self.spec(), now=10.0).reveal() == first.reveal()

    def test_past_the_ttl_it_reads_again(self) -> None:
        environ = {"TOKEN": "first"}
        resolver = CredentialResolver(environ=environ, ttl_seconds=60)
        resolver.resolve(self.spec(), now=0.0)
        environ["TOKEN"] = "second"
        assert resolver.resolve(self.spec(), now=120.0).reveal() == "second"

    def test_forgetting_makes_the_next_read_fresh(self) -> None:
        """Rotation has to take effect without a restart: a gate handing out
        a credential revoked a minute ago is a gate working against you."""
        environ = {"TOKEN": "first"}
        resolver = CredentialResolver(environ=environ, ttl_seconds=3600)
        resolver.resolve(self.spec(), now=0.0)
        environ["TOKEN"] = "rotated"
        resolver.forget()
        assert resolver.resolve(self.spec(), now=1.0).reveal() == "rotated"

    def test_forgetting_one_leaves_the_others(self) -> None:
        other = CredentialSpec.model_validate(
            {"source": "env", "ref": "OTHER", "inject": {"type": "env", "name": "Y"}}
        )
        environ = {"TOKEN": "a", "OTHER": "b"}
        resolver = CredentialResolver(environ=environ, ttl_seconds=3600)
        resolver.resolve(self.spec(), now=0.0)
        resolver.resolve(other, now=0.0)
        environ.update({"TOKEN": "a2", "OTHER": "b2"})
        resolver.forget(self.spec())
        assert resolver.resolve(self.spec(), now=1.0).reveal() == "a2"
        assert resolver.resolve(other, now=1.0).reveal() == "b"
