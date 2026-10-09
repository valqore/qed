"""`qed.sdk` (SPEC §12.4), against the real app.

The transport is a `TestClient`, so the request travels the whole path: signed
by the SDK, verified by the API's adapter auth, decided by the kernel, written
to the chain. What is faked is the socket, not the signature or the policy.

That matters because the SDK's one job is to be a correct client of an
interface it does not own. A mocked server would make every test here agree
with whatever the SDK believed.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qed.api.app import create_app
from qed.core.schemas import Enforcement
from qed.infra.keys.file import init_keys
from qed.infra.storage.sqlite import SqliteStore
from qed.sdk import (
    Qed,
    QedApprovalPending,
    QedBlocked,
    QedError,
    QedUnavailable,
    guard,
)
from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV

HUMAN = "ali@example.com"


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    return directory


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(SECRET_ENV, SECRET)
    path = tmp_path / "qed.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "instance_id": "qed-local",
                "mode": "enforce",
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "sdk"}],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def app(qed_dir: Path, config: Path) -> FastAPI:
    return create_app(directory=qed_dir, config_path=config)


@pytest.fixture
def transport(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as started:
        yield started


@pytest.fixture
def qed(transport: TestClient) -> Iterator[Qed]:
    """A client whose httpx session is the TestClient's own.

    `TestClient` *is* an `httpx.Client`, so handing it over is enough: the SDK
    signs and sends exactly as it would over a socket.
    """
    client = Qed(
        url="http://testserver",
        adapter_id=ADAPTER_ID,
        adapter_secret=SECRET,
        environment="prod",
        human=HUMAN,
        client=transport,
    )
    yield client


def chain(qed_dir: Path, type_: str) -> list[dict[str, Any]]:
    with SqliteStore(qed_dir / "qed.db") as store:
        return [
            record.payload or {} for record in store.iter_evidence() if record.type.value == type_
        ]


# --------------------------------------------------------------------------
# Construction, which is where most mistakes are made
# --------------------------------------------------------------------------


class TestItRefusesToBeMisconfigured:
    def test_without_a_url(self) -> None:
        with pytest.raises(QedError, match="no QED url"):
            Qed(url="", adapter_id="a", adapter_secret="s", human=HUMAN)

    def test_the_url_error_explains_why_there_is_no_local_mode(self) -> None:
        """An SDK that decided locally would need the evidence signing key in
        every application process, which is a signing key in a container
        image."""
        with pytest.raises(QedError, match="signing key in every application process"):
            Qed(url="", adapter_id="a", adapter_secret="s", human=HUMAN)

    def test_without_an_identity(self) -> None:
        """Otherwise every call looks refused for a reason no rule explains."""
        with pytest.raises(QedError, match="AG-IDN-007"):
            Qed(url="http://x", adapter_id="a", adapter_secret="s")

    def test_a_mandate_is_an_identity(self) -> None:
        Qed(url="http://x", adapter_id="a", adapter_secret="s", mandate_id="md_1")

    def test_without_an_adapter_credential(self) -> None:
        with pytest.raises(QedError, match="AG-IDN-005"):
            Qed(url="http://x", adapter_id="", adapter_secret="", human=HUMAN)

    def test_from_env_reads_the_spec_12_4_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QED_URL", "http://qed.internal:8710/")
        monkeypatch.setenv("QED_ADAPTER_ID", "adp_env")
        monkeypatch.setenv("QED_ADAPTER_SECRET", "s" * 40)
        monkeypatch.setenv("QED_HUMAN", HUMAN)
        monkeypatch.setenv("QED_ENV", "staging")
        client = Qed.from_env()
        assert client.url == "http://qed.internal:8710"  # trailing slash trimmed
        assert client.adapter_id == "adp_env"
        assert client.environment == "staging"

    def test_an_explicit_argument_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QED_URL", "http://from-env")
        monkeypatch.setenv("QED_ADAPTER_ID", "a")
        monkeypatch.setenv("QED_ADAPTER_SECRET", "s")
        monkeypatch.setenv("QED_HUMAN", HUMAN)
        assert Qed.from_env(url="http://explicit").url == "http://explicit"

    def test_it_is_advisory_unless_told_otherwise(self) -> None:
        """ADR-001 class A: whoever can edit the code can delete the
        decorator."""
        client = Qed(url="http://x", adapter_id="a", adapter_secret="s", human=HUMAN)
        assert client.enforcement is Enforcement.advisory

    def test_it_fails_closed_unlike_the_hook(self) -> None:
        """An application has no human watching, so a QED it cannot reach must
        stop the action rather than wave it through."""
        client = Qed(url="http://x", adapter_id="a", adapter_secret="s", human=HUMAN)
        assert client.fail_mode == "closed"


# --------------------------------------------------------------------------
# propose
# --------------------------------------------------------------------------


class TestPropose:
    def test_a_harmless_action_is_allowed_and_recorded(self, qed: Qed, qed_dir: Path) -> None:
        verdict = qed.propose(name="crm.read_account", target="crm:accounts/42")
        assert verdict.allowed
        assert verdict.decision == "ALLOW"
        assert len(chain(qed_dir, "proposal")) == 1
        assert len(chain(qed_dir, "verdict")) == 1

    def test_the_verdict_exposes_the_rules_without_re_modelling_it(self, qed: Qed) -> None:
        """A second schema here would drift from `qed.core.schemas` the first
        time a field was added, so the raw document is kept."""
        verdict = qed.propose(
            name="postgres.execute_sql",
            target="db:prod/orders",
            params={"sql": "DROP TABLE orders"},
            writes=True,
            deletes=True,
            scope="multi_resource",
        )
        assert verdict.decision in {"BLOCK", "REQUIRE_APPROVAL"}
        assert verdict.rule_ids
        assert verdict.blast_radius > 0
        assert verdict.raw["policy_hash"]

    def test_propose_does_not_raise_on_a_refusal(self, qed: Qed) -> None:
        """So a caller who wants to branch rather than catch can. `check` and
        `guard` are the catching versions."""
        verdict = qed.propose(
            name="postgres.execute_sql",
            target="db:prod/orders",
            params={"sql": "DROP TABLE orders"},
            deletes=True,
        )
        assert not verdict.allowed

    def test_the_explanation_is_one_line_with_the_fix(self, qed: Qed) -> None:
        verdict = qed.propose(
            name="postgres.execute_sql",
            target="db:prod/orders",
            params={"sql": "DROP TABLE orders"},
            deletes=True,
        )
        line = verdict.explain()
        assert line.startswith("[qed ")
        assert "Fix:" in line

    def test_the_intent_reaches_the_chain(self, qed: Qed, qed_dir: Path) -> None:
        qed.propose(name="stripe.refund", target="stripe:charges/ch_1", intent="refund order 123")
        proposal = chain(qed_dir, "proposal")[0]["proposal"]
        assert proposal["context"]["intent"] == "refund order 123"

    def test_an_unknown_adapter_is_refused_by_the_server(self, transport: TestClient) -> None:
        """The SDK signs correctly with the wrong secret, and the API refuses
        it: proof the signature is really being checked rather than the
        transport trusting the caller."""
        client = Qed(
            url="http://testserver",
            adapter_id=ADAPTER_ID,
            adapter_secret="not-the-registered-secret",
            human=HUMAN,
            client=transport,
        )
        with pytest.raises(QedUnavailable, match="401"):
            client.propose(name="x", target="y")


class TestWhenQedCannotBeReached:
    """ "The policy says no" and "I could not find out what the policy says"
    are different facts. An application that treats them the same will
    eventually treat an outage as permission."""

    def unreachable(self, **overrides: Any) -> Qed:
        settings: dict[str, Any] = {
            "url": "http://127.0.0.1:9",  # discard port, nothing listens
            "adapter_id": ADAPTER_ID,
            "adapter_secret": SECRET,
            "human": HUMAN,
            "timeout": 0.25,
        }
        settings.update(overrides)
        return Qed(**settings)

    def test_it_is_a_distinct_exception(self) -> None:
        with pytest.raises(QedUnavailable):
            self.unreachable().propose(name="x", target="y")

    def test_it_is_not_a_block(self) -> None:
        with pytest.raises(QedUnavailable) as caught:
            self.unreachable().propose(name="x", target="y")
        assert not isinstance(caught.value, QedBlocked)

    def test_check_fails_closed_by_default(self) -> None:
        with pytest.raises(QedUnavailable):
            self.unreachable().check(name="x", target="y")

    def test_fail_open_has_to_be_asked_for(self) -> None:
        verdict = self.unreachable(fail_mode="open").check(name="x", target="y")
        assert verdict.allowed
        assert verdict.raw["ungated"] is True


# --------------------------------------------------------------------------
# guard
# --------------------------------------------------------------------------


class TestGuard:
    def test_an_allowed_call_runs_and_returns(self, qed: Qed) -> None:
        @guard(qed, target="crm:accounts/42", writes=False)
        def read_account(account_id: str) -> str:
            return f"account {account_id}"

        assert read_account("42") == "account 42"

    def test_a_blocked_call_never_runs(self, qed: Qed) -> None:
        """The property that matters. A refused action does not happen."""
        ran: list[str] = []

        @guard(qed, target="qed:evidence", deletes=True)
        def delete_the_evidence() -> None:
            ran.append("it ran")

        with pytest.raises((QedBlocked, QedApprovalPending)):
            delete_the_evidence()
        assert ran == []

    def test_the_exception_carries_the_verdict(self, qed: Qed) -> None:
        @guard(qed, target="qed:evidence", deletes=True)
        def delete_the_evidence() -> None:
            pass

        with pytest.raises(QedError) as caught:
            delete_the_evidence()
        assert caught.value.verdict.rule_ids  # type: ignore[attr-defined]

    def test_a_callable_target_describes_the_specific_call(self, qed: Qed, qed_dir: Path) -> None:
        """An approver needs to know *which* account is being deleted."""

        @guard(qed, target=lambda account_id, **_: f"crm:accounts/{account_id}", writes=False)
        def read_account(account_id: str) -> None:
            pass

        read_account("8812")
        proposal = chain(qed_dir, "proposal")[0]["proposal"]
        assert proposal["action"]["target"] == "crm:accounts/8812"

    def test_a_callable_summary_and_intent_reach_the_chain(self, qed: Qed, qed_dir: Path) -> None:
        @guard(
            qed,
            target="crm:accounts/1",
            summary=lambda account_id, **_: f"update account {account_id}",
            intent="quarterly cleanup",
            writes=False,
        )
        def update(account_id: str) -> None:
            pass

        update("1")
        context = chain(qed_dir, "proposal")[0]["proposal"]["context"]
        assert context["summary"] == "update account 1"
        assert context["intent"] == "quarterly cleanup"

    def test_the_action_name_defaults_to_the_function(self, qed: Qed, qed_dir: Path) -> None:
        @guard(qed, target="crm:accounts/1", writes=False)
        def some_specific_operation() -> None:
            pass

        some_specific_operation()
        name = chain(qed_dir, "proposal")[0]["proposal"]["action"]["name"]
        assert "some_specific_operation" in name

    def test_the_arguments_are_what_the_engine_sees(self, qed: Qed, qed_dir: Path) -> None:
        """Positional ones are named rather than dropped: a parameter the
        engine never saw cannot be matched by a rule."""

        @guard(qed, target="crm:accounts/1", writes=False)
        def update(account_id: str, fields: dict[str, str]) -> None:
            pass

        update("1", fields={"tier": "gold"})
        params = chain(qed_dir, "proposal")[0]["proposal"]["action"]["params_redacted"]
        assert params["arg0"] == "1"
        assert params["fields"] == {"tier": "gold"}

    def test_it_preserves_the_functions_identity(self, qed: Qed) -> None:
        @guard(qed, target="x", writes=False)
        def documented() -> None:
            """The docstring."""

        assert documented.__name__ == "documented"
        assert documented.__doc__ == "The docstring."

    def test_writes_defaults_true_because_that_is_the_safe_mistake(self, qed: Qed) -> None:
        """A hint that under-reports the damage routes a destructive call past
        the blast-radius score; one that over-reports asks a person about a
        harmless call. Only one of those is recoverable."""

        @guard(qed, target="crm:accounts/1")
        def anything() -> None:
            pass

        from qed.sdk.client import guard as the_guard

        assert the_guard.__defaults__ is None  # keyword-only, so read the signature
        import inspect

        assert inspect.signature(the_guard).parameters["writes"].default is True


class TestReporting:
    def test_a_successful_call_is_reported(self, qed: Qed, qed_dir: Path) -> None:
        @guard(qed, target="crm:accounts/1", writes=False)
        def fine() -> str:
            return "ok"

        fine()
        results = chain(qed_dir, "execution_result")
        assert len(results) == 1
        assert results[0]["status"] == "ok"
        assert results[0]["duration_ms"] >= 0

    def test_a_failing_call_is_reported_and_the_exception_is_untouched(
        self, qed: Qed, qed_dir: Path
    ) -> None:
        """The application's failure is the application's to handle; QED's job
        was to record it."""

        @guard(qed, target="crm:accounts/1", writes=False)
        def explodes() -> None:
            raise ZeroDivisionError("the application's own bug")

        with pytest.raises(ZeroDivisionError, match="the application's own bug"):
            explodes()
        results = chain(qed_dir, "execution_result")
        assert results[0]["status"] == "error"
        assert "ZeroDivisionError" in results[0]["error"]

    def test_a_report_that_cannot_be_delivered_does_not_replace_the_result(
        self, qed: Qed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The only place the SDK swallows an error. The action already
        happened; raising here would lose the application's own result."""

        @guard(qed, target="crm:accounts/1", writes=False)
        def fine() -> str:
            return "the result the caller wanted"

        original = qed._post

        def fail_only_results(path: str, body: dict[str, Any]) -> dict[str, Any]:
            if path.endswith("/result"):
                # What `_post` raises in production: it converts every
                # httpx.HTTPError into this before it leaves the method.
                raise QedUnavailable("the reporting leg went away")
            return original(path, body)

        monkeypatch.setattr(qed, "_post", fail_only_results)
        assert fine() == "the result the caller wanted"

    def test_an_advisory_result_is_recorded_as_the_agents_testimony(
        self, qed: Qed, qed_dir: Path
    ) -> None:
        """ADR-007.1. The SDK is advisory by default, so its report is `self`
        and the chain says so."""

        @guard(qed, target="crm:accounts/1", writes=False)
        def fine() -> None:
            pass

        fine()
        with SqliteStore(qed_dir / "qed.db") as store:
            assurance = [
                record.assurance.value
                for record in store.iter_evidence()
                if record.type.value == "execution_result"
            ]
        assert assurance == ["self"]


class TestWait:
    def test_a_timeout_is_not_an_approval(self, qed: Qed) -> None:
        """ "Nobody answered in ten minutes" must not be mistaken for a yes by
        a caller checking truthiness."""
        verdict = qed.propose(
            name="postgres.execute_sql",
            target="db:prod/orders",
            params={"sql": "DROP TABLE orders"},
            deletes=True,
        )
        if verdict.decision != "REQUIRE_APPROVAL":
            pytest.skip("the baseline pack blocked this outright; nothing to wait on")
        assert verdict.approval_id
        with pytest.raises(QedUnavailable, match="not the same as somebody approving"):
            qed.wait(verdict.approval_id, timeout=0.2, interval=0.05)
