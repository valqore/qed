"""The API's rate limits, over real HTTP (SPEC §13).

The arithmetic is in `tests/core/test_ratelimit.py`. What this file asserts is
that it is wired to the right place and answers the right way:

* a **429** with a **`Retry-After` header**, which is the half of SPEC §13 a
  client actually reads -- a number in the JSON body alone would mean every
  client has to parse a problem document to back off correctly;
* **off by default**, because a rate limit on a gate is a kill switch under
  load: an adapter in `fail: closed` that cannot reach a decision treats a 429
  as a refusal, so throttling the kernel stops the agent's work;
* **nothing in the chain**, because recording refusals would let the flood this
  exists to stop fill the evidence instead of the request queue.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qed.api import app_state
from qed.api.app import create_app
from qed.core.ratelimit import BURST_SECONDS
from qed.infra.keys.file import init_keys
from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV, Signer
from tests.conftest import BASE_PROPOSAL, deep_merge


def proposal(index: int) -> dict[str, Any]:
    """One envelope with a fresh id. Ids are single use, so every request in a
    burst needs its own or the second one is a 409 rather than a 429."""
    return {"proposal": deep_merge(BASE_PROPOSAL, {"id": f"01JBRATELIMIT{index:012d}"})}


class Clock:
    """The limiter's clock, frozen and advanced on purpose.

    These tests spend a bucket and assert that the next request is refused.
    The bucket also *refills*, at `rps` per second, so the assertion holds
    only while the burst takes less than `1 / rps` seconds -- half a second at
    `TIGHT_RPS`. Six signed proposals, each an fsync to SQLite, fit in that on
    a developer's machine and did not on a Windows CI runner, where the burst
    refilled a token and the next request came back `200`.

    That is not flakiness to paper over with a wider margin: the margin is a
    wall-clock race in a test whose subject is arithmetic. `enforce_rate_limit`
    has taken a `now` argument since it was written and nothing ever passed
    one, so the HTTP path fell through to `time.monotonic()` and the suite
    inherited the race. This supplies it.

    `qed/api/app_state.py` reads `time` exactly once, for the limiter, so
    replacing the module reference there affects nothing else.
    """

    def __init__(self, now: float = 1_000.0) -> None:
        self._now = now

    def monotonic(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def install_clock(monkeypatch: pytest.MonkeyPatch, *, at: float = 1_000.0) -> Clock:
    monkeypatch.setattr(app_state, "time", Clock(at))
    clock = app_state.time
    assert isinstance(clock, Clock)
    return clock


def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **limits: float) -> FastAPI:
    monkeypatch.setenv(SECRET_ENV, SECRET)
    config = tmp_path / "limited.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "instance_id": "qed-local",
                "mode": "shadow",
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}],
                "api": {"rate_limit": limits},
            }
        ),
        encoding="utf-8",
    )
    directory = tmp_path / "state"
    init_keys(directory)
    return create_app(directory=directory, config_path=config)


class TestOffByDefault:
    def test_the_default_config_does_not_throttle(self, signed: Signer) -> None:
        """A rate limit on a gate is a kill switch under load. The shipped
        numbers are high enough that nothing legitimate reaches them, and the
        test suite would be the first thing to notice otherwise."""
        for index in range(30):
            response = signed.post("/v1/proposals", proposal(index))
            assert response.status_code == 200, response.text

    def test_a_zero_limit_is_off_rather_than_refusing_everything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = configured(tmp_path, monkeypatch, per_adapter_rps=0, per_principal_rps=0)
        with TestClient(app) as client:
            caller = Signer(client)
            for index in range(20):
                assert caller.post("/v1/proposals", proposal(index)).status_code == 200


#: The tight tests configure 2/s and then spend the whole bucket. Written as
#: `rps * BURST_SECONDS` rather than as a number, because the burst factor is a
#: deliberate choice that may be revisited and these tests should state what
#: they depend on rather than quietly encode today's value.
TIGHT_RPS = 2.0
TIGHT_BURST = int(TIGHT_RPS * BURST_SECONDS)


class TestWhenTheLimitIsSpent:
    @pytest.fixture
    def clock(self, monkeypatch: pytest.MonkeyPatch) -> Clock:
        return install_clock(monkeypatch)

    @pytest.fixture
    def tight(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: Clock) -> Any:
        app = configured(tmp_path, monkeypatch, per_adapter_rps=TIGHT_RPS, per_principal_rps=0)
        with TestClient(app) as client:
            yield Signer(client)

    def spend(self, caller: Signer) -> None:
        for index in range(TIGHT_BURST):
            assert caller.post("/v1/proposals", proposal(index)).status_code == 200

    def test_the_burst_is_more_than_one_second(self, tight: Signer) -> None:
        """An agent making a short burst of tool calls is an ordinary agent,
        and on `fail: closed` a 429 is a blocked action. The sustained rate is
        the spec's; only the first burst is free."""
        self.spend(tight)

    def test_the_next_one_is_429(self, tight: Signer) -> None:
        self.spend(tight)
        response = tight.post("/v1/proposals", proposal(99))
        assert response.status_code == 429, response.text

    def test_it_carries_a_retry_after_header(self, tight: Signer) -> None:
        """The half of SPEC §13 a client reads. A number in the body alone
        would make every client parse a problem document to back off."""
        self.spend(tight)
        response = tight.post("/v1/proposals", proposal(99))
        assert "retry-after" in {key.lower() for key in response.headers}
        assert float(response.headers["retry-after"]) > 0

    def test_the_problem_document_names_the_scope_and_the_setting(self, tight: Signer) -> None:
        self.spend(tight)
        body = tight.post("/v1/proposals", proposal(99)).json()
        assert body["status"] == 429
        assert body["scope"] == "adapter"
        assert "api.rate_limit" in body["detail"]
        assert "replica count" in body["detail"], "the per-process caveat belongs here"

    def test_it_is_a_problem_document_like_every_other_refusal(self, tight: Signer) -> None:
        self.spend(tight)
        response = tight.post("/v1/proposals", proposal(99))
        assert response.headers["content-type"].startswith("application/problem+json")

    def test_nothing_was_written_to_the_chain(self, tight: Signer) -> None:
        """The attack this stops is a caller flooding the API. Recording every
        refusal would let them flood the evidence chain instead -- the one
        thing that has to stay readable."""
        self.spend(tight)
        before = tight.get("/v1/evidence?from=0&to=999").text
        tight.post("/v1/proposals", proposal(99))
        tight.post("/v1/proposals", proposal(98))
        assert tight.get("/v1/evidence?from=0&to=999").text == before

    def test_a_throttled_proposal_id_can_be_submitted_later(
        self, tight: Signer, clock: Clock
    ) -> None:
        """A 429 must not burn the proposal id. Ids are single use, and a
        caller whose request was refused for load has not spent theirs --
        otherwise backing off and retrying would get a 409.

        The wait is a clock advance and not a `sleep`: the point is that the
        bucket refilled, not that six tenths of a second of wall time passed,
        and a suite that sleeps to wait for arithmetic pays for it on every
        run.
        """
        self.spend(tight)
        assert tight.post("/v1/proposals", proposal(50)).status_code == 429
        clock.advance(1.0 / TIGHT_RPS)
        assert tight.post("/v1/proposals", proposal(50)).status_code == 200


class TestTheLimitIsNotAuthentication:
    def test_an_unsigned_request_is_still_401_not_429(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Authentication comes first, and must: a 429 for an unauthenticated
        caller would tell them an adapter id exists, and would let an anonymous
        flood spend a real adapter's allowance."""
        app = configured(tmp_path, monkeypatch, per_adapter_rps=1, per_principal_rps=0)
        with TestClient(app) as client:
            body = json.dumps(proposal(0)).encode()
            for _ in range(5):
                response = client.post(
                    "/v1/proposals", content=body, headers={"content-type": "application/json"}
                )
                assert response.status_code == 401, response.text


class TestItIsReported:
    def test_status_carries_the_limits(self, signed: Signer) -> None:
        body = signed.get("/v1/status").json()
        assert "rate_limit" in body
        assert body["rate_limit"]["scope"] == ("this process only; multiply by your replica count")

    def test_the_refusals_are_counted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Frozen for the same reason as the class above: at 1/s the bucket
        holds three and this sends four, so one second anywhere in those four
        requests refills the token that makes the count zero."""
        install_clock(monkeypatch)
        app = configured(tmp_path, monkeypatch, per_adapter_rps=1, per_principal_rps=0)
        with TestClient(app) as client:
            caller = Signer(client)
            for index in range(int(BURST_SECONDS) + 1):
                caller.post("/v1/proposals", proposal(index))
            body = caller.get("/v1/status").json()
            assert body["rate_limit"]["refused"] == {"adapter": 1}
