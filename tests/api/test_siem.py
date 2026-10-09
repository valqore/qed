"""Shipping OCSF events (SPEC §18, `docs/siem.md`).

`test_ocsf.py` covers the mapping. This covers the shipping, which has exactly
one hard requirement: **a SIEM must never be able to slow down or fail a
decision.** The chain is the record and an event is a copy, so every way this
can go wrong — a dead endpoint, a slow one, a full queue, a serialisation
failure — ends in a counter rather than an exception.

The second requirement is that a gap is visible. A webhook that has been down
for an hour has lost an hour of events, and the operator needs to know that,
which `dropped` says and an infinite retry queue does not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from qed.config import SiemConfig, load_config
from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType, utcnow
from qed.infra.siem import QUEUE_MAX, SiemShipper


def record(seq: int = 1, type_: EvidenceType = EvidenceType.proposal) -> EvidenceRecord:
    return EvidenceRecord(
        seq=seq,
        ts=utcnow(),
        type=type_,
        assurance=Assurance.kernel,
        payload={"n": seq},
        payload_hash="b" * 64,
        prev_hash="c" * 64,
        hash=f"{seq:064x}",
        key_id="ed25519:0123456789abcdef",
        sig="s" * 86,
    )


class Spy:
    """A stand-in for the POST. Records bodies, or fails on demand."""

    def __init__(self, *, status: int = 200, raises: Exception | None = None) -> None:
        self.status = status
        self.raises = raises
        self.bodies: list[dict[str, object]] = []

    def __call__(self, url: str, body: bytes, timeout: float) -> int:
        if self.raises is not None:
            raise self.raises
        self.bodies.append(json.loads(body))
        return self.status


def shipper(spy: Spy | None = None, **kwargs: object) -> SiemShipper:
    return SiemShipper(
        instance_id="qed-test",
        webhook="https://siem.example/hec",
        post=spy,  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def drain(ship: SiemShipper) -> None:
    """Run the worker's drain synchronously, so a test does not sleep."""
    ship._drain()


# --------------------------------------------------------------------------
# It never gets in the way
# --------------------------------------------------------------------------


class TestItCannotFailADecision:
    def test_an_unreachable_endpoint_is_counted_not_raised(self) -> None:
        spy = Spy(raises=OSError("connection refused"))
        ship = shipper(spy)
        ship.send(record())
        drain(ship)
        assert ship.stats.failed == 1
        assert ship.stats.sent == 0

    def test_a_non_2xx_answer_is_counted_not_raised(self) -> None:
        ship = shipper(Spy(status=503))
        ship.send(record())
        drain(ship)
        assert ship.stats.failed == 1

    def test_send_returns_immediately(self) -> None:
        """It appends to a deque. Nothing about the endpoint is consulted on
        the request path."""
        spy = Spy(raises=RuntimeError("would have blocked"))
        ship = shipper(spy)
        ship.send(record())  # no exception, nothing posted yet
        assert ship.stats.failed == 0

    def test_nothing_happens_when_no_siem_is_configured(self) -> None:
        ship = SiemShipper(instance_id="qed-test")
        assert ship.active is False
        ship.send(record())
        ship.start()  # a no-op
        assert ship.stats == ship.stats  # nothing raised is the assertion

    def test_a_2xx_is_counted_as_sent(self) -> None:
        spy = Spy()
        ship = shipper(spy)
        ship.send(record())
        drain(ship)
        assert ship.stats.sent == 1
        assert spy.bodies[0]["class_name"] == "API Activity"


class TestTheQueue:
    def test_it_is_bounded(self) -> None:
        """An unbounded queue in front of a dead webhook is a memory leak with
        a plausible excuse."""
        ship = shipper(Spy(raises=OSError("down")))
        for seq in range(QUEUE_MAX + 50):
            ship.send(record(seq))
        assert len(ship._queue) == QUEUE_MAX

    def test_the_oldest_are_dropped(self) -> None:
        """Dropping the newest would mean a burst hid itself. Dropping the
        oldest means the queue holds what is happening now, which is what
        somebody reading a SIEM during an incident wants."""
        ship = shipper(Spy(raises=OSError("down")))
        for seq in range(QUEUE_MAX + 10):
            ship.send(record(seq))
        first = ship._queue[0]
        assert first["unmapped"]["qed_seq"] == 10  # type: ignore[index]

    def test_drops_are_counted(self) -> None:
        """The number that matters: it is the gap in somebody's SIEM."""
        ship = shipper(Spy(raises=OSError("down")))
        for seq in range(QUEUE_MAX + 7):
            ship.send(record(seq))
        assert ship.stats.dropped == 7

    def test_a_drained_queue_is_empty(self) -> None:
        ship = shipper(Spy())
        for seq in range(5):
            ship.send(record(seq))
        drain(ship)
        assert not ship._queue
        assert ship.stats.sent == 5


class TestStdout:
    def test_one_json_object_per_line(self, capsys: pytest.CaptureFixture[str]) -> None:
        """What every log collector reads, and what `docker logs | jq` reads."""
        ship = SiemShipper(instance_id="qed-test", to_stdout=True)
        ship.send(record(1))
        ship.send(record(2))
        drain(ship)
        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert len(lines) == 2
        assert [json.loads(line)["unmapped"]["qed_seq"] for line in lines] == [1, 2]

    def test_stdout_counts_as_sent_without_a_webhook(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ship = SiemShipper(instance_id="qed-test", to_stdout=True)
        ship.send(record())
        drain(ship)
        capsys.readouterr()
        assert ship.stats.sent == 1


class TestWhatItSaysAboutItself:
    def test_describe_redacts_the_url(self) -> None:
        """A webhook URL often carries a token in its path or query -- Splunk
        HEC and Slack both do -- and `qed doctor` output ends up in a support
        ticket."""
        ship = SiemShipper(
            instance_id="qed-test",
            webhook="https://splunk.example:8088/services/collector?token=SECRET-TOKEN",
        )
        described = ship.describe()
        assert "SECRET-TOKEN" not in described
        assert "collector" not in described
        assert "splunk.example:8088" in described

    def test_describe_says_when_nothing_is_configured(self) -> None:
        assert SiemShipper(instance_id="x").describe() == "siem: not configured"

    def test_the_stats_are_json_shaped(self) -> None:
        ship = shipper(Spy())
        assert set(ship.stats.as_dict()) == {"sent", "failed", "dropped"}


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


class TestTheConfig:
    def test_it_is_off_by_default(self) -> None:
        assert load_config(None).config.observability.siem.active is False

    def test_a_webhook_can_be_named_by_environment_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """For the same reason the database DSN is named rather than inlined: a
        Splunk HEC URL carries its token, and `qed.yaml` is a file somebody
        commits."""
        monkeypatch.setenv("QED_TEST_SIEM", "https://siem.example/x?token=t")
        config = SiemConfig(webhook_env="QED_TEST_SIEM")
        assert config.resolved_webhook() == "https://siem.example/x?token=t"
        assert config.active is True

    def test_an_unset_variable_means_off_rather_than_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty string would be a webhook pointing at nothing, which fails
        on every event."""
        monkeypatch.delenv("QED_TEST_SIEM", raising=False)
        config = SiemConfig(webhook_env="QED_TEST_SIEM")
        assert config.resolved_webhook() is None
        assert config.active is False

    def test_a_literal_webhook_is_accepted(self) -> None:
        config = SiemConfig(webhook="https://siem.internal/ingest")
        assert config.resolved_webhook() == "https://siem.internal/ingest"

    def test_stdout_alone_is_enough_to_be_active(self) -> None:
        assert SiemConfig(stdout=True).active is True

    def test_the_section_is_no_longer_ignored(self, tmp_path: Path) -> None:
        """`observability` was in `UNIMPLEMENTED_SECTIONS`, which means a
        config naming it was silently dropped."""
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump({"observability": {"siem": {"stdout": True}}}), encoding="utf-8"
        )
        loaded = load_config(config)
        assert "observability" not in loaded.ignored_sections
        assert loaded.config.observability.siem.stdout is True


# --------------------------------------------------------------------------
# End to end, through the API
# --------------------------------------------------------------------------


class TestThroughTheApi:
    def test_a_decision_ships_its_records(
        self,
        api_dir: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from qed.api.app import create_app
        from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV, Signer
        from tests.conftest import BASE_PROPOSAL

        monkeypatch.setenv(SECRET_ENV, SECRET)
        config = tmp_path / "qed.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "instance_id": "qed-siem",
                    "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}],
                    "observability": {"siem": {"stdout": True}},
                }
            ),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            assert Signer(client).post("/v1/proposals", BASE_PROPOSAL).status_code == 200

        lines = [
            json.loads(line)
            for line in capsys.readouterr().out.splitlines()
            if line.strip().startswith("{")
        ]
        kinds = {entry["unmapped"]["qed_type"]: entry for entry in lines}
        assert "proposal" in kinds
        assert "verdict" in kinds
        assert kinds["verdict"]["class_name"] == "Authorization"
        # The principal reaches the Authorization event, which its own payload
        # does not carry.
        assert kinds["verdict"]["actor"]["user"]["uid"] != "unknown"
        assert kinds["verdict"]["unmapped"]["qed_instance_id"] == "qed-siem"

    def test_no_siem_configured_prints_nothing(
        self, client: TestClient, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from tests.api.conftest import Signer
        from tests.conftest import BASE_PROPOSAL

        Signer(client).post("/v1/proposals", BASE_PROPOSAL)
        assert "class_name" not in capsys.readouterr().out
