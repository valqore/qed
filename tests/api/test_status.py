"""``GET /v1/status`` (SPEC §19 badge, ADR-0007).

The interesting assertion is the last class. SPEC §19 asks the badge to show
"verify ok", and this endpoint deliberately refuses to answer that: a verdict
an instance delivers about its own chain is worth almost nothing, and a green
tick served by the thing being audited invites exactly the reading the
architecture exists to prevent.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from qed.core.schemas import Assurance, EvidenceType
from qed.infra.chain_writer import ChainWriter
from qed.infra.keys.file import load_signer
from qed.infra.storage.sqlite import SqliteStore
from tests.api.conftest import Signer


class TestWhatItReports:
    def test_it_needs_a_credential(self, client: TestClient) -> None:
        assert client.get("/v1/status").status_code == 401

    def test_it_reports_the_chain_and_the_policy(self, client: TestClient) -> None:
        payload = Signer(client).get("/v1/status").json()
        assert payload["instance_id"]
        assert payload["key_id"].startswith("ed25519:")
        assert payload["rules_active"] >= 1
        assert payload["mode"] in {"shadow", "enforce"}
        assert payload["policy_hash"]

    def test_it_agrees_with_the_cli(self, client: TestClient, api_dir: Path) -> None:
        """Same function behind both, so the page and `qed status` cannot come
        to different conclusions about one instance."""
        from qed.runtime import chain_status, open_session

        over_http = Signer(client).get("/v1/status").json()
        session = open_session(directory=api_dir, strict_policy=False)
        try:
            from_cli = chain_status(session)
        finally:
            session.close()
        for field in ("instance_id", "key_id", "policy_hash", "rules_active", "mode"):
            assert over_http[field] == from_cli[field]

    def test_it_names_the_caller(self, client: TestClient) -> None:
        assert Signer(client).get("/v1/status").json()["caller"].startswith("adapter:")


class TestTheCheckpointAge:
    def test_there_is_no_age_before_the_first_checkpoint(self, client: TestClient) -> None:
        payload = Signer(client).get("/v1/status").json()
        assert payload["last_checkpoint"] is None
        assert payload["last_checkpoint_age_seconds"] is None

    def test_a_checkpoint_is_dated_from_its_own_record(
        self, client: TestClient, api_dir: Path
    ) -> None:
        """Not from `seq_to`, which is the last record *covered*. The
        checkpoint's own seq comes out of the table."""
        signer = load_signer(api_dir)
        with SqliteStore(api_dir / "qed.db") as store:
            writer = ChainWriter(store, signer, instance_id="qed-local")
            writer.append(
                type_=EvidenceType.admin_action,
                assurance=Assurance.kernel,
                payload={"note": "something to cover"},
            )
            record = writer.checkpoint(force=True)
        assert record is not None

        payload = Signer(client).get("/v1/status").json()
        assert payload["last_checkpoint"]["evidence_seq"] == record.seq
        age = payload["last_checkpoint_age_seconds"]
        assert age is not None
        assert 0 <= age < 120


class TestItDoesNotVouchForItself:
    def test_verified_is_always_empty(self, client: TestClient) -> None:
        """ADR-0007. The field is present and explicitly null, so a page can
        say "not verified here" -- which is true -- rather than show a tick
        that means less than it looks."""
        payload = Signer(client).get("/v1/status").json()
        assert "verified" in payload
        assert payload["verified"] is None

    def test_it_names_the_real_procedure_instead(self, client: TestClient) -> None:
        payload = Signer(client).get("/v1/status").json()
        assert "qed-verify" in payload["verify_with"]

    def test_it_stays_empty_once_there_is_a_checkpoint_to_check(
        self, client: TestClient, api_dir: Path
    ) -> None:
        """The tempting moment to fill it in is when there is a Merkle root
        sitting right there. Still no."""
        signer = load_signer(api_dir)
        with SqliteStore(api_dir / "qed.db") as store:
            ChainWriter(store, signer, instance_id="qed-local").checkpoint(force=True)
        assert Signer(client).get("/v1/status").json()["verified"] is None
