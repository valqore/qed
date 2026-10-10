"""The transparency-log anchor client (SPEC §10.4, §16, invariant §1.7).

Tested against a **real HTTP server** in a thread, not a mocked `httpx`. The
thing worth asserting is what crosses the wire, and a mock tells you what the
code meant to send.

The privacy assertions are the point of this file. The other three publishers
copy the whole checkpoint record, because they copy it into infrastructure the
operator owns. This one posts to a third party, and a checkpoint payload
carries the **previous checkpoint's receipts** -- whose `target` is an
`s3://bucket/key` or a git remote. Sending the record would hand an anchor
service an inventory of the operator's buckets. So there is a test that looks
for each of those strings in the body and fails if it finds one.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, ClassVar

import pytest

from qed.core.schemas import Assurance, EvidenceRecord, EvidenceType
from qed.infra.publishers import build_publishers, publish_checkpoint
from qed.infra.publishers.model import PublicationError
from qed.remote.anchor import DEFAULT_TIMEOUT_S, AnchorPublisher

#: A bucket name and a git remote, as a receipt in a checkpoint payload carries
#: them. If either reaches the wire, the privacy test fails.
SECRET_BUCKET = "s3://acme-internal-qed-anchors/qed-checkpoint-0000000001.json"
SECRET_REMOTE = "git@github.com:acme-finance/qed-anchors.git"


def checkpoint(seq: int = 7) -> EvidenceRecord:
    """A checkpoint record whose payload carries the previous receipts.

    Exactly as SPEC §10.4 says it must: "the **next** checkpoint's payload
    includes the previous checkpoint's receipts". Which is why this publisher
    cannot send the payload.
    """
    return EvidenceRecord(
        seq=seq,
        ts=datetime(2026, 10, 10, 12, 0, tzinfo=UTC),
        type=EvidenceType.checkpoint,
        assurance=Assurance.kernel,
        payload_hash="f" * 64,
        payload={
            "from_seq": 0,
            "to_seq": seq - 1,
            "merkle_root": "a" * 64,
            "published_to": [
                {"publisher": "s3-object-lock", "target": SECRET_BUCKET, "ok": True},
                {"publisher": "git-tag", "target": SECRET_REMOTE, "ok": True},
            ],
        },
        prev_hash="b" * 64,
        hash="c" * 64,
        key_id="ed25519:0123456789abcdef",
        sig="signature-value",
    )


class Stub(BaseHTTPRequestHandler):
    """The server stub SPEC §22 week 9 asks for. The log itself is qed-cloud's."""

    received: ClassVar[list[dict[str, Any]]] = []
    headers_seen: ClassVar[list[dict[str, str]]] = []
    status = 201
    reply: ClassVar[dict[str, Any] | str] = {
        "log_index": 4242,
        "tree_size": 9001,
        "signed_timestamp": "2026-10-10T12:00:01Z",
        # Something qed must not keep: a log that echoed a kilobyte would put a
        # kilobyte in the chain for good.
        "motd": "x" * 5000,
    }

    def do_POST(self) -> None:  # BaseHTTPRequestHandler's own naming
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        Stub.received.append(json.loads(raw))
        Stub.headers_seen.append({key.lower(): value for key, value in self.headers.items()})
        body = (
            json.dumps(Stub.reply).encode() if isinstance(Stub.reply, dict) else Stub.reply.encode()
        )
        self.send_response(Stub.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        """Quiet. The suite treats stderr noise as noise."""


@pytest.fixture
def stub() -> Any:
    Stub.received = []
    Stub.headers_seen = []
    Stub.status = 201
    Stub.reply = {
        "log_index": 4242,
        "tree_size": 9001,
        "signed_timestamp": "2026-10-10T12:00:01Z",
        "motd": "x" * 5000,
    }
    server = HTTPServer(("127.0.0.1", 0), Stub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def publisher_for(server: HTTPServer, **kwargs: Any) -> AnchorPublisher:
    host, port = server.server_address[0], server.server_address[1]
    return AnchorPublisher(url=f"http://{host}:{port}", log_id="acme-log", **kwargs)


# --------------------------------------------------------------------------
# What crosses the wire
# --------------------------------------------------------------------------


class TestTheBodyIsNarrow:
    def test_it_carries_only_the_six_values(self) -> None:
        body = AnchorPublisher(url="https://x", log_id="l").body(checkpoint())
        assert set(body) == {"log_id", "seq", "hash", "merkle_root", "key_id", "sig"}

    def test_no_bucket_name_or_git_remote_reaches_it(self) -> None:
        """The invariant this publisher exists to keep (SPEC §1.7: hashes and
        signatures only). A checkpoint payload carries the previous
        checkpoint's receipts, and a receipt names an operator's bucket."""
        rendered = json.dumps(AnchorPublisher(url="https://x", log_id="l").body(checkpoint()))
        assert SECRET_BUCKET not in rendered
        assert SECRET_REMOTE not in rendered
        assert "acme-internal" not in rendered
        assert "github.com" not in rendered

    def test_nothing_from_the_payload_but_the_root(self) -> None:
        """`from_seq`, `to_seq` and `published_to` all stay home. The root is
        the only payload field an auditor needs the log to witness."""
        body = AnchorPublisher(url="https://x", log_id="l").body(checkpoint())
        assert body["merkle_root"] == "a" * 64
        assert "from_seq" not in body
        assert "to_seq" not in body
        assert "published_to" not in body

    def test_the_values_are_ones_the_auditor_already_holds(self) -> None:
        """So the log learns nothing the export does not already say, and the
        auditor can check the log's entry against their own copy."""
        record = checkpoint()
        body = AnchorPublisher(url="https://x", log_id="l").body(record)
        assert body["hash"] == record.hash
        assert body["key_id"] == record.key_id
        assert body["sig"] == record.sig
        assert body["seq"] == record.seq

    def test_the_log_id_is_the_operators_word(self) -> None:
        body = AnchorPublisher(url="https://x", log_id="whatever-they-chose").body(checkpoint())
        assert body["log_id"] == "whatever-they-chose"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


class TestFromConfig:
    def test_a_url_is_required(self) -> None:
        with pytest.raises(PublicationError, match="needs a `url`"):
            AnchorPublisher.from_config({"log_id": "l"})

    def test_http_is_refused(self) -> None:
        """The root is the evidence that the chain was not rewritten; in clear,
        anything on the path can substitute it."""
        with pytest.raises(PublicationError, match="must be https"):
            AnchorPublisher.from_config({"url": "http://anchor.example", "log_id": "l"})

    def test_plain_http_to_loopback_is_allowed(self) -> None:
        """A local relay or sidecar is a legitimate deployment -- one process
        holding the log credential and talking https onward -- and the body
        never leaves the machine. Refusing it made operators turn the publisher
        off instead, which is strictly worse than anchoring through a relay."""
        for host in ("127.0.0.1:9000", "localhost:9000", "[::1]:9000"):
            built = AnchorPublisher.from_config({"url": f"http://{host}", "log_id": "l"})
            assert built.url.startswith("http://")

    def test_the_exemption_is_the_literal_host_not_a_name(self) -> None:
        """Otherwise a DNS name pointing at 127.0.0.1 -- or one that merely
        contains the word -- would resolve its way through the guard."""
        for url in (
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://notlocalhost",
        ):
            with pytest.raises(PublicationError, match="must be https"):
                AnchorPublisher.from_config({"url": url, "log_id": "l"})

    def test_a_log_id_is_required(self) -> None:
        """No default on purpose: `instance_id` names a company and an
        environment, and deriving one from the signing key would move an
        instance's entries at the next rotation."""
        with pytest.raises(PublicationError, match="needs a `log_id`"):
            AnchorPublisher.from_config({"url": "https://anchor.example"})

    def test_a_token_in_the_config_file_is_refused(self) -> None:
        """SPEC §16: secrets are never in `qed.yaml`, only env names."""
        with pytest.raises(PublicationError, match="environment variable"):
            AnchorPublisher.from_config(
                {"url": "https://anchor.example", "log_id": "l", "token": "shhh"}
            )

    def test_it_builds_from_the_publisher_list(self) -> None:
        built = build_publishers(
            [{"type": "qed-anchor", "url": "https://anchor.example", "log_id": "acme"}]
        )
        assert [item.kind for item in built] == ["qed-anchor"]

    def test_the_default_timeout_is_short(self) -> None:
        """It runs inside the maintenance tick that also drains the outbox. A
        log that has gone away must cost one checkpoint's latency, not the
        chain's progress -- and a failed receipt is durable, so giving up
        quickly loses nothing."""
        assert DEFAULT_TIMEOUT_S <= 10

    def test_describe_carries_no_credential(self) -> None:
        line = AnchorPublisher.from_config(
            {"url": "https://anchor.example", "log_id": "acme", "token_env": "QED_ANCHOR_TOKEN"}
        ).describe()
        assert "QED_ANCHOR_TOKEN" in line, "the env *name* is useful to an operator"
        assert "Bearer" not in line
        assert "shhh" not in line


# --------------------------------------------------------------------------
# Against a real server
# --------------------------------------------------------------------------


class TestAgainstTheStub:
    def test_it_posts_and_returns_an_ok_receipt(self, stub: HTTPServer) -> None:
        receipt = publisher_for(stub).publish(checkpoint())
        assert receipt.ok, receipt.error
        assert receipt.publisher == "qed-anchor"
        assert receipt.target.endswith("/v1/anchors")
        assert len(Stub.received) == 1

    def test_the_server_sees_exactly_the_narrow_body(self, stub: HTTPServer) -> None:
        publisher_for(stub).publish(checkpoint())
        assert set(Stub.received[0]) == {
            "log_id",
            "seq",
            "hash",
            "merkle_root",
            "key_id",
            "sig",
        }
        assert SECRET_BUCKET not in json.dumps(Stub.received[0])

    def test_the_receipt_keeps_the_logs_attestation(self, stub: HTTPServer) -> None:
        receipt = publisher_for(stub).publish(checkpoint())
        assert receipt.proof["log_index"] == 4242
        assert receipt.proof["tree_size"] == 9001
        assert receipt.proof["status"] == 201

    def test_it_does_not_keep_whatever_the_log_felt_like_sending(self, stub: HTTPServer) -> None:
        """A receipt lands in the chain, which is immutable. A log answering
        with a kilobyte would put a kilobyte there for good."""
        receipt = publisher_for(stub).publish(checkpoint())
        assert "motd" not in receipt.proof
        assert len(json.dumps(receipt.as_payload())) < 1000

    def test_a_token_is_sent_as_a_bearer_header(
        self, stub: HTTPServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QED_TEST_ANCHOR_TOKEN", "t0ken")
        publisher_for(stub, token_env="QED_TEST_ANCHOR_TOKEN").publish(checkpoint())
        assert Stub.headers_seen[0]["authorization"] == "Bearer t0ken"

    def test_a_token_is_never_in_the_body(
        self, stub: HTTPServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QED_TEST_ANCHOR_TOKEN", "t0ken")
        publisher_for(stub, token_env="QED_TEST_ANCHOR_TOKEN").publish(checkpoint())
        assert "t0ken" not in json.dumps(Stub.received[0])

    def test_an_empty_token_env_sends_nothing_at_all(
        self, stub: HTTPServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The log would refuse it anyway, and a request that was going to fail
        is better not made: it is one fewer thing in somebody's access log."""
        monkeypatch.delenv("QED_TEST_ANCHOR_TOKEN", raising=False)
        receipt = publisher_for(stub, token_env="QED_TEST_ANCHOR_TOKEN").publish(checkpoint())
        assert not receipt.ok
        assert "Nothing was sent" in receipt.error
        assert Stub.received == []

    def test_an_error_status_is_a_failed_receipt_not_an_exception(self, stub: HTTPServer) -> None:
        """SPEC §10.4: a failed publication never stops the chain."""
        Stub.status = 503
        Stub.reply = "the log is down for maintenance"
        receipt = publisher_for(stub).publish(checkpoint())
        assert not receipt.ok
        assert "503" in receipt.error
        assert "maintenance" in receipt.error

    def test_a_vast_error_body_is_truncated(self, stub: HTTPServer) -> None:
        Stub.status = 500
        Stub.reply = "<html>" + "e" * 20000 + "</html>"
        receipt = publisher_for(stub).publish(checkpoint())
        assert not receipt.ok
        assert len(receipt.error) < 400

    def test_a_log_that_is_not_there_is_a_failed_receipt(self) -> None:
        """Nothing is listening on this port."""
        publisher = AnchorPublisher(url="http://127.0.0.1:1", log_id="acme", timeout=2.0)
        receipt = publisher.publish(checkpoint())
        assert not receipt.ok
        assert "could not reach the anchor log" in receipt.error

    def test_a_non_json_answer_still_gives_a_receipt(self, stub: HTTPServer) -> None:
        Stub.reply = "OK"
        receipt = publisher_for(stub).publish(checkpoint())
        assert receipt.ok
        assert receipt.proof == {"status": 201}

    def test_a_failure_does_not_stop_the_other_publishers(
        self, tmp_path: Any, stub: HTTPServer
    ) -> None:
        """Two anchors are configured because one of them working is useful."""
        from qed.infra.publishers.file import FilePublisher

        Stub.status = 500
        Stub.reply = "no"
        local = FilePublisher.from_config({"path": str(tmp_path / "anchors")})
        receipts = publish_checkpoint([publisher_for(stub), local], checkpoint())
        assert [item.ok for item in receipts] == [False, True]

    def test_the_receipt_round_trips_into_a_payload(self, stub: HTTPServer) -> None:
        """A receipt goes into the next checkpoint's payload, which is hashed
        and signed -- so it has to be JSON-serialisable with no surprises."""
        receipt = publisher_for(stub).publish(checkpoint())
        document = receipt.as_payload()
        assert json.loads(json.dumps(document))["ok"] is True
        assert "proof" in document


class TestItIsOptIn:
    def test_no_anchor_publisher_means_no_import_of_httpx_at_module_scope(self) -> None:
        """`httpx` is imported inside `publish`, so an instance with no anchor
        configured pays nothing for it -- the same discipline the S3 publisher
        follows with boto3."""
        import inspect

        import qed.remote.anchor as module

        before_publish = inspect.getsource(module).split("    def publish", 1)[0]
        assert "import httpx" not in before_publish

    def test_an_instance_with_no_publishers_sends_nothing(self) -> None:
        assert build_publishers([]) == []
        assert publish_checkpoint([], checkpoint()) == []

    def test_the_environment_is_not_read_at_construction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Building a publisher must not require the token to exist: config
        loads at startup and a secret may arrive later."""
        monkeypatch.delenv("QED_TEST_ANCHOR_TOKEN", raising=False)
        built = AnchorPublisher.from_config(
            {
                "url": "https://anchor.example",
                "log_id": "acme",
                "token_env": "QED_TEST_ANCHOR_TOKEN",
            }
        )
        assert built.token_env == "QED_TEST_ANCHOR_TOKEN"
        assert "QED_TEST_ANCHOR_TOKEN" not in os.environ
