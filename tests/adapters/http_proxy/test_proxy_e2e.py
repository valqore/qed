"""`qed proxy` end to end (SPEC §12.3).

A real listening socket, a real upstream, and the written chain read back
afterwards. The unit tests prove the proposal is right; these prove the
request actually went where the verdict said it could, that the credential
the upstream received came from QED rather than the agent, and that
``context.enforcement`` in the evidence is the derived answer.

The raw-socket style is on purpose. An HTTP client library would hide the
request line, and the request line is the thing under test: absolute form,
CONNECT, and the exact headers that reach the upstream.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
import yaml

from qed.adapters.http_proxy.proxy import HttpProxyOptions, HttpProxyStats, http_upstreams, serving
from qed.core.broker.model import Upstream, UpstreamSet
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import Enforcement
from qed.infra.keys.file import init_keys
from qed.infra.secrets.broker import CredentialBroker
from qed.infra.secrets.resolver import CredentialResolver
from qed.runtime import open_session
from tests.adapters.http_proxy.upstream import closed_port, echo_server, tcp_echo

pytestmark = pytest.mark.anyio

TIMEOUT = 15


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    return directory


def config_file(tmp_path: Path, mode: str = "shadow") -> Path:
    path = tmp_path / "qed.yaml"
    path.write_text(yaml.safe_dump({"mode": mode}), encoding="utf-8")
    return path


def broker_for(upstreams: list[dict[str, object]], environ: dict[str, str]) -> CredentialBroker:
    return CredentialBroker(
        upstreams=http_upstreams(
            UpstreamSet(upstreams=[Upstream.model_validate(u) for u in upstreams])
        ),
        resolver=CredentialResolver(environ=environ),
    )


OPTIONS = HttpProxyOptions(
    environment="dev",
    human_hash=principal_hash("tester@example.com"),
    enforcement=Enforcement.enforcing,
)


class Harness:
    """A running proxy plus the chain it is writing."""

    def __init__(self, host: str, port: int, stats: HttpProxyStats, qed_dir: Path) -> None:
        self.host = host
        self.port = port
        self.stats = stats
        self.qed_dir = qed_dir

    async def speak(self, request: bytes, then: bytes = b"", *, expect: int | None = None) -> bytes:
        """Send raw bytes to the proxy and read what it says back.

        ``expect`` reads exactly that many bytes instead of reading to EOF,
        which is what a tunnel needs: nothing closes a tunnel on its own, so
        a read to EOF would sit there until the timeout every time.
        """
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            writer.write(request)
            await writer.drain()
            if then:
                # The tunnel case: the payload goes after the 200.
                opened = await reader.readuntil(b"\r\n\r\n")
                if not opened.startswith(b"HTTP/1.1 200"):
                    return opened
                writer.write(then)
                await writer.drain()
            async with asyncio.timeout(TIMEOUT):
                if expect is not None:
                    return await reader.readexactly(expect)
                return await reader.read()
        finally:
            writer.close()

    async def wait_for_results(self, count: int, timeout: float = 5.0) -> list[dict[str, object]]:
        """A tunnel's execution_result is written when the tunnel ends, which
        is after the client has stopped reading rather than before."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self.results()
            if len(found) >= count:
                return found
            await asyncio.sleep(0.02)
        return self.results()

    def chain(self) -> list[dict[str, object]]:
        from qed.infra.storage.sqlite import SqliteStore

        with SqliteStore(self.qed_dir / "qed.db") as store:
            return [
                {"type": record.type.value, "payload": record.payload or {}}
                for record in store.iter_evidence()
            ]

    def enforcement_recorded(self) -> list[str]:
        return [
            str(
                ((record["payload"]) or {})
                .get("proposal", {})
                .get("context", {})
                .get("enforcement")
            )  # type: ignore[union-attr]
            for record in self.chain()
            if record["type"] == "proposal"
        ]

    def record_enforcement(self, type_: str) -> list[str]:
        """``_enforcement`` on the record envelope, not inside the payload."""
        from qed.infra.storage.sqlite import SqliteStore

        with SqliteStore(self.qed_dir / "qed.db") as store:
            return [
                record.enforcement.value if record.enforcement is not None else "none"
                for record in store.iter_evidence()
                if record.type.value == type_
            ]

    def results(self) -> list[dict[str, object]]:
        return [
            record["payload"]  # type: ignore[misc]
            for record in self.chain()
            if record["type"] == "execution_result"
        ]


@pytest.fixture
async def proxy(qed_dir: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    """A proxy with no broker: everything is advisory, as it should be."""
    session = open_session(directory=qed_dir, config_path=config_file(tmp_path))
    stats = HttpProxyStats()
    try:
        async with serving(session=session, options=OPTIONS, port=0, stats=stats) as (
            host,
            port,
            counters,
        ):
            yield Harness(host, port, counters, qed_dir)
    finally:
        session.close()


# --------------------------------------------------------------------------
# Plain HTTP
# --------------------------------------------------------------------------


async def test_a_plain_request_is_forwarded_and_recorded(proxy: Harness) -> None:
    async with echo_server() as (up_host, up_port):
        answer = await proxy.speak(
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n"
            f"Host: {up_host}:{up_port}\r\nUser-Agent: claude-code\r\n\r\n".encode()
        )
    assert answer.startswith(b"HTTP/1.1 200 OK")
    seen = json.loads(answer.split(b"\r\n\r\n", 1)[1])
    # Origin form upstream, Host from the resolved target, and Via added.
    assert seen["request_line"] == "GET /v1/orders HTTP/1.1"
    assert seen["headers"]["user-agent"] == "claude-code"
    assert seen["headers"]["via"] == "1.1 qed"
    assert proxy.stats.requests == 1
    assert proxy.stats.allowed == 1
    assert [p["http_status"] for p in proxy.results()] == [200]


async def test_a_request_body_is_forwarded_whole(proxy: Harness) -> None:
    body = json.dumps({"amount": 1200}).encode()
    async with echo_server() as (up_host, up_port):
        answer = await proxy.speak(
            f"POST http://{up_host}:{up_port}/v1/charges HTTP/1.1\r\n"
            f"Host: {up_host}:{up_port}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
    seen = json.loads(answer.split(b"\r\n\r\n", 1)[1])
    assert json.loads(seen["body"]) == {"amount": 1200}
    assert proxy.stats.bytes_to_upstream == len(body)


async def test_an_unreachable_upstream_is_a_502_and_a_recorded_error(proxy: Harness) -> None:
    """Not a policy decision, and the agent is told which it was."""
    port = await closed_port()
    answer = await proxy.speak(f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert answer.startswith(b"HTTP/1.1 502")
    assert b"could not reach" in answer
    assert [p["status"] for p in proxy.results()] == ["error"]


# --------------------------------------------------------------------------
# Tunnels
# --------------------------------------------------------------------------


async def test_a_tunnel_carries_bytes_both_ways_and_counts_them(proxy: Harness) -> None:
    payload = b"\x16\x03\x01not-really-tls-but-arbitrary-bytes"
    async with tcp_echo() as (up_host, up_port):
        answer = await proxy.speak(
            f"CONNECT {up_host}:{up_port} HTTP/1.1\r\nHost: {up_host}\r\n\r\n".encode(),
            then=payload,
            expect=len(payload),
        )
        results = await proxy.wait_for_results(1)
    assert answer == payload
    assert proxy.stats.tunnels == 1
    assert proxy.stats.bytes_to_upstream == len(payload)
    assert proxy.stats.bytes_to_client == len(payload)
    result = results[0]
    assert result["tunnel"] is True
    assert result["bytes_to_upstream"] == len(payload)
    assert "the request inside the tunnel is encrypted" in str(result["visibility"])


async def test_every_tunnel_is_recorded_as_advisory(proxy: Harness) -> None:
    """QED can refuse to open it, which is real. It cannot see inside it
    or replace the credential, so claiming `enforcing` would put a control in
    the evidence that the transport does not allow."""
    async with tcp_echo() as (up_host, up_port):
        await proxy.speak(
            f"CONNECT {up_host}:{up_port} HTTP/1.1\r\n\r\n".encode(),
            then=b"ping",
            expect=4,
        )
    assert proxy.enforcement_recorded() == ["advisory"]
    assert proxy.stats.advisory == 1


async def test_a_tunnel_to_nowhere_is_refused_before_the_200(proxy: Harness) -> None:
    port = await closed_port()
    answer = await proxy.speak(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
    assert answer.startswith(b"HTTP/1.1 502")
    assert b"Connection Established" not in answer


# --------------------------------------------------------------------------
# Malformed requests
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (b"GET /only-a-path HTTP/1.1\r\n\r\n", b"400"),
        (b"CONNECT example.test HTTP/1.1\r\n\r\n", b"400"),
        (b"GET ftp://files.test/x HTTP/1.1\r\n\r\n", b"501"),
        (b"GET http://a.test/ HTTP/2.0\r\n\r\n", b"505"),
        (b"GET http://a.test/ HTTP/1.1\r\nX-A: 1\r\n continued\r\n\r\n", b"400"),
        (
            b"POST http://a.test/ HTTP/1.1\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n",
            b"400",
        ),
        (b"POST http://a.test/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", b"501"),
    ],
)
async def test_an_ambiguous_request_is_refused_with_a_status(
    proxy: Harness, request_bytes: bytes, status: bytes
) -> None:
    """A proxy that resolves an ambiguity can be made to disagree with its
    upstream about where the request ends, and the smuggled half would be the
    half QED never decided."""
    answer = await proxy.speak(request_bytes)
    assert answer.split(b" ")[1] == status
    assert proxy.stats.malformed >= 1
    assert proxy.stats.allowed == 0


async def test_an_empty_connection_is_not_an_error(proxy: Harness) -> None:
    """A health check or a port scan, not something to answer with a 400."""
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.close()
    await asyncio.sleep(0.05)
    assert proxy.stats.malformed == 0
    assert proxy.stats.errors == 0
    del reader


# --------------------------------------------------------------------------
# The credential
# --------------------------------------------------------------------------


UPSTREAM_CONFIG: list[dict[str, object]] = [
    {
        "id": "orders-api",
        "kind": "http",
        "match": {"host_globs": ["127.0.0.1"]},
        "credential": {
            "source": "env",
            "ref": "ORDERS_API_TOKEN",
            "inject": {
                "type": "header",
                "name": "Authorization",
                "format": "Bearer {value}",
            },
        },
    }
]


async def run_with_broker(
    qed_dir: Path,
    tmp_path: Path,
    upstreams: list[dict[str, object]],
    environ: dict[str, str],
    request: bytes,
    *,
    options: HttpProxyOptions = OPTIONS,
) -> tuple[bytes, Harness]:
    session = open_session(directory=qed_dir, config_path=config_file(tmp_path))
    stats = HttpProxyStats()
    try:
        async with serving(
            session=session,
            options=options,
            port=0,
            stats=stats,
            broker=broker_for(upstreams, environ),
        ) as (host, port, counters):
            harness = Harness(host, port, counters, qed_dir)
            return await harness.speak(request), harness
    finally:
        session.close()


async def test_the_brokered_credential_replaces_the_agents(qed_dir: Path, tmp_path: Path) -> None:
    """Stripping comes before attaching. An adapter that added the broker's
    header while leaving the agent's in place would be an adapter where the
    agent still chooses which credential is used."""
    async with echo_server() as (up_host, up_port):
        answer, harness = await run_with_broker(
            qed_dir,
            tmp_path,
            UPSTREAM_CONFIG,
            {"ORDERS_API_TOKEN": "from-the-qed"},
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n"
            f"Authorization: Bearer the-agents-own-token\r\n\r\n".encode(),
        )
    seen = json.loads(answer.split(b"\r\n\r\n", 1)[1])
    assert seen["headers"]["authorization"] == "Bearer from-the-qed"
    assert "the-agents-own-token" not in json.dumps(seen)
    assert harness.stats.stripped == ["Authorization"]
    assert harness.enforcement_recorded() == ["enforcing"]


async def test_a_capitalised_header_does_not_get_past_the_strip(
    qed_dir: Path, tmp_path: Path
) -> None:
    async with echo_server() as (up_host, up_port):
        answer, _ = await run_with_broker(
            qed_dir,
            tmp_path,
            UPSTREAM_CONFIG,
            {"ORDERS_API_TOKEN": "from-the-qed"},
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n"
            f"AUTHORIZATION: Bearer sneaky\r\nX-Api-Key: also-sneaky\r\n\r\n".encode(),
        )
    seen = json.loads(answer.split(b"\r\n\r\n", 1)[1])
    assert "sneaky" not in json.dumps(seen)
    assert seen["headers"]["authorization"] == "Bearer from-the-qed"


async def test_a_missing_credential_is_advisory_and_the_request_still_goes(
    qed_dir: Path, tmp_path: Path
) -> None:
    """Failing the request would make an unset environment variable look like a
    policy decision, and the operator would go looking in the wrong place."""
    async with echo_server() as (up_host, up_port):
        answer, harness = await run_with_broker(
            qed_dir,
            tmp_path,
            UPSTREAM_CONFIG,
            {},
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n\r\n".encode(),
        )
    assert answer.startswith(b"HTTP/1.1 200")
    assert harness.enforcement_recorded() == ["advisory"]
    assert harness.stats.advisory == 1


async def test_an_advisory_flag_overrides_a_held_credential(qed_dir: Path, tmp_path: Path) -> None:
    """The flag is a ceiling. An operator can ask for less than the broker can
    give, never for more."""
    async with echo_server() as (up_host, up_port):
        _, harness = await run_with_broker(
            qed_dir,
            tmp_path,
            UPSTREAM_CONFIG,
            {"ORDERS_API_TOKEN": "x"},
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n\r\n".encode(),
            options=HttpProxyOptions(
                human_hash=principal_hash("tester@example.com"),
                enforcement=Enforcement.advisory,
            ),
        )
    assert harness.enforcement_recorded() == ["advisory"]


async def test_the_credential_never_reaches_the_chain(qed_dir: Path, tmp_path: Path) -> None:
    secret = "tok-hunter2-do-not-log"
    async with echo_server() as (up_host, up_port):
        _, harness = await run_with_broker(
            qed_dir,
            tmp_path,
            UPSTREAM_CONFIG,
            {"ORDERS_API_TOKEN": secret},
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n\r\n".encode(),
        )
    blob = json.dumps(harness.chain())
    assert secret not in blob
    assert "hunter2" not in blob
    assert "orders-api" in blob  # the upstream id is recorded; the value is not


async def test_sigv4_is_refused_rather_than_forwarded_unsigned(
    qed_dir: Path, tmp_path: Path
) -> None:
    """The signature covers the request body, so it cannot be planned ahead.
    Forwarding unsigned would mean the agent's own credentials get used after
    all, which is the one outcome the broker exists to prevent."""
    config: list[dict[str, object]] = [
        {
            "id": "aws-prod",
            "kind": "http",
            "match": {"host_globs": ["127.0.0.1"]},
            "credential": {"source": "env", "ref": "AWS_KEY", "inject": {"type": "sigv4"}},
        }
    ]
    async with echo_server() as (up_host, up_port):
        answer, harness = await run_with_broker(
            qed_dir,
            tmp_path,
            config,
            {"AWS_KEY": "AKIAnotreal"},
            f"GET http://{up_host}:{up_port}/ HTTP/1.1\r\n\r\n".encode(),
        )
    assert answer.startswith(b"HTTP/1.1 501")
    assert b"sigv4" in answer
    assert [p["status"] for p in harness.results()] == ["error"]


async def test_an_env_injection_is_reported_as_a_config_error(qed_dir: Path) -> None:
    """An `env` injection means "put it in the child's environment", which an
    HTTP request does not have. Caught at startup, where somebody is still
    reading the output, rather than silently dropped per request."""
    from qed.adapters.http_proxy.proxy import injection_problems

    problems = injection_problems(
        UpstreamSet(
            upstreams=[
                Upstream.model_validate(
                    {
                        "id": "wrong",
                        "kind": "http",
                        "credential": {
                            "source": "env",
                            "ref": "X",
                            "inject": {"type": "env", "name": "DATABASE_URL"},
                        },
                    }
                )
            ]
        )
    )
    assert len(problems) == 1
    assert "does not have" in problems[0]
    del qed_dir


async def test_an_mcp_upstream_is_not_used_for_http(qed_dir: Path) -> None:
    """`match_upstream` does not look at `kind`, so an upstream written for an
    MCP server with a loose match would otherwise be picked up here and the
    proxy would try to put a database URL in an HTTP header."""
    mixed = UpstreamSet(
        upstreams=[
            Upstream.model_validate({"id": "a-db", "kind": "mcp"}),
            Upstream.model_validate({"id": "an-api", "kind": "http"}),
        ]
    )
    assert [u.id for u in http_upstreams(mixed).upstreams] == ["an-api"]
    del qed_dir


# --------------------------------------------------------------------------
# Enforcement
# --------------------------------------------------------------------------


async def test_a_blocked_request_never_reaches_the_upstream(qed_dir: Path, tmp_path: Path) -> None:
    """The metadata service is the sharpest case: one unauthenticated GET to a
    link-local address returns the instance role's keys."""
    path = tmp_path / "qed.yaml"
    path.write_text(yaml.safe_dump({"mode": "enforce"}), encoding="utf-8")
    session = open_session(directory=qed_dir, config_path=path)
    stats = HttpProxyStats()
    try:
        async with serving(session=session, options=OPTIONS, port=0, stats=stats) as (
            host,
            port,
            counters,
        ):
            harness = Harness(host, port, counters, qed_dir)
            answer = await harness.speak(
                b"GET http://169.254.169.254/latest/meta-data/iam/ HTTP/1.1\r\n\r\n"
            )
    finally:
        session.close()
    assert answer.startswith(b"HTTP/1.1 403")
    assert b"AG-DAT-013" in answer
    assert stats.refused == 1
    assert stats.allowed == 0
    # Nothing was forwarded, so there is no execution_result at all.
    assert harness.results() == []


async def test_shadow_mode_forwards_what_it_would_have_blocked(
    qed_dir: Path, tmp_path: Path
) -> None:
    """ADR-003: the verdict is recorded with `mode: shadow` and the request
    goes through, which is what makes "we have been observing since this date"
    a provable statement rather than a claim."""
    policy = tmp_path / "block-everything.yaml"
    policy.write_text(
        yaml.safe_dump(
            [
                {
                    "rule_id": "TEST-HTTP-001",
                    "name": "Block every HTTP action",
                    "severity": "HIGH",
                    "mode": "enforce",
                    "applies_to": {"kinds": ["http"]},
                    "when": {"field": "action.kind", "equals": "http"},
                    "verdict": "BLOCK",
                    "message": "no outbound HTTP in this test",
                }
            ]
        ),
        encoding="utf-8",
    )
    session = open_session(
        directory=qed_dir, config_path=config_file(tmp_path), policy_paths=[policy]
    )
    stats = HttpProxyStats()
    try:
        async with (
            echo_server() as (up_host, up_port),
            serving(session=session, options=OPTIONS, port=0, stats=stats) as (
                host,
                port,
                counters,
            ),
        ):
            harness = Harness(host, port, counters, qed_dir)
            answer = await harness.speak(
                f"GET http://{up_host}:{up_port}/ HTTP/1.1\r\n\r\n".encode()
            )
    finally:
        session.close()
    assert answer.startswith(b"HTTP/1.1 200")
    assert stats.would_block == 1
    assert stats.refused == 0
    assert stats.allowed == 1


# --------------------------------------------------------------------------
# The proposal and its result have to agree
# --------------------------------------------------------------------------


async def test_the_result_records_the_same_enforcement_as_the_proposal(
    proxy: Harness,
) -> None:
    """Found by running `qed proxy` against the real internet rather than
    against a fixture.

    The proposal said `advisory`, correctly -- no upstream was configured.
    Two records later the `execution_result` said `enforcing`, because the
    recording path read the operator's flag instead of the answer that had
    just been derived. One chain, one call, two different claims about
    whether QED was holding the credential.
    """
    async with echo_server() as (up_host, up_port):
        await proxy.speak(f"GET http://{up_host}:{up_port}/ HTTP/1.1\r\n\r\n".encode())
    assert proxy.record_enforcement("proposal") == ["advisory"]
    assert proxy.record_enforcement("execution_result") == ["advisory"]


async def test_an_advisory_result_is_recorded_as_the_agents_own_testimony(
    proxy: Harness,
) -> None:
    """ADR-007.1: an advisory adapter is one the agent could have gone
    around, so `assurance` is `self` and not `adapter`."""
    from qed.infra.storage.sqlite import SqliteStore

    async with echo_server() as (up_host, up_port):
        await proxy.speak(f"GET http://{up_host}:{up_port}/ HTTP/1.1\r\n\r\n".encode())
    with SqliteStore(proxy.qed_dir / "qed.db") as store:
        assurance = [
            record.assurance.value
            for record in store.iter_evidence()
            if record.type.value == "execution_result"
        ]
    assert assurance == ["self"]


async def test_a_held_credential_makes_the_result_say_enforcing(
    qed_dir: Path, tmp_path: Path
) -> None:
    async with echo_server() as (up_host, up_port):
        _, harness = await run_with_broker(
            qed_dir,
            tmp_path,
            UPSTREAM_CONFIG,
            {"ORDERS_API_TOKEN": "held"},
            f"GET http://{up_host}:{up_port}/v1/orders HTTP/1.1\r\n\r\n".encode(),
        )
    assert harness.record_enforcement("proposal") == ["enforcing"]
    assert harness.record_enforcement("execution_result") == ["enforcing"]


async def test_a_tunnel_result_says_advisory_even_with_a_credential_held(
    qed_dir: Path, tmp_path: Path
) -> None:
    """A tunnel cannot be enforcing however well the broker is configured,
    and the result has to agree with the proposal about that."""
    async with tcp_echo() as (up_host, up_port):
        session = open_session(directory=qed_dir, config_path=config_file(tmp_path))
        stats = HttpProxyStats()
        try:
            async with serving(
                session=session,
                options=OPTIONS,
                port=0,
                stats=stats,
                broker=broker_for(UPSTREAM_CONFIG, {"ORDERS_API_TOKEN": "held"}),
            ) as (host, port, counters):
                harness = Harness(host, port, counters, qed_dir)
                await harness.speak(
                    f"CONNECT {up_host}:{up_port} HTTP/1.1\r\n\r\n".encode(),
                    then=b"ping",
                    expect=4,
                )
                await harness.wait_for_results(1)
        finally:
            session.close()
    assert harness.record_enforcement("proposal") == ["advisory"]
    assert harness.record_enforcement("execution_result") == ["advisory"]


async def test_an_advisory_proxy_does_not_strip_the_agents_own_credential(
    proxy: Harness,
) -> None:
    """Removing it would break the call and put nothing in its place, which is
    worse than letting a credential QED did not choose reach a host the
    agent was always going to reach."""
    async with echo_server() as (up_host, up_port):
        answer = await proxy.speak(
            f"GET http://{up_host}:{up_port}/ HTTP/1.1\r\n"
            f"Authorization: Bearer the-agents-own\r\n\r\n".encode()
        )
    seen = json.loads(answer.split(b"\r\n\r\n", 1)[1])
    assert seen["headers"]["authorization"] == "Bearer the-agents-own"
    assert proxy.stats.stripped == []
