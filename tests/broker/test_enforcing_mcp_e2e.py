"""`qed mcp` with a broker, end to end (SPEC §7.2).

The unit tests prove the broker derives the right answer. This one proves the
answer reaches the chain: a real `qed mcp` subprocess, a real upstream MCP
server, a real tool call, and then the written evidence is read back to see
what `context.enforcement` actually says.

That distinction matters here more than usual. The thing being tested is a
claim recorded in evidence, and a claim is only worth what the record says.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
import yaml
from mcp import ClientSession, StdioServerParameters, stdio_client

from qed.infra.keys.file import init_keys

REPO = Path(__file__).resolve().parents[2]
UPSTREAM = REPO / "tests" / "adapters" / "upstream_server.py"
TIMEOUT = 30

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def write_config(tmp_path: Path, *, with_upstreams: bool, ref: str = "BROKER_TEST_URL") -> Path:
    config: dict[str, object] = {"mode": "shadow"}
    if with_upstreams:
        (tmp_path / "upstreams.yaml").write_text(
            yaml.safe_dump(
                {
                    "upstreams": [
                        {
                            "id": "orders",
                            "kind": "mcp",
                            "match": {"mcp_server": "orders"},
                            "credential": {
                                "source": "env",
                                "ref": ref,
                                "inject": {"type": "env", "name": "DATABASE_URL"},
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        config["broker"] = {"upstreams_file": "upstreams.yaml"}
    path = tmp_path / "qed.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def params(qed_dir: Path, config: Path) -> StdioServerParameters:
    # The MCP SDK gives a child a *safe subset* of the environment when `env`
    # is None, not the parent's. A test that relied on inheritance would set
    # the variable and watch the subprocess not see it -- which is how this
    # was found.
    return StdioServerParameters(
        env=dict(os.environ),
        command=sys.executable,
        args=[
            "-c",
            "from qed.cli import main; main()",
            "mcp",
            "--dir",
            str(qed_dir),
            "--config",
            str(config),
            "--env",
            "prod",
            "--server-name",
            "orders",
            "--human",
            "tester@example.com",
            "--target-template",
            "db:{env}/{args.table}",
            "--",
            sys.executable,
            str(UPSTREAM),
        ],
        cwd=str(REPO),
    )


def enforcement_in_chain(qed_dir: Path) -> list[str]:
    """What `context.enforcement` says on every proposal the proxy wrote."""
    from qed.infra.storage.sqlite import SqliteStore

    with SqliteStore(qed_dir / "qed.db") as store:
        return [
            str(
                ((record.payload or {}).get("proposal") or {}).get("context", {}).get("enforcement")
            )
            for record in store.iter_evidence()
            if record.type.value == "proposal"
        ]


async def call_one(qed_dir: Path, config: Path) -> None:
    async with (
        stdio_client(params(qed_dir, config)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        await client.call_tool("list_tables", {})


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    return directory


async def test_a_held_credential_is_recorded_as_enforcing(
    qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BROKER_TEST_URL", "postgres://real/orders")
    config = write_config(tmp_path, with_upstreams=True)
    await call_one(qed_dir, config)
    assert "enforcing" in enforcement_in_chain(qed_dir)


async def test_a_missing_credential_is_recorded_as_advisory(
    qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter was not told to be advisory. It worked it out, because the
    environment variable the config names does not exist -- and the evidence
    says so rather than carrying the claim the flag would have made."""
    monkeypatch.delenv("BROKER_TEST_URL", raising=False)
    config = write_config(tmp_path, with_upstreams=True)
    await call_one(qed_dir, config)
    recorded = enforcement_in_chain(qed_dir)
    assert recorded, "the proxy wrote no proposal"
    assert all(value == "advisory" for value in recorded), recorded


async def test_an_unmatched_server_is_advisory(
    qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BROKER_TEST_URL", "postgres://real/orders")
    (tmp_path / "upstreams.yaml").write_text(
        yaml.safe_dump(
            {
                "upstreams": [
                    {
                        "id": "github",
                        "kind": "mcp",
                        "match": {"mcp_server": "github"},
                        "credential": {
                            "source": "env",
                            "ref": "BROKER_TEST_URL",
                            "inject": {"type": "header", "name": "Authorization"},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = tmp_path / "qed.yaml"
    config.write_text(
        yaml.safe_dump({"mode": "shadow", "broker": {"upstreams_file": "upstreams.yaml"}}),
        encoding="utf-8",
    )
    await call_one(qed_dir, config)
    assert all(value == "advisory" for value in enforcement_in_chain(qed_dir))


async def test_the_credential_never_reaches_the_chain(
    qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Evidence records `upstream_id` and nothing else (SPEC §7.2)."""
    secret = "postgres://user:hunter2@db/orders"
    monkeypatch.setenv("BROKER_TEST_URL", secret)
    config = write_config(tmp_path, with_upstreams=True)
    await call_one(qed_dir, config)

    from qed.infra.storage.sqlite import SqliteStore

    with SqliteStore(qed_dir / "qed.db") as store:
        blob = json.dumps([record.payload for record in store.iter_evidence()])
    assert secret not in blob
    assert "hunter2" not in blob


async def test_the_credential_reaches_the_upstream_process(
    qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the whole feature: the agent did not supply this, the
    qed did, and it arrived in the child process rather than in the chain.

    A stdio child gets its environment once at spawn, so this is the moment
    the injection has to happen -- before any tool call exists to be
    per-action about.
    """
    monkeypatch.setenv("BROKER_TEST_URL", "postgres://injected/orders")
    config = write_config(tmp_path, with_upstreams=True)
    async with (
        stdio_client(params(qed_dir, config)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        result = await client.call_tool("echo_env", {"name": "DATABASE_URL"})
    rendered = str(result.content)
    assert "postgres://injected/orders" in rendered


async def test_without_a_broker_the_flag_still_decides(qed_dir: Path, tmp_path: Path) -> None:
    """A deployment with no upstreams behaves exactly as it did before the
    broker existed, rather than quietly going advisory on everybody."""
    config = write_config(tmp_path, with_upstreams=False)
    await call_one(qed_dir, config)
    assert all(value == "enforcing" for value in enforcement_in_chain(qed_dir))


async def test_the_result_records_the_same_enforcement_as_the_proposal(
    qed_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same bug the HTTP proxy's first live run exposed, in this adapter.

    The proposal recorded the derived answer and the `execution_result`
    beside it recorded the operator's flag, so a chain could hold one call
    making two different claims about whether QED held the credential.
    """
    monkeypatch.delenv("BROKER_TEST_URL", raising=False)
    config = write_config(tmp_path, with_upstreams=True)
    await call_one(qed_dir, config)

    from qed.infra.storage.sqlite import SqliteStore

    with SqliteStore(qed_dir / "qed.db") as store:
        recorded = {
            record.type.value: (
                record.enforcement.value if record.enforcement else None,
                record.assurance.value,
            )
            for record in store.iter_evidence()
            if record.type.value in {"proposal", "execution_result"}
        }
    assert recorded["proposal"][0] == "advisory"
    assert recorded["execution_result"][0] == "advisory"
    # ADR-007.1: an advisory adapter's report is the agent's testimony.
    assert recorded["execution_result"][1] == "self"
