"""The week 2 exit criterion, as a test (SPEC §22).

``gate mcp -- <a real MCP server>`` proxies calls, writes proposal and verdict
records, and ``gate-verify`` validates the chain.

Nothing here is mocked. There are three processes: this test as the MCP client,
``gate mcp`` as the proxy, and ``tests/adapters/upstream_server.py`` as a real
MCP server. The bytes between them are real MCP over real pipes, because the
things most likely to be wrong -- capability mirroring, the shape of a tool
error, whether stdout stays clean -- are exactly the things an in-process fake
would hide.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import mcp.types as types
import pytest
from mcp import ClientSession, StdioServerParameters, stdio_client

from gate.infra.keys.file import PUBLIC_DIR_NAME, init_keys
from tests.adapters import upstream_server

REPO = Path(__file__).resolve().parents[2]
UPSTREAM = REPO / "tests" / "adapters" / "upstream_server.py"

#: Seconds to wait for any one call. Generous: it spawns two processes.
TIMEOUT = 60.0


def proxy_params(
    gate_dir: Path, *, extra: list[str] | None = None, env: str = "prod"
) -> StdioServerParameters:
    """``gate mcp`` as a subprocess, via the installed entry point's module.

    ``python -c`` rather than the ``gate`` console script so the test does not
    depend on where pip put the wrapper, which differs between Windows and
    POSIX and between a venv and a user install.
    """
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            "from gate.cli import main; main()",
            "mcp",
            "--dir",
            str(gate_dir),
            "--env",
            env,
            "--server-name",
            "orders",
            "--human",
            "tester@example.com",
            "--target-template",
            "db:{env}/{args.table}",
            *(extra or []),
            "--",
            sys.executable,
            str(UPSTREAM),
        ],
        cwd=str(REPO),
    )


@pytest.fixture
def proxy_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "gate"
    init_keys(directory)
    return directory


def read_chain(gate_dir: Path) -> list[dict[str, object]]:
    """Export the chain with the CLI, so the test reads what an auditor would."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from gate.cli import main; main()",
            "export",
            "--dir",
            str(gate_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        check=True,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def records_of(chain: list[dict[str, object]], type_: str) -> list[dict[str, object]]:
    return [record for record in chain if record["type"] == type_]


def payload_of(record: dict[str, object]) -> dict[str, object]:
    payload = record["payload"]
    assert isinstance(payload, dict)
    return payload


# --------------------------------------------------------------------------
# The exit criterion
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_proxy_forwards_a_call_and_records_the_decision(proxy_dir: Path) -> None:
    async with (
        stdio_client(proxy_params(proxy_dir)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        init = await client.initialize()

        # SPEC §12.1: keep the upstream's identity, add a note to instructions.
        assert init.server_info is not None
        assert init.server_info.name == upstream_server.NAME
        assert init.server_info.version == upstream_server.VERSION
        assert init.instructions is not None
        assert upstream_server.INSTRUCTIONS in init.instructions
        assert "gate" in init.instructions

        tools = await client.list_tools()
        assert [tool.name for tool in tools.tools] == [tool.name for tool in upstream_server.TOOLS]

        result = await client.call_tool("list_tables", {})
        assert isinstance(result, types.CallToolResult)
        assert not result.is_error
        assert "orders-db.list_tables ran" in _text(result)

    chain = read_chain(proxy_dir)
    proposals = records_of(chain, "proposal")
    verdicts = records_of(chain, "verdict")
    results = records_of(chain, "execution_result")
    assert len(proposals) == 1
    assert len(verdicts) == 1
    assert len(results) == 1

    proposal = payload_of(proposals[0])["proposal"]
    assert isinstance(proposal, dict)
    action = proposal["action"]
    assert isinstance(action, dict)
    assert action["name"] == "orders.list_tables"
    assert action["kind"] == "mcp_tool"

    assert payload_of(results[0])["status"] == "ok"
    # An enforcing adapter's report is `adapter`, not `self` (ADR-007.1).
    assert results[0]["assurance"] == "adapter"


@pytest.mark.asyncio
async def test_the_chain_the_proxy_wrote_passes_gate_verify(proxy_dir: Path) -> None:
    async with (
        stdio_client(proxy_params(proxy_dir)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        await client.call_tool("list_tables", {})
        await client.call_tool("execute_sql", {"sql": "SELECT 1", "table": "orders"})

    from gate_verify.verify import load_jsonl, verify_records

    from gate.core.evidence.export.jsonl import to_jsonl
    from gate.infra.keys.file import load_public_keys
    from gate.infra.storage.sqlite import SqliteStore

    store = SqliteStore(proxy_dir / "gate.db")
    text = to_jsonl(store.iter_evidence())
    store.close()

    report = verify_records(
        load_jsonl(text),
        load_public_keys(proxy_dir / PUBLIC_DIR_NAME),
        instance_id="gate-local",
    )
    assert report.ok, report.summary()


# --------------------------------------------------------------------------
# Shadow mode
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shadow_mode_records_a_would_be_approval_and_forwards_anyway(
    proxy_dir: Path,
) -> None:
    """The point of week 2: nothing is blocked, everything is recorded.

    ``execute_sql`` carrying ``DROP TABLE`` in prod is the case the week 1
    review was about. It must reach REQUIRE_APPROVAL in ``would_decision`` --
    not ALLOW -- while still being forwarded, because the default mode is
    shadow.
    """
    async with (
        stdio_client(proxy_params(proxy_dir)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        result = await client.call_tool(
            "execute_sql", {"sql": "DROP TABLE orders_archive;", "table": "orders_archive"}
        )
        assert isinstance(result, types.CallToolResult)
        assert not result.is_error, "shadow mode must not stop the call"
        assert "[gate" not in _text(result)

    chain = read_chain(proxy_dir)
    verdict = payload_of(records_of(chain, "verdict")[0])["verdict"]
    assert isinstance(verdict, dict)

    assert verdict["decision"] == "REQUIRE_APPROVAL"
    assert verdict["would_decision"] == "REQUIRE_APPROVAL"
    hit_ids = [hit["rule_id"] for hit in verdict["hits"]]  # type: ignore[index,union-attr]
    assert "AG-BLR-003" in hit_ids, (
        "a destructive statement in the parameters of a mild-verb tool must still route "
        "to approval; this is the regression the week 1 review carried forward"
    )
    assert records_of(chain, "verdict")[0]["mode"] == "shadow"


@pytest.mark.asyncio
async def test_the_target_template_is_filled_in_from_the_arguments(proxy_dir: Path) -> None:
    async with (
        stdio_client(proxy_params(proxy_dir)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        await client.call_tool("delete_rows", {"table": "payments", "selector": "status=old"})

    chain = read_chain(proxy_dir)
    proposal = payload_of(records_of(chain, "proposal")[0])["proposal"]
    assert isinstance(proposal, dict)
    action = proposal["action"]
    context = proposal["context"]
    assert isinstance(action, dict)
    assert isinstance(context, dict)

    assert action["target"] == "db:prod/payments"
    hints = context["blast_radius_hints"]
    assert isinstance(hints, dict)
    assert hints["deletes"] is True
    assert hints["scope"] == "multi_resource", "a `selector` argument selects many rows"


@pytest.mark.asyncio
async def test_enforce_mode_blocks_and_tells_the_model_why(proxy_dir: Path, tmp_path: Path) -> None:
    """The same proxy in enforce mode. Week 10 flips this on; it works now."""
    import yaml

    config = tmp_path / "gate.yaml"
    config.write_text(yaml.safe_dump({"mode": "enforce"}), encoding="utf-8")

    params = proxy_params(proxy_dir, extra=["--config", str(config)])
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        result = await client.call_tool(
            "execute_sql", {"sql": "DROP TABLE orders_archive;", "table": "orders_archive"}
        )
        assert isinstance(result, types.CallToolResult)
        assert result.is_error
        text = _text(result)
        assert text.startswith("[gate APPROVAL PENDING]")
        assert "AG-BLR-003" in text
        assert "week 4" in text, "be honest that there is no approval route yet"

    chain = read_chain(proxy_dir)
    assert len(records_of(chain, "proposal")) == 1
    assert len(records_of(chain, "verdict")) == 1
    assert not records_of(chain, "execution_result"), (
        "a refused call never ran, so there is no execution result to report"
    )
    assert records_of(chain, "verdict")[0]["mode"] == "enforce"


# --------------------------------------------------------------------------
# Read-through surfaces
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_resource_read_is_recorded_and_never_refused(proxy_dir: Path) -> None:
    """SPEC §12.1: resources pass through, logged, never blocked in v1."""
    import yaml

    config = proxy_dir.parent / "enforce.yaml"
    config.write_text(yaml.safe_dump({"mode": "enforce"}), encoding="utf-8")

    params = proxy_params(proxy_dir, extra=["--config", str(config)])
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        resources = await client.list_resources()
        assert [str(r.uri) for r in resources.resources] == ["db://orders/schema"]
        read_result = await client.read_resource("db://orders/schema")  # type: ignore[arg-type]
        assert "CREATE TABLE orders" in read_result.contents[0].text  # type: ignore[union-attr]

        prompts = await client.list_prompts()
        assert [p.name for p in prompts.prompts] == ["explain-schema"]
        prompt = await client.get_prompt("explain-schema")
        assert prompt.messages

    chain = read_chain(proxy_dir)
    names = []
    for record in records_of(chain, "proposal"):
        proposal = payload_of(record)["proposal"]
        assert isinstance(proposal, dict)
        action = proposal["action"]
        assert isinstance(action, dict)
        names.append(action["name"])
    assert "orders.resources/read" in names
    assert "orders.prompts/get" in names


# --------------------------------------------------------------------------
# Failure paths
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_upstream_failure_is_reported_not_swallowed(proxy_dir: Path) -> None:
    async with (
        stdio_client(proxy_params(proxy_dir)) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        result = await client.call_tool("explode", {})
        assert isinstance(result, types.CallToolResult)
        assert result.is_error
        assert "the upstream server failed" in _text(result)

    chain = read_chain(proxy_dir)
    results = records_of(chain, "execution_result")
    assert len(results) == 1
    payload = payload_of(results[0])
    assert payload["status"] == "error"
    assert "on purpose" in str(payload["error"])


@pytest.mark.asyncio
async def test_an_advisory_adapter_reports_results_as_self(proxy_dir: Path) -> None:
    """An adapter the agent could have switched off is giving testimony."""
    params = proxy_params(proxy_dir, extra=["--enforcement", "advisory"])
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write, read_timeout_seconds=TIMEOUT) as client,
    ):
        await client.initialize()
        await client.call_tool("list_tables", {})

    chain = read_chain(proxy_dir)
    assert records_of(chain, "execution_result")[0]["assurance"] == "self"


def test_the_proxy_refuses_to_start_without_a_signing_key(tmp_path: Path) -> None:
    """SPEC §17: an unsigned decision is not evidence, so there is nothing to run."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from gate.cli import main; main()",
            "mcp",
            "--dir",
            str(tmp_path / "empty"),
            "--human",
            "tester@example.com",
            "--",
            sys.executable,
            str(UPSTREAM),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=TIMEOUT,
    )
    assert result.returncode == 1
    assert "gate keys init" in result.stderr
    assert result.stdout == "", "stdout is the MCP transport and must stay empty"


def test_the_proxy_says_nothing_on_stdout_except_mcp(proxy_dir: Path) -> None:
    """A single stray line on stdout is a protocol error, not a cosmetic one."""
    result = subprocess.run(
        [
            *proxy_params(proxy_dir).command.split(),
            *proxy_params(proxy_dir).args,
        ],
        input="",
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=TIMEOUT,
    )
    # The client sent nothing and closed stdin, so the proxy had no request to
    # answer: stdout must be empty even though stderr carries the banner.
    assert result.stdout == "", result.stdout
    assert "proxying orders" in result.stderr


def _text(result: types.CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, types.TextContent))
