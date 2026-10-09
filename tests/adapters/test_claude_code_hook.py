"""The Claude Code `PreToolUse` hook (SPEC §12.2, ADR-0008).

Two classes here are the ones that matter, and both are about what the hook
does *not* do.

`TestAllowIsNeverEmitted` guards the decision in ADR-0008: the hook contract
has a `permissionDecision: "allow"` that bypasses the operator's own
permission rules, so a governance layer answering `allow` to everything it did
not block would be granting permissions nobody asked it to grant — and would
switch off the user's allow-list while doing it.

`TestNoExitCodeThatSilentlyDisablesTheGate` guards the other one. The hook
contract treats any non-zero exit that is **not 2** as non-blocking: the tool
call proceeds and the transcript shows a small notice. So a traceback out of
this adapter does not fail closed, it fails silently open. The documentation
calls this out — a mistyped path "silently disables the gate" — and it is the
exact shape of degradation this product exists to stop.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from qed.adapters.hooks.claude_code import (
    EXIT_ALLOW,
    EXIT_BLOCK,
    HookInput,
    HookOptions,
    build_hook_proposal,
    main,
    parse_hook_input,
    run_hook,
)
from qed.core.evidence.hashing import principal_hash
from qed.core.schemas import ActionKind, Enforcement, Mode
from qed.infra.keys.file import init_keys
from qed.infra.storage.sqlite import SqliteStore
from qed.runtime import open_session

OPTIONS = HookOptions(environment="prod", human_hash=principal_hash("dana@example.com"))


def payload(**fields: Any) -> HookInput:
    base: dict[str, Any] = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
        "session_id": "abc123",
        "cwd": "/home/dev/project",
    }
    base.update(fields)
    return parse_hook_input(json.dumps(base))


def proposal(**fields: Any):  # type: ignore[no-untyped-def]
    built, _ = build_hook_proposal(payload(**fields), OPTIONS, Mode.enforce)
    return built


# --------------------------------------------------------------------------
# Reading the payload
# --------------------------------------------------------------------------


class TestParsing:
    def test_the_fields_spec_12_2_names(self) -> None:
        parsed = payload()
        assert parsed.tool_name == "Bash"
        assert parsed.tool_input == {"command": "echo hello"}
        assert parsed.session_id == "abc123"
        assert parsed.cwd == "/home/dev/project"

    def test_fields_the_contract_grew_later(self) -> None:
        """`tool_use_id`, `permission_mode`, `agent_id` and `agent_type` are
        not in SPEC §12.2, which was written against an older contract."""
        parsed = payload(
            tool_use_id="toolu_1", permission_mode="default", agent_id="ag", agent_type="Explore"
        )
        assert parsed.tool_use_id == "toolu_1"
        assert parsed.permission_mode == "default"
        assert parsed.agent_type == "Explore"

    def test_an_unknown_field_is_kept_and_not_refused(self) -> None:
        """An adapter that rejected a payload because it had learned a new
        field would break on an upgrade of the thing it is governing."""
        parsed = payload(prompt_id="550e", scratchpad_dir="/tmp/s", effort="high")
        assert parsed.extra["prompt_id"] == "550e"
        assert parsed.extra["effort"] == "high"

    @pytest.mark.parametrize("raw", ["", "not json", "[]", '"a string"', "null"])
    def test_an_unusable_payload_raises(self, raw: str) -> None:
        with pytest.raises(ValueError):
            parse_hook_input(raw)

    def test_a_payload_with_no_tool_name_raises(self) -> None:
        with pytest.raises(ValueError, match="no `tool_name`"):
            parse_hook_input(json.dumps({"tool_input": {}}))

    def test_a_non_object_tool_input_becomes_empty(self) -> None:
        """Rather than raising. The call is still worth recording, and which
        tool it was is the part a rule matches on."""
        assert (
            parse_hook_input(json.dumps({"tool_name": "Bash", "tool_input": "x"})).tool_input == {}
        )


# --------------------------------------------------------------------------
# SPEC §12.2's mapping
# --------------------------------------------------------------------------


class TestTheMapping:
    @pytest.mark.parametrize(
        ("tool", "kind", "name"),
        [
            ("Bash", ActionKind.shell, "shell.bash"),
            ("Edit", ActionKind.custom, "fs.write"),
            ("Write", ActionKind.custom, "fs.write"),
            ("NotebookEdit", ActionKind.custom, "fs.write"),
            ("Skill", ActionKind.skill, "skill"),
            ("Read", ActionKind.custom, "fs.read"),
            ("WebFetch", ActionKind.http, "web.fetch"),
        ],
    )
    def test_spec_12_2s_table(self, tool: str, kind: ActionKind, name: str) -> None:
        built = proposal(tool_name=tool, tool_input={})
        assert built.action.kind is kind
        assert built.action.name == name

    def test_an_mcp_tool_gets_the_same_name_the_proxy_writes(self) -> None:
        """`mcp__postgres__execute_sql` -> `postgres.execute_sql`, which is
        exactly what the MCP proxy writes for the same call. A rule written
        for one adapter then matches the other, which is the point."""
        built = proposal(tool_name="mcp__postgres__execute_sql", tool_input={})
        assert built.action.kind is ActionKind.mcp_tool
        assert built.action.name == "postgres.execute_sql"

    def test_an_mcp_tool_whose_name_contains_underscores_survives(self) -> None:
        built = proposal(tool_name="mcp__my_server__do__thing", tool_input={})
        assert built.action.name == "my_server.do__thing"

    def test_an_unmapped_tool_is_recorded_rather_than_ignored(self) -> None:
        """An unmapped tool that silently left no record would be the one an
        investigation needed."""
        built = proposal(tool_name="SomeNewTool", tool_input={})
        assert built.action.kind is ActionKind.custom
        assert built.action.name == "tool.SomeNewTool"


class TestTheTarget:
    def test_a_path_under_the_session_directory_is_relative(self) -> None:
        """An absolute path carries the developer's home directory into the
        chain, and a rule written against `src/*` should match on two
        machines."""
        built = proposal(
            tool_name="Write",
            tool_input={"file_path": "/home/dev/project/src/app.py"},
            cwd="/home/dev/project",
        )
        assert built.action.target == "file:src/app.py"

    def test_a_path_outside_it_stays_absolute(self) -> None:
        built = proposal(
            tool_name="Write", tool_input={"file_path": "/etc/passwd"}, cwd="/home/dev/project"
        )
        assert built.action.target == "file:/etc/passwd"

    def test_a_shell_command_targets_the_host_not_the_command(self) -> None:
        """The command is the parameters. A rule that wants it matches
        `params_redacted.command`."""
        built = proposal(tool_name="Bash", tool_input={"command": "rm -rf /"})
        assert built.action.target.startswith("host:")
        assert built.action.params_redacted is not None
        assert built.action.params_redacted["command"] == "rm -rf /"

    def test_a_web_fetch_targets_the_url(self) -> None:
        built = proposal(tool_name="WebFetch", tool_input={"url": "https://example.test/x"})
        assert built.action.target == "https://example.test/x"

    def test_an_mcp_call_with_no_path_targets_the_server(self) -> None:
        """Found by running it: the session-id fallback gave every call through
        one server a different target, so a rule against `mcp:postgres*` would
        have matched none of them."""
        built = proposal(tool_name="mcp__postgres__execute_sql", tool_input={"sql": "SELECT 1"})
        assert built.action.target == "mcp:postgres"


class TestIdentity:
    def test_the_chain_is_one_agent_outside_a_subagent(self) -> None:
        assert len(proposal().principal.agent_chain) == 1

    def test_a_subagent_appears_as_a_second_link(self) -> None:
        """Outermost first (SPEC §3.1). Claude Code sends `agent_type` only
        inside a subagent, so two links mean one really is acting rather than
        that the adapter guessed."""
        chain = proposal(agent_id="ag_1", agent_type="Explore").principal.agent_chain
        assert len(chain) == 2
        assert chain[0].startswith("claude-code@")
        assert chain[1] == "sub:Explore"

    def test_it_is_always_advisory(self) -> None:
        """SPEC §12.2 and ADR-001. Whoever can edit the settings can delete
        the entry that calls this, so the chain must not claim the call could
        not have happened without it."""
        assert proposal().context.enforcement is Enforcement.advisory

    def test_even_when_the_options_say_otherwise(self) -> None:
        built, _ = build_hook_proposal(
            payload(),
            HookOptions(human_hash=principal_hash("x@y.z"), environment="prod"),
            Mode.enforce,
        )
        assert built.context.enforcement is Enforcement.advisory

    def test_an_identityless_hook_is_refused_at_construction(self) -> None:
        """Without a principal every verdict is a synthetic AG-IDN-007 BLOCK
        reached before any rule runs."""
        with pytest.raises(ValueError, match="AG-IDN-007"):
            build_hook_proposal(payload(), HookOptions(), Mode.enforce)

    def test_the_summary_leads_with_the_command(self) -> None:
        """An approver sees this and not the transcript."""
        built = proposal(
            tool_name="Bash", tool_input={"command": "terraform destroy -auto-approve"}
        )
        assert "terraform destroy" in built.context.summary


# --------------------------------------------------------------------------
# What it answers
# --------------------------------------------------------------------------


@pytest.fixture
def qed_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    return directory


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "qed.yaml"
    path.write_text(yaml.safe_dump({"mode": "enforce"}), encoding="utf-8")
    return path


def decide(qed_dir: Path, config: Path, **fields: Any):  # type: ignore[no-untyped-def]
    session = open_session(directory=qed_dir, config_path=config)
    try:
        return run_hook(session, payload(**fields), OPTIONS)
    finally:
        session.close()


class TestAllowIsNeverEmitted:
    """ADR-0008. `permissionDecision: "allow"` bypasses the operator's own
    permission rules, so a gate that answered it to everything it did not
    block would be granting permissions nobody asked for."""

    def test_an_allowed_call_says_nothing_at_all(self, qed_dir: Path, config: Path) -> None:
        outcome = decide(qed_dir, config, tool_name="Read", tool_input={"file_path": "README.md"})
        assert outcome.decision == "none"
        assert outcome.payload() is None
        assert outcome.exit_code == EXIT_ALLOW

    def test_the_word_allow_never_reaches_stdout(
        self, qed_dir: Path, config: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The mechanical version, across several harmless calls."""
        for tool, arguments in [
            ("Read", {"file_path": "README.md"}),
            ("Glob", {"pattern": "*.py"}),
            ("Grep", {"pattern": "def "}),
        ]:
            code = main(
                ["--human", "dana@example.com", "--dir", str(qed_dir), "--config", str(config)],
                stdin=io.StringIO(json.dumps({"tool_name": tool, "tool_input": arguments})),
            )
            assert code == EXIT_ALLOW
        captured = capsys.readouterr()
        assert "allow" not in captured.out


class TestWhatItRefuses:
    def test_a_block_denies_and_exits_two(self, qed_dir: Path, config: Path) -> None:
        """Exit 2 is the only code the contract treats as blocking."""
        outcome = decide(
            qed_dir,
            config,
            tool_name="Write",
            tool_input={"file_path": "qed/core/evidence/signing.py", "content": "x"},
            cwd=".",
        )
        assert outcome.decision == "deny"
        assert outcome.exit_code == EXIT_BLOCK
        assert "[qed BLOCK]" in outcome.reason

    def test_the_reason_carries_the_rule_and_the_fix(self, qed_dir: Path, config: Path) -> None:
        outcome = decide(
            qed_dir,
            config,
            tool_name="Write",
            tool_input={"file_path": "qed/core/evidence/signing.py", "content": "x"},
            cwd=".",
        )
        assert "AG-IDN-009" in outcome.reason
        assert "Fix:" in outcome.reason

    def test_an_approval_asks_rather_than_blocking(self, qed_dir: Path, config: Path) -> None:
        """ADR-0008. SPEC §12.2 degraded this to exit 2 because the old
        contract had no way to put a question to anybody. There is a person at
        this terminal, and `ask` hands them the question the rule asked for."""
        outcome = decide(
            qed_dir,
            config,
            tool_name="Bash",
            tool_input={"command": "rm -rf /var/lib/postgresql/data"},
        )
        assert outcome.decision == "ask"
        assert outcome.exit_code == EXIT_ALLOW
        assert "[qed APPROVAL]" in outcome.reason

    def test_the_ask_names_the_open_approval(self, qed_dir: Path, config: Path) -> None:
        outcome = decide(
            qed_dir,
            config,
            tool_name="Bash",
            tool_input={"command": "rm -rf /var/lib/postgresql/data"},
        )
        assert "qed approvals" in outcome.reason

    def test_the_structured_output_matches_the_contract(self, qed_dir: Path, config: Path) -> None:
        outcome = decide(
            qed_dir,
            config,
            tool_name="Bash",
            tool_input={"command": "rm -rf /var/lib/postgresql/data"},
        )
        body = outcome.payload()
        assert body is not None
        specific = body["hookSpecificOutput"]
        assert specific["hookEventName"] == "PreToolUse"
        assert specific["permissionDecision"] == "ask"
        assert specific["permissionDecisionReason"]


# --------------------------------------------------------------------------
# The exit code, which is where a hook fails silently
# --------------------------------------------------------------------------


class TestNoExitCodeThatSilentlyDisablesTheGate:
    """Any non-zero code that is not 2 is *non-blocking*: the call proceeds
    and the transcript shows a notice. So there is no code that means "I
    failed, stop" other than 2, and a traceback would mean the gate is off.
    """

    def run(self, raw: str, *extra: str, qed_dir: Path, config: Path) -> int:
        return main(
            [
                "--human",
                "dana@example.com",
                "--dir",
                str(qed_dir),
                "--config",
                str(config),
                *extra,
            ],
            stdin=io.StringIO(raw),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )

    @pytest.mark.parametrize("raw", ["", "not json", "{}", '{"tool_input": {}}'])
    def test_a_malformed_payload_never_exits_one(
        self, raw: str, qed_dir: Path, config: Path
    ) -> None:
        code = self.run(raw, qed_dir=qed_dir, config=config)
        assert code in {EXIT_ALLOW, EXIT_BLOCK}

    def test_a_malformed_payload_is_refused_when_closed(self, qed_dir: Path, config: Path) -> None:
        code = self.run("not json", "--fail-mode", "closed", qed_dir=qed_dir, config=config)
        assert code == EXIT_BLOCK

    def test_a_malformed_payload_gets_out_of_the_way_when_open(
        self, qed_dir: Path, config: Path
    ) -> None:
        code = self.run("not json", "--fail-mode", "open", qed_dir=qed_dir, config=config)
        assert code == EXIT_ALLOW

    def test_a_missing_qed_directory_never_exits_one(self, tmp_path: Path, config: Path) -> None:
        """No signing key, so the kernel cannot start. `open` gets out of the
        way, and neither answer is exit 1."""
        code = main(
            ["--human", "d@e.f", "--dir", str(tmp_path / "nothing"), "--config", str(config)],
            stdin=io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {}})),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == EXIT_ALLOW

    def test_the_same_failure_refuses_when_closed(self, tmp_path: Path, config: Path) -> None:
        out = io.StringIO()
        code = main(
            [
                "--human",
                "d@e.f",
                "--dir",
                str(tmp_path / "nothing"),
                "--config",
                str(config),
                "--fail-mode",
                "closed",
            ],
            stdin=io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {}})),
            stdout=out,
            stderr=io.StringIO(),
        )
        assert code == EXIT_BLOCK
        assert "[qed ERROR]" in out.getvalue()

    def test_no_identity_is_refused_with_the_reason(self, qed_dir: Path, config: Path) -> None:
        err = io.StringIO()
        code = main(
            ["--dir", str(qed_dir), "--config", str(config)],
            stdin=io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {}})),
            stdout=io.StringIO(),
            stderr=err,
        )
        assert code == EXIT_ALLOW
        assert "AG-IDN-007" in err.getvalue()
        assert "qed install claude-code" in err.getvalue()


class TestTheChain:
    def test_an_allowed_call_is_still_recorded(self, qed_dir: Path, config: Path) -> None:
        """The record is the product. A call nobody stopped is still a call
        somebody made."""
        main(
            ["--human", "dana@example.com", "--dir", str(qed_dir), "--config", str(config)],
            stdin=io.StringIO(
                json.dumps({"tool_name": "Read", "tool_input": {"file_path": "README.md"}})
            ),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        with SqliteStore(qed_dir / "qed.db") as store:
            kinds = [record.type.value for record in store.iter_evidence()]
        assert "proposal" in kinds
        assert "verdict" in kinds

    def test_a_fail_open_gap_is_written_as_an_ungated_window(
        self, qed_dir: Path, config: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Otherwise `fail_mode: open` is indistinguishable from a quiet
        afternoon."""
        import qed.adapters.hooks.claude_code as module

        def explode(*args: object, **kwargs: object) -> None:
            raise RuntimeError("the kernel fell over")

        monkeypatch.setattr(module, "run_hook", explode)
        code = main(
            ["--human", "dana@example.com", "--dir", str(qed_dir), "--config", str(config)],
            stdin=io.StringIO(json.dumps({"tool_name": "Read", "tool_input": {}})),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == EXIT_ALLOW
        with SqliteStore(qed_dir / "qed.db") as store:
            windows = [
                record.payload or {}
                for record in store.iter_evidence()
                if record.type.value == "ungated_window"
            ]
        assert len(windows) == 1
        assert "the kernel fell over" in str(windows[0]["reason"])
        assert windows[0]["fail_mode"] == "open"
