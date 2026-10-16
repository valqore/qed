"""Every command the documentation tells a reader to run, run (SPEC §26).

`tests/docs/` already checks what the documents *say*. This checks what they
*instruct*, which is a different thing and the one this repository keeps
getting wrong:

* #27 was a mandate signature nothing verified for eight weeks while its unit
  tests passed. It was found by executing a document.
* #48 was an install command a guard could not see because it sat inside a
  quote.
* #59 was `qed adapters add`, recommended by another command's error message
  for twelve weeks while not existing.

Each of those is the same shape: prose and reality drifting apart in the one
direction a reader notices first. A CLI test proves a command works; it does
not prove the invocation somebody copies out of `docs/replay.md` works, with
those flags, in that order.

Two guards, and they fail differently.

:class:`TestEveryDocumentedFlagExists` is static, fast and covers every
document. A flag a document names and the CLI does not have is a reader whose
first command fails, and it costs nothing to rule out.

:class:`TestTheDocumentedJourneyRuns` executes the sequence the documents are
built around -- demo, register an adapter, rotate it, replay a decision -- and
asserts the output still says what the samples show. It is slower and it is
the one that catches a flag that exists and does not do what the page claims.

Both run through the installed package, not the shipped binary.
`tests/deploy/test_binary.py` covers that, and it is a different artifact.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qed.cli import app

REPO = Path(__file__).resolve().parents[2]
DOCS = [*sorted((REPO / "docs").glob("*.md")), REPO / "README.md"]

runner = CliRunner()

#: Lines inside fenced blocks that begin a `qed` invocation. Continuations
#: (`\` at the end) are joined first, because the auditor example in
#: `docs/replay.md` spans five lines and its flags are on the last four.
_FENCE = re.compile(r"^```")


def _command_lines(text: str) -> list[str]:
    """Every `qed …` invocation inside a fenced code block."""
    out: list[str] = []
    inside = False
    buffer = ""
    for raw in text.splitlines():
        if _FENCE.match(raw.strip()):
            inside = not inside
            continue
        if not inside:
            continue
        line = raw.strip()
        if buffer:
            buffer = buffer[:-1].rstrip() + " " + line
        elif line.startswith("qed ") or line.startswith("$ qed "):
            buffer = line.removeprefix("$ ").strip()
        else:
            continue
        if buffer.endswith("\\"):
            continue
        out.append(buffer)
        buffer = ""
    return out


#: Matches a long option wherever it appears in a help screen.
_FLAG = re.compile(r"--[a-z][a-z0-9-]*")


def _flags_from_help(*path: str) -> set[str]:
    """The long options `qed <path> --help` shows a reader.

    Read out of the help screen rather than off the Typer callback, and the
    reason is the subject of this file: the help text is what a reader sees,
    so it is the right thing to hold a document to. Introspecting the
    callback would check the documents against the code's intent and miss a
    flag that exists but is never shown.

    `COLUMNS` is set wide because Typer renders options in a Rich table and a
    narrow terminal wraps `--instance-id` onto two lines, which would make it
    look absent and the assertion below fail for a reason that has nothing to
    do with the documents.
    """
    result = runner.invoke(app, [*path, "--help"], env={"COLUMNS": "400"})
    assert result.exit_code == 0, f"`qed {' '.join(path)} --help` failed"
    return set(_FLAG.findall(result.output))


def _cli_commands() -> dict[str, set[str]]:
    """``{"adapters add": {"--dir", …}}`` for every command the CLI has.

    The command inventory comes from the same place
    `tests/cli/test_command_set.py` reads it, so the two cannot disagree
    about what exists.
    """
    found: dict[str, set[str]] = {}
    for info in app.registered_commands:
        name = info.name or (info.callback.__name__.replace("_", "-") if info.callback else "")
        if name:
            found[name] = _flags_from_help(name)
    for group in app.registered_groups:
        assert group.name is not None
        found[group.name] = _flags_from_help(group.name)
        for info in group.typer_instance.registered_commands:
            sub_name = info.name or (
                info.callback.__name__.replace("_", "-") if info.callback else ""
            )
            if sub_name:
                found[f"{group.name} {sub_name}"] = _flags_from_help(group.name, sub_name)
    return found


COMMANDS = _cli_commands()


def _own_tokens(line: str) -> list[str]:
    """The tokens that belong to *this* `qed` invocation.

    Two things end it, and both appear in the documents:

    * a shell pipe. `docs/validation.md` has
      ``qed export --dir .qed | qed-verify - --keys .qed/public``, where
      ``--keys`` is `qed-verify`'s flag and attributing it to `qed export`
      would be a failure in the test rather than in the page.
    * a bare ``--``, which hands everything after it to the wrapped process.
      `qed mcp --config qed.yaml -- npx -y @some/mcp-server` passes ``-y`` to
      npx, and `qed` never sees it.
    """
    tokens: list[str] = []
    for token in line.split():
        if token in {"|", "||", "&&", ";", ">", ">>"}:
            break
        if token == "--":
            break
        tokens.append(token)
    return tokens


def _resolve(tokens: list[str]) -> tuple[str | None, list[str]]:
    """The command a documented line invokes, and the flags it passes."""
    words = [token for token in tokens[1:] if not token.startswith("-")]
    name: str | None = None
    if len(words) >= 2 and f"{words[0]} {words[1]}" in COMMANDS:
        name = f"{words[0]} {words[1]}"
    elif words and words[0] in COMMANDS:
        name = words[0]
    used = [token.split("=", 1)[0] for token in tokens if token.startswith("--") and token != "--"]
    return name, used


def documented() -> list[tuple[Path, str]]:
    return [
        (path, line)
        for path in DOCS
        if path.is_file()
        for line in _command_lines(path.read_text(encoding="utf-8"))
    ]


class TestEveryDocumentedFlagExists:
    """A flag a page names and the CLI has not is a reader's first command
    failing, in the document that was supposed to get them started."""

    def test_the_documents_contain_commands_to_check(self) -> None:
        """The guard this test's own value depends on. A parser that silently
        matched nothing would make every assertion below vacuous -- which is
        the failure mode of the guard in #60b, and it is cheaper to rule out
        than to wonder about."""
        lines = documented()
        assert len(lines) >= 20, f"only found {len(lines)} documented commands"
        assert any("replay" in line for _, line in lines)
        assert any("adapters" in line for _, line in lines)

    @pytest.mark.parametrize(("path", "line"), documented(), ids=lambda v: str(v)[:60])
    def test_the_command_and_its_flags_are_real(self, path: Path, line: str) -> None:
        tokens = _own_tokens(line)
        name, used = _resolve(tokens)
        if name is None:
            # A shell pipeline or a placeholder; the journey test covers the
            # real invocations. Not a silent pass: a line that names a
            # *command* which does not exist is caught below.
            spelled = [token for token in tokens[1:] if not token.startswith("-")]
            if spelled and spelled[0].isalpha():
                assert spelled[0] in {word.split()[0] for word in COMMANDS}, (
                    f"{path.name}: `qed {spelled[0]}` is not a command"
                )
            return
        unknown = sorted(set(used) - COMMANDS[name])
        assert not unknown, f"{path.name}: `qed {name}` has no {', '.join(unknown)}"


class TestTheDocumentedJourneyRuns:
    """The sequence the documents are built around, executed in order.

    Separate from the CLI tests on purpose: those call the commands the way a
    test author would, and this calls them the way `docs/api.md` and
    `docs/replay.md` tell a stranger to.

    Deliberately **not** marked `slow`, although it drives `qed demo` and a
    dozen commands: the whole file runs in about two seconds, and the `check`
    job runs `-m "not slow and not perf"`. A marker here would buy nothing
    and would let the journey be skipped on the jobs most people look at.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def journey(cls, tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
        root = tmp_path_factory.mktemp("documented")
        state = root / ".qed"
        demo = runner.invoke(app, ["demo", "--dir", str(state)])
        assert demo.exit_code == 0, demo.output
        config = state / "qed.yaml"
        export = runner.invoke(app, ["export", "--dir", str(state), "--config", str(config)])
        assert export.exit_code == 0, export.output
        records = [json.loads(line) for line in export.stdout.splitlines() if line.strip()]
        return {
            "root": root,
            "state": state,
            "config": config,
            "export": export.stdout,
            "ids": [
                record["payload"]["verdict"]["proposal_id"]
                for record in records
                if record["type"] == "verdict" and record.get("payload")
            ],
            "instance_id": next(
                record["payload"]["instance_id"]
                for record in records
                if record["type"] == "genesis"
            ),
        }

    def qed(self, journey: dict[str, object], *args: str) -> object:
        return runner.invoke(
            app,
            [*args, "--dir", str(journey["state"]), "--config", str(journey["config"])],
        )

    def test_the_demo_ends_verified(self, journey: dict[str, object]) -> None:
        """README's first command, and the first thing a stranger sees."""
        assert journey["ids"], "the demo wrote no verdicts"

    def test_registering_an_adapter_writes_what_the_page_shows(
        self, journey: dict[str, object]
    ) -> None:
        """`docs/api.md` prints the resulting `qed.yaml` block. A derived
        variable name that changed would make that sample wrong."""
        result = self.qed(journey, "adapters", "add", "adp_laptop_ali")
        assert result.exit_code == 0, result.output
        text = Path(str(journey["config"])).read_text(encoding="utf-8")
        assert "adapter_id: adp_laptop_ali" in text
        assert "secret_env: QED_ADAPTER_SECRET_ADP_LAPTOP_ALI" in text

    def test_the_rotation_is_the_two_steps_the_page_describes(
        self, journey: dict[str, object]
    ) -> None:
        rotated = self.qed(journey, "adapters", "rotate", "adp_laptop_ali")
        assert rotated.exit_code == 0, rotated.output
        config = Path(str(journey["config"]))
        assert "previous_secret_env: QED_ADAPTER_SECRET_ADP_LAPTOP_ALI" in config.read_text(
            encoding="utf-8"
        )
        finished = self.qed(journey, "adapters", "rotate", "adp_laptop_ali", "--finish")
        assert finished.exit_code == 0, finished.output
        assert "previous_secret_env" not in config.read_text(encoding="utf-8")

    def test_replay_prints_what_the_sample_prints(self, journey: dict[str, object]) -> None:
        """`docs/replay.md` shows `reproduced`, `(matches)` and the budget
        named as assumed. All three are claims about this output."""
        ids = list(journey["ids"])  # type: ignore[call-overload]
        result = self.qed(journey, "replay", ids[0])
        assert result.exit_code == 0, result.output
        assert "reproduced" in result.output
        assert "(matches)" in result.output
        assert "assumed (not in any record): budget" in result.output

    def test_the_page_is_right_that_history_is_not_assumed(
        self, journey: dict[str, object]
    ) -> None:
        """The counters are recovered from the chain, so they must not appear
        in the assumed line. This is the assertion that would have caught the
        page going stale when the collection landed."""
        ids = list(journey["ids"])  # type: ignore[call-overload]
        result = self.qed(journey, "replay", ids[0])
        assert "history" not in result.output

    def test_the_exit_codes_are_the_table_in_the_page(self, journey: dict[str, object]) -> None:
        """0 reproduced, 1 unanswerable. A pipeline reads these."""
        ids = list(journey["ids"])  # type: ignore[call-overload]
        assert self.qed(journey, "replay", ids[0]).exit_code == 0
        assert self.qed(journey, "replay", "01JBZZZZZZZZZZZZZZZZZZZZZZ").exit_code == 1

    def test_a_policy_mismatch_prints_the_refusal_in_the_page(
        self, journey: dict[str, object]
    ) -> None:
        root = Path(str(journey["root"]))
        other = root / "other-policies"
        other.mkdir(exist_ok=True)
        (other / "rules.yaml").write_text(
            "- rule_id: LOCAL-001\n  name: Local\n  severity: LOW\n"
            "  mode: shadow\n  verdict: ALLOW\n  message: local\n",
            encoding="utf-8",
        )
        ids = list(journey["ids"])  # type: ignore[call-overload]
        result = self.qed(journey, "replay", ids[0], "--policy", str(other))
        assert result.exit_code == 1
        assert "cannot replay" in result.output
        # The sample block's own labels, which are aligned in the page.
        assert "decided under    :" in result.output
        assert "replayed against :" in result.output

    def test_the_auditor_invocation_works_with_only_an_export(
        self, journey: dict[str, object]
    ) -> None:
        """`docs/replay.md`'s "For an auditor with an export": `--from` and
        `--instance-id`, which is the one path a reader cannot try against
        their own instance by accident."""
        root = Path(str(journey["root"]))
        chain = root / "chain.jsonl"
        chain.write_text(str(journey["export"]), encoding="utf-8")
        ids = list(journey["ids"])  # type: ignore[call-overload]
        result = self.qed(
            journey,
            "replay",
            ids[0],
            "--from",
            str(chain),
            "--instance-id",
            str(journey["instance_id"]),
        )
        assert result.exit_code == 0, result.output
        assert "reproduced" in result.output

    def test_the_json_keys_the_page_promises_are_there(self, journey: dict[str, object]) -> None:
        ids = list(journey["ids"])  # type: ignore[call-overload]
        result = self.qed(journey, "replay", ids[0], "--json")
        payload = json.loads(result.stdout)
        for key in (
            "proposal_id",
            "reproduced",
            "inconclusive",
            "policy_matches",
            "recorded_policy_hash",
            "assumed_inputs",
            "differences",
        ):
            assert key in payload, key
