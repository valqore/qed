"""`qed install claude-code` (SPEC §12.2).

Editing somebody else's settings file is the kind of thing that goes wrong
quietly, so most of these are about what survives: the hooks they already had,
the rest of the file, and the absence of a second entry after a second run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qed.adapters.hooks.install import (
    EVENT,
    apply_plan,
    plan_install,
    settings_path,
)


def make_plan(path: Path, **overrides: Any):  # type: ignore[no-untyped-def]
    options: dict[str, Any] = {
        "path": path,
        "human": "dana@example.com",
        "environment": "prod",
        "directory": None,
        "config": None,
        "fail_mode": "closed",
        "executable": "/usr/local/bin/qed",
    }
    options.update(overrides)
    return plan_install(**options)


def written(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class TestWhereItWrites:
    def test_local_is_the_default_because_it_is_gitignored(self, tmp_path: Path) -> None:
        """An entry naming one person's email in a file the team commits would
        attribute everybody's actions to whoever ran the installer."""
        assert settings_path(scope="local", project=tmp_path).name == "settings.local.json"

    def test_project_is_the_committed_one(self, tmp_path: Path) -> None:
        assert settings_path(scope="project", project=tmp_path).name == "settings.json"

    def test_user_scope_is_in_the_home_directory(self) -> None:
        resolved = settings_path(scope="user")
        assert resolved.parent.name == ".claude"
        assert resolved.parent.parent == Path.home()


class TestThePlan:
    def test_the_executable_is_absolute(self, tmp_path: Path) -> None:
        """A bare `qed` would depend on the agent's PATH at the moment the
        hook fires, and a hook whose command cannot be found is *non-blocking*
        -- the call proceeds with the gate silently off."""
        plan = make_plan(tmp_path / "s.json")
        assert Path(plan.command).is_absolute()

    def test_it_falls_back_to_the_running_interpreter(self, tmp_path: Path) -> None:
        """`python -m qed.cli` always exists if qed is importable at all."""
        plan = make_plan(tmp_path / "s.json", executable=None)
        assert "qed.cli" in " ".join(plan.args) or Path(plan.command).name.startswith("qed")

    def test_it_uses_the_exec_form(self, tmp_path: Path) -> None:
        """`args` spawns the executable directly with no shell, so a path with
        spaces needs no quoting -- and a Windows path has spaces twice over."""
        handler = make_plan(tmp_path / "s.json").handler()
        assert handler["type"] == "command"
        assert isinstance(handler["args"], list)
        assert " " not in handler["command"] or handler["args"]

    def test_the_flags_carry_the_identity_and_the_fail_mode(self, tmp_path: Path) -> None:
        joined = " ".join(make_plan(tmp_path / "s.json").args)
        assert "--human dana@example.com" in joined
        assert "--env prod" in joined
        assert "--fail-mode closed" in joined

    def test_a_relative_state_directory_is_made_absolute(self, tmp_path: Path) -> None:
        """The hook's working directory is the session's, so a relative
        `.qed` would resolve somewhere else on the next project."""
        plan = make_plan(tmp_path / "s.json", directory=Path(".qed"))
        index = plan.args.index("--dir")
        assert Path(plan.args[index + 1]).is_absolute()

    def test_the_matcher_covers_every_tool(self, tmp_path: Path) -> None:
        """A gate that only saw `Bash` would miss every file write and every
        MCP call."""
        assert make_plan(tmp_path / "s.json").group()["matcher"] == "*"


class TestMerging:
    def existing(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "permissions": {"allow": ["Bash(git status)"]},
                    "hooks": {
                        EVENT: [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {"type": "command", "command": "/usr/local/bin/theirs.sh"}
                                ],
                            }
                        ],
                        "Stop": [
                            {"hooks": [{"type": "command", "command": "/usr/local/bin/notify.sh"}]}
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )

    def test_it_creates_the_file_when_there_is_none(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        result = apply_plan(make_plan(path))
        assert result.path.is_file()
        assert len(written(path)["hooks"][EVENT]) == 1

    def test_somebody_elses_hook_on_the_same_event_survives(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        self.existing(path)
        result = apply_plan(make_plan(path))
        groups = written(path)["hooks"][EVENT]
        assert len(groups) == 2
        assert result.preserved == 1
        assert any(h["command"] == "/usr/local/bin/theirs.sh" for g in groups for h in g["hooks"])

    def test_other_events_and_the_rest_of_the_file_survive(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        self.existing(path)
        apply_plan(make_plan(path))
        document = written(path)
        assert document["permissions"] == {"allow": ["Bash(git status)"]}
        assert len(document["hooks"]["Stop"]) == 1

    def test_running_it_twice_leaves_one_entry(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        apply_plan(make_plan(path))
        second = apply_plan(make_plan(path))
        assert second.replaced is True
        assert len(written(path)["hooks"][EVENT]) == 1

    def test_a_second_run_with_a_different_human_updates_rather_than_adds(
        self, tmp_path: Path
    ) -> None:
        """Matched on the executable, not on the whole command line. Two
        entries that both fire would write two records for one call and
        attribute them to two different people."""
        path = tmp_path / ".claude" / "settings.local.json"
        apply_plan(make_plan(path))
        apply_plan(make_plan(path, human="someone.else@example.com"))
        groups = written(path)["hooks"][EVENT]
        assert len(groups) == 1
        joined = " ".join(groups[0]["hooks"][0]["args"])
        assert "someone.else@example.com" in joined
        assert "dana@example.com" not in joined

    def test_a_moved_executable_updates_rather_than_duplicating(self, tmp_path: Path) -> None:
        """A recreated virtualenv changes the path. If the path were part of
        the match, the dead entry would stay -- and an entry pointing at a
        missing executable is non-blocking, so the call would proceed with the
        gate off while a live entry ran beside it."""
        path = tmp_path / ".claude" / "settings.local.json"
        apply_plan(make_plan(path, executable="/old/venv/bin/qed"))
        apply_plan(make_plan(path, executable="/new/venv/bin/qed"))
        groups = written(path)["hooks"][EVENT]
        assert len(groups) == 1
        assert "new" in groups[0]["hooks"][0]["command"]

    def test_an_older_shell_form_install_is_still_recognised(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "hooks": {
                        EVENT: [
                            {
                                "matcher": "*",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": "/usr/local/bin/qed hook claude-code --env dev",
                                    }
                                ],
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        result = apply_plan(make_plan(path))
        assert result.replaced is True
        assert len(written(path)["hooks"][EVENT]) == 1


class TestItRefusesRatherThanLosingTheFile:
    def test_unparseable_json_is_not_overwritten(self, tmp_path: Path) -> None:
        """Rewriting a settings file we cannot read would lose whatever is in
        it, which may be the only copy."""
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text('{"hooks": {', encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            apply_plan(make_plan(path))
        assert path.read_text(encoding="utf-8") == '{"hooks": {'

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            ('{"hooks": []}', "`hooks` is not an object"),
            ('{"hooks": {"PreToolUse": {}}}', "is not a list"),
            ("[1, 2]", "does not contain a JSON object"),
        ],
    )
    def test_a_shape_it_does_not_understand_is_refused(
        self, tmp_path: Path, body: str, message: str
    ) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text(body, encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            apply_plan(make_plan(path))

    def test_an_empty_file_is_fine(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text("", encoding="utf-8")
        apply_plan(make_plan(path))
        assert len(written(path)["hooks"][EVENT]) == 1
