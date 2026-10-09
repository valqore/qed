"""Writing the hook into Claude Code's settings (SPEC §12.2, `qed install`).

Editing somebody's settings file is the kind of thing that goes wrong quietly,
so three rules hold here:

**Merge, never replace.** The file belongs to the developer. Hook entries in
Claude Code merge across settings levels and a duplicate handler runs once, so
adding one group to the ``PreToolUse`` array is enough — there is no need to
own the array, and owning it would mean silently dropping somebody's existing
hooks.

**Idempotent.** Running ``qed install`` twice leaves one entry, matched on the
executable rather than on the whole command line, so re-running it with a
different ``--human`` updates the entry instead of adding a second one that
fires alongside the first.

**Exec form.** The handler is written with ``args``, which spawns the
executable directly with no shell involved. The shell form would need quoting
for a path with spaces, and a Windows developer's path has spaces in it twice
over.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

__all__ = [
    "EVENT",
    "InstallPlan",
    "InstallResult",
    "apply_plan",
    "plan_install",
    "settings_path",
]

#: The one event this adapter uses. `PreToolUse` fires before the tool runs,
#: which is the only moment a decision can still change the outcome.
EVENT: Final = "PreToolUse"

#: Matches every tool. A governance gate that only saw `Bash` would miss every
#: file write and every MCP call.
MATCHER: Final = "*"


@dataclass(frozen=True)
class InstallPlan:
    """The entry to write, and where."""

    path: Path
    command: str
    args: list[str]

    def handler(self) -> dict[str, Any]:
        return {"type": "command", "command": self.command, "args": list(self.args)}

    def group(self) -> dict[str, Any]:
        return {"matcher": MATCHER, "hooks": [self.handler()]}


@dataclass(frozen=True)
class InstallResult:
    path: Path
    #: True when an entry for this executable was already there and was
    #: rewritten rather than added beside.
    replaced: bool
    #: Other hooks on the same event that were left exactly as they were.
    preserved: int


def settings_path(*, scope: str, project: Path | None = None) -> Path:
    """Where to write. SPEC §12.2 says project or user.

    ``local`` is the default because it is the gitignored one: installing a
    hook that names a particular person's email into a file the whole team
    commits would attribute everybody's actions to whoever ran the installer.
    """
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    base = project if project is not None else Path.cwd()
    if scope == "project":
        return base / ".claude" / "settings.json"
    return base / ".claude" / "settings.local.json"


def plan_install(
    *,
    path: Path,
    human: str | None,
    environment: str,
    directory: Path | None,
    config: Path | None,
    fail_mode: str,
    mandate: Path | None = None,
    executable: str | None = None,
) -> InstallPlan:
    """What would be written, without writing it.

    The executable is resolved to an absolute path. A bare ``qed`` would
    depend on the agent's ``PATH`` at the moment the hook fires, and a hook
    whose command cannot be found is *non-blocking* -- the tool call proceeds
    and the gate is silently off, which the hook documentation calls out and
    which is the failure this product exists to prevent.
    """
    resolved = executable or shutil.which("qed")
    if resolved is None:
        # Fall back to the running interpreter plus `-m`, which always exists
        # if qed is importable at all.
        return InstallPlan(
            path=path,
            command=sys.executable,
            args=[
                "-m",
                "qed.cli",
                "hook",
                "claude-code",
                *_flags(human, environment, directory, config, fail_mode, mandate),
            ],
        )
    return InstallPlan(
        path=path,
        command=str(Path(resolved).resolve()),
        args=[
            "hook",
            "claude-code",
            *_flags(human, environment, directory, config, fail_mode, mandate),
        ],
    )


def _flags(
    human: str | None,
    environment: str,
    directory: Path | None,
    config: Path | None,
    fail_mode: str,
    mandate: Path | None,
) -> list[str]:
    flags: list[str] = ["--env", environment, "--fail-mode", fail_mode]
    if human:
        flags += ["--human", human]
    if mandate is not None:
        flags += ["--mandate", str(mandate.resolve())]
    if directory is not None:
        # Absolute, because the hook's working directory is the session's and
        # a relative `.qed` would resolve somewhere else on the next project.
        flags += ["--dir", str(directory.resolve())]
    if config is not None:
        flags += ["--config", str(config.resolve())]
    return flags


def apply_plan(plan: InstallPlan) -> InstallResult:
    """Merge the entry into the settings file, creating it if need be."""
    existing: dict[str, Any] = {}
    if plan.path.is_file():
        text = plan.path.read_text(encoding="utf-8")
        if text.strip():
            try:
                loaded = json.loads(text)
            except ValueError as exc:
                raise ValueError(
                    f"{plan.path} is not valid JSON ({exc}). Refusing to touch it: "
                    "rewriting a settings file we cannot parse would lose whatever is "
                    "in it."
                ) from exc
            if not isinstance(loaded, dict):
                raise ValueError(f"{plan.path} does not contain a JSON object")
            existing = loaded

    hooks = existing.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{plan.path}: `hooks` is not an object")
    groups = hooks.setdefault(EVENT, [])
    if not isinstance(groups, list):
        raise ValueError(f"{plan.path}: `hooks.{EVENT}` is not a list")

    kept: list[Any] = []
    replaced = False
    for group in groups:
        if _is_ours(group, plan.command):
            replaced = True
            continue
        kept.append(group)
    kept.append(plan.group())
    hooks[EVENT] = kept

    plan.path.parent.mkdir(parents=True, exist_ok=True)
    plan.path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return InstallResult(path=plan.path, replaced=replaced, preserved=len(kept) - 1)


def _is_ours(group: object, command: str) -> bool:
    """Whether a group is a previous install of ours.

    Matched on the *invocation* -- a handler that runs ``hook claude-code`` --
    and deliberately not on the executable path. Nothing else invokes that,
    and the path is the fragile half: a recreated virtualenv, a reinstalled
    Python or a moved checkout all change it.

    That matters more than tidiness. An entry pointing at an executable that
    no longer exists is *non-blocking* under the hook contract, so the call
    proceeds with the gate silently off. If the path were part of the match,
    moving the venv would leave that dead entry in place and add a live one
    beside it: two records for one call, attributed to whatever each was
    installed with. Matching on the invocation replaces it instead.

    ``command`` is still taken so that the shell form, which an older install
    may have written, is recognised by the same rule.
    """
    del command  # kept for the older signature; the invocation is the signal
    if not isinstance(group, dict):
        return False
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        return False
    for handler in handlers:
        if not isinstance(handler, dict):
            continue
        args = handler.get("args")
        joined = " ".join(str(a) for a in args) if isinstance(args, list) else ""
        whole = f"{handler.get('command', '')} {joined}"
        if "hook" in whole and "claude-code" in whole:
            return True
    return False
