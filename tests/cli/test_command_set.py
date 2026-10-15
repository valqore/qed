"""SPEC §14's command list is the CLI's command list.

`qed/cli.py` opens with "SPEC 14 forbids adding a top-level command without a
spec update". Nothing checked it for twelve weeks, and in that time `approvals`,
`status` and `checkpoint` were built without being listed -- so the rule held
for the commands somebody remembered and not for the others.

Both directions matter and they fail differently. A command the CLI gained and
the spec did not is an undocumented surface. A name in the spec that the CLI
does not have is worse: it is a command somebody will try, and the spec is the
document this project asks people to read first.

Group subcommands are checked too, because `qed keys` quietly gaining a fourth
one is the same drift one level down.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from qed.cli import app

SPEC = Path(__file__).resolve().parents[2] / "QED_SPEC.md"


def _spec_section() -> str:
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("## 14. CLI")
    return text[start : text.index("\n## ", start)]


def _listed() -> dict[str, set[str]]:
    """``{command: {subcommands}}`` from the ``·``-separated inventory line."""
    section = _spec_section()
    line = next(line for line in section.splitlines() if line.startswith("`demo`"))
    out: dict[str, set[str]] = {}
    for entry in re.findall(r"`([^`]+)`", line):
        head, *rest = entry.split()
        out[head] = set(rest[0].split("|")) if rest and "|" in rest[0] else set()
    return out


def _unbuilt() -> set[str]:
    """The names SPEC §14 says are specified and absent, if it names any.

    Empty is a legitimate answer and became the real one on 2026-10-15, when
    `replay` was built and the sentence was deleted. The test below therefore
    checks the drift it was written for -- a name in that sentence that is
    now built -- rather than insisting the sentence exist.
    """
    section = _spec_section()
    line = next((line for line in section.splitlines() if "not built**:" in line), "")
    if not line:
        return set()
    return {re.findall(r"[a-z-]+", entry)[0] for entry in re.findall(r"`([^`]+)`", line)}


def _implemented() -> dict[str, set[str]]:
    def names(commands: object) -> set[str]:
        return {
            (info.name or info.callback.__name__.replace("_", "-"))
            for info in commands  # type: ignore[attr-defined]
        }

    built = {name: set() for name in names(app.registered_commands)}
    for group in app.registered_groups:
        assert group.name is not None
        built[group.name] = names(group.typer_instance.registered_commands)
    return built


def test_the_spec_lists_every_command_the_cli_has() -> None:
    missing = sorted(set(_implemented()) - set(_listed()))
    assert not missing, f"built and unlisted in SPEC 14: {missing}"


def test_the_cli_has_every_command_the_spec_lists_as_built() -> None:
    absent = sorted(set(_listed()) - set(_implemented()))
    assert not absent, f"SPEC 14 lists commands that do not exist: {absent}"


def test_nothing_is_named_as_unbuilt_while_being_built() -> None:
    """A command cannot be both. `adapters` and `replay` were each listed as
    specified-and-absent while being built, which is how the spec came to
    recommend `qed adapters add` to operators for twelve weeks before it
    existed -- so the day a name moves into the CLI it has to leave that
    sentence, and this says so if it does not.

    The other direction -- a name the spec lists as built that the CLI does
    not have -- is `test_the_cli_has_every_command_the_spec_lists_as_built`.
    """
    overlap = sorted(_unbuilt() & set(_implemented()))
    assert not overlap, f"named as not built, but built: {overlap}"


@pytest.mark.parametrize("group", sorted(g.name for g in app.registered_groups))
def test_each_group_lists_its_subcommands(group: str) -> None:
    assert _listed()[group] == _implemented()[group]


def test_the_count_in_the_heading_is_the_number_listed() -> None:
    """The heading sells the restraint ("20 vs Valqore's 208"), so the number
    has to be the one in the line below it."""
    heading = _spec_section().splitlines()[0]
    claimed = int(re.search(r"— (\d+) top-level commands", heading).group(1))  # type: ignore[union-attr]
    assert claimed == len(_listed())
