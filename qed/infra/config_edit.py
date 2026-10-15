"""Adding one adapter to ``qed.yaml`` without rewriting the rest of it.

This is the first thing in the product that edits an operator's configuration
file, which is why it is its own module with its own tests rather than twenty
lines inside a CLI command.

**Why not load the YAML and dump it back.** `qed.yaml` is hand-written. It has
comments explaining why `fail: closed` is set, blank lines between sections,
a key order that matches how somebody thinks about the deployment, and quite
possibly a licence header. `yaml.safe_dump` of a parsed document returns none
of that: comments are not in the parse tree at all, so a round-trip silently
deletes every one of them. A tool that destroys the reasoning an operator
wrote down, in the file that configures a policy kernel, has done more damage
than the typing it saved.

So the edit is textual: find the sequence, insert one item, leave every other
byte alone. That is the only change this module knows how to make.

**What makes a textual edit safe here is the check afterwards, not the care
beforehand.** Any insertion can be wrong -- the wrong indentation lands the
item in a neighbouring block, and YAML is perfectly happy to parse the result
into something else. So the new file is parsed and validated before it is
kept, and the resulting configuration must equal the old one plus exactly the
one adapter that was asked for. Anything else and the original bytes go back.
The check is cheap and it is the difference between an editor and a hazard.

**It refuses rather than guessing.** A flow-style sequence (`adapters: [...]`)
and a file whose `adapters:` key holds something that is not a list are both
left alone, with a message naming the file and what to add by hand. Refusing
to edit costs an operator one paste; editing the wrong line of a policy
kernel's configuration costs considerably more.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from qed.config import AdapterCredential, ConfigError, QedConfig, load_config

__all__ = ["ConfigEditRefused", "add_adapter", "rewrite_adapter"]


class ConfigEditRefused(Exception):
    """The file was not changed, and why.

    The message is for an operator at a terminal: what this module would not
    do, and the YAML they can paste instead.
    """


@dataclass(frozen=True)
class _Block:
    """Where an adapter sequence lives in the text."""

    #: Index of the line holding `adapters:`.
    header: int
    #: Column the `adapters` key starts at.
    key_indent: int
    #: Column the `- ` items start at, once there is one.
    item_indent: int
    #: Index one past the last line belonging to the sequence.
    end: int
    #: False when the key is there with no items under it.
    has_items: bool


def _is_blank(line: str) -> bool:
    return not line.strip()


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _find_adapters_block(lines: list[str]) -> _Block | None:
    """The `adapters:` sequence, at the top level or under `api:`.

    Both spellings are accepted by `QedConfig.registered_adapters`, so both
    have to be found here -- appending to the top level while the operator's
    adapters are under `api:` would produce a file with two adapter lists and
    an explanation nobody asked for.
    """
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped not in {"adapters:", "adapters: []", "adapters:[]"}:
            continue
        if stripped != "adapters:":
            # Flow style. Parsed correctly by YAML, appended to incorrectly by
            # anything that works in lines.
            raise ConfigEditRefused(
                f"line {index + 1} writes `adapters:` as a flow sequence. This editor only "
                "appends to block sequences; add the entry by hand, or rewrite the key as "
                "a block list first."
            )
        key_indent = _indent(line)
        if not _owned_by_root_or_api(lines, index, key_indent):
            continue
        return _measure(lines, index, key_indent)
    return None


def _owned_by_root_or_api(lines: list[str], index: int, key_indent: int) -> bool:
    """Whether this `adapters:` is the one the config reader will see.

    A nested `adapters:` under some other section is a different key with the
    same name, and appending a credential to it would register nothing while
    looking like it had.
    """
    if key_indent == 0:
        return True
    for above in range(index - 1, -1, -1):
        line = lines[above]
        if _is_blank(line) or _is_comment(line):
            continue
        if _indent(line) < key_indent:
            return line.strip() == "api:"
    return False


def _measure(lines: list[str], header: int, key_indent: int) -> _Block:
    """How far the sequence under `adapters:` runs."""
    item_indent = key_indent + 2
    has_items = False
    last_content = header + 1
    for index in range(header + 1, len(lines)):
        line = lines[index]
        if _is_blank(line) or _is_comment(line):
            continue
        indent = _indent(line)
        if indent <= key_indent:
            break
        if line.lstrip().startswith("- "):
            item_indent = indent
            has_items = True
        last_content = index + 1
    # Trailing blanks and comments after the last real line belong to whatever
    # comes next, not to the sequence. Inserting after them would put the new
    # item below a comment introducing the following section.
    return _Block(
        header=header,
        key_indent=key_indent,
        item_indent=item_indent,
        end=last_content if has_items else header + 1,
        has_items=has_items,
    )


def _render(entry: AdapterCredential, indent: int) -> list[str]:
    """One adapter as YAML lines. Never the secret -- only its variable name."""
    pad = " " * indent
    inner = " " * (indent + 2)
    lines = [
        f"{pad}- adapter_id: {entry.adapter_id}",
        f"{inner}secret_env: {entry.secret_env}",
        f"{inner}kind: {entry.kind}",
    ]
    if entry.previous_secret_env:
        lines.append(f"{inner}previous_secret_env: {entry.previous_secret_env}")
    return lines


def _verify_and_keep(
    path: Path, original: str, updated: str, expected: list[AdapterCredential]
) -> None:
    """Write `updated`, confirm it means what it should, or put `original` back.

    The textual edit is a guess about indentation; this is the part that knows
    whether the guess was right. A new file that parses but says something
    else is the failure mode worth paying for, because it is invisible: the
    command prints success and the adapter is registered somewhere that
    nothing reads.
    """
    before = load_config(path).config
    path.write_text(updated, encoding="utf-8")
    try:
        after = load_config(path).config
    except ConfigError as exc:
        path.write_text(original, encoding="utf-8")
        raise ConfigEditRefused(
            f"the edit would have made {path} unreadable, so it was not kept: {exc}"
        ) from exc

    if after.registered_adapters != expected:
        path.write_text(original, encoding="utf-8")
        raise ConfigEditRefused(
            f"the edit did not land where it was meant to, so {path} was left as it was. "
            "Add the entry by hand."
        )
    if _without_adapters(after) != _without_adapters(before):
        path.write_text(original, encoding="utf-8")
        raise ConfigEditRefused(
            f"the edit changed something other than the adapter list, so {path} was "
            "restored. Add the entry by hand."
        )


def _without_adapters(config: QedConfig) -> dict[str, object]:
    """The configuration with both adapter lists removed.

    Both, because either spelling is honoured, and a change that moved
    credentials from one to the other would otherwise compare equal.
    """
    dumped = config.model_dump(mode="json")
    dumped["adapters"] = []
    if isinstance(dumped.get("api"), dict):
        dumped["api"]["adapters"] = []
    return dumped


def add_adapter(path: Path, entry: AdapterCredential) -> None:
    """Append one adapter to `qed.yaml`, or refuse and change nothing."""
    original = path.read_text(encoding="utf-8") if path.is_file() else ""
    existing = load_config(path).config.registered_adapters if path.is_file() else []
    if any(item.adapter_id == entry.adapter_id for item in existing):
        raise ConfigEditRefused(
            f"adapter {entry.adapter_id} is already registered in {path}. "
            "Use `qed adapters rotate` to give it a new secret."
        )
    expected = sorted([*existing, entry], key=lambda item: item.adapter_id)

    lines = original.splitlines()
    block = _find_adapters_block(lines)
    if block is None:
        # No list yet. A new top-level one, which is where SPEC 16's reference
        # file puts it.
        prefix = lines if not lines or lines[-1].strip() else lines[:-1]
        body = [*prefix, "", "adapters:", *_render(entry, 2)]
    else:
        indent = block.item_indent if block.has_items else block.key_indent + 2
        body = [*lines[: block.end], *_render(entry, indent), *lines[block.end :]]

    updated = "\n".join(body).lstrip("\n") + "\n"
    _verify_and_keep(path, original, updated, expected)


def rewrite_adapter(path: Path, entry: AdapterCredential) -> None:
    """Replace a registered adapter's entry in place, keeping its position.

    Rotation only ever changes which environment variables an entry names, so
    the lines around it -- including whatever comment explains what this
    adapter is -- stay where the operator put them.
    """
    original = path.read_text(encoding="utf-8") if path.is_file() else ""
    existing = load_config(path).config.registered_adapters if path.is_file() else []
    if not any(item.adapter_id == entry.adapter_id for item in existing):
        raise ConfigEditRefused(f"adapter {entry.adapter_id} is not registered in {path}")
    expected = sorted(
        [entry if item.adapter_id == entry.adapter_id else item for item in existing],
        key=lambda item: item.adapter_id,
    )

    lines = original.splitlines()
    start, end, indent = _locate_entry(lines, entry.adapter_id)
    body = [*lines[:start], *_render(entry, indent), *lines[end:]]
    updated = "\n".join(body).lstrip("\n") + "\n"
    _verify_and_keep(path, original, updated, expected)


def _locate_entry(lines: list[str], adapter_id: str) -> tuple[int, int, int]:
    """The line range holding one adapter's mapping, and its indentation.

    The whole item is read before it is matched, because `adapter_id` is not
    necessarily its first key: `- kind: mcp` then `adapter_id:` underneath is
    the same mapping to YAML, and matching only the `- ` line would miss it
    and then refuse an adapter the config reader can see.
    """
    for index, line in enumerate(lines):
        if not line.strip().startswith("- "):
            continue
        indent = _indent(line)
        end = index + 1
        for below in range(index + 1, len(lines)):
            following = lines[below]
            if _is_blank(following) or _is_comment(following):
                break
            if _indent(following) <= indent:
                break
            end = below + 1
        item = [
            lines[index].strip().removeprefix("- "),
            *(following.strip() for following in lines[index + 1 : end]),
        ]
        for field in item:
            key, _, value = field.partition(":")
            if key.strip() == "adapter_id" and value.strip().strip("'\"") == adapter_id:
                return index, end, indent
    raise ConfigEditRefused(
        f"adapter {adapter_id} is registered but its entry could not be found as a line "
        "in the file. Edit it by hand."
    )
