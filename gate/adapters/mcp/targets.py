"""Target derivation for MCP calls (SPEC §12.1, "Target derivation").

``action.target`` is what policy is written against: ``db:prod/orders``,
``repo:acme/payments``, ``aws:iam:roles``. A tool name is not a target --
``execute_sql`` says nothing about which database -- so the operator supplies a
template per upstream and the proxy fills it in from the arguments.

Default when no template is configured: ``"<server>:<tool>"``. That is a usable
target for allow- and deny-listing by tool, and it is honest about knowing
nothing more. A template that silently fell back to a *narrower*-looking target
such as ``db:prod/unknown`` would make ``target_globs`` in a rule match things
the operator never meant.
"""

from __future__ import annotations

from typing import Final

import regex

__all__ = ["DEFAULT_TEMPLATE", "TemplateError", "derive_target", "validate_template"]

DEFAULT_TEMPLATE: Final = "{server}:{tool}"

#: ``{server}``, ``{tool}``, ``{env}``, or ``{args.<dotted.path>}``.
_PLACEHOLDER: Final = regex.compile(r"\{(server|tool|env|args\.[A-Za-z0-9_.\[\]-]+)\}")

#: Substituted for a placeholder whose argument the call did not supply. Visible
#: in a target, unlikely to collide with a real resource name, and built only
#: from characters :data:`_UNSAFE` leaves alone so it survives :func:`_safe`
#: unchanged.
MISSING: Final = "-absent-"

#: Characters that would let an argument value break out of the target shape a
#: policy author expects. A tool argument is attacker-influenced input.
_UNSAFE: Final = regex.compile(r"[^A-Za-z0-9._:/@=+-]")

_MAX_SEGMENT: Final = 120


class TemplateError(ValueError):
    """The configured ``target_template`` is not usable."""


def validate_template(template: str) -> None:
    """Raise :class:`TemplateError` for a template that cannot be filled in.

    Called when the proxy starts rather than on the first call, so a typo in
    ``gate.yaml`` is a startup error and not a surprise halfway through a
    session with half the chain written against the wrong target.
    """
    if not template.strip():
        raise TemplateError("target_template is empty")
    stripped = _PLACEHOLDER.sub("", template)
    if "{" in stripped or "}" in stripped:
        raise TemplateError(
            f"{template!r} has a placeholder that is not {{server}}, {{tool}}, {{env}} "
            "or {args.<path>}"
        )


def derive_target(
    *,
    server: str,
    tool: str,
    arguments: object,
    environment: str,
    template: str = DEFAULT_TEMPLATE,
) -> str:
    """Fill ``template`` in from one call. Pure."""

    def replace(match: regex.Match[str]) -> str:
        token = match.group(1)
        if token == "server":
            return _safe(server)
        if token == "tool":
            return _safe(tool)
        if token == "env":
            return _safe(environment)
        return _safe(_lookup(arguments, token.removeprefix("args.")))

    return str(_PLACEHOLDER.sub(replace, template))


def _lookup(arguments: object, path: str) -> str:
    """Resolve a dotted path through the argument object.

    ``args.table`` reads a top-level key; ``args.filter.namespace`` walks in;
    ``args.targets[0]`` indexes a list. A path that does not resolve returns
    :data:`MISSING` rather than raising: one missing argument must not take the
    call out of the chain.
    """
    current: object = arguments
    for part in _split(path):
        if isinstance(part, int):
            if not isinstance(current, list | tuple) or not -len(current) <= part < len(current):
                return MISSING
            current = current[part]
        else:
            if not isinstance(current, dict) or part not in current:
                return MISSING
            current = current[part]
    if current is None:
        return MISSING
    if isinstance(current, bool):
        return "true" if current else "false"
    if isinstance(current, int | float | str):
        return str(current)
    return MISSING


def _split(path: str) -> list[str | int]:
    parts: list[str | int] = []
    for chunk in path.split("."):
        name, _, rest = chunk.partition("[")
        if name:
            parts.append(name)
        while rest:
            index, _, rest = rest.partition("]")
            if index.lstrip("-").isdigit():
                parts.append(int(index))
            else:
                return [path]  # unparseable: resolves to MISSING
            _, _, rest = rest.partition("[")
    return parts


def _safe(value: str) -> str:
    """Make one substituted value safe to put in a target."""
    cleaned = _UNSAFE.sub("_", value)[:_MAX_SEGMENT]
    return cleaned or MISSING
