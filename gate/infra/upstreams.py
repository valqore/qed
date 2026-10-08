"""Loading ``upstreams.yaml`` (SPEC §7.1).

Separate from the broker's own model because reading a file is I/O and the
matching logic has to stay importable with no filesystem in reach.

An unreadable or malformed file is an **error**, not an empty set. Falling
back to "no upstreams" would silently turn every enforcing adapter advisory,
and the symptom — agents carrying their own credentials again — is one nobody
would notice until it mattered.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from gate.config import GateConfig
from gate.core.broker.model import UpstreamSet

__all__ = ["UpstreamsError", "load_upstreams"]


class UpstreamsError(RuntimeError):
    """The upstreams file is missing, unreadable or not valid."""


def load_upstreams(config: GateConfig, *, base: Path | None = None) -> UpstreamSet:
    """Read the configured upstreams file, or return an empty set.

    ``base`` is the config file, so a relative ``upstreams_file`` resolves
    next to it rather than against whatever directory the command was run
    from.
    """
    configured = config.broker.upstreams_file
    if not configured:
        return UpstreamSet()

    path = Path(configured)
    if not path.is_absolute() and base is not None:
        path = base.parent / path

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise UpstreamsError(
            f"could not read {path}: {exc}. Refusing to continue: carrying on with "
            "no upstreams would quietly turn every enforcing adapter advisory."
        ) from exc
    except yaml.YAMLError as exc:
        raise UpstreamsError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict) or "upstreams" not in raw:
        raise UpstreamsError(f"{path} needs a top-level `upstreams:` list")
    try:
        loaded = UpstreamSet.model_validate(raw)
    except ValueError as exc:
        raise UpstreamsError(f"{path}: {exc}") from exc

    seen: set[str] = set()
    for upstream in loaded.upstreams:
        if upstream.id in seen:
            raise UpstreamsError(
                f"{path}: two upstreams share the id {upstream.id!r}, so which one "
                "injects a credential would depend on file order"
            )
        seen.add(upstream.id)
    return loaded
