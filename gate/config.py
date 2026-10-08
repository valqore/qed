"""Configuration (SPEC §16).

Only the week 1 subset is honoured. A ``gate.yaml`` may legitimately contain the
later sections (``identity``, ``approvals``, ``broker``, ``remote`` …) because
the reference file in SPEC §16 is the complete one; rather than rejecting them
or pretending to read them, :func:`load_config` returns the list of sections it
ignored so the CLI can say so out loud. Silently accepting a setting that has no
effect is how an operator ends up believing an approval channel is configured
when nothing is listening.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ConfigDict, Field

from gate.core.evidence.masking import MaskingProfile
from gate.core.schemas import Decision, Frozen, Mode

__all__ = ["DEFAULT_DIR", "GateConfig", "LoadedConfig", "load_config"]

DEFAULT_DIR = Path(".gate")

#: Sections of SPEC §16 that week 1 does not implement yet.
UNIMPLEMENTED_SECTIONS = (
    "identity",
    "approvals",
    "adapters",
    "broker",
    "remote",
    "observability",
    "ui",
)


class EvidenceConfig(Frozen):
    store: str | None = None
    signing_key: str | None = None
    masking: MaskingProfile = "default"


class GateConfig(Frozen):
    instance_id: str = "gate-local"
    mode: Mode = Mode.shadow
    default_verdict: Decision = Decision.ALLOW
    environment_profile: str = "dev"
    policies: list[str] = Field(default_factory=list)
    evidence: EvidenceConfig = EvidenceConfig()

    model_config = ConfigDict(frozen=True, extra="ignore")


class LoadedConfig(Frozen):
    config: GateConfig
    path: Path | None = None
    ignored_sections: list[str] = Field(default_factory=list)


def load_config(path: Path | None) -> LoadedConfig:
    """Read ``gate.yaml`` if it exists; otherwise return defaults."""
    if path is None or not path.is_file():
        return LoadedConfig(config=GateConfig(), path=None)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    ignored = [key for key in UNIMPLEMENTED_SECTIONS if key in raw]
    return LoadedConfig(config=GateConfig.model_validate(raw), path=path, ignored_sections=ignored)
