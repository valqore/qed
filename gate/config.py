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
from gate.core.schemas import Budget, Decision, Frozen, Mode

__all__ = [
    "DEFAULT_DIR",
    "AdapterCredential",
    "ApiConfig",
    "GateConfig",
    "LoadedConfig",
    "load_config",
]

DEFAULT_DIR = Path(".gate")

#: Sections of SPEC §16 that are still unimplemented after week 2.
UNIMPLEMENTED_SECTIONS = (
    "identity",
    "approvals",
    "broker",
    "remote",
    "observability",
    "ui",
)


class EvidenceConfig(Frozen):
    store: str | None = None
    signing_key: str | None = None
    masking: MaskingProfile = "default"


class AdapterCredential(Frozen):
    """One registered adapter and where its shared secret comes from.

    The secret is never in ``gate.yaml``. ``secret_env`` names the environment
    variable holding it, so the config file stays safe to commit and the secret
    stays out of the process table and out of any backup of the repo. SPEC §12.6
    moves this to ``gate adapters add`` with per-adapter rotation in week 5.
    """

    adapter_id: str
    secret_env: str
    kind: str = "mcp"


class ApiConfig(Frozen):
    host: str = "127.0.0.1"
    port: int = 8710
    adapters: list[AdapterCredential] = Field(default_factory=list)
    #: Reject a signed request whose timestamp is further away than this.
    max_clock_skew_seconds: int = 300


class IssuerConfig(Frozen):
    """One identity provider the gate will accept tokens from (SPEC §6.1)."""

    issuer: str
    #: Left unset, it is resolved once through OIDC discovery. Set it to skip
    #: discovery entirely, which an air-gapped install has to do.
    jwks_uri: str | None = None
    #: What an IdP may sign with. `none` is absent and the list is never read
    #: from the token, which is where JWT implementations historically go wrong.
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    #: IdP group -> scopes the group may request (SPEC §6.2).
    scopes_by_group: dict[str, list[str]] = Field(default_factory=dict)


class DelegationConfig(Frozen):
    """Token exchange (SPEC §6.2). Empty means `/v1/token` is not offered."""

    issuers: list[IssuerConfig] = Field(default_factory=list)
    #: The `iss` of tokens this gate mints. Not an IdP; its own name.
    self_issuer: str = "https://gate.local"
    token_ttl_default_seconds: int = 900
    #: Ceiling applied to every requested budget, per group. A request is
    #: granted the minimum of what it asked for and what its group allows.
    budget_caps: dict[str, Budget] = Field(default_factory=dict)
    #: Where fetched JWKS sets are cached. Relative to the gate directory.
    jwks_cache: str = "."
    #: Never reach for a JWKS over the network; the cache is all there is.
    offline: bool = False


class GateConfig(Frozen):
    instance_id: str = "gate-local"
    mode: Mode = Mode.shadow
    default_verdict: Decision = Decision.ALLOW
    environment_profile: str = "dev"
    policies: list[str] = Field(default_factory=list)
    evidence: EvidenceConfig = EvidenceConfig()
    api: ApiConfig = ApiConfig()
    adapters: list[AdapterCredential] = Field(default_factory=list)
    delegation: DelegationConfig = DelegationConfig()

    model_config = ConfigDict(frozen=True, extra="ignore")

    @property
    def registered_adapters(self) -> list[AdapterCredential]:
        """Adapters from either ``api.adapters`` or the top-level ``adapters``.

        SPEC §16's reference file puts them at the top level and SPEC §13 reads
        them as an API concern. Both spellings are accepted rather than making
        an operator guess which one this build wants.
        """
        seen: dict[str, AdapterCredential] = {}
        for entry in [*self.adapters, *self.api.adapters]:
            seen[entry.adapter_id] = entry
        return [seen[key] for key in sorted(seen)]


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
