"""Configuration (SPEC §16).

Only the week 1 subset is honoured. A ``qed.yaml`` may legitimately contain the
later sections (``identity``, ``approvals``, ``broker``, ``remote`` …) because
the reference file in SPEC §16 is the complete one; rather than rejecting them
or pretending to read them, :func:`load_config` returns the list of sections it
ignored so the CLI can say so out loud. Silently accepting a setting that has no
effect is how an operator ends up believing an approval channel is configured
when nothing is listening.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ConfigDict, Field

from qed.core.evidence.masking import MaskingProfile
from qed.core.schemas import Budget, Decision, Frozen, Mode

__all__ = [
    "DEFAULT_DIR",
    "AdapterCredential",
    "ApiConfig",
    "LoadedConfig",
    "QedConfig",
    "load_config",
]

DEFAULT_DIR = Path(".qed")

#: Sections of SPEC §16 that are still unimplemented after week 2.
#: Sections a config file may carry that this build does not act on yet. A
#: silently ignored section is a setting somebody believes is in force, so
#: `load_config` reports them. `approvals` left this list in week 4 and
#: `delegation` was never on it.
UNIMPLEMENTED_SECTIONS = (
    "identity",
    "remote",
    "observability",
    "ui",
)


class EvidenceConfig(Frozen):
    #: Where the chain lives. Unset or ``sqlite`` means the file in the state
    #: directory; a ``postgresql://`` URL means that server (SPEC §15).
    #:
    #: A URL here carries a password, so it may instead name an environment
    #: variable: ``store_env: QED_DATABASE_URL``. A config file is a file
    #: somebody commits, and the credential-broker reasoning applies to the
    #: store's own credential too.
    store: str | None = None
    #: Environment variable holding the connection URL. Wins over `store`.
    store_env: str | None = None
    #: Path to the Ed25519 private key, when it does not live in the state
    #: directory. A container's chain is on a writable volume while its key
    #: arrives from a read-only secret mount, and nesting the one inside the
    #: other to satisfy a fixed filename works until a kubelet orders the
    #: mounts differently. Unset means `<state dir>/evidence-key.pem`.
    signing_key: str | None = None
    masking: MaskingProfile = "default"

    @property
    def is_postgres(self) -> bool:
        return (self.resolved_store() or "").startswith(("postgresql://", "postgres://"))

    def resolved_store(self) -> str | None:
        """The connection URL, from the environment when one is named.

        Returns None for the default SQLite file. Raises nothing: an unset
        variable is reported by the caller, which can say which key was
        expected and where it was configured.
        """
        import os

        if self.store_env:
            return os.environ.get(self.store_env) or ""
        return self.store


class AdapterCredential(Frozen):
    """One registered adapter and where its shared secret comes from.

    The secret is never in ``qed.yaml``. ``secret_env`` names the environment
    variable holding it, so the config file stays safe to commit and the secret
    stays out of the process table and out of any backup of the repo. SPEC §12.6
    moves this to ``qed adapters add`` with per-adapter rotation in week 5.
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
    """One identity provider QED will accept tokens from (SPEC §6.1)."""

    issuer: str
    #: Left unset, it is resolved once through OIDC discovery. Set it to skip
    #: discovery entirely, which an air-gapped install has to do.
    jwks_uri: str | None = None
    #: What an IdP may sign with. `none` is absent and the list is never read
    #: from the token, which is where JWT implementations historically go wrong.
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    #: IdP group -> scopes the group may request (SPEC §6.2).
    scopes_by_group: dict[str, list[str]] = Field(default_factory=dict)
    #: The **public** OAuth client the web pages log in as (SPEC §19 SSO).
    #: A browser cannot keep a secret, so this is a public client using PKCE
    #: and the value is not one: every single-page app ships its client id in
    #: plain JavaScript. Unset means the pages cannot sign anybody in against
    #: this issuer, which `qed serve --ui` says out loud.
    ui_client_id: str | None = None


class DelegationConfig(Frozen):
    """Token exchange (SPEC §6.2). Empty means `/v1/token` is not offered."""

    issuers: list[IssuerConfig] = Field(default_factory=list)
    #: The `iss` of tokens this qed mints. Not an IdP; its own name.
    self_issuer: str = "https://qed.local"
    token_ttl_default_seconds: int = 900
    #: Ceiling applied to every requested budget, per group. A request is
    #: granted the minimum of what it asked for and what its group allows.
    budget_caps: dict[str, Budget] = Field(default_factory=dict)
    #: Where fetched JWKS sets are cached. Relative to QED directory.
    jwks_cache: str = "."
    #: Never reach for a JWKS over the network; the cache is all there is.
    offline: bool = False


class SlackConfig(Frozen):
    """Slack as an approval channel (SPEC §9.5)."""

    #: Env var holding the bot token. The token itself never goes in the file:
    #: a config a person edits is a config that ends up in a repository.
    bot_token_env: str | None = None
    signing_secret_env: str | None = None
    channel: str | None = None


class ApprovalsConfig(Frozen):
    """How approvals reach a person, and who that person is allowed to be."""

    slack: SlackConfig = SlackConfig()
    #: Generic outbound notification, one-way. Teams, PagerDuty, anything.
    webhook_url: str | None = None
    #: email -> groups. Needed because a channel knows an email and a rule
    #: names a group, and nothing in between has told QED which is which.
    #: Week 6 replaces this with the IdP's own claims; until then it is
    #: explicit rather than assumed, so nobody is accidentally an approver.
    groups_by_email: dict[str, list[str]] = Field(default_factory=dict)
    require_reason_for_deny: bool = False

    def slack_bot_token(self) -> str | None:
        name = self.slack.bot_token_env
        return os.environ.get(name) if name else None

    def slack_signing_secret_value(self) -> str | None:
        name = self.slack.signing_secret_env
        return os.environ.get(name) if name else None

    def groups_for(self, email: str) -> list[str]:
        return list(self.groups_by_email.get(email, ()))


class BrokerConfig(Frozen):
    """Credential broker (SPEC §7). Empty means every adapter is advisory."""

    #: Path to `upstreams.yaml`, relative to the config file or absolute.
    upstreams_file: str | None = None
    #: Seconds a resolved credential is reused before the source is re-read.
    ttl_seconds: float = 60.0


class QedConfig(Frozen):
    instance_id: str = "qed-local"
    mode: Mode = Mode.shadow
    default_verdict: Decision = Decision.ALLOW
    environment_profile: str = "dev"
    policies: list[str] = Field(default_factory=list)
    evidence: EvidenceConfig = EvidenceConfig()
    api: ApiConfig = ApiConfig()
    adapters: list[AdapterCredential] = Field(default_factory=list)
    delegation: DelegationConfig = DelegationConfig()
    approvals: ApprovalsConfig = ApprovalsConfig()
    broker: BrokerConfig = BrokerConfig()

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
    config: QedConfig
    path: Path | None = None
    ignored_sections: list[str] = Field(default_factory=list)


def load_config(path: Path | None) -> LoadedConfig:
    """Read ``qed.yaml`` if it exists; otherwise return defaults."""
    if path is None or not path.is_file():
        return LoadedConfig(config=QedConfig(), path=None)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    ignored = [key for key in UNIMPLEMENTED_SECTIONS if key in raw]
    return LoadedConfig(config=QedConfig.model_validate(raw), path=path, ignored_sections=ignored)
