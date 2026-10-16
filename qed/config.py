"""Configuration (SPEC §16).

Not every section is honoured. A ``qed.yaml`` may legitimately contain sections
this build does not act on (see ``UNIMPLEMENTED_SECTIONS``) because
the reference file in SPEC §16 is the complete one; rather than rejecting them
or pretending to read them, :func:`load_config` returns the list of sections it
ignored so the CLI can say so out loud. Silently accepting a setting that has no
effect is how an operator ends up believing an approval channel is configured
when nothing is listening.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import ConfigDict, Field, field_validator, model_validator

from qed.core.evidence.masking import MaskingProfile
from qed.core.history import DEFAULT_REFRESH_SECONDS
from qed.core.schemas import Budget, Decision, EvidenceType, Frozen, Mode

if TYPE_CHECKING:  # the policy object is pure core; config only names it
    from qed.core.evidence.retention import RetentionPolicy

__all__ = [
    "DEFAULT_DIR",
    "AdapterCredential",
    "ApiConfig",
    "LoadedConfig",
    "QedConfig",
    "load_config",
]

DEFAULT_DIR = Path(".qed")

#: Sections a config file may carry that this build does not act on. A silently
#: ignored section is a setting somebody believes is in force, so `load_config`
#: reports them. The list shrinks as sections are implemented -- `approvals`
#: left it once there was an approval service -- and `delegation` was never on
#: it.
UNIMPLEMENTED_SECTIONS = (
    "identity",
    "remote",
    "ui",
)


class CheckpointConfig(Frozen):
    """When to checkpoint, and where to publish the root (SPEC §10.4, §16).

    ```yaml
    evidence:
      checkpoint:
        every_records: 1000
        every_seconds: 3600
        publishers:
          - { type: s3-object-lock, bucket: acme-qed-anchors }
          - { type: file, path: /data/anchors }
    ```

    Publishing is what turns a checkpoint into an anchor. Without it the
    Merkle root sits in the same chain it summarises, so an operator who could
    rewrite the chain could recompute the root -- and nothing in an export
    would say so. With it, the root is also somewhere the instance does not
    control, and a rewritten chain fails the comparison.

    Both thresholds are a *first reached* pair, not an and.
    """

    every_records: int = 1000
    every_seconds: int = 3600
    publishers: list[dict[str, object]] = Field(default_factory=list)

    @property
    def publishing(self) -> bool:
        return bool(self.publishers)


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
    checkpoint: CheckpointConfig = CheckpointConfig()
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


class RetentionConfig(Frozen):
    """How long payloads are kept (SPEC §10.6, §16).

    ```yaml
    retention:
      payload: 7y          # the default age; `forever` or absent keeps them
      by_type:
        proposal: 90d      # per type, which SPEC §10.6 asks for
        execution_result: 90d
    ```

    Absent means nothing is ever purged. A kernel that began deleting evidence
    because nobody had configured retention would be the wrong default by a
    long way, and the obligation a retention policy comes from is always
    written down somewhere before it is configured here.

    Some types are never purged whatever this says -- a checkpoint's payload
    holds its Merkle root, a `key_rotated`'s holds the new public key, and an
    `admin_action`'s is the record of a purge. See
    `qed.core.evidence.retention.NEVER_PURGE`.
    """

    payload: str | None = None
    by_type: dict[str, str | None] = Field(default_factory=dict)

    def policy(self) -> RetentionPolicy:
        """Parse into the pure policy the planner takes."""
        from qed.core.evidence.retention import RetentionPolicy, parse_retention

        return RetentionPolicy(
            payload=parse_retention(self.payload),
            by_type={
                EvidenceType(name): parse_retention(age) for name, age in self.by_type.items()
            },
            # Verbatim, so what is reported back is what was written down.
            declared={"payload": self.payload, **self.by_type},
        )


class SiemConfig(Frozen):
    """Where OCSF events go (SPEC §18).

    ```yaml
    observability:
      siem:
        format: ocsf
        webhook_env: QED_SIEM_WEBHOOK   # a URL with a token in it
        stdout: false
    ```

    `webhook_env` and not `webhook`, for the same reason the database DSN is
    named rather than inlined: a Splunk HEC or Slack webhook URL carries its
    token in the path or query, and `qed.yaml` is a file somebody commits. A
    literal `webhook` is accepted for a URL that genuinely has no secret in it.
    """

    format: Literal["ocsf"] = "ocsf"
    webhook: str | None = None
    webhook_env: str | None = None
    stdout: bool = False

    def resolved_webhook(self) -> str | None:
        import os

        if self.webhook_env:
            return os.environ.get(self.webhook_env) or None
        return self.webhook

    @property
    def active(self) -> bool:
        return bool(self.resolved_webhook()) or self.stdout


class ObservabilityConfig(Frozen):
    """SPEC §16's `observability`. Metrics and SSE are always on.

    `/metrics` and `/v1/events` cost nothing when nobody scrapes or subscribes,
    and a flag to turn off observability is a flag somebody sets during an
    incident and forgets. So the only thing configured here is where events are
    shipped, which is the part that leaves the machine.
    """

    siem: SiemConfig = SiemConfig()


class AdapterCredential(Frozen):
    """One registered adapter and where its shared secret comes from.

    The secret is never in ``qed.yaml``. ``secret_env`` names the environment
    variable holding it, so the config file stays safe to commit and the secret
    stays out of the process table and out of any backup of the repo.
    ``qed adapters add|list|rotate`` (SPEC §12.6) maintains this list.

    ``previous_secret_env`` is the overlap a rotation needs. A shared secret
    cannot be changed on two machines at the same instant: between the moment
    the instance starts accepting the new secret and the moment the last
    adapter is restarted with it, every request signed with the old one is
    refused as ``AG-IDN-005`` -- an unknown adapter, which on ``fail: closed``
    is a blocked action. So a rotation names the old variable here, both are
    accepted while it is set, and ``qed adapters rotate --finish`` removes it
    once the fleet has caught up. A rotation with no overlap is an outage with
    a changelog entry.
    """

    adapter_id: str
    secret_env: str
    kind: str = "mcp"
    previous_secret_env: str = ""


class RateLimitConfig(Frozen):
    """Per-adapter and per-principal limits on proposals (SPEC §13).

    ```yaml
    api:
      rate_limit:
        per_adapter_rps: 100
        per_principal_rps: 20
    ```

    **Under `api:`, not the spec's `adapters.rate_limit`.** In this build
    `adapters` is a *list* of credentials, so a mapping with `rate_limit` in it
    would not parse at all -- an operator following §16 literally would get a
    validation error. `api` is where the limit actually applies, because the
    limit is on requests to the API and nothing else in the product has a
    request rate.

    **0 means off, not "refuse everything".** Zero reads as "no limit" to
    everyone who has ever written a config file, and a kernel that refused
    every proposal because somebody typed 0 would be an outage with a
    plausible cause. Negative is refused outright, because there is no reading
    of it that is a limit.
    """

    per_adapter_rps: float = 100.0
    per_principal_rps: float = 20.0

    @field_validator("per_adapter_rps", "per_principal_rps")
    @classmethod
    def _not_negative(cls, value: float) -> float:
        if value < 0:
            raise ValueError(
                f"a rate limit cannot be negative, and this is {value}. Use 0 to turn the "
                "limit off."
            )
        return value


class ApiConfig(Frozen):
    host: str = "127.0.0.1"
    port: int = 8710
    adapters: list[AdapterCredential] = Field(default_factory=list)
    #: Reject a signed request whose timestamp is further away than this.
    max_clock_skew_seconds: int = 300
    rate_limit: RateLimitConfig = RateLimitConfig()


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
    #: Unioned with the IdP's own `groups`/`roles` claims rather than replaced
    #: by them (:mod:`qed.api.human_auth`), because an installation whose IdP
    #: has no group mapper yet is the state every installation starts in.
    #: Explicit rather than assumed, so nobody is accidentally an approver.
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


class AdminConfig(Frozen):
    """Self-governance: which of qed's own operations need an approval.

    ```yaml
    admin:
      self_governed: true
      approvers: ["group:platform-oncall"]
      operations: [keys_rotate, packs_import, adapters_add, adapters_rotate]
      timeout: 24h
    ```

    **Off by default**, and that is a considered default rather than a
    placeholder. Self-governance needs a second person, and the common case is
    one operator on a laptop; on by default would make `qed keys rotate` stop
    working on first use, which teaches people the feature is an obstacle. What
    makes it honest is that `qed doctor` reports it either way, so an instance
    that is not self-governed says so rather than being quiet about it.

    `operations` is validated against :class:`~qed.core.admin.AdminOperation`,
    so a typo is an error at load. A misspelt operation name that silently
    governed nothing would be the worst kind of security setting: one an
    operator believes is on.
    """

    self_governed: bool = False
    #: Groups or subjects who may approve. Empty with `self_governed: true` is
    #: refused: a gate nobody can open is not a gate, it is an outage waiting
    #: for the first rotation.
    approvers: list[str] = Field(default_factory=list)
    #: The default stays `keys_rotate` and `packs_import`: widening it would
    #: turn self-governance on for operations an existing instance was not
    #: gating yesterday, on upgrade, with no edit to its config. An operator
    #: who wants `adapters_add` gated adds the name.
    operations: list[str] = Field(default_factory=lambda: ["keys_rotate", "packs_import"])
    #: How long a request stays open. Longer than an agent's approval by
    #: default: nobody rotates a key in the ninety seconds an agent waits.
    timeout: str = "24h"

    @field_validator("operations")
    @classmethod
    def _known_operations(cls, value: list[str]) -> list[str]:
        from qed.core.admin import AdminOperation

        known = {item.value for item in AdminOperation}
        unknown = [item for item in value if item not in known]
        if unknown:
            raise ValueError(
                f"unknown admin operation(s) {unknown}. The ones qed can gate are: "
                f"{sorted(known)}. A name that is nearly right would be a setting you "
                "believe is in force and is not."
            )
        return value

    @model_validator(mode="after")
    def _a_gate_needs_somebody_to_open_it(self) -> AdminConfig:
        if self.self_governed and not self.approvers:
            raise ValueError(
                "`admin.self_governed: true` with no `admin.approvers` is a gate nobody "
                "can open: the first `qed keys rotate` would be refused with no way "
                "forward but break-glass. Name the group that may approve."
            )
        return self

    def governed(self) -> frozenset[object]:
        """The operations this instance gates, as `AdminOperation` members."""
        from qed.core.admin import AdminOperation

        if not self.self_governed:
            return frozenset()
        return frozenset(AdminOperation(item) for item in self.operations)


class HistoryConfig(Frozen):
    """The 24-hour counters two shipped rules read (SPEC §5).

    ```yaml
    history:
      refresh_seconds: 60
    ```

    `AG-BUD-007` and `AG-IDN-010` read `derived.history.calls_24h` and
    `derived.history.blocks_24h`. Nothing collected them until 2026-10-15, so
    neither rule could fire; the spec claimed the API layer did.

    `refresh_seconds` is what makes collecting them affordable **and**
    replayable. The counters cover ``[end - 24h, end)`` with `end` floored to
    this many seconds, so every decision inside one bucket shares a value --
    one query per principal per bucket instead of one per decision -- and the
    window stays a pure function of the decision's own timestamp, which is
    what lets `qed replay` recompute the same numbers from the chain.

    A cache with a TTL would have been easier to write and would have made
    every replay of a history-dependent rule permanently inconclusive, because
    nothing records which stale value a decision happened to see.

    **0 means no alignment**, not "off": the window ends at the decision's own
    timestamp, the counters are exact, and every decision pays for a query.
    Turning collection off is not a setting because it does not need to be --
    a bundle whose active rules do not read `derived.history.*` is never
    queried at all.
    """

    refresh_seconds: int = DEFAULT_REFRESH_SECONDS

    @field_validator("refresh_seconds")
    @classmethod
    def _not_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError(
                f"`history.refresh_seconds` cannot be negative, and this is {value}. "
                "Use 0 for an exact window ending at each decision."
            )
        return value


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
    retention: RetentionConfig = RetentionConfig()
    observability: ObservabilityConfig = ObservabilityConfig()
    admin: AdminConfig = AdminConfig()
    history: HistoryConfig = HistoryConfig()

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


class ConfigError(ValueError):
    """`qed.yaml` is not usable, said in sentences.

    Pydantic's `ValidationError` is a good developer message and a poor
    operator one: `mode: nonsense` produced forty lines of frames and a URL,
    and the answer -- "mode must be shadow or enforce, and your file says
    nonsense" -- was in the middle of it. Worse, nothing caught it, so every
    command printed a traceback for a one-character typo in a config file.

    So the file path and the field path travel together here, and the CLI's
    group handler prints it without a traceback like any other statement about
    the operator's own setup.
    """


def _readable(path: Path, error: Exception) -> ConfigError:
    """Turn a pydantic `ValidationError` into something worth reading."""
    from pydantic import ValidationError

    if not isinstance(error, ValidationError):
        return ConfigError(f"{path}: {error}")

    lines = [f"{path} is not valid:"]
    for item in error.errors():
        # `('admin', 'operations')` -> `admin.operations`, and `()` -> the file
        # itself, which is what a model-level validator reports against.
        where = ".".join(str(part) for part in item["loc"]) or "(top level)"
        message = item["msg"].removeprefix("Value error, ")
        lines.append(f"  {where}: {message}")
    return ConfigError("\n".join(lines))


def load_config(path: Path | None) -> LoadedConfig:
    """Read ``qed.yaml`` if it exists; otherwise return defaults."""
    if path is None or not path.is_file():
        return LoadedConfig(config=QedConfig(), path=None)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    ignored = [key for key in UNIMPLEMENTED_SECTIONS if key in raw]
    try:
        config = QedConfig.model_validate(raw)
    except Exception as exc:
        raise _readable(path, exc) from exc
    return LoadedConfig(config=config, path=path, ignored_sections=ignored)
