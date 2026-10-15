"""`qed` command line (SPEC 14).

SPEC 14 forbids adding a top-level command without a spec update, so the
missing ones are absent rather than stubbed -- a command that prints "not
implemented" is worse than one that does not exist, because it ends up in
somebody's script.

``check`` exit codes (SPEC 12.5): 0 ALLOW, 2 BLOCK, 3 REQUIRE_APPROVAL, 1
error. In shadow mode the decision is recorded and the exit code is 0
(ADR-003), because a pipeline that failed in shadow mode would make shadow mode
useless as a way to find out what a policy would do.

``mcp`` is the one command that must not print to stdout: stdout is the MCP
transport, and a stray line of status text there is a protocol error that
presents to the user as "the server crashed". Everything it says goes to stderr.
"""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, cast

import typer
from typer.core import TyperGroup

from qed.config import DEFAULT_DIR, ConfigError
from qed.core.clock import assess_clock
from qed.core.evidence.export.jsonl import to_csv, to_jsonl
from qed.core.evidence.export.oscal import to_oscal
from qed.core.mandates import MandateError
from qed.core.policy.engine import explain as explain_proposal
from qed.core.policy.loader import baseline_pack_dir, load_bundle
from qed.core.schemas import (
    ActionProposal,
    Assurance,
    BudgetState,
    Decision,
    Enforcement,
    Environment,
    EvalContext,
    EvidenceType,
    HistoryDerived,
    Mandate,
    Verdict,
    rfc3339_ms,
    utcnow,
)
from qed.infra.chain_writer import InstanceMismatch, KeyDiscontinuity
from qed.infra.keys.file import PUBLIC_DIR_NAME, MissingSigningKey, init_keys
from qed.runtime import (
    EXIT_ALLOW,
    EXIT_APPROVAL,
    EXIT_BLOCK,
    EXIT_ERROR,
    DuplicateProposal,
    PolicyErrors,
    RotationRefused,
    Session,
    chain_status,
    check_proposal,
    open_session,
    plan_retention,
    rotate_signing_key,
    settle,
)

if TYPE_CHECKING:  # `qed mcp` imports the MCP SDK lazily: it is an
    # adapters-only dependency (SPEC 20.3) and `qed check` should not pay for
    # importing it on every invocation.
    from qed.adapters.http_proxy.proxy import HttpProxyStats
    from qed.adapters.mcp.proxy import ProxyStats
    from qed.core.admin import AdminOperation, GateDecision
    from qed.core.replay import ReplayReport
    from qed.core.schemas import EvidenceRecord
    from qed.demo import Step

#: Failures that are a statement about the operator's chain, not a bug in qed.
#:
#: Each already carries a sentence written for a person, and a traceback around
#: it helps nobody: "this chain was last signed by X" is the whole answer and
#: the frames above it are noise.
#:
#: `MandateError` joined the list when mandate signatures started being
#: verified: a forged or unsigned mandate is the most load-bearing refusal the
#: CLI makes, and printing it as a stack trace would make the one case that
#: matters look like a crash.
OPERATOR_ERRORS: Final = (InstanceMismatch, KeyDiscontinuity, ConfigError, MandateError)


class QedGroup(TyperGroup):
    """The command group, with one exception handler for the whole CLI.

    On the group rather than in :func:`main` because `main` is not the only
    way in -- the test runner and anything embedding `qed.cli.app` invoke the
    group directly, and a handler they skip is a handler that is not there.

    It also beats a `try` at each of the fifteen `open_session` call sites: a
    new command cannot forget to have one.
    """

    def invoke(self, ctx: Any) -> object:
        try:
            return super().invoke(ctx)
        except OPERATOR_ERRORS as exc:
            typer.secho(f"qed: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(EXIT_ERROR) from None

    def list_commands(self, ctx: Any) -> list[str]:
        """Definition order, with `demo` first.

        Typer keeps the order the commands were written in, which is roughly
        the order an operator meets them. `demo` is the exception: it is the
        first command a stranger should run and it was written last, so it is
        lifted to the front of `--help` here rather than by moving its hundred
        lines away from the helpers they belong with.
        """
        names = super().list_commands(ctx)
        if "demo" not in names:  # pragma: no cover - defensive
            return names
        return ["demo", *(name for name in names if name != "demo")]


app = typer.Typer(
    cls=QedGroup,
    add_completion=False,
    no_args_is_help=True,
    help="Policy and evidence kernel for AI-agent actions.",
)
keys_app = typer.Typer(no_args_is_help=True, help="Evidence signing keys.")
policy_app = typer.Typer(no_args_is_help=True, help="Policy bundle tools.")
packs_app = typer.Typer(no_args_is_help=True, help="Compliance control catalogues.")
mandate_app = typer.Typer(no_args_is_help=True, help="Mandates for unattended agents.")
adapters_app = typer.Typer(no_args_is_help=True, help="Adapter identities (SPEC 12.6).")
app.add_typer(keys_app, name="keys")
app.add_typer(policy_app, name="policy")
app.add_typer(packs_app, name="packs")
app.add_typer(mandate_app, name="mandate")
app.add_typer(adapters_app, name="adapters")

DirOption = Annotated[Path, typer.Option("--dir", help="qed state directory (keys and chain).")]

# Self-governance (SPEC 17). Three options shared by every gated command, so
# `qed keys rotate` and `qed packs import` take the same words for the same
# thing -- an operator should not have to remember which one spells it how.
ByOption = Annotated[
    str, typer.Option("--by", help="Your subject, when this operation is self-governed.")
]
ApprovalOption = Annotated[
    str | None, typer.Option("--approval", help="An approval id that authorises this.")
]
BreakGlassOption = Annotated[
    str,
    typer.Option(
        "--break-glass",
        help="Proceed without an approval, recording this reason. For incidents.",
    ),
]
PolicyOption = Annotated[
    list[Path] | None,
    typer.Option("--policy", help="Extra policy file or directory. Repeatable."),
]
ConfigOption = Annotated[Path | None, typer.Option("--config", help="Path to qed.yaml.")]


def _fail(message: str) -> None:
    typer.secho(f"qed: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


# ---------------------------------------------------------------------- keys


def _admin_gate(
    session: Session,
    operation: AdminOperation,
    *,
    by: str,
    approval: str | None,
    break_glass: str,
    detail: dict[str, object] | None = None,
) -> GateDecision | None:
    """Run the self-governance gate, or open a request and stop.

    Returns the decision when the operation may proceed, and **None** when a
    request was opened instead -- in which case the caller must not act. The
    exit code is 3, SPEC 12.5's REQUIRE_APPROVAL, the same number a gated agent
    action gets: a pipeline that already branches on 3 does not need to learn a
    second convention for qed's own operations.
    """
    from qed.core.admin import AdminRefusal
    from qed.runtime import admin_gate, open_admin_request

    governed = operation in session.config.admin.governed()
    if governed and approval is None and not break_glass:
        if not by:
            session.close()
            _fail(
                f"{operation.value} is self-governed on this instance, so it needs to know "
                "who is asking: pass `--by you@example.com`."
            )
            return None
        request = open_admin_request(session, operation, requester=by, detail=detail)
        session.close()
        typer.secho(f"approval required: {request.id}", fg=typer.colors.YELLOW, bold=True)
        typer.echo(f"  operation : {operation.value}")
        typer.echo(f"  approvers : {', '.join(session.config.admin.approvers)}")
        typer.echo(f"  expires   : {rfc3339_ms(request.expires_at)}")
        typer.echo("")
        typer.echo(f"  qed approve {request.id} --by someone-else@example.com")
        typer.echo(f"  qed {operation.value.replace('_', ' ')} --approval {request.id} --by {by}")
        raise typer.Exit(code=EXIT_APPROVAL)

    try:
        decision = admin_gate(
            session, operation, requester=by, approval_id=approval, break_glass=break_glass
        )
    except AdminRefusal as exc:
        session.close()
        _fail(str(exc))
        return None

    if decision.break_glass:
        typer.secho(
            f"BREAK-GLASS: {operation.value} proceeding without an approval. "
            f"This is recorded in the chain. Reason: {decision.reason}",
            fg=typer.colors.RED,
            bold=True,
            err=True,
        )
    return decision


@keys_app.command("init")
def keys_init(
    directory: DirOption = DEFAULT_DIR,
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Replace an existing key. Breaks the chain.")
    ] = False,
) -> None:
    """Create the Ed25519 evidence signing key."""
    try:
        info = init_keys(directory, overwrite=overwrite)
    except FileExistsError as exc:
        _fail(f"{exc}. Use `qed keys rotate` to change keys without breaking the chain.")
        return
    typer.echo(f"key_id : {info.key_id}")
    typer.echo(f"private: {directory / 'evidence-key.pem'}  (keep this; 0600)")
    typer.echo(f"public : {directory / PUBLIC_DIR_NAME}  (give this to auditors)")


@keys_app.command("rotate")
def keys_rotate(
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Do not ask. For a scripted rotation."),
    ] = False,
    by: ByOption = "",
    approval: ApprovalOption = None,
    break_glass: BreakGlassOption = "",
) -> None:
    """Replace the signing key, keeping the chain verifiable across the change.

    Appends a `key_rotated` record signed by the **retiring** key, then
    activates the new one (SPEC 10.5, ADR-0010). The old private key is
    destroyed: rotation exists because a key might have leaked, and leaving the
    old one on disk would reduce nothing. The old *public* key stays, and must
    -- without it the chain before this point cannot be verified at all.
    """
    try:
        session = open_session(directory=directory, config_path=config, strict_policy=False)
    except MissingSigningKey as exc:
        _fail(str(exc))
        return

    from qed.core.admin import AdminOperation

    decision = _admin_gate(
        session,
        AdminOperation.keys_rotate,
        by=by,
        approval=approval,
        break_glass=break_glass,
        detail={"retiring_key_id": session.signer.key_id},
    )
    if decision is None:
        return

    if not yes:
        typer.echo(f"active key : {session.signer.key_id}")
        typer.echo("")
        typer.echo("Rotation will:")
        typer.echo("  - append `key_rotated` to the chain, signed by the key above")
        typer.echo("  - generate a new key and make it active")
        typer.echo("  - DESTROY the old private key (the public key is kept)")
        typer.echo("")
        typer.echo("Everything already in the chain stays verifiable, with both public keys.")
        if not typer.confirm("Rotate now?"):
            session.close()
            typer.echo("nothing was changed")
            return

    try:
        rotation = rotate_signing_key(session)
    except RotationRefused as exc:
        session.close()
        _fail(str(exc))
        return
    except MissingSigningKey as exc:
        session.close()
        _fail(str(exc))
        return

    # The authorisation travels with the operation's own record. `key_rotated`
    # is the chain event; this `admin_action` is who allowed it, and an auditor
    # reading one wants the other.
    session.writer.append(
        type_=EvidenceType.admin_action,
        assurance=Assurance.kernel,
        payload={
            "action": "keys_rotate",
            "retired_key_id": rotation.old_key_id,
            "active_key_id": rotation.new_key_id,
            **decision.payload(),
        },
    )
    session.close()
    typer.secho("rotated", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  retired : {rotation.old_key_id}")
    typer.echo(f"  active  : {rotation.new_key_id}")
    typer.echo(f"  record  : seq {rotation.record.seq} (key_rotated, signed by the old key)")
    typer.echo(f"  keep    : {rotation.retired_public_key}")
    typer.echo("")
    typer.echo(
        "Give auditors the whole `public/` directory. A chain that spans a rotation "
        "cannot be verified from the active key alone."
    )


@keys_app.command("export-public")
def keys_export_public(
    directory: DirOption = DEFAULT_DIR,
    active_only: Annotated[
        bool,
        typer.Option("--active", help="Only the key signing now."),
    ] = False,
) -> None:
    """Print the public keys an auditor needs, newest last.

    Every key by default, not just the active one: a chain that spans a
    rotation cannot be verified without the retired keys, and the usual way
    that goes wrong is somebody sending one PEM because that is what this
    command used to print.
    """
    try:
        session = open_session(directory=directory, strict_policy=False)
    except MissingSigningKey as exc:
        _fail(str(exc))
        return

    if active_only:
        typer.echo(session.signer.public_pem.rstrip())
        session.close()
        return

    keys = session.store.signing_keys()
    active = session.signer.key_id
    session.close()
    if not keys:  # pragma: no cover - the writer records the active key on open
        typer.echo(session.signer.public_pem.rstrip())
        return
    for key in keys:
        state = "active" if key.key_id == active else "retired"
        # A comment line, so the output stays a concatenation of valid PEM:
        # `qed keys export-public > public.pem` has to be usable as it is.
        typer.echo(f"# {key.key_id}  {state}")
        typer.echo(key.public_pem.rstrip())


# ------------------------------------------------------------------ adapters


#: What an adapter id may contain. It travels in an HTTP header
#: (`X-QED-Adapter-Id`) and lands in evidence that an auditor reads, so the
#: character set is narrow on purpose: a header value with a newline in it is
#: a request-splitting bug, and an id that renders differently in two tools is
#: an identity nobody can follow through the chain.
ADAPTER_ID_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")


def _secret_env_name(adapter_id: str) -> str:
    """The conventional variable name for an adapter's secret."""
    return "QED_ADAPTER_SECRET_" + re.sub(r"[^A-Z0-9]", "_", adapter_id.upper())


def _new_secret() -> str:
    """A secret the operator never has to think about the strength of.

    32 bytes from `secrets.token_urlsafe` is 43 characters, comfortably past
    the 32 the API requires. Generated here rather than asked for, because a
    shared secret somebody invents is a password, and `MIN_SECRET_LENGTH`
    exists to catch exactly that.
    """
    import secrets as _secrets

    return _secrets.token_urlsafe(32)


def _adapters_config(directory: Path, explicit: Path | None) -> Path:
    """Which `qed.yaml` these commands read and write.

    `--config` when given, otherwise `<dir>/qed.yaml`. The fallback is a
    convention and not discovery: nothing else in `qed` looks for a config
    file it was not handed, and these commands print the path they used so
    that editing the wrong file is a thing an operator can see rather than
    deduce.

    A missing file is refused rather than created. An `add` that invented a
    `qed.yaml` would leave a config the running instance never reads -- the
    adapter would look registered and be refused as `AG-IDN-005`, which is
    the most expensive way to learn where the file should have gone.
    """
    path = explicit if explicit is not None else directory / "qed.yaml"
    if not path.is_file():
        _fail(
            f"there is no config file at {path}, so there is nothing to register the "
            "adapter in. Create one (SPEC 16), or pass `--config`."
        )
        raise AssertionError  # pragma: no cover - `_fail` raises
    return path


@adapters_app.command("add")
def adapters_add(
    adapter_id: Annotated[str, typer.Argument(help="The identity to register, e.g. mcp-proxy-ci.")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    kind: Annotated[str, typer.Option("--kind", help="What sort of adapter this is.")] = "mcp",
    secret_env: Annotated[
        str,
        typer.Option("--secret-env", help="Variable the secret will live in. Default is derived."),
    ] = "",
    by: ByOption = "",
    approval: ApprovalOption = None,
    break_glass: BreakGlassOption = "",
) -> None:
    """Register an adapter and print its secret once (SPEC 12.6).

    Writes `adapter_id`, `secret_env` and `kind` into `qed.yaml` and generates
    the shared secret. **The secret is printed and never stored**: it goes in
    the environment variable named here, which is why `qed.yaml` stays safe to
    commit. There is no command that will show it again -- `qed adapters
    rotate` issues a new one.

    Registering an adapter grants an identity the right to submit proposals to
    this kernel, so it is a self-governed admin operation (SPEC 17) and it
    leaves an `admin_action` record naming the adapter and the variable. Not
    the secret: evidence is the one place a shared secret must never reach.
    """
    from qed.config import AdapterCredential
    from qed.core.admin import AdminOperation
    from qed.infra.config_edit import ConfigEditRefused, add_adapter

    if not ADAPTER_ID_PATTERN.match(adapter_id):
        _fail(
            f"{adapter_id!r} is not a usable adapter id. Lower-case letters, digits, "
            "hyphens and underscores, 2 to 63 characters, starting with a letter or "
            "digit -- it travels in an HTTP header and into evidence."
        )
        return

    path = _adapters_config(directory, config)
    try:
        session = open_session(directory=directory, config_path=path, strict_policy=False)
    except MissingSigningKey as exc:
        _fail(str(exc))
        return

    entry = AdapterCredential(
        adapter_id=adapter_id,
        secret_env=secret_env or _secret_env_name(adapter_id),
        kind=kind,
    )

    decision = _admin_gate(
        session,
        AdminOperation.adapters_add,
        by=by,
        approval=approval,
        break_glass=break_glass,
        detail={"adapter_id": adapter_id, "secret_env": entry.secret_env},
    )
    if decision is None:
        return

    try:
        add_adapter(path, entry)
    except ConfigEditRefused as exc:
        session.close()
        _fail(str(exc))
        return

    secret = _new_secret()
    session.writer.append(
        type_=EvidenceType.admin_action,
        assurance=Assurance.kernel,
        payload={
            "action": "adapters_add",
            "adapter_id": adapter_id,
            "secret_env": entry.secret_env,
            "kind": entry.kind,
            **decision.payload(),
        },
    )
    session.close()

    typer.secho("registered", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  adapter : {adapter_id}")
    typer.echo(f"  kind    : {entry.kind}")
    typer.echo(f"  config  : {path}")
    typer.echo("")
    typer.echo("Set this on the instance and on the adapter, then restart both:")
    typer.echo("")
    typer.echo(f"  export {entry.secret_env}={secret}")
    typer.echo("")
    typer.secho(
        "This is the only time the secret is shown. It is not in qed.yaml and not in the chain.",
        fg=typer.colors.YELLOW,
    )


@adapters_app.command("list")
def adapters_list(
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit as JSON.")] = False,
) -> None:
    """Show registered adapters and whether each one can actually authenticate.

    The second half is the point. A registered adapter whose `secret_env` is
    unset is refused at runtime with `AG-IDN-005` -- an unknown adapter -- and
    the only previous way to discover that was to start the server and read
    `/v1/status`. Secrets are never printed; what is reported is whether the
    variable is set and long enough.
    """
    from qed.api.auth import MIN_SECRET_LENGTH
    from qed.config import load_config

    path = config if config is not None else directory / "qed.yaml"
    loaded = load_config(path if path.is_file() else None)
    rows: list[dict[str, object]] = []
    for entry in loaded.config.registered_adapters:
        secret = os.environ.get(entry.secret_env, "")
        if not secret:
            state = "no secret"
        elif len(secret) < MIN_SECRET_LENGTH:
            state = "too short"
        else:
            state = "ready"
        row: dict[str, object] = {
            "adapter_id": entry.adapter_id,
            "kind": entry.kind,
            "secret_env": entry.secret_env,
            "state": state,
        }
        if entry.previous_secret_env:
            # The overlap's own state, checked the same way as the current
            # secret. `/readyz` deliberately stays green on a stale rotation
            # variable -- an instance that can authenticate restarted
            # adapters must keep serving -- so this is where an operator
            # mid-rotation finds out the grace period is not actually there.
            previous = os.environ.get(entry.previous_secret_env, "")
            row["previous_secret_env"] = entry.previous_secret_env
            row["overlap"] = (
                "accepted"
                if len(previous) >= MIN_SECRET_LENGTH
                else ("too short" if previous else "unset")
            )
        rows.append(row)

    if as_json:
        typer.echo(json.dumps({"config": str(loaded.path or ""), "adapters": rows}, indent=2))
        return

    if not rows:
        typer.echo("no adapters are registered")
        typer.echo("")
        typer.echo("  qed adapters add <id>")
        return

    width = max(len(str(row["adapter_id"])) for row in rows)
    for row in rows:
        colour = {
            "ready": typer.colors.GREEN,
            "no secret": typer.colors.RED,
            "too short": typer.colors.RED,
        }[str(row["state"])]
        typer.echo(f"{row['adapter_id']!s:<{width}}  {row['kind']:<6}  ", nl=False)
        typer.secho(f"{row['state']:<9}", fg=colour, nl=False)
        typer.echo(f"  ${row['secret_env']}")
        if row.get("previous_secret_env"):
            # "unset" is not "finished": the entry still names the old
            # variable, so the overlap it promises simply is not in effect.
            # Saying `rotation complete` here would tell an operator the
            # opposite of what `--finish` is for.
            note = {
                "accepted": "still accepted",
                "unset": "unset, so no overlap is in effect",
                "too short": "set but too short, so no overlap is in effect",
            }[str(row["overlap"])]
            typer.echo(f"{'':<{width}}  rotating via ${row['previous_secret_env']} ({note})")


@adapters_app.command("rotate")
def adapters_rotate(
    adapter_id: Annotated[str, typer.Argument(help="The adapter to give a new secret.")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    finish: Annotated[
        bool,
        typer.Option("--finish", help="End a rotation: stop accepting the previous secret."),
    ] = False,
    by: ByOption = "",
    approval: ApprovalOption = None,
    break_glass: BreakGlassOption = "",
) -> None:
    """Issue a new secret for an adapter, keeping the old one working meanwhile.

    A shared secret cannot change on two machines at the same instant. Between
    the instance taking the new secret and the last adapter being restarted
    with it, every request signed with the old one would be refused as
    `AG-IDN-005` -- and under `fail: closed` a refused request is a blocked
    action. So rotation is two steps:

        qed adapters rotate mcp-proxy-ci     # new secret; both accepted
        ...roll it out across the fleet...
        qed adapters rotate mcp-proxy-ci --finish    # old one stops working

    Until `--finish`, the entry names both variables and either signature
    verifies. A rotation that skipped the overlap would be an outage with a
    changelog entry, which is why it is not offered as a flag.
    """
    from qed.config import AdapterCredential
    from qed.core.admin import AdminOperation
    from qed.infra.config_edit import ConfigEditRefused, rewrite_adapter

    path = _adapters_config(directory, config)
    try:
        session = open_session(directory=directory, config_path=path, strict_policy=False)
    except MissingSigningKey as exc:
        _fail(str(exc))
        return

    current = next(
        (entry for entry in session.config.registered_adapters if entry.adapter_id == adapter_id),
        None,
    )
    if current is None:
        session.close()
        _fail(
            f"adapter {adapter_id} is not registered in {path}. "
            "`qed adapters list` shows the ones that are."
        )
        return

    if finish and not current.previous_secret_env:
        session.close()
        _fail(
            f"adapter {adapter_id} is not mid-rotation, so there is no previous secret to "
            "stop accepting."
        )
        return

    decision = _admin_gate(
        session,
        AdminOperation.adapters_rotate,
        by=by,
        approval=approval,
        break_glass=break_glass,
        detail={"adapter_id": adapter_id, "finish": finish},
    )
    if decision is None:
        return

    if finish:
        updated = AdapterCredential(
            adapter_id=adapter_id,
            secret_env=current.secret_env,
            kind=current.kind,
        )
    else:
        # The new secret goes in a *new* variable, and the old name becomes
        # the previous one. Reusing one variable would mean the overlap had
        # nowhere to live: the moment it is overwritten the old secret is gone
        # from the machine, which is the cutover this exists to avoid.
        updated = AdapterCredential(
            adapter_id=adapter_id,
            secret_env=_next_secret_env(current.secret_env),
            kind=current.kind,
            previous_secret_env=current.secret_env,
        )

    try:
        rewrite_adapter(path, updated)
    except ConfigEditRefused as exc:
        session.close()
        _fail(str(exc))
        return

    secret = "" if finish else _new_secret()
    session.writer.append(
        type_=EvidenceType.admin_action,
        assurance=Assurance.kernel,
        payload={
            "action": "adapters_rotate",
            "adapter_id": adapter_id,
            "secret_env": updated.secret_env,
            "previous_secret_env": updated.previous_secret_env,
            "finished": finish,
            **decision.payload(),
        },
    )
    session.close()

    if finish:
        typer.secho("rotation finished", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"  adapter : {adapter_id}")
        typer.echo(f"  accepts : ${updated.secret_env} only")
        typer.echo("")
        typer.echo(f"${current.previous_secret_env} can now be removed from the environment.")
        return

    typer.secho("rotating", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  adapter  : {adapter_id}")
    typer.echo(f"  new      : ${updated.secret_env}")
    typer.echo(f"  previous : ${current.secret_env} (still accepted)")
    typer.echo("")
    typer.echo("Set the new secret on the instance and on the adapter, then restart both:")
    typer.echo("")
    typer.echo(f"  export {updated.secret_env}={secret}")
    typer.echo("")
    typer.echo("When every adapter is using it:")
    typer.echo("")
    typer.echo(f"  qed adapters rotate {adapter_id} --finish")
    typer.echo("")
    typer.secho(
        "This is the only time the new secret is shown.",
        fg=typer.colors.YELLOW,
    )


def _next_secret_env(current: str) -> str:
    """The variable name for the next secret in a rotation.

    `..._V2`, `..._V3`, and so on. A counter rather than a date because the
    name goes in a config file that lives for years and `_20261015` reads as
    an expiry to the next person.
    """
    match = re.search(r"_V(\d+)$", current)
    if match:
        return f"{current[: match.start()]}_V{int(match.group(1)) + 1}"
    return f"{current}_V2"


# --------------------------------------------------------------------- check


@app.command()
def check(
    proposal_file: Annotated[Path, typer.Argument(help="ActionProposal as JSON.")],
    directory: DirOption = DEFAULT_DIR,
    policy: PolicyOption = None,
    config: ConfigOption = None,
    budget_file: Annotated[
        Path | None, typer.Option("--budget", help="BudgetState as JSON.")
    ] = None,
    mandate_file: Annotated[Path | None, typer.Option("--mandate", help="Mandate as JSON.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the verdict as JSON.")] = False,
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            envvar="QED_URL",
            help="Decide on a QED instance instead of locally. The evidence lives there.",
        ),
    ] = None,
    adapter_id: Annotated[
        str | None,
        typer.Option("--adapter-id", envvar="QED_ADAPTER_ID", help="With --server."),
    ] = None,
    adapter_secret_env: Annotated[
        str,
        typer.Option(
            "--adapter-secret-env",
            help="Environment variable holding the adapter secret. With --server.",
        ),
    ] = "QED_ADAPTER_SECRET",
    evidence_out: Annotated[
        Path | None,
        typer.Option(
            "--evidence-out",
            help=(
                "Write the chain to this file as JSONL after deciding locally, so an "
                "ephemeral runner leaves something `qed-verify` can check."
            ),
        ),
    ] = None,
) -> None:
    """Decide one proposal, append proposal and verdict to the chain.

    Exit 0 ALLOW, 2 BLOCK, 3 REQUIRE_APPROVAL, 1 if QED could not decide at
    all (SPEC 12.5). The last one is separate on purpose: a pipeline has to
    be able to tell a refusal from a misconfigured runner, and conflating them
    would let a missing signing key read as a policy that allows everything.
    """
    try:
        proposal = ActionProposal.model_validate_json(proposal_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"cannot read proposal: {exc}")
        return

    if server:
        _check_remote(
            proposal,
            server=server,
            adapter_id=adapter_id,
            adapter_secret_env=adapter_secret_env,
            as_json=as_json,
        )
        return

    budget = (
        BudgetState.model_validate_json(budget_file.read_text(encoding="utf-8"))
        if budget_file
        else None
    )
    mandate = (
        Mandate.model_validate_json(mandate_file.read_text(encoding="utf-8"))
        if mandate_file
        else None
    )

    try:
        session = open_session(directory=directory, policy_paths=policy, config_path=config)
    except MissingSigningKey as exc:
        _fail(str(exc))
        return
    except PolicyErrors as exc:
        for finding in exc.findings:
            typer.secho(f"  {finding.format()}", fg=typer.colors.RED, err=True)
        _fail("the policy bundle has errors; refusing to decide against a broken bundle")
        return

    try:
        outcome = check_proposal(session, proposal, budget=budget, mandate=mandate)
    except DuplicateProposal as exc:
        session.close()
        _fail(str(exc))
        return

    verdict = outcome.verdict
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "verdict": verdict.model_dump(mode="json"),
                    "enforced": outcome.enforced,
                    "effective_decision": outcome.effective_decision.value,
                    "evidence_seq": [r.seq for r in outcome.records],
                },
                indent=2,
            )
        )
    else:
        colour = {
            Decision.ALLOW: typer.colors.GREEN,
            Decision.REQUIRE_APPROVAL: typer.colors.YELLOW,
            Decision.BLOCK: typer.colors.RED,
        }[verdict.decision]
        typer.secho(f"{verdict.decision.value}", fg=colour, bold=True)
        if not outcome.enforced:
            typer.echo("  (shadow mode: recorded, not enforced -- would be above)")
        typer.echo(f"  blast radius : {verdict.blast_radius}/100")
        typer.echo(f"  would decide : {verdict.would_decision.value}")
        typer.echo(f"  policy hash  : {verdict.policy_hash[:16]}...")
        typer.echo(f"  evidence seq : {', '.join(str(r.seq) for r in outcome.records)}")
        for hit in verdict.hits:
            marker = "~" if hit.mode.value == "shadow" else "!"
            typer.echo(f"  {marker} {hit.rule_id} [{hit.severity.value}] {hit.message}")
            if hit.fix:
                typer.echo(f"      fix: {hit.fix}")

    if evidence_out is not None:
        _write_evidence_artifact(session, evidence_out, as_json=as_json)

    session.close()
    raise typer.Exit(outcome.exit_code)


def _check_remote(
    proposal: ActionProposal,
    *,
    server: str,
    adapter_id: str | None,
    adapter_secret_env: str,
    as_json: bool,
) -> None:
    """``qed check --server`` (SPEC 12.5): somebody else decides and keeps the record.

    This is the mode that makes sense in CI. The local path needs a signing key
    in the runner and leaves the chain in a workspace that is deleted with the
    build, so the evidence for a decision that gated a deployment would live
    for the length of one job.
    """
    from qed.adapters.remote import RemoteError, submit

    secret = os.environ.get(adapter_secret_env, "")
    if not adapter_id or not secret:
        _fail(
            f"--server needs an adapter identity: --adapter-id (or QED_ADAPTER_ID) and "
            f"the secret in ${adapter_secret_env}. Register it on the instance first "
            f"with `qed adapters add` (SPEC 12.6); an unknown adapter is refused "
            f"with AG-IDN-005."
        )
        return

    try:
        remote = submit(proposal, url=server, adapter_id=adapter_id, adapter_secret=secret)
    except RemoteError as exc:
        # Exit 1 and not 2. An instance that could not be reached has not
        # refused anything, and a pipeline that read this as a BLOCK would
        # report a policy violation that no policy produced.
        _fail(str(exc))
        return

    if as_json:
        typer.echo(json.dumps(remote.raw, indent=2))
    else:
        colour = {
            Decision.ALLOW: typer.colors.GREEN,
            Decision.REQUIRE_APPROVAL: typer.colors.YELLOW,
            Decision.BLOCK: typer.colors.RED,
        }[remote.decision]
        typer.secho(remote.decision.value, fg=colour, bold=True)
        if not remote.enforced:
            typer.echo("  (shadow mode on the server: recorded, not enforced)")
        typer.echo(f"  decided by   : {server}")
        typer.echo(f"  evidence ref : {remote.evidence_ref}")
        if remote.approval_id:
            typer.echo(f"  approval     : {remote.approval_id}")
        verdict = remote.raw.get("verdict")
        if isinstance(verdict, dict):
            for hit in verdict.get("hits", []):
                if isinstance(hit, dict):
                    typer.echo(f"  ! {hit.get('rule_id')} {hit.get('message')}")

    raise typer.Exit(
        {
            Decision.ALLOW: EXIT_ALLOW,
            Decision.BLOCK: EXIT_BLOCK,
            Decision.REQUIRE_APPROVAL: EXIT_APPROVAL,
        }[remote.effective_decision]
    )


def _write_evidence_artifact(session: Session, path: Path, *, as_json: bool) -> None:
    """Export the chain so the decision outlives the runner (SPEC 12.5).

    The whole chain and not just this verdict: `qed-verify` walks linkage from
    genesis, so a file holding only the last two records is a file that cannot
    be verified. A CI chain is short by nature -- it starts at genesis in a
    fresh workspace -- so there is nothing to trim.
    """
    # Queued records have no sequence number yet, and an export missing them
    # would be a gap `qed-verify` reports as a broken chain.
    settle(session)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(to_jsonl(session.store.iter_evidence()), encoding="utf-8")
    except OSError as exc:
        # Loud, and not fatal: the verdict has already been printed and the
        # exit code is about the policy, not about a full disk.
        typer.secho(f"could not write {path}: {exc}", fg=typer.colors.RED, err=True)
        return
    if not as_json:
        typer.echo(f"  evidence     : {path} ({session.store.count_evidence()} records)")


# --------------------------------------------------------------------- packs


@packs_app.command("list")
def packs_list(
    directory: DirOption = DEFAULT_DIR,
    policy: PolicyOption = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    include_baseline: Annotated[
        bool, typer.Option("--baseline/--no-baseline", help="Include the shipped pack.")
    ] = True,
) -> None:
    """Control catalogues, and what this rule set maps to (SPEC 11).

    The question an auditor asks first is not "which controls do you claim?"
    but "which do you *not*". So this prints the unmapped ones too, and refuses
    to print a percentage for a catalogue that is only partial -- over a list
    of the controls somebody chose to list, a percentage reads as complete and
    is not.
    """
    from qed.compliance.packs import coverage, packs, use_imported
    from qed.remote.packs import installed_dir

    # Same as a session: an imported catalogue replaces a shipped one, and this
    # report is where somebody looks to find out whether one has.
    use_imported(installed_dir(directory))

    paths = list(policy or [])
    if include_baseline:
        paths.insert(0, baseline_pack_dir())
    result = load_bundle([p for p in paths if p.exists()])
    rows = coverage(result.bundle.rules)

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "catalogues": [row.describe() for row in rows],
                    "sources": {item.framework: item.source for item in packs()},
                },
                indent=2,
            )
        )
        return

    typer.echo(f"{'FRAMEWORK':<16} {'DEPTH':<9} {'MAPPED':>9}  {'COVERAGE':>9}  RULES")
    for row in rows:
        share = f"{row.percentage}%" if row.percentage is not None else "partial"
        colour = (
            typer.colors.YELLOW
            if row.mapped == 0
            else (typer.colors.GREEN if row.percentage == 100.0 else None)
        )
        typer.secho(
            f"{row.framework:<16} {row.depth:<9} {row.mapped:>4}/{row.controls:<4} "
            f"{share:>9}  {len(row.rules)}",
            fg=colour,
        )

    # Every percentage above is a share of a *scope*, and the scope is the half a
    # reader drops. `eu_ai_act 44.4%` reads as 44% of the Regulation and is 4 of
    # the 9 articles this catalogue covers, out of 113. So the scope prints with
    # the number rather than staying in the YAML file nobody opens.
    typer.echo("")
    typer.echo("Each figure is a share of the catalogue's scope:")
    for row in rows:
        if not row.scope:
            continue
        scope = " ".join(row.scope.split())
        wrapped = textwrap.wrap(scope, width=76, initial_indent="    ", subsequent_indent="    ")
        typer.echo(f"  {row.framework}:")
        for line in wrapped:
            typer.echo(line)

    # A gap with a stated reason is something an auditor can disagree with; a
    # bare absence is something they can only guess at. So the ones that say
    # why are separated from the ones that do not.
    typer.echo("")
    for row in rows:
        if not row.unmapped:
            continue
        silent = [item for item in row.unmapped if item not in row.unmapped_notes]
        if silent:
            typer.echo(f"{row.framework}: not mapped -- {', '.join(silent)}")
        for control, note in row.unmapped_notes.items():
            reason = " ".join(note.split())
            lines = textwrap.wrap(reason, width=72, initial_indent="    ", subsequent_indent="    ")
            typer.echo(f"{row.framework}: not mapped -- {control}:")
            for line in lines:
                typer.echo(line)
    typer.echo("")
    typer.echo(
        "`partial` means the catalogue lists the controls this rule set maps to and not "
        "the whole framework, so there is no honest percentage to print. A `complete` "
        "catalogue is complete for the scope above it and not for the whole standard. "
        "`depth` is SPEC 11's flag: how deep the mapping goes, not how good it is."
    )


@packs_app.command("verify")
def packs_verify(
    path: Annotated[Path, typer.Argument(help="A pack bundle.")],
    public_key: Annotated[
        Path | None,
        typer.Option("--public-key", help="PEM public key of the publisher's pack key."),
    ] = None,
) -> None:
    """Show what a bundle contains, and whether it verifies. Installs nothing.

    Separate from `import` on purpose: whether to trust a catalogue is a
    decision somebody should make with the contents in front of them, and a
    command that showed you the contents by installing them would not be
    giving you the choice.
    """
    from qed.remote.packs import BundleRejected, load_bundle_file, load_public_key, verify

    try:
        bundle = load_bundle_file(path)
    except BundleRejected as exc:
        _fail(str(exc))
        return

    typer.echo(f"issuer     : {bundle.issuer}")
    typer.echo(f"issued at  : {bundle.issued_at}")
    typer.echo(f"bundle hash: {bundle.bundle_hash}")
    typer.echo(f"key id     : {bundle.key_id or '(none: unsigned)'}")
    for item in bundle.packs:
        mark = "complete" if item.complete else "partial"
        typer.echo(f"  {item.framework:<16} {len(item.controls):>3} controls  {mark}")

    if public_key is None:
        typer.secho(
            "not verified: no --public-key given. A bundle names the key that signed "
            "it, which proves nothing on its own -- get the public key from the "
            "publisher, by some route other than the bundle.",
            fg=typer.colors.YELLOW,
        )
        return

    try:
        verify(bundle, load_public_key(public_key))
    except BundleRejected as exc:
        _fail(str(exc))
        return
    typer.secho(f"signature verifies under {bundle.key_id}", fg=typer.colors.GREEN)


@packs_app.command("import")
def packs_import(
    path: Annotated[Path, typer.Argument(help="A pack bundle.")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    public_key: Annotated[
        Path | None,
        typer.Option("--public-key", help="PEM public key of the publisher's pack key."),
    ] = None,
    unsigned: Annotated[
        bool,
        typer.Option(
            "--unsigned",
            help="Import a bundle with no signature. Recorded as unsigned, for good.",
        ),
    ] = False,
    allow_rollback: Annotated[
        bool,
        typer.Option("--allow-rollback", help="Permit a bundle older than the installed one."),
    ] = False,
    allow_orphans: Annotated[
        bool,
        typer.Option(
            "--allow-orphaned-rules",
            help="Import even if it leaves rules citing controls it does not define.",
        ),
    ] = False,
    by: ByOption = "",
    approval: ApprovalOption = None,
    break_glass: BreakGlassOption = "",
) -> None:
    """Import a control catalogue (SPEC 11).

    An imported catalogue decides what `qed packs list` reports and what an
    OSCAL finding's `control-label` says, so the import is recorded in the
    chain as an `admin_action`: a control title an auditor reads has to be
    traceable to a moment and a key.

    Reads a file and nothing else. That is the air-gap case, and it is the only
    case there is until the `remote.packs` feed exists -- which is this same
    verification with a download in front of it.
    """
    from qed.compliance.packs import use_imported
    from qed.core.schemas import Assurance, EvidenceType
    from qed.remote.packs import (
        BundleRejected,
        check_not_older,
        installed_dir,
        load_bundle_file,
        load_public_key,
        verify,
        would_break,
        write_installed,
    )

    try:
        bundle = load_bundle_file(path)
        if unsigned:
            if bundle.signed:
                _fail(
                    "this bundle is signed, so `--unsigned` is not what you want: pass "
                    "`--public-key` and have the signature checked. Importing a signed "
                    "bundle as unsigned throws away the one thing that makes its "
                    "control titles traceable."
                )
                return
        elif public_key is None:
            _fail(
                "pass `--public-key PEM` to check the signature, or `--unsigned` to "
                "accept a bundle that has none. There is no default key: a publisher's "
                "key has to arrive by some route other than the bundle, or the "
                "signature is checking the bundle against itself."
            )
            return
        else:
            verify(bundle, load_public_key(public_key))

        if not allow_rollback:
            check_not_older(bundle, directory)
    except BundleRejected as exc:
        _fail(str(exc))
        return

    # The session is opened *before* anything is written, and with
    # `strict_policy=False`. Two reasons, both learned the hard way elsewhere in
    # this file. A missing signing key must fail before the catalogues land on
    # disk, or the import happened and nothing recorded it. And the installed
    # rules may well cite a control that only this bundle defines -- refusing to
    # open because the bundle is not installed yet would make the import
    # impossible, which is the wrong way round.
    try:
        session = open_session(directory=directory, config_path=config, strict_policy=False)
    except MissingSigningKey as exc:
        _fail(f"{exc}. An import has to be recordable before it is allowed to happen.")
        return

    from qed.core.admin import AdminOperation

    decision = _admin_gate(
        session,
        AdminOperation.packs_import,
        by=by,
        approval=approval,
        break_glass=break_glass,
        detail={"bundle_hash": bundle.bundle_hash, "issuer": bundle.issuer},
    )
    if decision is None:
        return

    # Before writing: an imported catalogue replaces the shipped one, so a
    # bundle that omits a control an installed rule cites leaves that rule
    # citing nothing -- which is a lint error, and the engine refuses to decide
    # against a bundle with errors. An import that stops the kernel deciding is
    # not an import, so it is refused while the instance is still untouched.
    orphans = would_break(bundle, session.bundle.rules)
    if orphans and not allow_orphans:
        session.close()
        for rule_id, framework, control_id in orphans:
            typer.secho(
                f"  {rule_id} cites {framework} {control_id}, which this bundle does not define",
                fg=typer.colors.RED,
                err=True,
            )
        _fail(
            f"refusing to import: {len(orphans)} rule mapping(s) would be left citing a "
            "control no catalogue defines, which is a lint error -- the engine would "
            "then refuse to decide anything at all. Fix the rules first, or pass "
            "`--allow-orphaned-rules` if you intend to fix them next and accept that "
            "this instance decides nothing until you do. Nothing was written."
        )
        return

    try:
        written = write_installed(bundle, directory)
        use_imported(installed_dir(directory))
        # The catalogues behind the rules changed, so the next session must
        # append a fresh `policy_loaded` even though the policy hash did not
        # move. Otherwise the only trace of an unsigned catalogue is this
        # `admin_action`, while every later `policy_loaded` -- the record each
        # verdict points at -- keeps saying the labels were vouched for.
        session.store.forget_bundles()
        appended = session.writer.append(
            type_=EvidenceType.admin_action,
            assurance=Assurance.kernel,
            payload={
                "action": "packs_imported",
                **bundle.describe(),
                "source": path.name,
                "unsigned": not bundle.signed,
                "rollback_allowed": allow_rollback,
                **decision.payload(),
            },
        )
    finally:
        session.close()

    # `ref` rather than `record.seq`: on a Postgres HA deployment the record is
    # in the outbox until the chain leader drains it, and `Appended.record.seq`
    # is None exactly then. `ref` is the sequence number once chained and the
    # outbox id before that, which is the thing somebody can look up either way.
    for item in written:
        typer.echo(f"wrote {item}")
    typer.secho(
        f"imported {len(bundle.packs)} catalogue(s) from {bundle.issuer}"
        f"{'' if bundle.signed else ' -- UNSIGNED'}; recorded as {appended.ref}",
        fg=typer.colors.GREEN if bundle.signed else typer.colors.YELLOW,
    )


@policy_app.command("normalize-frameworks")
def policy_normalize_frameworks(
    paths: Annotated[
        list[Path], typer.Argument(help="Rule files or directories to rewrite in place.")
    ],
    check: Annotated[
        bool,
        typer.Option("--check", help="Report what would change and exit 1 if anything would."),
    ] = False,
) -> None:
    """Rewrite `compliance.framework` values to their canonical ids (SPEC 11).

    `EU AI Act`, `eu-ai-act` and `AI Act` all mean `eu_ai_act`. The engine
    normalises on read, so a rule with an alias decides correctly either way --
    what it does not do is *group*: two spellings are two rows in a coverage
    report and two control sets in an OSCAL export, and the auditor reading it
    has no way to know they are one framework.

    Text substitution on the file, not a YAML round-trip: a reformat would
    rewrite every comment and quote style in a rule file somebody wrote by
    hand, and the diff would be unreviewable.
    """
    import re

    from qed.compliance.loader import canonical_framework

    files: list[Path] = []
    for target in paths:
        if target.is_dir():
            files.extend(sorted(target.rglob("*.yaml")))
        elif target.exists():
            files.append(target)
        else:
            _fail(f"{target} does not exist")
            return

    pattern = re.compile(r"(framework:\s*)([\"']?)([^\"',}\n]+)(\2)")
    changed_files = 0
    changes: list[str] = []

    for path in files:
        original = path.read_text(encoding="utf-8")

        def replace(match: re.Match[str], path: Path = path) -> str:
            raw = match.group(3).strip()
            canonical = canonical_framework(raw)
            if canonical is None or canonical == raw:
                return match.group(0)
            changes.append(f"{path}: {raw} -> {canonical}")
            return f"{match.group(1)}{match.group(2)}{canonical}{match.group(4)}"

        rewritten = pattern.sub(replace, original)
        if rewritten != original:
            changed_files += 1
            if not check:
                path.write_text(rewritten, encoding="utf-8")

    for line in changes:
        typer.echo(f"  {line}")

    if not changes:
        typer.secho("every framework id is already canonical", fg=typer.colors.GREEN)
        return
    if check:
        _fail(f"{len(changes)} alias(es) in {changed_files} file(s) are not canonical")
        return
    typer.secho(
        f"rewrote {len(changes)} alias(es) in {changed_files} file(s)", fg=typer.colors.GREEN
    )


# -------------------------------------------------------------------- policy


@policy_app.command("lint")
def policy_lint(
    policy: PolicyOption = None,
    include_baseline: Annotated[
        bool, typer.Option("--baseline/--no-baseline", help="Include the shipped pack.")
    ] = True,
) -> None:
    """Check a policy bundle without needing keys or a chain."""
    paths = list(policy or [])
    if include_baseline:
        paths.insert(0, baseline_pack_dir())
    result = load_bundle([p for p in paths if p.exists()])

    for finding in result.findings:
        colour = typer.colors.RED if finding.severity == "error" else typer.colors.YELLOW
        typer.secho(finding.format(), fg=colour)

    active = len(result.bundle.active_rules())
    typer.echo(
        f"{len(result.bundle.rules)} rules ({active} active), "
        f"policy_hash {result.bundle.hash[:16]}..."
    )
    if not result.ok:
        typer.secho(f"{len(result.errors)} error(s)", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    typer.secho("ok", fg=typer.colors.GREEN)


@policy_app.command("explain")
def policy_explain(
    proposal_file: Annotated[Path, typer.Argument(help="ActionProposal as JSON.")],
    policy: PolicyOption = None,
    budget_file: Annotated[Path | None, typer.Option("--budget")] = None,
    mandate_file: Annotated[Path | None, typer.Option("--mandate")] = None,
) -> None:
    """Show why a proposal decides the way it does. Writes nothing."""
    from qed.core.schemas import EvalContext, utcnow

    proposal = ActionProposal.model_validate_json(proposal_file.read_text(encoding="utf-8"))
    paths = [baseline_pack_dir(), *(policy or [])]
    result = load_bundle([p for p in paths if p.exists()])
    budget = (
        BudgetState.model_validate_json(budget_file.read_text(encoding="utf-8"))
        if budget_file
        else BudgetState(token_jti=proposal.principal.token_jti)
    )
    mandate = (
        Mandate.model_validate_json(mandate_file.read_text(encoding="utf-8"))
        if mandate_file
        else None
    )
    ctx = EvalContext(now=utcnow(), mandate=mandate)
    if mandate is not None:
        # `explain` takes no `--dir`, so it holds no public keys and cannot
        # check the signature. `check_proposal` does, and refuses a forgery.
        # Saying so matters because the derived output below reports
        # `"mandate": {"present": true}` either way, and an operator using
        # `explain` to find out whether a mandate works would read that as a
        # mandate that will work.
        typer.secho(
            "qed: this is a policy dry-run with no keys, so the mandate's signature "
            "was NOT verified -- only its window, revocation and `allowed` envelope. "
            "`qed check` verifies it and refuses a forged one.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    typer.echo(json.dumps(explain_proposal(proposal, result.bundle, budget, ctx), indent=2))


@policy_app.command("test")
def policy_test(
    cases_file: Annotated[Path, typer.Argument(help="Case file (YAML or JSON).")],
    policy: PolicyOption = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    no_order_check: Annotated[
        bool,
        typer.Option("--no-order-check", help="Skip the rule-order independence check."),
    ] = False,
    coverage: Annotated[
        bool, typer.Option("--coverage", help="Also list rules no case mentions.")
    ] = False,
) -> None:
    """Run policy cases against your rules. Writes nothing to the chain.

    A case is a proposal plus the verdict it should get. `expect.rules` is the
    exact set of rule ids, not a subset, so a case fails both when a rule stops
    firing and when an unrelated one starts -- the second is what catches a
    rule widened by accident.

    Every case is also evaluated against a reshuffled copy of the bundle: a
    decision must not depend on the order rules load in (ADR-002.2).

    Exit codes: 0 all passed, 1 a case failed or the file is unusable.
    """
    import yaml

    from qed.core.policy.cases import CaseError, load_cases, run_cases, uncovered_rules
    from qed.core.schemas import utcnow

    try:
        document = yaml.safe_load(cases_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        _fail(f"{cases_file} is not readable: {exc}")
        return
    try:
        case_file = load_cases(document)
    except CaseError as exc:
        _fail(f"{cases_file}: {exc}")
        return

    paths = [baseline_pack_dir(), *(policy or [])]
    result = load_bundle([p for p in paths if p.exists()])
    if not result.ok:
        for finding in result.errors:
            typer.echo(finding.format(), err=True)
        _fail("the policy bundle has errors; fix those before testing against it")
        return

    results = run_cases(case_file, result.bundle, now=utcnow(), check_order=not no_order_check)
    failed = [r for r in results if not r.passed]
    missing = uncovered_rules(case_file, result.bundle) if coverage else []

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "total": len(results),
                    "passed": len(results) - len(failed),
                    "failed": [{"id": r.case_id, "failures": r.failures} for r in failed],
                    **({"uncovered_rules": missing} if coverage else {}),
                },
                indent=2,
            )
        )
    else:
        for case_result in failed:
            typer.echo(f"FAIL  {case_result.case_id}")
            for failure in case_result.failures:
                typer.echo(f"        {failure}")
        typer.echo(f"{len(results) - len(failed)}/{len(results)} cases passed")
        if coverage and missing:
            typer.echo(f"rules with no case: {', '.join(missing)}")

    if failed:
        raise typer.Exit(code=1)


# -------------------------------------------------------------------- export


@app.command()
def export(
    directory: DirOption = DEFAULT_DIR,
    out: Annotated[Path | None, typer.Option("--out", help="Write here instead of stdout.")] = None,
    export_format: Annotated[str, typer.Option("--format", help="jsonl, csv or oscal.")] = "jsonl",
    from_seq: Annotated[int, typer.Option("--from", help="First seq to include.")] = 0,
    to_seq: Annotated[int | None, typer.Option("--to", help="Last seq to include.")] = None,
    config: ConfigOption = None,
) -> None:
    """Export the evidence chain. JSONL is what `qed-verify` reads.

    `oscal` writes an OSCAL 1.1.2 assessment-results document: one observation
    per record, one finding per rule hit, public keys in back-matter. It maps
    only the control references the rules themselves declare (SPEC 10.8).
    """
    if export_format not in {"jsonl", "csv", "oscal"}:
        _fail("--format must be jsonl, csv or oscal")
    session = open_session(directory=directory, config_path=config, strict_policy=False)
    records = list(session.store.iter_evidence(from_seq, to_seq))
    if export_format == "oscal":
        if not records:
            session.close()
            _fail("that range holds no records; an OSCAL result needs at least one observation")
            return
        text = (
            json.dumps(
                to_oscal(
                    records,
                    instance_id=session.config.instance_id,
                    generated_at=utcnow(),
                    signing_keys=session.store.signing_keys(),
                    policy_hash=session.bundle.hash,
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    else:
        text = to_jsonl(records) if export_format == "jsonl" else to_csv(records)
    session.close()
    if out is None:
        sys.stdout.write(text)
    else:
        out.write_text(text, encoding="utf-8")
        typer.echo(f"{len(records)} record(s) -> {out}")


@mandate_app.command("sign")
def mandate_sign(
    mandate_file: Annotated[Path, typer.Argument(help="Mandate document as JSON.")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the signed mandate here.")
    ] = None,
) -> None:
    """Sign a mandate and record its issue in the chain (SPEC 6.5).

    The signature covers the whole document except its own `signature` field
    and `revoked_at`, so a mandate keeps verifying after it is revoked -- the
    record of who granted the authority has to survive the withdrawal of it.
    """
    from qed.core.mandates import MANDATE_ALG, signing_payload
    from qed.core.schemas import Assurance, EvidenceType, Mandate, MandateSignature

    try:
        document = Mandate.model_validate_json(mandate_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"{mandate_file} is not a readable mandate: {exc}")
        return

    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        signed = document.model_copy(
            update={
                "signature": MandateSignature(
                    key_id=session.signer.key_id,
                    alg=MANDATE_ALG,
                    sig=session.signer.sign(signing_payload(document)),
                )
            }
        )
        now = utcnow()
        session.store.record_mandate(signed, created_at=now)
        session.writer.append(
            type_=EvidenceType.mandate_issued,
            assurance=Assurance.kernel,
            payload={
                "mandate_id": signed.id,
                "for_agent": signed.for_agent,
                "purpose": signed.purpose,
                "issued_by_hash": signed.issued_by_hash,
                "valid_from": signed.valid.from_.isoformat(),
                "valid_until": signed.valid.until.isoformat(),
                "key_id": session.signer.key_id,
            },
            principal_hash=signed.issued_by_hash,
            ts=now,
        )
    finally:
        session.close()

    text = signed.model_dump_json(by_alias=True, indent=2)
    if out is not None:
        out.write_text(text + chr(10), encoding="utf-8")
        typer.echo(f"signed {signed.id} -> {out}")
    else:
        typer.echo(text)


@mandate_app.command("list")
def mandate_list(
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    for_agent: Annotated[
        str | None, typer.Option("--for-agent", help="Only mandates for this subject.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List stored mandates and whether each one is usable right now."""
    from qed.core.mandates import is_active

    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        mandates = session.store.list_mandates(for_agent=for_agent)
    finally:
        session.close()

    now = utcnow()
    if as_json:
        typer.echo(
            json.dumps(
                [
                    {
                        **json.loads(m.model_dump_json(by_alias=True)),
                        "active": is_active(m, now=now),
                    }
                    for m in mandates
                ],
                indent=2,
            )
        )
        return
    if not mandates:
        typer.echo("no mandates")
        return
    for mandate in mandates:
        state = "active" if is_active(mandate, now=now) else "inactive"
        if mandate.revoked_at is not None:
            state = "revoked"
        typer.echo(f"{mandate.id}  {state:<8}  {mandate.for_agent}  {mandate.purpose}")


@mandate_app.command("revoke")
def mandate_revoke(
    mandate_id: Annotated[str, typer.Argument(help="Mandate id to revoke.")],
    reason: Annotated[str, typer.Option("--reason", help="Why it is being revoked.")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    by: Annotated[str, typer.Option("--by", help="principal_hash of the revoker.")] = "",
) -> None:
    """Revoke a mandate. Tokens that reference it fail on next use (6.1 step 5).

    Nothing is deleted. The signed document stays exactly as issued and the
    revocation is a separate fact, in its own column and in the chain.
    """
    from qed.core.schemas import Assurance, EvidenceType

    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        if session.store.load_mandate(mandate_id) is None:
            _fail(f"no mandate {mandate_id}")
            return
        now = utcnow()
        if not session.store.revoke_mandate(mandate_id, at=now, by_hash=by or None, reason=reason):
            _fail(f"mandate {mandate_id} is already revoked")
            return
        session.writer.append(
            type_=EvidenceType.mandate_revoked,
            assurance=Assurance.kernel,
            payload={"mandate_id": mandate_id, "reason": reason, "revoked_by_hash": by or None},
            principal_hash=by or None,
            ts=now,
        )
    finally:
        session.close()
    typer.echo(f"revoked {mandate_id}")


@app.command()
def approve(
    approval_id: Annotated[str, typer.Argument(help="Approval request id.")],
    by: Annotated[str, typer.Option("--by", help="Your subject, e.g. you@example.com")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    deny: Annotated[bool, typer.Option("--deny", help="Refuse it instead.")] = False,
    window: Annotated[
        str | None,
        typer.Option("--window", help="Approve for a period, e.g. 15m, instead of once."),
    ] = None,
    reason: Annotated[str, typer.Option("--reason", help="Why.")] = "",
    groups: Annotated[
        str, typer.Option("--groups", help="Comma-separated groups you belong to.")
    ] = "",
) -> None:
    """Decide a pending approval (SPEC 9.3).

    Separation of duties is enforced here, not reported: you cannot approve
    your own action, a service identity cannot approve anything, and you have
    to be in the group the rule named.

    `--window 15m` grants every identical action for that period rather than
    this one. Windows are not extendable; when one runs out the next action
    opens a fresh request.
    """
    from qed.core.approval.model import (
        DecisionKind,
        SoDViolation,
        decide,
        parse_duration,
    )
    from qed.core.evidence.hashing import principal_hash
    from qed.core.schemas import Assurance, EvidenceType

    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        request = session.store.load_approval(approval_id)
        if request is None:
            _fail(f"no approval {approval_id}")
            return

        kind = (
            DecisionKind.deny
            if deny
            else (DecisionKind.approve_window if window else DecisionKind.approve_once)
        )
        now = utcnow()
        try:
            decision = decide(
                request,
                kind=kind,
                approver_hash=principal_hash(by),
                approver_subject=by,
                approver_groups=[g.strip() for g in groups.split(",") if g.strip()],
                now=now,
                reason=reason,
                requested_window=parse_duration(window),
            )
        except SoDViolation as violation:
            # Recorded, not just refused: an attempt to approve one's own
            # action is exactly the thing an auditor wants to find later.
            session.writer.append(
                type_=EvidenceType.approval_decided,
                assurance=Assurance.kernel,
                payload={
                    "approval_id": approval_id,
                    "refused": violation.rule_id,
                    # How the approver was established. The API router records
                    # `oidc:<issuer>` or `adapter-asserted:<id>`; this path is
                    # whoever ran the command, which is weaker and should say
                    # so. A field present on some approval_decided rows and
                    # absent on others would leave an auditor guessing.
                    "identity": "cli-asserted:--by",
                    "detail": str(violation),
                    "attempted_by_hash": principal_hash(by),
                },
                approval_id=approval_id,
                ts=now,
            )
            _fail(f"{violation.rule_id}: {violation}")
            return
        except ValueError as exc:
            _fail(str(exc))
            return

        if not session.store.apply_decision(decision):
            _fail(f"approval {approval_id} was decided by someone else first")
            return
        if decision.window_until is not None:
            session.store.open_window(request.dedupe_key, request.id, decision.window_until)

        session.writer.append(
            type_=EvidenceType.approval_decided,
            assurance=Assurance.kernel,
            payload={
                "approval_id": approval_id,
                "decision": decision.kind.value,
                "approver_hash": decision.approver_hash,
                "identity": "cli-asserted:--by",
                "reason": decision.reason,
                "window_until": (
                    None if decision.window_until is None else decision.window_until.isoformat()
                ),
            },
            approval_id=approval_id,
            principal_hash=decision.approver_hash,
            ts=now,
        )
    finally:
        session.close()

    if decision.window_until is not None:
        typer.echo(f"{decision.kind.value} until {decision.window_until.isoformat()}")
    else:
        typer.echo(decision.kind.value)


@app.command()
def approvals(
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    status_filter: Annotated[
        str | None, typer.Option("--status", help="pending | approved | denied | expired")
    ] = None,
    expire: Annotated[
        bool, typer.Option("--expire", help="First move overdue requests to expired.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List approval requests.

    `--expire` runs the timeout sweep (SPEC 9.4) and writes one
    `approval_expired` record per request. A request that simply vanished
    from the queue would not be evidence of anything.
    """
    from qed.core.schemas import Assurance, EvidenceType

    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        now = utcnow()
        if expire:
            for stale in session.store.expire_approvals(now=now):
                session.writer.append(
                    type_=EvidenceType.approval_expired,
                    assurance=Assurance.kernel,
                    payload={
                        "approval_id": stale.id,
                        "expired_at": stale.expires_at.isoformat(),
                        "approvers": stale.approvers,
                    },
                    approval_id=stale.id,
                    ts=now,
                )
        found = session.store.list_approvals(status=status_filter)
    finally:
        session.close()

    if as_json:
        typer.echo(json.dumps([json.loads(r.model_dump_json()) for r in found], indent=2))
        return
    if not found:
        typer.echo("no approvals")
        return
    for item in found:
        typer.echo(
            f"{item.id}  {item.status.value:<10}  expires {item.expires_at.isoformat()}  "
            f"{', '.join(item.approvers) or '(nobody named)'}"
        )


@app.command()
def doctor(
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="Skip anything that needs the network.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Report posture: what this instance can actually enforce (SPEC 7.2).

    The question it answers is the uncomfortable one. For every upstream:
    does QED hold the credential, or is the agent carrying its own? An
    adapter in the second case still gets a verdict and still writes
    evidence, but it could be bypassed entirely, and an operator deserves to
    be told which of their upstreams are which.
    """
    from qed.core.broker.model import Enforcement, describe
    from qed.infra.secrets.resolver import CredentialResolver, SecretResolutionError
    from qed.infra.upstreams import load_upstreams

    report: dict[str, object] = {}
    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        report["instance_id"] = session.config.instance_id
        report["mode"] = session.config.mode.value
        report["signing_key"] = session.signer.key_id
        report["policy_rules"] = len(session.bundle.rules)
        # SPEC 17's clock warning. `doctor` builds its own report rather than
        # reusing `chain_status`, so this has to be added in both places --
        # which is how the first version of this silently printed nothing.
        report["clock"] = assess_clock(session.store.last_ts(), now=utcnow()).describe()
        report["delegation"] = {
            "issuers": [i.issuer for i in session.config.delegation.issuers],
            "offline": session.config.delegation.offline,
        }
        upstreams = load_upstreams(session.config, base=config)
        resolver = CredentialResolver(ttl_seconds=session.config.broker.ttl_seconds)

        rows: list[dict[str, object]] = []
        for upstream in upstreams.upstreams:
            row = describe(upstream)
            if upstream.credential is None:
                row["credential"] = "not configured"
            elif offline and upstream.credential.source == "vault":
                row["credential"] = "not checked (offline)"
            else:
                try:
                    secret = resolver.resolve(upstream.credential)
                except SecretResolutionError as exc:
                    # The reference and the reason, never the value. Both are
                    # already in the operator's own config file.
                    row["credential"] = f"unavailable: {exc}"
                    row["enforcement"] = Enforcement.advisory.value
                else:
                    row["credential"] = f"resolved ({len(secret)} chars)"
            rows.append(row)
        report["upstreams"] = rows
        report["enforcing"] = sum(1 for r in rows if r["enforcement"] == "enforcing")
        report["advisory"] = sum(1 for r in rows if r["enforcement"] == "advisory")

        # Retention is the only destructive thing qed does to its own chain,
        # so what it *would* do is posture an operator should be able to read
        # before it runs rather than after.
        policy = session.config.retention.policy()
        pending = plan_retention(session)
        report["retention"] = {
            **policy.describe(),
            "would_purge_now": pending.summary() if not pending.empty else None,
        }

        from qed.infra.keys.rotation import pending_rotation
        from qed.infra.maintenance import publishers_for
        from qed.infra.siem import SiemShipper

        staged = pending_rotation(session.directory)
        report["interrupted_rotation"] = None if staged is None else str(staged)

        # A checkpoint whose root is published nowhere is a Merkle root inside
        # the chain it summarises, which an operator who could rewrite the
        # chain could recompute. Saying so is the point of this line.
        siem = session.config.observability.siem
        report["siem"] = {
            "configured": siem.active,
            # Scheme, host and port only. A webhook URL often carries a token,
            # and this output ends up in support tickets.
            "target": SiemShipper(
                instance_id=session.config.instance_id,
                webhook=siem.resolved_webhook(),
                to_stdout=siem.stdout,
            ).describe(),
        }

        anchors, anchor_problems = publishers_for(session.config)
        last = session.store.last_checkpoint()
        report["checkpoints"] = {
            "publishers": [publisher.describe() for publisher in anchors],
            "config_errors": anchor_problems,
            "last": None
            if last is None
            else {
                "to_seq": last.seq_to,
                "merkle_root": last.merkle_root,
                "published_to": [
                    {"publisher": r.get("publisher"), "ok": r.get("ok"), "target": r.get("target")}
                    for r in last.published_to
                ],
            },
        }
    finally:
        session.close()

    if as_json:
        typer.echo(json.dumps(report, indent=2))
        return

    typer.echo(f"instance   : {report['instance_id']}  (mode {report['mode']})")
    typer.echo(f"signing key: {report['signing_key']}")
    typer.echo(f"policy     : {report['policy_rules']} rules")

    retention = cast("dict[str, object]", report["retention"])
    keep = retention["payload"] or "forever"
    typer.echo(f"retention  : payloads {keep}")
    would = retention["would_purge_now"]
    if isinstance(would, dict):
        typer.secho(
            f"             {would['records']} payload(s) are past it and will be purged "
            f"on the next maintenance pass",
            fg=typer.colors.YELLOW,
        )
    siem_report = cast("dict[str, object]", report["siem"])
    if siem_report["configured"]:
        typer.echo(f"{siem_report['target']}".replace("siem: ", "siem       : ", 1))

    checkpoint_report = cast("dict[str, object]", report["checkpoints"])
    configured = cast("list[str]", checkpoint_report["publishers"])
    if configured:
        typer.echo(f"anchors    : {'; '.join(configured)}")
    else:
        typer.secho(
            "anchors    : none -- a checkpoint's Merkle root lives only in the chain it "
            "summarises,\n"
            "             so it attests to nothing an operator who could rewrite the "
            "chain could not\n"
            "             recompute. Configure `evidence.checkpoint.publishers`.",
            fg=typer.colors.YELLOW,
        )
    for problem in cast("list[str]", checkpoint_report["config_errors"]):
        typer.secho(f"             ! {problem}", fg=typer.colors.RED)

    # SPEC 17: an operator should be able to see whether the thing doing the
    # governing is itself governed. Reported either way -- a silence here would
    # read as "fine" on an instance where nothing gates a key rotation.
    admin = session.config.admin
    gated = sorted(item.value for item in cast("frozenset[Any]", admin.governed()))
    if gated:
        approvers = ", ".join(admin.approvers)
        typer.echo(f"self-gov   : {', '.join(gated)} need an approval from {approvers}")
    else:
        typer.secho(
            "self-gov   : off -- `qed keys rotate` and `qed packs import` need nobody's "
            "agreement.\n"
            "             The operator is the one actor no rule constrains. Set "
            "`admin.self_governed`\n"
            "             with `admin.approvers` to change that (SPEC 17).",
            fg=typer.colors.YELLOW,
        )

    # SPEC 17's clock warning, where an operator will see it before handing an
    # export to an auditor.
    clock = cast("dict[str, object]", report.get("clock") or {})
    if clock.get("suspect"):
        from qed.core.clock import ClockReport

        ahead = cast("float", clock["newest_record_ahead_seconds"])
        tolerance = cast("float", clock["tolerance_seconds"])
        typer.secho(
            "clock      : "
            + ClockReport(ahead_seconds=ahead, tolerance_seconds=tolerance).message(),
            fg=typer.colors.YELLOW,
        )

    if report["interrupted_rotation"]:
        typer.secho(
            f"rotation   : INTERRUPTED -- a staged key is at "
            f"{report['interrupted_rotation']}.\n"
            "             If the chain has no `key_rotated` at its tip the file is safe to "
            "delete; if it has, that key must be activated.",
            fg=typer.colors.RED,
        )
    rows_out = cast("list[dict[str, object]]", report["upstreams"])
    if not rows_out:
        typer.echo("")
        typer.echo(
            "upstreams  : none configured, so every adapter is ADVISORY -- QED "
            "decides and records, but the agent holds its own credentials and could "
            "go around it."
        )
        return
    typer.echo("")
    typer.echo(f"{'UPSTREAM':<20} {'MODE':<10} {'INJECT':<8} CREDENTIAL")
    for row in rows_out:
        typer.echo(
            f"{row['id']!s:<20} {str(row['enforcement']).upper():<10} "
            f"{row['inject'] or '-'!s:<8} {row['credential']}"
        )
    typer.echo("")
    typer.echo(f"{report['enforcing']} enforcing, {report['advisory']} advisory")


@app.command()
def status(
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
) -> None:
    """Chain and policy posture."""
    session = open_session(directory=directory, config_path=config, strict_policy=False)
    typer.echo(json.dumps(chain_status(session), indent=2))
    session.close()


@app.command()
def login(
    issuer: Annotated[str, typer.Option("--issuer", help="OIDC issuer URL")],
    client_id: Annotated[str, typer.Option("--client-id", help="Public client id")],
    scope: Annotated[
        str, typer.Option("--scope", help="Scopes to request from the identity provider")
    ] = "openid profile email offline_access",
    no_keyring: Annotated[
        bool, typer.Option("--no-keyring", help="Skip the OS keychain and use a 0600 file")
    ] = False,
) -> None:
    """Sign in to an identity provider (RFC 8628 device flow).

    Prints a URL and a short code. Open the URL anywhere you have a browser --
    it does not have to be this machine -- approve, and the refresh token is
    stored in the OS keychain.
    """
    from qed.infra.credentials import CredentialStore, StoredLogin
    from qed.infra.device_flow import (
        DeviceFlowError,
        discover_endpoints,
        poll_for_token,
        start_device_authorization,
    )

    try:
        endpoints = discover_endpoints(issuer)
        authorization = start_device_authorization(
            endpoints["device_authorization_endpoint"], client_id=client_id, scope=scope
        )
    except DeviceFlowError as exc:
        _fail(str(exc))
        return

    typer.echo("")
    if authorization.verification_uri_complete:
        typer.echo(f"  Open:  {authorization.verification_uri_complete}")
        typer.echo(f"  Code:  {authorization.user_code}   (already filled in on that link)")
    else:
        typer.echo(f"  Open:  {authorization.verification_uri}")
        typer.echo(f"  Code:  {authorization.user_code}")
    typer.echo("")
    typer.echo("  Waiting for approval. Ctrl-C to give up.")

    try:
        token = poll_for_token(endpoints["token_endpoint"], authorization, client_id=client_id)
    except DeviceFlowError as exc:
        _fail(str(exc))
        return
    if token.refresh_token is None:
        _fail(
            "the identity provider returned no refresh token; request the "
            "`offline_access` scope, or the login cannot be reused"
        )
        return

    store = CredentialStore(use_keyring=not no_keyring)
    store.save(StoredLogin(issuer=issuer, client_id=client_id, refresh_token=token.refresh_token))
    typer.echo(f"  Signed in. Credential stored in the {store.backend}.")


@app.command()
def token(
    issuer: Annotated[str, typer.Option("--issuer", help="The issuer you logged in to")],
    qed_url: Annotated[
        str, typer.Option("--qed-url", help="Base URL of QED API")
    ] = "http://127.0.0.1:8710",
    scope: Annotated[str, typer.Option("--scope", help="Scopes to request")] = "",
    adapter: Annotated[str, typer.Option("--adapter", help="Adapter id for signing")] = "",
    secret_env: Annotated[
        str, typer.Option("--secret-env", help="Env var holding the adapter secret")
    ] = "QED_ADAPTER_SECRET",
    raw: Annotated[bool, typer.Option("--raw", help="Print only the token")] = False,
) -> None:
    """Exchange the stored login for a budgeted qed token (SPEC 6.2).

    Adapters call this transparently when their cached token is close to
    expiry; a person runs it to get a token for a one-off command.
    """
    import os

    import httpx

    from qed.api.auth import canonical_string, sign
    from qed.core.schemas import rfc3339_ms
    from qed.infra.credentials import CredentialStore
    from qed.infra.device_flow import DeviceFlowError, discover_endpoints, refresh_access_token

    stored = CredentialStore().load(issuer)
    if stored is None:
        _fail(f"not signed in to {issuer}; run `qed login --issuer {issuer} --client-id ...`")
        return

    try:
        endpoints = discover_endpoints(issuer)
        refreshed = refresh_access_token(
            endpoints["token_endpoint"], stored.refresh_token, client_id=stored.client_id
        )
    except DeviceFlowError as exc:
        _fail(str(exc))
        return

    body = json.dumps(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": refreshed.access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": scope,
        }
    ).encode("utf-8")

    secret = os.environ.get(secret_env, "")
    if not adapter or not secret:
        _fail(
            "the token endpoint is adapter-authenticated: pass --adapter and put its "
            f"secret in ${secret_env}. The subject token proves who you are, not which "
            "deployment is asking on your behalf."
        )
        return

    timestamp = rfc3339_ms(utcnow())
    path = "/v1/token"
    headers = {
        "content-type": "application/json",
        "x-qed-adapter": adapter,
        "x-qed-timestamp": timestamp,
        "x-qed-nonce": "",
        "x-qed-signature": sign(
            secret,
            canonical_string(method="POST", path=path, timestamp=timestamp, nonce="", body=body),
        ),
    }
    try:
        response = httpx.post(
            f"{qed_url.rstrip('/')}{path}", content=body, headers=headers, timeout=10.0
        )
    except httpx.HTTPError as exc:
        _fail(f"could not reach QED at {qed_url}: {exc}")
        return

    if response.status_code != 200:
        _fail(f"the exchange was refused ({response.status_code}): {response.text}")
        return
    payload = response.json()
    if raw:
        typer.echo(payload["access_token"])
    else:
        typer.echo(json.dumps(payload, indent=2))


@app.command()
def checkpoint(
    directory: DirOption = DEFAULT_DIR,
    force: Annotated[
        bool, typer.Option("--force", help="Checkpoint now, below the normal threshold.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Append a Merkle checkpoint, publish its root, and apply retention.

    One maintenance pass, run now rather than waiting for the running
    instance's own loop (SPEC 10.4, 10.6). The three are together because
    they have to happen in that order: a root is fixed, it is anchored
    somewhere the instance does not control, and only then may payloads the
    retention policy has expired be dropped.

    The caller must be the chain's only writer. On the HA path a running
    `qed serve` holds that lock, so this reports what it could not do rather
    than racing it.
    """
    from qed.infra.maintenance import maintain

    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        result = maintain(session, force_checkpoint=force)
    finally:
        session.close()

    for problem in result.errors:
        typer.secho(f"  ! {problem}", fg=typer.colors.RED, err=True)
    if result.purged:
        typer.echo(f"retention: {result.purged} payload(s) purged")
    for receipt in result.receipts:
        mark = "ok" if receipt.ok else "FAILED"
        typer.echo(f"published: {receipt.publisher} -> {receipt.target} [{mark}]")

    record = result.checkpoint
    if record is None:
        typer.echo("nothing to checkpoint yet")
        return
    payload = record.payload or {}
    typer.echo(
        f"checkpoint seq {record.seq}: records {payload.get('from_seq')}-{payload.get('to_seq')}, "
        f"root {str(payload.get('merkle_root'))[:16]}..."
    )


# -------------------------------------------------------------------- verify


@app.command()
def verify(
    records: Annotated[
        Path | None, typer.Argument(help="JSONL export. Default: export the local chain.")
    ] = None,
    directory: DirOption = DEFAULT_DIR,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    config: ConfigOption = None,
    instance_id: Annotated[
        str | None,
        typer.Option(
            "--instance-id",
            help="Instance the export should belong to. Required to bind a chain read "
            "from a file; taken from the local config when no file is given.",
        ),
    ] = None,
) -> None:
    """Verify a chain. A thin wrapper; auditors should run `qed-verify` itself.

    With no argument this verifies the local chain and binds it to the instance
    id in the local configuration, so every check runs. Given a *file*, there is
    no configuration to trust: the id has to come from `--instance-id`, and
    without it the genesis binding does not run and the report says so. Binding
    a foreign export to the local instance id by default would turn a real check
    into a coincidence, so this does not do that.
    """
    try:
        from qed_verify.verify import load_jsonl, verify_records
    except ImportError:
        _fail("qed-verify is not installed: pip install ./packages/qed-verify")
        return

    from qed.infra.keys.file import load_public_keys

    if records is None:
        session = open_session(directory=directory, config_path=config, strict_policy=False)
        text = to_jsonl(session.store.iter_evidence())
        instance_id = instance_id or session.config.instance_id
        session.close()
    else:
        text = records.read_text(encoding="utf-8")

    report = verify_records(
        load_jsonl(text), load_public_keys(directory / PUBLIC_DIR_NAME), instance_id=instance_id
    )
    typer.echo(json.dumps(report.to_dict(), indent=2) if as_json else report.summary())
    for note in report.unchecked:
        typer.echo(f"not checked -- {note}", err=True)
    raise typer.Exit(0 if report.ok else 1)


# ------------------------------------------------------------------- replay


#: `replay` answers three different things and they must not share an exit
#: code. 0 the record follows from its policy; 2 it does not, and nothing
#: accounts for the difference; 1 the question could not be answered at all --
#: no such proposal, a chain that does not verify, or a policy whose hash does
#: not match the one the decision was made under. Folding "differs" into 1
#: would make a real finding indistinguishable from a missing file, which is
#: the state a pipeline is most likely to be in.
EXIT_REPLAY_DIFFERS: Final = 2


def _records_for_replay(
    source: Path | None, directory: Path, config: Path | None, instance_id: str | None
) -> tuple[str, str | None]:
    """The chain text to replay from, and the instance id to bind it to."""
    if source is not None:
        return source.read_text(encoding="utf-8"), instance_id
    session = open_session(directory=directory, config_path=config, strict_policy=False)
    try:
        return to_jsonl(session.store.iter_evidence()), instance_id or session.config.instance_id
    finally:
        session.close()


@app.command()
def replay(
    proposal_id: Annotated[str, typer.Argument(help="The proposal id to re-decide.")],
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    policy: PolicyOption = None,
    source: Annotated[
        Path | None,
        typer.Option("--from", help="JSONL export to read. Default: the local chain."),
    ] = None,
    budget_file: Annotated[
        Path | None,
        typer.Option("--budget", help="BudgetState as JSON, as it was when this was decided."),
    ] = None,
    mandate_file: Annotated[
        Path | None, typer.Option("--mandate", help="The Mandate the decision was made under.")
    ] = None,
    calls_24h: Annotated[
        int | None, typer.Option("--calls-24h", help="History counter as it was.")
    ] = None,
    blocks_24h: Annotated[
        int | None, typer.Option("--blocks-24h", help="History counter as it was.")
    ] = None,
    instance_id: Annotated[
        str | None,
        typer.Option("--instance-id", help="Instance an export belongs to, for the chain check."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Decide a recorded proposal again and report whether the record follows.

    `qed verify` shows a record is authentic; a chain rewritten wholesale and
    re-signed passes it. This answers the other question: **does this verdict
    follow from the policy it says it was decided under.**

    The chain holds the proposal, the verdict and the timestamp that was the
    engine's clock, so those are exact. It holds the policy's *hash* and not
    its rules, so replaying needs the bundle itself -- and if its hash does
    not match, this refuses rather than quietly answering "what would today's
    policy decide", which is a different question with a much weaker answer.
    Point `--policy` at the archived bundle.

    Three inputs are in no record: the budget ledger state, the signed mandate
    (`mandate_issued` keeps its id and window, not the document) and the
    24-hour history counters. Supply them, or they are defaulted and **named
    as assumed** -- and any difference in a rule that reads them is then
    attributed to the assumption instead of reported as a finding. A
    difference in a rule that reads only the proposal is reported, because
    nothing else can explain it.

    Exit 0 reproduced, 2 differs with nothing to explain it, 1 the question
    could not be answered.
    """
    try:
        from qed_verify.verify import load_jsonl, verify_records
    except ImportError:
        _fail("qed-verify is not installed: pip install ./packages/qed-verify")
        return

    from qed.core.replay import replay_verdict
    from qed.infra.keys.file import load_public_keys

    text, bound_to = _records_for_replay(source, directory, config, instance_id)
    records = load_jsonl(text)

    # A record that has not been verified cannot support a statement about
    # what follows from it: "this verdict matches the policy" is worth
    # nothing if the verdict is not the one the kernel signed.
    report = verify_records(
        records, load_public_keys(directory / PUBLIC_DIR_NAME), instance_id=bound_to
    )
    if not report.ok:
        _fail(
            f"the chain does not verify, so a replay of it would prove nothing:\n{report.summary()}"
        )
        return

    proposal_record = _find_record(records, "proposal", "proposal", "id", proposal_id)
    verdict_record = _find_record(records, "verdict", "verdict", "proposal_id", proposal_id)
    if proposal_record is None or verdict_record is None:
        missing = "proposal" if proposal_record is None else "verdict"
        _fail(
            f"no {missing} record for {proposal_id} in this chain. A payload stripped by "
            "retention cannot be replayed, and `qed export` only carries what is left "
            "(SPEC 10.6)."
        )
        return

    proposal = ActionProposal.model_validate(_inner(proposal_record, "proposal"))
    recorded = Verdict.model_validate(_inner(verdict_record, "verdict"))

    try:
        session = open_session(
            directory=directory, policy_paths=policy, config_path=config, strict_policy=False
        )
    except MissingSigningKey as exc:
        _fail(str(exc))
        return
    bundle = session.bundle
    ledger_budget = session.store.load_budget(proposal.principal.token_jti)
    session.close()

    assumed: list[str] = []
    if budget_file is not None:
        budget = BudgetState.model_validate_json(budget_file.read_text(encoding="utf-8"))
    else:
        # The ledger as it is now, which is what `check_proposal` reads when a
        # caller passes no budget. It is still an assumption -- the ledger has
        # moved since, and that is exactly why it is named -- but it is a far
        # better one than an empty state, which would make every rule reading
        # `derived.budget.*` fire differently and turn each replay
        # inconclusive for no reason.
        budget = ledger_budget or BudgetState(token_jti=proposal.principal.token_jti)
        assumed.append("budget")
    mandate = None
    if mandate_file is not None:
        mandate = Mandate.model_validate_json(mandate_file.read_text(encoding="utf-8"))
    elif proposal.principal.mandate_id:
        # Only assumed when the proposal claimed one. A proposal with no
        # `mandate_id` was decided with no mandate, which is recorded fact.
        assumed.append("mandate")
    # Not assumed: nothing in `qed` ever passes `history` to `check_proposal`,
    # so every decision it has made saw zeros and replaying with zeros
    # reproduces the real input. The flags exist for a chain from a build that
    # does supply them. See `qed/core/replay.py` and the test that pins it.
    history = HistoryDerived(calls_24h=calls_24h or 0, blocks_24h=blocks_24h or 0)

    # The clock is not assumed: `check_proposal` stamps the proposal record,
    # the verdict record and `ctx.now` from one value, so the record's own
    # timestamp *is* what the engine was told the time was.
    ctx = EvalContext(
        now=datetime.fromisoformat(str(proposal_record["ts"]).replace("Z", "+00:00")),
        mandate=mandate,
        history=history,
    )

    result = replay_verdict(proposal, recorded, bundle, budget, ctx, assumed_inputs=tuple(assumed))

    if as_json:
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        _print_replay(result)

    if not result.policy_matches:
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(EXIT_ALLOW if not result.unexplained else EXIT_REPLAY_DIFFERS)


def _inner(record: dict[str, Any], key: str) -> dict[str, Any]:
    payload = record.get("payload")
    assert isinstance(payload, dict)  # `_find_record` only returns matches
    inner = payload[key]
    assert isinstance(inner, dict)
    return inner


def _find_record(
    records: list[dict[str, Any]], type_: str, key: str, id_field: str, wanted: str
) -> dict[str, Any] | None:
    """The one record of `type_` whose payload names `wanted`.

    Works in dictionaries rather than `EvidenceRecord`, because these come
    from `qed_verify.load_jsonl`, which deliberately does not import the
    writer's models -- a verifier that parsed with the same code that wrote
    the record could not catch the record being wrong.
    """
    for record in records:
        if record.get("type") != type_:
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            # Stripped by retention. Not an error here: a later record may
            # still carry it, and the caller reports the absence.
            continue
        inner = payload.get(key)
        if isinstance(inner, dict) and inner.get(id_field) == wanted:
            return record
    return None


def _print_replay(result: ReplayReport) -> None:
    if not result.policy_matches:
        typer.secho("cannot replay", fg=typer.colors.RED, bold=True)
        typer.echo(f"  proposal         : {result.proposal_id}")
        typer.echo(f"  decided under    : {result.recorded_policy_hash}")
        typer.echo(f"  replayed against : {result.replayed_policy_hash}")
        typer.echo("")
        typer.echo(
            "The chain records a policy's hash, not its rules, so the bundle that made "
            "this decision cannot be reconstructed from evidence. Point `--policy` at "
            "the bundle that was in force. Re-deciding under today's policy would "
            "answer a different question."
        )
        return

    if result.reproduced:
        typer.secho("reproduced", fg=typer.colors.GREEN, bold=True)
    elif result.inconclusive:
        typer.secho("inconclusive", fg=typer.colors.YELLOW, bold=True)
    else:
        typer.secho("DIFFERS", fg=typer.colors.RED, bold=True)

    typer.echo(f"  proposal : {result.proposal_id}")
    typer.echo(f"  policy   : {result.recorded_policy_hash[:16]}... (matches)")
    engine = result.recorded_engine_version
    if not result.engine_matches:
        typer.echo(f"  engine   : recorded {engine}, running {result.replayed_engine_version}")
    else:
        typer.echo(f"  engine   : {engine}")
    if result.approval_overlay:
        typer.echo(f"  approval : {result.approval_overlay}")

    if result.assumed_inputs:
        typer.echo("")
        typer.echo(f"assumed (not in any record): {', '.join(result.assumed_inputs)}")

    if result.differences:
        typer.echo("")
        for difference in result.differences:
            colour = typer.colors.YELLOW if difference.attributed_to else typer.colors.RED
            typer.secho(f"  {difference.format()}", fg=colour)

    if result.inconclusive:
        typer.echo("")
        typer.echo(
            "Every difference is explained by an input this replay had to assume, so "
            "this is neither a pass nor a failure. Supply the real one to settle it."
        )
    elif not result.engine_matches and result.unexplained:
        typer.echo("")
        typer.echo(
            "The engine version differs, which can change a decision on its own. "
            "Replay with the version named above before reading this as tampering."
        )


# -------------------------------------------------------------------- serve


@app.command()
def serve(
    directory: DirOption = DEFAULT_DIR,
    policy: PolicyOption = None,
    config: ConfigOption = None,
    host: Annotated[str | None, typer.Option("--host", help="Bind address.")] = None,
    port: Annotated[int | None, typer.Option("--port", help="Bind port.")] = None,
    ui: Annotated[
        bool,
        typer.Option("--ui", help="Also serve the web pages from the separate qed-ui package."),
    ] = False,
    dev: Annotated[
        bool,
        typer.Option(
            "--dev",
            help="Skip adapter signature checks and mark records as dev. Local use only.",
        ),
    ] = False,
) -> None:
    """Run the HTTP API (SPEC 13), and with `--ui` the web pages too (SPEC 19).

    `/readyz` answers 503 until there is a signing key and a way to
    authenticate adapters, so `qed keys init` comes first, then
    `qed adapters add <id>`. Without `--dev` an instance with no registered
    adapter cannot tell callers apart, and SPEC 17 requires it to refuse
    them rather than guess.

    `--ui` needs the separate `qed-ui` package, which is AGPL-3.0 and ships
    apart from this Apache-2.0 wheel on purpose (SPEC 20.4). Without it the
    API runs and the command says what to install. The pages sign in through
    the identity providers under `delegation.issuers`, so configure one or
    nobody can log in.
    """
    try:
        import uvicorn
    except ImportError:  # pragma: no cover - fastapi and uvicorn are install deps
        _fail("uvicorn is not installed: pip install 'valqore-qed'")
        return

    from qed.api.app import create_app
    from qed.config import load_config

    settings = load_config(config).config
    bind_host = host if host is not None else settings.api.host
    bind_port = port if port is not None else settings.api.port

    if dev:
        typer.secho(
            "qed: --dev is on. Adapter signatures are NOT checked and every record is "
            "marked dev. Do not point real agents at this.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    typer.echo(f"qed: serving on http://{bind_host}:{bind_port} (mode {settings.mode.value})")

    application = create_app(directory=directory, config_path=config, policy_paths=policy, dev=dev)

    if ui:
        from qed.api.ui import UiUnavailable, mount_ui

        try:
            assets = mount_ui(application)
        except UiUnavailable as exc:
            # Not fatal. An operator who asked for the pages and did not get
            # them needs to be told, but refusing to serve the API because a
            # separate optional wheel is missing would be the wrong trade.
            typer.secho(f"qed: {exc}", fg=typer.colors.YELLOW, err=True)
        else:
            typer.echo(f"qed: web pages on http://{bind_host}:{bind_port}/ui/ (from {assets})")
            if not settings.delegation.issuers:
                typer.secho(
                    "qed: no identity provider is configured under `delegation.issuers`, so "
                    "the pages have no way to sign anybody in. They will load and every "
                    "request they make will be refused.",
                    fg=typer.colors.YELLOW,
                    err=True,
                )

    uvicorn.run(application, host=bind_host, port=bind_port, log_level="info")


# ---------------------------------------------------------------------- mcp


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def mcp(
    ctx: typer.Context,
    directory: DirOption = DEFAULT_DIR,
    policy: PolicyOption = None,
    config: ConfigOption = None,
    upstream_url: Annotated[
        str | None,
        typer.Option("--upstream-url", help="Streamable HTTP upstream instead of a command."),
    ] = None,
    server_name: Annotated[
        str | None,
        typer.Option("--server-name", help="Name used in action.name. Default: the command."),
    ] = None,
    target_template: Annotated[
        str | None,
        typer.Option(
            "--target-template",
            help="How to build action.target, e.g. 'db:{env}/{args.table}'.",
        ),
    ] = None,
    environment: Annotated[
        str, typer.Option("--env", help="dev, staging or prod. Scores the blast radius.")
    ] = "dev",
    enforcement: Annotated[
        str,
        typer.Option("--enforcement", help="advisory or enforcing (SPEC 3.1)."),
    ] = "enforcing",
    fail_mode: Annotated[
        str,
        typer.Option("--fail-mode", help="closed or open, when the kernel itself fails."),
    ] = "closed",
    adapter_id: Annotated[
        str, typer.Option("--adapter-id", help="Registered adapter id (SPEC 12.6).")
    ] = "adp_mcp_local",
    token_jti: Annotated[
        str, typer.Option("--token-jti", help="Token id to attribute calls to. See `qed token`.")
    ] = "mcp-proxy-local",
    human: Annotated[
        str | None,
        typer.Option(
            "--human",
            help="Who this session acts for, e.g. an email. Hashed into principal_hash.",
        ),
    ] = None,
    issuer: Annotated[
        str,
        typer.Option("--issuer", help="Identity provider that `--human` belongs to."),
    ] = "local",
    mandate_file: Annotated[
        Path | None,
        typer.Option("--mandate", help="Mandate as JSON, for an unattended agent."),
    ] = None,
) -> None:
    """Proxy an MCP server through the kernel, deciding every tool call.

        qed mcp --human you@acme.com -- npx -y @scope/server

    Everything after `--` is the upstream command. Decisions and results go into
    the evidence chain; in shadow mode (the default) nothing is stopped.

    `--human` or `--mandate` is required. Without one, every proposal has no
    principal and no delegated authority, the engine answers with a synthetic
    AG-IDN-007 identity BLOCK before any rule is evaluated, and the chain fills
    with identical verdicts that say nothing about your policy.
    """
    import anyio

    from qed.adapters.mcp.proxy import ProxyOptions, ProxyStats, UpstreamSpec, run_proxy
    from qed.adapters.mcp.targets import DEFAULT_TEMPLATE, TemplateError
    from qed.core.evidence.hashing import principal_hash

    command = list(ctx.args)
    if bool(command) == bool(upstream_url):
        _fail("give either an upstream command after `--` or --upstream-url, not both")
        return
    if environment not in {"dev", "staging", "prod"}:
        _fail("--env must be dev, staging or prod")
        return
    if enforcement not in {"advisory", "enforcing"}:
        _fail("--enforcement must be advisory or enforcing")
        return
    if fail_mode not in {"closed", "open"}:
        _fail("--fail-mode must be closed or open")
        return
    if human is None and mandate_file is None:
        _fail(
            "give --human <who you are> or --mandate <file>. Without either, every verdict "
            "is a synthetic AG-IDN-007 identity BLOCK and no policy rule is evaluated. "
            "--human is this adapter's own assertion and is recorded as such; --mandate is "
            "signed and verified. Identity is proven on the API path, where a delegation "
            "token or an OIDC bearer says who is asking."
        )
        return

    mandate = None
    if mandate_file is not None:
        try:
            mandate = Mandate.model_validate_json(mandate_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _fail(f"cannot read mandate: {exc}")
            return

    name = server_name or _default_server_name(command, upstream_url)
    try:
        upstream = UpstreamSpec(
            name=name,
            command=command[0] if command else None,
            args=command[1:],
            url=upstream_url,
            target_template=target_template or DEFAULT_TEMPLATE,
        )
    except (TemplateError, ValueError) as exc:
        _fail(str(exc))
        return

    try:
        session = open_session(directory=directory, policy_paths=policy, config_path=config)
    except MissingSigningKey as exc:
        _fail(f"{exc}. Run `qed keys init` first: an unsigned decision is not evidence.")
        return
    except PolicyErrors as exc:
        for finding in exc.findings:
            typer.secho(f"  {finding.format()}", fg=typer.colors.RED, err=True)
        _fail("the policy bundle has errors; refusing to proxy against a broken bundle")
        return

    options = ProxyOptions(
        environment=cast(Environment, environment),
        enforcement=Enforcement(enforcement),
        token_jti=token_jti,
        human_hash=None if human is None else principal_hash(human, issuer=issuer),
        mandate=mandate,
        adapter_id=adapter_id,
        identity_note=None if human is None else f"adapter-asserted:--human:{issuer}",
        fail_mode="closed" if fail_mode == "closed" else "open",
    )
    stats = ProxyStats()
    mode = session.config.mode.value
    # stderr, always: stdout is the MCP transport.
    typer.secho(
        f"qed: proxying {name} in {mode} mode, env {environment}, "
        f"target template {upstream.target_template!r}",
        fg=typer.colors.CYAN,
        err=True,
    )
    if human is not None:
        typer.secho(
            f"qed: calls are attributed to {human} at issuer {issuer!r}, on this adapter's "
            "word alone. Use --mandate for a signed identity, or the API path for a "
            "verified one.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if mode == "shadow":
        typer.secho(
            "qed: shadow mode. Every call is decided and recorded; nothing is stopped.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    from qed.infra.secrets.broker import CredentialBroker
    from qed.infra.secrets.resolver import CredentialResolver
    from qed.infra.upstreams import load_upstreams

    upstreams = load_upstreams(session.config, base=config)
    broker = (
        CredentialBroker(
            upstreams=upstreams,
            resolver=CredentialResolver(ttl_seconds=session.config.broker.ttl_seconds),
        )
        if upstreams.upstreams
        else None
    )
    if broker is None:
        typer.secho(
            "qed: no upstreams configured, so this session is ADVISORY -- every call is "
            "decided and recorded, but the agent is using its own credentials and could "
            "go around QED. `qed doctor` says the same thing at more length.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    try:
        anyio.run(
            lambda: run_proxy(
                session=session,
                upstream=upstream,
                options=options,
                stats=stats,
                broker=broker,
            )
        )
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        session.close()
        _print_stats(stats)


def _default_server_name(command: list[str], url: str | None) -> str:
    """A readable server name when the operator did not supply one.

    The last path-ish segment of the command, or the URL host. It ends up in
    every ``action.name`` in the chain, so it is worth getting a sensible
    default rather than the whole command line.
    """
    if url:
        host = url.split("//", 1)[-1].split("/", 1)[0]
        return host or "upstream"
    if not command:  # pragma: no cover - guarded by the caller
        return "upstream"
    candidates = [part for part in command if not part.startswith("-")]
    tail = candidates[-1] if candidates else command[0]
    return Path(tail).name.removesuffix(".js").removesuffix(".py") or "upstream"


def _print_stats(stats: ProxyStats) -> None:
    typer.secho(
        f"qed: {stats.calls} tool call(s); {stats.allowed} forwarded, "
        f"{stats.refused} refused, {stats.would_block} would BLOCK, "
        f"{stats.would_require_approval} would need approval, "
        f"{stats.passthrough} read-through, {stats.ungated} ungated, "
        f"{stats.errors} error(s)",
        fg=typer.colors.CYAN,
        err=True,
    )
    if stats.advisory:
        # Said separately and last, because a session that was entirely
        # advisory looks identical to an enforcing one in every number above.
        typer.secho(
            f"qed: {stats.advisory} of those call(s) were ADVISORY -- decided and "
            "recorded, but QED was not holding the credential.",
            fg=typer.colors.YELLOW,
            err=True,
        )


# ---------------------------------------------------------------------- proxy


@app.command()
def proxy(
    directory: DirOption = DEFAULT_DIR,
    policy: PolicyOption = None,
    config: ConfigOption = None,
    host: Annotated[
        str, typer.Option("--host", help="Interface to listen on. Loopback by default.")
    ] = "127.0.0.1",
    port: Annotated[
        int, typer.Option("--port", help="Port to listen on. 0 picks a free one.")
    ] = 8888,
    allow_non_loopback: Annotated[
        bool,
        typer.Option(
            "--allow-non-loopback",
            help="Required to bind anything but loopback. An open forward proxy is a relay.",
        ),
    ] = False,
    environment: Annotated[
        str, typer.Option("--env", help="dev, staging or prod. Scores the blast radius.")
    ] = "dev",
    enforcement: Annotated[
        str,
        typer.Option(
            "--enforcement",
            help="A ceiling: advisory forces advisory, enforcing allows it where the "
            "broker holds the credential.",
        ),
    ] = "enforcing",
    fail_mode: Annotated[
        str,
        typer.Option("--fail-mode", help="closed or open, when the kernel itself fails."),
    ] = "closed",
    adapter_id: Annotated[
        str, typer.Option("--adapter-id", help="Registered adapter id (SPEC 12.6).")
    ] = "adp_http_local",
    token_jti: Annotated[
        str, typer.Option("--token-jti", help="Token id to attribute requests to.")
    ] = "http-proxy-local",
    human: Annotated[
        str | None,
        typer.Option("--human", help="Who this session acts for. Hashed into principal_hash."),
    ] = None,
    issuer: Annotated[
        str, typer.Option("--issuer", help="Identity provider that `--human` belongs to.")
    ] = "local",
    mandate_file: Annotated[
        Path | None,
        typer.Option("--mandate", help="Mandate as JSON, for an unattended agent."),
    ] = None,
) -> None:
    """Run an HTTP forward proxy that decides every outbound request.

        qed proxy --human you@acme.com
        HTTPS_PROXY=http://127.0.0.1:8888 your-agent

    Plain HTTP is decided on method, path and query, and the broker's
    credential replaces whatever the agent supplied. A CONNECT tunnel is
    decided on the host alone and is always recorded as ADVISORY: QED can
    refuse to open it, but the request inside it is encrypted, so the agent is
    using its own credential and the evidence says so.

    `--human` or `--mandate` is required. Without one, every proposal has no
    principal and no delegated authority, the engine answers with a synthetic
    AG-IDN-007 identity BLOCK before any rule is evaluated, and the chain
    fills with identical verdicts that say nothing about your policy.
    """
    import anyio

    from qed.adapters.http_proxy.proxy import (
        HttpProxyOptions,
        HttpProxyStats,
        http_upstreams,
        injection_problems,
        run_http_proxy,
    )
    from qed.core.evidence.hashing import principal_hash

    if environment not in {"dev", "staging", "prod"}:
        _fail("--env must be dev, staging or prod")
        return
    if enforcement not in {"advisory", "enforcing"}:
        _fail("--enforcement must be advisory or enforcing")
        return
    if fail_mode not in {"closed", "open"}:
        _fail("--fail-mode must be closed or open")
        return
    if human is None and mandate_file is None:
        _fail(
            "give --human <who you are> or --mandate <file>. Without either, every verdict "
            "is a synthetic AG-IDN-007 identity BLOCK and no policy rule is evaluated."
        )
        return
    if host not in {"127.0.0.1", "::1", "localhost"} and not allow_non_loopback:
        # A forward proxy reachable from the network is an open relay: anything
        # that can see the port gets to make requests that the chain then
        # attributes to this session's principal. Loopback is the access
        # control in v1, so leaving it takes a deliberate flag.
        _fail(
            f"refusing to bind {host}: a forward proxy on a reachable interface is an open "
            "relay, and every request through it would be recorded against --human. Pass "
            "--allow-non-loopback if you have put your own access control in front of it."
        )
        return

    mandate = None
    if mandate_file is not None:
        try:
            mandate = Mandate.model_validate_json(mandate_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _fail(f"cannot read mandate: {exc}")
            return

    try:
        session = open_session(directory=directory, policy_paths=policy, config_path=config)
    except MissingSigningKey as exc:
        _fail(f"{exc}. Run `qed keys init` first: an unsigned decision is not evidence.")
        return
    except PolicyErrors as exc:
        for finding in exc.findings:
            typer.secho(f"  {finding.format()}", fg=typer.colors.RED, err=True)
        _fail("the policy bundle has errors; refusing to proxy against a broken bundle")
        return

    from qed.infra.secrets.broker import CredentialBroker
    from qed.infra.secrets.resolver import CredentialResolver
    from qed.infra.upstreams import load_upstreams

    upstreams = http_upstreams(load_upstreams(session.config, base=config))
    problems = injection_problems(upstreams)
    if problems:
        for problem in problems:
            typer.secho(f"  {problem}", fg=typer.colors.RED, err=True)
        session.close()
        _fail("fix the upstream configuration; a credential that cannot be injected is not held")
        return
    broker = (
        CredentialBroker(
            upstreams=upstreams,
            resolver=CredentialResolver(ttl_seconds=session.config.broker.ttl_seconds),
        )
        if upstreams.upstreams
        else None
    )

    options = HttpProxyOptions(
        environment=cast(Environment, environment),
        enforcement=Enforcement(enforcement),
        token_jti=token_jti,
        human_hash=None if human is None else principal_hash(human, issuer=issuer),
        mandate=mandate,
        adapter_id=adapter_id,
        identity_note=None if human is None else f"adapter-asserted:--human:{issuer}",
        fail_mode="closed" if fail_mode == "closed" else "open",
    )
    stats = HttpProxyStats()
    mode = session.config.mode.value
    typer.secho(
        f"qed: forward proxy on {host}:{port} in {mode} mode, env {environment}",
        fg=typer.colors.CYAN,
    )
    typer.secho(
        f"qed: point your agent at it with  HTTPS_PROXY=http://{host}:{port} "
        f"HTTP_PROXY=http://{host}:{port}",
        fg=typer.colors.CYAN,
    )
    typer.secho(
        "qed: every CONNECT tunnel is ADVISORY -- QED decides whether the connection "
        "may be opened, but the request inside it is encrypted, so it cannot replace the "
        "credential and the agent is using its own.",
        fg=typer.colors.YELLOW,
    )
    if broker is None:
        typer.secho(
            "qed: no `kind: http` upstream is configured, so plain HTTP is advisory too -- "
            "decided and recorded, with the agent's own credentials. `qed doctor` says the "
            "same thing at more length.",
            fg=typer.colors.YELLOW,
        )
    if mode == "shadow":
        typer.secho(
            "qed: shadow mode. Every request is decided and recorded; nothing is stopped.",
            fg=typer.colors.YELLOW,
        )

    try:
        anyio.run(
            lambda: run_http_proxy(
                session=session,
                options=options,
                host=host,
                port=port,
                stats=stats,
                broker=broker,
            )
        )
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        session.close()
        _print_http_stats(stats)


def _print_http_stats(stats: HttpProxyStats) -> None:
    typer.secho(
        f"qed: {stats.calls} request(s); {stats.requests} plain, {stats.tunnels} tunnel(s); "
        f"{stats.allowed} forwarded, {stats.refused} refused, {stats.would_block} would BLOCK, "
        f"{stats.would_require_approval} would need approval, {stats.malformed} malformed, "
        f"{stats.ungated} ungated, {stats.errors} error(s)",
        fg=typer.colors.CYAN,
    )
    typer.secho(
        f"qed: {stats.bytes_to_upstream} bytes out, {stats.bytes_to_client} bytes in",
        fg=typer.colors.CYAN,
    )
    if stats.stripped:
        typer.secho(
            f"qed: removed {len(stats.stripped)} agent-supplied credential header(s): "
            f"{', '.join(sorted(set(stats.stripped)))}. Something is wiring a token into the "
            "agent; it is being ignored.",
            fg=typer.colors.YELLOW,
        )
    if stats.advisory:
        typer.secho(
            f"qed: {stats.advisory} of those request(s) were ADVISORY -- decided and "
            "recorded, but QED was not holding the credential.",
            fg=typer.colors.YELLOW,
        )


# ----------------------------------------------------------------------- hook


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    add_help_option=False,
)
def hook(ctx: typer.Context) -> None:
    """Decide one coding-agent tool call, reading the payload on stdin.

        qed hook claude-code --human you@example.com

    Not meant to be typed: `qed install claude-code` writes it into the
    agent's settings. Documented so that an operator who finds it in a
    settings file can tell what it is.

    Everything is parsed by hand rather than by Typer, and `--help` is off,
    because this runs on every tool call the agent makes: building a command
    tree to read four flags is latency its user feels. Exit 0 leaves the
    normal permission flow alone, exit 2 blocks.
    """
    args = list(ctx.args)
    agent = args[0] if args and not args[0].startswith("-") else ""
    rest = args[1:] if agent else args

    if agent in {"", "-h", "--help"}:
        typer.echo("usage: qed hook claude-code [--human you@example.com] [--env dev]")
        typer.echo("")
        typer.echo("Agents: claude-code. Codex arrives when its hook API is confirmed")
        typer.echo("(SPEC 12.2); there is no wrapper yet and a stub would be worse")
        typer.echo("than its absence.")
        raise typer.Exit(0)

    if agent != "claude-code":
        typer.secho(
            f"qed: no hook for {agent!r}. Only `claude-code` exists today; Codex "
            "arrives when its hook API is confirmed (SPEC 12.2).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    from qed.adapters.hooks.claude_code import main as hook_main

    raise typer.Exit(hook_main(rest))


# -------------------------------------------------------------------- install


@app.command()
def install(
    agent: Annotated[str, typer.Argument(help="claude-code")],
    human: Annotated[
        str | None,
        typer.Option("--human", help="Who the session acts for. Hashed into principal_hash."),
    ] = None,
    directory: DirOption = DEFAULT_DIR,
    config: ConfigOption = None,
    environment: Annotated[
        str, typer.Option("--env", help="dev, staging or prod. Scores the blast radius.")
    ] = "dev",
    fail_mode: Annotated[
        str,
        typer.Option(
            "--fail-mode",
            help="What to do when qed itself cannot decide. open or closed; "
            "SPEC 12.2 defaults open in dev and closed in prod.",
        ),
    ] = "",
    scope: Annotated[
        str,
        typer.Option(
            "--scope",
            help="local (gitignored, the default), project (committed) or user (all projects).",
        ),
    ] = "local",
    mandate_file: Annotated[
        Path | None, typer.Option("--mandate", help="Mandate as JSON, for an unattended agent.")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print what would be written and write nothing.")
    ] = False,
) -> None:
    """Write the qed hook into a coding agent's settings (SPEC 12.2).

        qed install claude-code --human you@example.com

    The entry is merged into the existing hooks rather than replacing them, is
    matched on the executable so re-running updates it instead of adding a
    second, and is written in exec form so a path with spaces needs no
    quoting.

    `--scope local` by default, which is the gitignored settings file: an
    entry naming one person's email in a file the team commits would
    attribute everybody's actions to whoever ran the installer.
    """
    if agent != "claude-code":
        _fail(
            f"no installer for {agent!r}. Only `claude-code` exists today; Codex arrives "
            "when its hook API is confirmed (SPEC 12.2)."
        )
        return
    if environment not in {"dev", "staging", "prod"}:
        _fail("--env must be dev, staging or prod")
        return
    if scope not in {"local", "project", "user"}:
        _fail("--scope must be local, project or user")
        return
    if human is None and mandate_file is None:
        _fail(
            "give --human <who you are> or --mandate <file>. Without either, every verdict "
            "is a synthetic AG-IDN-007 identity BLOCK reached before any rule is evaluated, "
            "and in shadow mode nothing would look wrong."
        )
        return

    mode = fail_mode or ("closed" if environment == "prod" else "open")
    if mode not in {"closed", "open"}:
        _fail("--fail-mode must be open or closed")
        return

    from qed.adapters.hooks.install import apply_plan, plan_install, settings_path

    target = settings_path(scope=scope)
    plan = plan_install(
        path=target,
        human=human,
        environment=environment,
        directory=directory,
        config=config,
        fail_mode=mode,
        mandate=mandate_file,
    )

    typer.echo(f"settings : {plan.path}")
    typer.echo(f"command  : {plan.command}")
    typer.echo(f"args     : {' '.join(plan.args)}")
    if dry_run:
        typer.echo("")
        typer.echo("--dry-run: nothing was written.")
        return

    try:
        result = apply_plan(plan)
    except (OSError, ValueError) as exc:
        _fail(str(exc))
        return

    typer.echo("")
    typer.secho(
        f"qed: {'updated' if result.replaced else 'installed'} the PreToolUse hook"
        + (f", leaving {result.preserved} other hook(s) alone" if result.preserved else ""),
        fg=typer.colors.GREEN,
    )
    typer.echo("")
    typer.secho(
        "This adapter is ADVISORY and always will be (SPEC 12.2, ADR-001). Whoever can "
        "edit these settings can delete this line, so the chain records every decision "
        "as advisory and never claims the call could not have happened.",
        fg=typer.colors.YELLOW,
    )
    typer.echo("")
    typer.echo("To stop a developer or a prompt-injected agent removing it, deploy the")
    typer.echo("same entry through Claude Code's managed settings and set")
    typer.echo("`allowManagedHooksOnly: true`. That hardens the adapter; it does not make")
    typer.echo("it enforcing. For that the agent has to be unable to reach the target")
    typer.echo("without qed: see `qed proxy` and the credential broker.")
    if mode == "open":
        typer.echo("")
        typer.secho(
            f"fail_mode is open (env {environment}), so a tool call proceeds when qed "
            "itself cannot decide. The gap is written to the chain as an ungated_window, "
            "not swallowed. Use --fail-mode closed to refuse instead.",
            fg=typer.colors.YELLOW,
        )


# ----------------------------------------------------------------------- demo


@app.command()
def demo(
    directory: Annotated[
        Path,
        typer.Option("--dir", help="Where to put the throwaway instance."),
    ] = Path("qed-demo"),
) -> None:
    """Decide five proposals against a throwaway instance, then verify the chain.

        qed demo

    Needs no configuration, no keys, no network and no agent: it generates a
    signing key, writes a `qed.yaml`, decides a read, a destructive migration,
    an open security group, an unapproved egress and an unauthorised agent, and
    verifies the chain it just wrote.

    **Exits 0 even though a BLOCK is in it.** `qed check` returns the verdict as
    its exit code (SPEC 12.5); this returns whether the demo ran, so pasting it
    into a pipeline to see what it does cannot fail the pipeline.

    Every record is marked `dev`, in the record itself -- a demo chain that
    could be mistaken for evidence would be worse than no demo. The directory
    it writes (`./qed-demo` by default) holds a `.gitignore` of its own, so a
    generated key and a demo chain cannot be committed by accident. Delete it
    when you are done; running the demo again into it extends the same chain.
    """
    from qed.demo import run

    steps, session = run(directory)
    try:
        _demo_report(directory, steps, session)
    finally:
        session.close()


def _demo_report(state: Path, steps: list[Step], session: Session) -> None:
    """Print the run. Separate from the command so the output has one home."""
    colour = {
        Decision.ALLOW: typer.colors.GREEN,
        Decision.REQUIRE_APPROVAL: typer.colors.YELLOW,
        Decision.BLOCK: typer.colors.RED,
    }
    typer.echo("")
    typer.secho("qed demo", bold=True, nl=False)
    typer.echo("  five proposals, one chain, nothing to configure")
    typer.echo("")
    typer.echo(f"  state   {state}{os.sep}  (generated key, sqlite chain, every record dev)")
    typer.echo(
        f"  policy  agent-baseline, {len(session.bundle.active_rules())} active rules, "
        f"mode {session.config.mode.value}"
    )
    typer.echo("")

    for index, step in enumerate(steps, start=1):
        verdict = step.outcome.verdict
        decided = verdict.decision
        suffix = (
            f"   (would be {verdict.would_decision.value} in enforce)"
            if verdict.would_decision is not decided
            else ""
        )
        typer.echo(f"  {index}  ", nl=False)
        typer.secho(f"{decided.value:<17}", fg=colour[decided], bold=True, nl=False)
        typer.echo(f" {step.scene.headline}{suffix}")
        typer.echo(
            f"       {step.proposal.action.name} -> {step.proposal.action.target}"
            f"   blast radius {verdict.blast_radius}/100"
        )
        for hit in verdict.hits:
            marker = "~" if hit.mode.value == "shadow" else "!"
            typer.echo(f"       {marker} {hit.rule_id}  {hit.message}")
        typer.secho(f"       {step.scene.teaches}", dim=True)
        typer.echo("")

    records = list(session.store.iter_evidence())
    # Counted rather than described, because the count is not "two per
    # decision": the chain opens with its genesis and the policy it loaded, and
    # the approval the second scene asked for is a record of its own.
    kinds = Counter(record.type.value for record in records)
    # In chain order, not alphabetical: the order is the story (genesis, the
    # policy it loaded, then the decisions).
    breakdown = ", ".join(f"{kinds[name]} {name}" for name in dict.fromkeys(kinds))
    typer.echo(f"  chain   {len(records)} records -- {breakdown}")
    typer.echo(f"          head {records[-1].hash[:16]}...")
    _demo_verify(state, session, records)

    config = state / "qed.yaml"
    typer.echo("")
    typer.secho("  Next", bold=True)
    typer.echo(f"    qed policy explain {steps[1].path}")
    typer.echo("          why the numbers came out that way -- writes nothing")
    typer.echo(f"    qed export --dir {state} --config {config} --format oscal")
    typer.echo("          the same chain as an OSCAL assessment result")
    typer.echo(f"    qed verify --dir {state} --config {config}")
    typer.echo("          check it yourself, or hand the export to `qed-verify`")
    typer.echo("")
    typer.echo("  Then put it in front of a real agent: `qed install claude-code --human you@`,")
    typer.echo("  and read docs/onboarding-shadow-to-enforce.md before turning `mode: enforce` on.")
    typer.echo("")


def _demo_verify(state: Path, session: Session, records: list[EvidenceRecord]) -> None:
    """Verify the demo chain with the standalone verifier, or say it was not verified.

    `qed-verify` is a separate distribution on purpose -- an auditor installs
    it without installing the kernel -- so a `pip install valqore-qed` may not
    have it. The demo says so plainly rather than printing a verification it
    did not do, which is the failure this repository already shipped once
    (`qed-verify` printed OK over a genesis check it had skipped).
    """
    try:
        from qed_verify.verify import load_jsonl, verify_records
    except ImportError:
        typer.secho(
            "          not verified: qed-verify is not installed (pip install qed-verify)",
            fg=typer.colors.YELLOW,
        )
        return

    from qed.infra.keys.file import load_public_keys

    report = verify_records(
        load_jsonl(to_jsonl(records)),
        load_public_keys(state / PUBLIC_DIR_NAME),
        instance_id=session.config.instance_id,
    )
    if report.ok and report.complete:
        typer.secho(
            "          verified: contiguous, unmodified, signed, and bound to "
            f"instance {session.config.instance_id!r}",
            fg=typer.colors.GREEN,
        )
        return
    for line in report.summary().splitlines():
        typer.secho(f"          {line}", fg=typer.colors.RED if not report.ok else None)


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
