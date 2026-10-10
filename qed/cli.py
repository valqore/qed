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
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, cast

import typer
from typer.core import TyperGroup

from qed.config import DEFAULT_DIR
from qed.core.evidence.export.jsonl import to_csv, to_jsonl
from qed.core.evidence.export.oscal import to_oscal
from qed.core.policy.engine import explain as explain_proposal
from qed.core.policy.loader import baseline_pack_dir, load_bundle
from qed.core.schemas import (
    ActionProposal,
    BudgetState,
    Decision,
    Enforcement,
    Environment,
    Mandate,
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

#: Failures that are a statement about the operator's chain, not a bug in qed.
#:
#: Each already carries a sentence written for a person, and a traceback around
#: it helps nobody: "this chain was last signed by X" is the whole answer and
#: the frames above it are noise.
OPERATOR_ERRORS: Final = (InstanceMismatch, KeyDiscontinuity)


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
app.add_typer(keys_app, name="keys")
app.add_typer(policy_app, name="policy")
app.add_typer(packs_app, name="packs")
app.add_typer(mandate_app, name="mandate")

DirOption = Annotated[Path, typer.Option("--dir", help="qed state directory (keys and chain).")]
PolicyOption = Annotated[
    list[Path] | None,
    typer.Option("--policy", help="Extra policy file or directory. Repeatable."),
]
ConfigOption = Annotated[Path | None, typer.Option("--config", help="Path to qed.yaml.")]


def _fail(message: str) -> None:
    typer.secho(f"qed: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


# ---------------------------------------------------------------------- keys


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
    from qed.compliance.packs import coverage, packs

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

    typer.echo("")
    for row in rows:
        if row.unmapped:
            typer.echo(f"{row.framework}: not mapped -- {', '.join(row.unmapped)}")
    typer.echo("")
    typer.echo(
        "`partial` means the catalogue lists the controls this rule set maps to and not "
        "the whole framework, so there is no honest percentage to print. `depth` is "
        "SPEC 11's flag: how deep the mapping goes, not how good it is."
    )


@packs_app.command("import")
def packs_import(
    path: Annotated[Path, typer.Argument(help="A signed pack bundle.")],
) -> None:
    """Import a signed control catalogue (SPEC 11, week 9).

    Not implemented. The signed-pack feed is `qed.remote.packs`, which week 9
    builds together with the signature verification this would need -- and an
    import that accepted an unsigned catalogue would be a way to put control
    titles an auditor reads in front of them without anybody vouching for the
    source.
    """
    _fail(
        "signed pack import is week 9 (SPEC 11's `qed.remote.packs`). Until then the "
        "catalogues ship with the package: `qed packs list` shows them. Importing an "
        "unsigned catalogue would put control titles in front of an auditor with nobody "
        "vouching for where they came from."
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
) -> None:
    """Verify a chain. A thin wrapper; auditors should run `qed-verify` itself."""
    try:
        from qed_verify.verify import load_jsonl, verify_records
    except ImportError:
        _fail("qed-verify is not installed: pip install ./packages/qed-verify")
        return

    from qed.infra.keys.file import load_public_keys

    if records is None:
        session = open_session(directory=directory, config_path=config, strict_policy=False)
        text = to_jsonl(session.store.iter_evidence())
        instance_id = session.config.instance_id
        session.close()
    else:
        text = records.read_text(encoding="utf-8")
        instance_id = None

    report = verify_records(
        load_jsonl(text), load_public_keys(directory / PUBLIC_DIR_NAME), instance_id=instance_id
    )
    typer.echo(json.dumps(report.to_dict(), indent=2) if as_json else report.summary())
    raise typer.Exit(0 if report.ok else 1)


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
    authenticate adapters, so `qed keys init` comes first. Without `--dev`,
    register an adapter under `adapters:` in qed.yaml with a `secret_env`.

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
        str, typer.Option("--token-jti", help="Token id to attribute calls to (week 3: real).")
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
            "Verified identity from an IdP arrives in week 3; until then --human is the "
            "adapter's own assertion and is recorded as such."
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
            "word alone. Verified identity arrives in week 3.",
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


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
