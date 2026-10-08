"""`gate` command line (SPEC §14).

Week 1 ships 5 of the 18 commands: ``keys``, ``check``, ``policy``, ``export``
and ``verify``. SPEC §14 forbids adding a top-level command without a spec
update, so the missing ones are absent rather than stubbed -- a command that
prints "not implemented" is worse than one that does not exist, because it ends
up in somebody's script.

``check`` exit codes: 0 ALLOW, 2 REQUIRE_APPROVAL, 3 BLOCK, 1 error. In shadow
mode the decision is recorded and the exit code is 0 (ADR-003).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from gate.config import DEFAULT_DIR
from gate.core.evidence.export.jsonl import to_csv, to_jsonl
from gate.core.policy.engine import explain as explain_proposal
from gate.core.policy.loader import baseline_pack_dir, load_bundle
from gate.core.schemas import ActionProposal, BudgetState, Decision, Mandate
from gate.infra.keys.file import PUBLIC_DIR_NAME, MissingSigningKey, init_keys
from gate.runtime import (
    DuplicateProposal,
    PolicyErrors,
    chain_status,
    check_proposal,
    open_session,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Policy and evidence kernel for AI-agent actions.",
)
keys_app = typer.Typer(no_args_is_help=True, help="Evidence signing keys.")
policy_app = typer.Typer(no_args_is_help=True, help="Policy bundle tools.")
app.add_typer(keys_app, name="keys")
app.add_typer(policy_app, name="policy")

DirOption = Annotated[Path, typer.Option("--dir", help="gate state directory (keys and chain).")]
PolicyOption = Annotated[
    list[Path] | None,
    typer.Option("--policy", help="Extra policy file or directory. Repeatable."),
]
ConfigOption = Annotated[Path | None, typer.Option("--config", help="Path to gate.yaml.")]


def _fail(message: str) -> None:
    typer.secho(f"gate: {message}", fg=typer.colors.RED, err=True)
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
        _fail(f"{exc}. Use `gate keys rotate` (week 7) to change keys without breaking the chain.")
        return
    typer.echo(f"key_id : {info.key_id}")
    typer.echo(f"private: {directory / 'evidence-key.pem'}  (keep this; 0600)")
    typer.echo(f"public : {directory / PUBLIC_DIR_NAME}  (give this to auditors)")


@keys_app.command("export-public")
def keys_export_public(directory: DirOption = DEFAULT_DIR) -> None:
    """Print the active public key in PEM form."""
    try:
        session = open_session(directory=directory)
    except MissingSigningKey as exc:
        _fail(str(exc))
        return
    typer.echo(session.signer.public_pem.rstrip())
    session.close()


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
) -> None:
    """Decide one proposal, append proposal and verdict to the chain."""
    try:
        proposal = ActionProposal.model_validate_json(proposal_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"cannot read proposal: {exc}")
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

    session.close()
    raise typer.Exit(outcome.exit_code)


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
    from gate.core.schemas import EvalContext, utcnow

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


# -------------------------------------------------------------------- export


@app.command()
def export(
    directory: DirOption = DEFAULT_DIR,
    out: Annotated[Path | None, typer.Option("--out", help="Write here instead of stdout.")] = None,
    export_format: Annotated[str, typer.Option("--format", help="jsonl or csv.")] = "jsonl",
    from_seq: Annotated[int, typer.Option("--from", help="First seq to include.")] = 0,
    to_seq: Annotated[int | None, typer.Option("--to", help="Last seq to include.")] = None,
) -> None:
    """Export the evidence chain. JSONL is what `gate-verify` reads."""
    if export_format not in {"jsonl", "csv"}:
        _fail("--format must be jsonl or csv (oscal lands in week 2)")
    session = open_session(directory=directory, strict_policy=False)
    records = list(session.store.iter_evidence(from_seq, to_seq))
    text = to_jsonl(records) if export_format == "jsonl" else to_csv(records)
    session.close()
    if out is None:
        sys.stdout.write(text)
    else:
        out.write_text(text, encoding="utf-8")
        typer.echo(f"{len(records)} record(s) -> {out}")


@app.command()
def status(directory: DirOption = DEFAULT_DIR) -> None:
    """Chain and policy posture."""
    session = open_session(directory=directory, strict_policy=False)
    typer.echo(json.dumps(chain_status(session), indent=2))
    session.close()


@app.command()
def checkpoint(
    directory: DirOption = DEFAULT_DIR,
    force: Annotated[
        bool, typer.Option("--force", help="Checkpoint now, below the normal threshold.")
    ] = False,
) -> None:
    """Append a Merkle checkpoint over the records since the last one."""
    session = open_session(directory=directory, strict_policy=False)
    record = session.writer.checkpoint(force=force)
    session.close()
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
) -> None:
    """Verify a chain. A thin wrapper; auditors should run `gate-verify` itself."""
    try:
        from gate_verify.verify import load_jsonl, verify_records
    except ImportError:
        _fail("gate-verify is not installed: pip install ./packages/gate-verify")
        return

    from gate.infra.keys.file import load_public_keys

    if records is None:
        session = open_session(directory=directory, strict_policy=False)
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


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
