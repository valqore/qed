"""`gate` command line (SPEC §14).

Week 2 ships 7 of the 18 commands: ``keys``, ``check``, ``policy``, ``export``,
``verify``, ``serve`` and ``mcp``. SPEC §14 forbids adding a top-level command
without a spec update, so the missing ones are absent rather than stubbed -- a
command that prints "not implemented" is worse than one that does not exist,
because it ends up in somebody's script.

``check`` exit codes: 0 ALLOW, 2 REQUIRE_APPROVAL, 3 BLOCK, 1 error. In shadow
mode the decision is recorded and the exit code is 0 (ADR-003).

``mcp`` is the one command that must not print to stdout: stdout is the MCP
transport, and a stray line of status text there is a protocol error that
presents to the user as "the server crashed". Everything it says goes to stderr.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, cast

import typer

from gate.config import DEFAULT_DIR
from gate.core.evidence.export.jsonl import to_csv, to_jsonl
from gate.core.evidence.export.oscal import to_oscal
from gate.core.policy.engine import explain as explain_proposal
from gate.core.policy.loader import baseline_pack_dir, load_bundle
from gate.core.schemas import (
    ActionProposal,
    BudgetState,
    Decision,
    Enforcement,
    Environment,
    Mandate,
    utcnow,
)
from gate.infra.keys.file import PUBLIC_DIR_NAME, MissingSigningKey, init_keys
from gate.runtime import (
    DuplicateProposal,
    PolicyErrors,
    chain_status,
    check_proposal,
    open_session,
)

if TYPE_CHECKING:  # `gate mcp` imports the MCP SDK lazily: it is an
    # adapters-only dependency (SPEC 20.3) and `gate check` should not pay for
    # importing it on every invocation.
    from gate.adapters.mcp.proxy import ProxyStats

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Policy and evidence kernel for AI-agent actions.",
)
keys_app = typer.Typer(no_args_is_help=True, help="Evidence signing keys.")
policy_app = typer.Typer(no_args_is_help=True, help="Policy bundle tools.")
mandate_app = typer.Typer(no_args_is_help=True, help="Mandates for unattended agents.")
app.add_typer(keys_app, name="keys")
app.add_typer(policy_app, name="policy")
app.add_typer(mandate_app, name="mandate")

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

    from gate.core.policy.cases import CaseError, load_cases, run_cases, uncovered_rules
    from gate.core.schemas import utcnow

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
    """Export the evidence chain. JSONL is what `gate-verify` reads.

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
    """Sign a mandate and record its issue in the chain (SPEC §6.5).

    The signature covers the whole document except its own `signature` field
    and `revoked_at`, so a mandate keeps verifying after it is revoked -- the
    record of who granted the authority has to survive the withdrawal of it.
    """
    from gate.core.mandates import MANDATE_ALG, signing_payload
    from gate.core.schemas import Assurance, EvidenceType, Mandate, MandateSignature

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
    from gate.core.mandates import is_active

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
    """Revoke a mandate. Tokens that reference it fail on next use (§6.1 step 5).

    Nothing is deleted. The signed document stays exactly as issued and the
    revocation is a separate fact, in its own column and in the chain.
    """
    from gate.core.schemas import Assurance, EvidenceType

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
    """Decide a pending approval (SPEC §9.3).

    Separation of duties is enforced here, not reported: you cannot approve
    your own action, a service identity cannot approve anything, and you have
    to be in the group the rule named.

    `--window 15m` grants every identical action for that period rather than
    this one. Windows are not extendable; when one runs out the next action
    opens a fresh request.
    """
    from gate.core.approval.model import (
        DecisionKind,
        SoDViolation,
        decide,
        parse_duration,
    )
    from gate.core.evidence.hashing import principal_hash
    from gate.core.schemas import Assurance, EvidenceType

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

    `--expire` runs the timeout sweep (SPEC §9.4) and writes one
    `approval_expired` record per request. A request that simply vanished
    from the queue would not be evidence of anything.
    """
    from gate.core.schemas import Assurance, EvidenceType

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
    """Report posture: what this instance can actually enforce (SPEC §7.2).

    The question it answers is the uncomfortable one. For every upstream:
    does the gate hold the credential, or is the agent carrying its own? An
    adapter in the second case still gets a verdict and still writes
    evidence, but it could be bypassed entirely, and an operator deserves to
    be told which of their upstreams are which.
    """
    from gate.core.broker.model import Enforcement, describe
    from gate.infra.secrets.resolver import CredentialResolver, SecretResolutionError
    from gate.infra.upstreams import load_upstreams

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
    finally:
        session.close()

    if as_json:
        typer.echo(json.dumps(report, indent=2))
        return

    typer.echo(f"instance   : {report['instance_id']}  (mode {report['mode']})")
    typer.echo(f"signing key: {report['signing_key']}")
    typer.echo(f"policy     : {report['policy_rules']} rules")
    rows_out = cast("list[dict[str, object]]", report["upstreams"])
    if not rows_out:
        typer.echo("")
        typer.echo(
            "upstreams  : none configured, so every adapter is ADVISORY -- the gate "
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
    from gate.infra.credentials import CredentialStore, StoredLogin
    from gate.infra.device_flow import (
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
    gate_url: Annotated[
        str, typer.Option("--gate-url", help="Base URL of the gate API")
    ] = "http://127.0.0.1:8710",
    scope: Annotated[str, typer.Option("--scope", help="Scopes to request")] = "",
    adapter: Annotated[str, typer.Option("--adapter", help="Adapter id for signing")] = "",
    secret_env: Annotated[
        str, typer.Option("--secret-env", help="Env var holding the adapter secret")
    ] = "GATE_ADAPTER_SECRET",
    raw: Annotated[bool, typer.Option("--raw", help="Print only the token")] = False,
) -> None:
    """Exchange the stored login for a budgeted gate token (SPEC §6.2).

    Adapters call this transparently when their cached token is close to
    expiry; a person runs it to get a token for a one-off command.
    """
    import os

    import httpx

    from gate.api.auth import canonical_string, sign
    from gate.core.schemas import rfc3339_ms
    from gate.infra.credentials import CredentialStore
    from gate.infra.device_flow import DeviceFlowError, discover_endpoints, refresh_access_token

    stored = CredentialStore().load(issuer)
    if stored is None:
        _fail(f"not signed in to {issuer}; run `gate login --issuer {issuer} --client-id ...`")
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
        "x-gate-adapter": adapter,
        "x-gate-timestamp": timestamp,
        "x-gate-nonce": "",
        "x-gate-signature": sign(
            secret,
            canonical_string(method="POST", path=path, timestamp=timestamp, nonce="", body=body),
        ),
    }
    try:
        response = httpx.post(
            f"{gate_url.rstrip('/')}{path}", content=body, headers=headers, timeout=10.0
        )
    except httpx.HTTPError as exc:
        _fail(f"could not reach the gate at {gate_url}: {exc}")
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
    """Append a Merkle checkpoint over the records since the last one."""
    session = open_session(directory=directory, config_path=config, strict_policy=False)
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
    config: ConfigOption = None,
) -> None:
    """Verify a chain. A thin wrapper; auditors should run `gate-verify` itself."""
    try:
        from gate_verify.verify import load_jsonl, verify_records
    except ImportError:
        _fail("gate-verify is not installed: pip install ./packages/gate-verify")
        return

    from gate.infra.keys.file import load_public_keys

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
    dev: Annotated[
        bool,
        typer.Option(
            "--dev",
            help="Skip adapter signature checks and mark records as dev. Local use only.",
        ),
    ] = False,
) -> None:
    """Run the HTTP API (SPEC 13).

    `/readyz` answers 503 until there is a signing key and a way to
    authenticate adapters, so `gate keys init` comes first. Without `--dev`,
    register an adapter under `adapters:` in gate.yaml with a `secret_env`.
    """
    try:
        import uvicorn
    except ImportError:  # pragma: no cover - fastapi and uvicorn are install deps
        _fail("uvicorn is not installed: pip install 'valqore-gate'")
        return

    from gate.api.app import create_app
    from gate.config import load_config

    settings = load_config(config).config
    bind_host = host if host is not None else settings.api.host
    bind_port = port if port is not None else settings.api.port

    if dev:
        typer.secho(
            "gate: --dev is on. Adapter signatures are NOT checked and every record is "
            "marked dev. Do not point real agents at this.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    typer.echo(f"gate: serving on http://{bind_host}:{bind_port} (mode {settings.mode.value})")

    application = create_app(directory=directory, config_path=config, policy_paths=policy, dev=dev)
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

        gate mcp --human you@acme.com -- npx -y @scope/server

    Everything after `--` is the upstream command. Decisions and results go into
    the evidence chain; in shadow mode (the default) nothing is stopped.

    `--human` or `--mandate` is required. Without one, every proposal has no
    principal and no delegated authority, the engine answers with a synthetic
    AG-IDN-007 identity BLOCK before any rule is evaluated, and the chain fills
    with identical verdicts that say nothing about your policy.
    """
    import anyio

    from gate.adapters.mcp.proxy import ProxyOptions, ProxyStats, UpstreamSpec, run_proxy
    from gate.adapters.mcp.targets import DEFAULT_TEMPLATE, TemplateError
    from gate.core.evidence.hashing import principal_hash

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
        _fail(f"{exc}. Run `gate keys init` first: an unsigned decision is not evidence.")
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
        f"gate: proxying {name} in {mode} mode, env {environment}, "
        f"target template {upstream.target_template!r}",
        fg=typer.colors.CYAN,
        err=True,
    )
    if human is not None:
        typer.secho(
            f"gate: calls are attributed to {human} at issuer {issuer!r}, on this adapter's "
            "word alone. Verified identity arrives in week 3.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if mode == "shadow":
        typer.secho(
            "gate: shadow mode. Every call is decided and recorded; nothing is stopped.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    from gate.infra.secrets.broker import CredentialBroker
    from gate.infra.secrets.resolver import CredentialResolver
    from gate.infra.upstreams import load_upstreams

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
            "gate: no upstreams configured, so this session is ADVISORY -- every call is "
            "decided and recorded, but the agent is using its own credentials and could "
            "go around the gate. `gate doctor` says the same thing at more length.",
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
        f"gate: {stats.calls} tool call(s); {stats.allowed} forwarded, "
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
            f"gate: {stats.advisory} of those call(s) were ADVISORY -- decided and "
            "recorded, but the gate was not holding the credential.",
            fg=typer.colors.YELLOW,
            err=True,
        )


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
