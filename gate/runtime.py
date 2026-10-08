"""Wiring: config → store → key → policy bundle → decision → chain.

This is the one place that knows how the pure kernel and the stateful
infrastructure fit together. `gate check` uses it today; the FastAPI
``/v1/proposals`` router in week 2 uses the same two functions, so the CLI and
the server cannot drift into deciding things differently.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from gate.config import DEFAULT_DIR, GateConfig, LoadedConfig, load_config
from gate.core import jcs
from gate.core.budget import charge_for, newly_exhausted
from gate.core.policy.engine import evaluate
from gate.core.policy.loader import LoadResult, baseline_pack_dir, load_bundle
from gate.core.policy.model import LintFinding, PolicyBundle
from gate.core.schemas import (
    ActionProposal,
    Assurance,
    BudgetState,
    Decision,
    EvalContext,
    EvidenceRecord,
    EvidenceType,
    HistoryDerived,
    Mandate,
    Mode,
    Verdict,
    rfc3339_ms,
    utcnow,
)
from gate.infra.chain_writer import ChainWriter
from gate.infra.keys.file import PUBLIC_DIR_NAME, FileSigner, load_signer
from gate.infra.storage.sqlite import SqliteStore

__all__ = [
    "CheckOutcome",
    "DuplicateProposal",
    "PolicyErrors",
    "Session",
    "check_proposal",
    "open_session",
]

DB_NAME = "gate.db"


class DuplicateProposal(RuntimeError):
    """A proposal id was submitted twice (SPEC §17, replay)."""


class PolicyErrors(RuntimeError):
    def __init__(self, findings: list[LintFinding]) -> None:
        self.findings = findings
        super().__init__(f"{len(findings)} policy error(s)")


@dataclass
class Session:
    config: GateConfig
    loaded_config: LoadedConfig
    directory: Path
    store: SqliteStore
    signer: FileSigner
    writer: ChainWriter
    bundle: PolicyBundle
    findings: list[LintFinding]

    @property
    def public_keys_dir(self) -> Path:
        return self.directory / PUBLIC_DIR_NAME

    def close(self) -> None:
        self.store.close()


def open_session(
    *,
    directory: Path = DEFAULT_DIR,
    policy_paths: list[Path] | None = None,
    config_path: Path | None = None,
    dev: bool = False,
    strict_policy: bool = True,
) -> Session:
    """Open a usable session, or raise.

    Refuses to proceed when the policy bundle has lint errors: an engine run
    against a bundle with a broken regex or a missing override target would make
    decisions nobody wrote. ``strict_policy=False`` is for `policy lint`, which
    needs to report the errors rather than trip over them.
    """
    loaded = load_config(config_path)
    config = loaded.config

    store = SqliteStore(directory / DB_NAME)
    # Everything from here on can fail — a missing signing key, a chain that
    # belongs to another instance, a policy error. The store has to be closed on
    # every one of those paths or the CLI leaks a file handle per invocation.
    try:
        signer = load_signer(directory)
        writer = ChainWriter(
            store,
            signer,
            instance_id=config.instance_id,
            dev=dev,
            masking=config.evidence.masking,
        )

        paths = [baseline_pack_dir(), *(policy_paths or [Path(p) for p in config.policies])]
        result: LoadResult = load_bundle(
            [p for p in paths if p.exists()],
            default_verdict=config.default_verdict,
            default_mode=Mode.enforce,
        )
        if strict_policy and not result.ok:
            raise PolicyErrors(result.errors)
    except BaseException:
        store.close()
        raise

    session = Session(
        config=config,
        loaded_config=loaded,
        directory=directory,
        store=store,
        signer=signer,
        writer=writer,
        bundle=result.bundle,
        findings=result.findings,
    )
    _record_bundle_once(session)
    return session


def _record_bundle_once(session: Session) -> None:
    """Append ``policy_loaded`` the first time a bundle hash is seen."""
    now = utcnow()
    first_time = session.store.record_bundle(
        bundle_hash=session.bundle.hash,
        version=session.bundle.version,
        rules_count=len(session.bundle.rules),
        loaded_at=now,
    )
    if not first_time:
        return
    disabled = [
        {"rule_id": r.rule_id, "reason": r.reason, "disabled_by": r.disabled_by}
        for r in session.bundle.rules
        if r.disabled
    ]
    session.writer.append(
        type_=EvidenceType.policy_loaded,
        assurance=Assurance.kernel,
        payload={
            "policy_hash": session.bundle.hash,
            "rules_total": len(session.bundle.rules),
            "rules_active": len(session.bundle.active_rules()),
            "rules_shadow": sum(1 for r in session.bundle.active_rules() if r.mode is Mode.shadow),
            "default_verdict": session.bundle.default_verdict.value,
            "sources": list(session.bundle.sources),
            "disabled": disabled,
            "lint_warnings": [f.format() for f in session.findings],
        },
        ts=now,
    )


@dataclass
class CheckOutcome:
    verdict: Verdict
    #: False when the service runs in shadow mode: the decision is recorded but
    #: the adapter is told to proceed (ADR-003).
    enforced: bool
    records: list[EvidenceRecord]

    @property
    def effective_decision(self) -> Decision:
        return self.verdict.decision if self.enforced else Decision.ALLOW

    @property
    def exit_code(self) -> int:
        """0 allow, 2 approval needed, 3 blocked. Shadow mode always allows."""
        return {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 2, Decision.BLOCK: 3}[
            self.effective_decision
        ]


def check_proposal(
    session: Session,
    proposal: ActionProposal,
    *,
    budget: BudgetState | None = None,
    mandate: Mandate | None = None,
    history: HistoryDerived | None = None,
    now: datetime | None = None,
) -> CheckOutcome:
    """Decide one proposal and write both records to the chain."""
    if session.store.proposal_exists(proposal.id):
        raise DuplicateProposal(
            f"proposal {proposal.id} has already been decided; ids are single-use"
        )

    stamp = now if now is not None else utcnow()
    jti = proposal.principal.token_jti
    # An explicit `budget` overrides the ledger: the CLI passes one for
    # `--budget` dry-runs and the tests pass one to pin a state. Otherwise the
    # ledger is the source of truth, and a token with no row is uncapped.
    state = (
        budget
        if budget is not None
        else (session.store.load_budget(jti) or BudgetState(token_jti=jti))
    )
    ctx = EvalContext(
        now=stamp, mandate=mandate, history=history if history is not None else HistoryDerived()
    )

    records: list[EvidenceRecord] = []
    records.append(
        session.writer.append(
            type_=EvidenceType.proposal,
            assurance=Assurance.kernel,
            payload={"proposal": proposal.model_dump(mode="json")},
            mode=session.config.mode,
            enforcement=proposal.context.enforcement,
            proposal_id=proposal.id,
            principal_hash=proposal.principal.human_hash,
            ts=stamp,
        )
    )

    verdict = evaluate(proposal, session.bundle, state, ctx)

    records.append(
        session.writer.append(
            type_=EvidenceType.verdict,
            assurance=Assurance.kernel,
            payload={"verdict": verdict.model_dump(mode="json")},
            mode=session.config.mode,
            enforcement=proposal.context.enforcement,
            proposal_id=proposal.id,
            principal_hash=proposal.principal.human_hash,
            ts=stamp,
        )
    )

    outcome = CheckOutcome(
        verdict=verdict, enforced=session.config.mode is Mode.enforce, records=records
    )

    # Charge only when the action is actually going to run. In enforce mode a
    # BLOCK stops it, so nothing is spent; in shadow mode the adapter proceeds
    # whatever the verdict says, and the tokens and money are spent for real.
    # `effective_decision` already encodes that difference, so the ledger
    # follows what happened rather than what was decided.
    #
    # A charge is skipped when the caller pinned a `budget`, because that is a
    # hypothetical state and writing it back would corrupt the real ledger.
    if budget is None and outcome.effective_decision is Decision.ALLOW:
        charge = charge_for(proposal)
        before, after = session.store.charge_budget(
            jti, charge, now=stamp, principal_hash=proposal.principal.human_hash
        )
        # No evidence record per charge. SPEC §8 writes one only on exhaustion,
        # and §6.2 writes `budget_update` only when a token is issued. A record
        # per allowed action would double the chain, restate what the verdict
        # record already implies (one ALLOW is one step), and put a signature
        # and an insert on the hot path the week-7 p95 target has to defend.
        # The running totals live in the ledger, which the next decision reads.
        if newly_exhausted(before, after, now=stamp):
            # Written after the update that caused it, so a reader of the chain
            # sees the charge and then the consequence, in that order. The next
            # action on this token short-circuits on AG-BUD-001.
            records.append(
                session.writer.append(
                    type_=EvidenceType.budget_exhausted,
                    assurance=Assurance.kernel,
                    payload={
                        "token_jti": jti,
                        "budget": after.budget.model_dump(mode="json"),
                        "steps_used": after.steps_used,
                        "tokens_used": after.tokens_used,
                        "money_used_cents": after.money_used_cents,
                    },
                    mode=session.config.mode,
                    enforcement=proposal.context.enforcement,
                    proposal_id=proposal.id,
                    principal_hash=proposal.principal.human_hash,
                    ts=stamp,
                )
            )

    session.store.record_proposal(
        proposal_json=jcs.dumps(proposal.model_dump(mode="json")),
        verdict_json=jcs.dumps(verdict.model_dump(mode="json")),
        proposal_id=proposal.id,
        ts=proposal.ts,
        token_jti=proposal.principal.token_jti,
        principal_hash=proposal.principal.human_hash,
        kind=proposal.action.kind.value,
        name=proposal.action.name,
        target=proposal.action.target,
        params_hash=proposal.action.params_hash,
        environment=proposal.context.environment,
        adapter_id=proposal.context.adapter_id,
        enforcement=proposal.context.enforcement.value,
        mode=session.config.mode.value,
    )

    return outcome


def chain_status(session: Session) -> dict[str, object]:
    """Small posture summary used by the CLI."""
    last = session.store.last_seq()
    checkpoint = session.store.last_checkpoint()
    return {
        "instance_id": session.config.instance_id,
        "records": session.store.count_evidence(),
        "last_seq": last,
        "key_id": session.signer.key_id,
        "policy_hash": session.bundle.hash,
        "rules_active": len(session.bundle.active_rules()),
        "mode": session.config.mode.value,
        "last_checkpoint": None
        if checkpoint is None
        else {"from_seq": checkpoint[0], "to_seq": checkpoint[1], "merkle_root": checkpoint[2]},
        "generated_at": rfc3339_ms(utcnow()),
    }
