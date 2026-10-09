"""Wiring: config → store → key → policy bundle → decision → chain.

This is the one place that knows how the pure kernel and the stateful
infrastructure fit together. `qed check` uses it today; the FastAPI
``/v1/proposals`` router in week 2 uses the same two functions, so the CLI and
the server cannot drift into deciding things differently.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from ulid import ULID

from qed.config import DEFAULT_DIR, LoadedConfig, QedConfig, load_config
from qed.core import jcs
from qed.core.approval.model import (
    DEFAULT_DEDUPE_WINDOW,
    ApprovalRequest,
    dedupe_key,
    parse_duration,
)
from qed.core.budget import charge_for, newly_exhausted
from qed.core.policy.engine import evaluate
from qed.core.policy.loader import LoadResult, baseline_pack_dir, load_bundle
from qed.core.policy.model import LintFinding, PolicyBundle
from qed.core.schemas import (
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
from qed.infra.chain_writer import ChainWriter
from qed.infra.keys.file import PUBLIC_DIR_NAME, FileSigner, load_signer
from qed.infra.storage.store import SqliteStore, SqlStore

__all__ = [
    "CheckOutcome",
    "DuplicateProposal",
    "PolicyErrors",
    "Session",
    "check_proposal",
    "open_session",
    "open_store",
]

DB_NAME = "qed.db"


class DuplicateProposal(RuntimeError):
    """A proposal id was submitted twice (SPEC §17, replay)."""


class PolicyErrors(RuntimeError):
    def __init__(self, findings: list[LintFinding]) -> None:
        self.findings = findings
        super().__init__(f"{len(findings)} policy error(s)")


@dataclass
class Session:
    config: QedConfig
    loaded_config: LoadedConfig
    directory: Path
    store: SqlStore
    signer: FileSigner
    writer: ChainWriter
    bundle: PolicyBundle
    findings: list[LintFinding]

    @property
    def public_keys_dir(self) -> Path:
        return self.directory / PUBLIC_DIR_NAME

    def close(self) -> None:
        self.store.close()


def open_store(config: QedConfig, directory: Path) -> SqlStore:
    """SQLite by default, Postgres when `evidence.store` names a server.

    SQLite is the default because a product that needs a database server to be
    tried is a product fewer people try, and the whole decision path works on
    one file. Postgres is for the case SQLite genuinely cannot serve: more than
    one replica sharing a chain (SPEC §15).
    """
    url = config.evidence.resolved_store()
    if not url or url == "sqlite":
        return SqliteStore(directory / DB_NAME)
    if url.startswith(("postgresql://", "postgres://")):
        from qed.infra.storage.postgres import PostgresStore

        return PostgresStore(url)
    raise ValueError(
        f"`evidence.store` is {url!r}, which is neither `sqlite` nor a postgresql:// URL. "
        "Leave it unset for the file in the state directory."
    )


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

    store = open_store(config, directory)
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


#: Used when no rule named a timeout. Long enough for somebody to look, short
#: enough that an unanswered request stops blocking an agent for a whole shift.
APPROVAL_TIMEOUT_DEFAULT = timedelta(minutes=15)


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


def _resolve_approval(
    session: Session,
    proposal: ActionProposal,
    verdict: Verdict,
    *,
    key: str,
    now: datetime,
) -> tuple[Verdict, list[EvidenceRecord]]:
    """Turn a REQUIRE_APPROVAL into whatever it actually is (SPEC §9.2).

    Four outcomes, in the order they are checked:

    * an open window for this exact action -> ALLOW, `via_approval` set;
    * a recent denial -> BLOCK, because an agent told no should not be able to
      ask again and have the second request look fresh to whoever sees it;
    * a pending request for the same action -> link to it rather than filing a
      copy, so the human sees one request instead of forty;
    * otherwise -> open a new request.
    """
    records: list[EvidenceRecord] = []
    store = session.store

    granted = store.active_window(key, now=now)
    if granted is not None:
        return (
            verdict.model_copy(update={"decision": Decision.ALLOW, "via_approval": granted}),
            records,
        )

    denied = store.recently_denied(key, now=now, window=DEFAULT_DEDUPE_WINDOW)
    if denied is not None:
        return (
            verdict.model_copy(update={"decision": Decision.BLOCK, "approval_id": denied.id}),
            records,
        )

    existing = store.pending_for_dedupe(key, now=now, window=DEFAULT_DEDUPE_WINDOW)
    if existing is not None:
        return verdict.model_copy(update={"approval_id": existing.id}), records

    request = _build_request(proposal, verdict, session.bundle, key=key, now=now)
    store.record_approval(
        request, request_json=jcs.dumps(_approver_view(proposal, verdict, request))
    )
    records.append(
        session.writer.append(
            type_=EvidenceType.approval_requested,
            assurance=Assurance.kernel,
            payload={
                "approval_id": request.id,
                "dedupe_key": key,
                "approvers": request.approvers,
                "expires_at": request.expires_at.isoformat(),
                "blast_radius": verdict.blast_radius,
                "hits": [hit.rule_id for hit in verdict.hits],
            },
            mode=session.config.mode,
            enforcement=proposal.context.enforcement,
            proposal_id=proposal.id,
            approval_id=request.id,
            principal_hash=proposal.principal.human_hash,
            ts=now,
        )
    )
    return verdict.model_copy(update={"approval_id": request.id}), records


def _build_request(
    proposal: ActionProposal,
    verdict: Verdict,
    bundle: PolicyBundle,
    *,
    key: str,
    now: datetime,
) -> ApprovalRequest:
    """Assemble the request from the rules that asked for it.

    The approver list, the timeout and the window ceiling are read from the
    rules that actually fired, and they are written onto the request rather
    than looked up again when somebody decides. The bundle can be reloaded in
    between, and an approver should be bounded by the rule that was in force
    when the action was proposed, not by whatever replaced it.

    Where two rules disagree the tighter one wins: the shortest timeout, the
    smallest window. A rule that asked for a narrow bound should not have it
    widened by another rule happening to fire at the same time.
    """
    by_id = {rule.rule_id: rule for rule in bundle.rules}
    approvers: list[str] = []
    timeout = APPROVAL_TIMEOUT_DEFAULT
    window_max: timedelta | None = None
    escalate_after: timedelta | None = None
    for hit in verdict.hits:
        rule = by_id.get(hit.rule_id)
        approval = None if rule is None else rule.approval
        if approval is None:
            continue
        for group in approval.approvers:
            if group not in approvers:
                approvers.append(group)
        hit_timeout = parse_duration(approval.timeout)
        if hit_timeout is not None:
            timeout = min(timeout, hit_timeout)
        hit_window = parse_duration(approval.window_max)
        if hit_window is not None:
            window_max = hit_window if window_max is None else min(window_max, hit_window)
        hit_escalate = parse_duration(approval.escalate_after)
        if hit_escalate is not None:
            escalate_after = (
                hit_escalate if escalate_after is None else min(escalate_after, hit_escalate)
            )

    return ApprovalRequest(
        id=f"apr_{ULID()}",
        proposal_id=proposal.id,
        dedupe_key=key,
        approvers=approvers,
        principal_hash=proposal.principal.human_hash,
        created_at=now,
        expires_at=now + timeout,
        escalate_at=None if escalate_after is None else now + escalate_after,
        window_max=window_max,
    )


def _approver_view(
    proposal: ActionProposal, verdict: Verdict, request: ApprovalRequest
) -> dict[str, object]:
    """What a person sees when deciding (SPEC §9.2).

    Enough to judge the action, and nothing that would make the queue itself
    a place secrets accumulate: parameters are the already-redacted ones the
    engine saw, never the raw call.
    """
    return {
        "approval_id": request.id,
        "summary": proposal.context.summary,
        "intent": proposal.context.intent,
        "environment": proposal.context.environment,
        "agent_chain": proposal.principal.agent_chain,
        "action": {
            "kind": proposal.action.kind.value,
            "name": proposal.action.name,
            "target": proposal.action.target,
        },
        "params_redacted": proposal.action.params_redacted,
        "blast_radius": verdict.blast_radius,
        "hits": [{"rule_id": hit.rule_id, "message": hit.message} for hit in verdict.hits],
        "expires_at": request.expires_at.isoformat(),
        "window_max_seconds": (
            None if request.window_max is None else int(request.window_max.total_seconds())
        ),
    }


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

    # An approval already granted turns a REQUIRE_APPROVAL into an ALLOW, and
    # a REQUIRE_APPROVAL nobody has seen yet opens a request. Both happen
    # before the verdict is written, so the chain records the decision that
    # was actually acted on rather than one the next record silently revises.
    key = dedupe_key(proposal)
    if verdict.decision is Decision.REQUIRE_APPROVAL:
        verdict, approval_records = _resolve_approval(
            session, proposal, verdict, key=key, now=stamp
        )
        records.extend(approval_records)

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
        else {
            "from_seq": checkpoint.seq_from,
            "to_seq": checkpoint.seq_to,
            "merkle_root": checkpoint.merkle_root,
            "evidence_seq": checkpoint.evidence_seq,
        },
        "generated_at": rfc3339_ms(utcnow()),
    }
