"""Wiring: config → store → key → policy bundle → decision → chain.

This is the one place that knows how the pure kernel and the stateful
infrastructure fit together. `qed check` uses it today; the FastAPI
``/v1/proposals`` router in week 2 uses the same two functions, so the CLI and
the server cannot drift into deciding things differently.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final, cast

from ulid import ULID

from qed.compliance.packs import unsigned_catalogues, use_imported
from qed.config import DEFAULT_DIR, LoadedConfig, QedConfig, load_config
from qed.core import jcs
from qed.core.approval.model import (
    DEFAULT_DEDUPE_WINDOW,
    ApprovalRequest,
    dedupe_key,
    parse_duration,
)
from qed.core.budget import charge_for, newly_exhausted
from qed.core.evidence.retention import PurgePlan, plan_purge
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
    SigningKeyInfo,
    Verdict,
    rfc3339_ms,
    utcnow,
)
from qed.infra.chain_writer import Appended, ChainWriter
from qed.infra.keys.file import (
    PUBLIC_DIR_NAME,
    FileSigner,
    load_signer,
    public_key_filename,
)
from qed.infra.storage.store import SqliteStore, SqlStore
from qed.remote.packs import installed_dir

__all__ = [
    "EXIT_ALLOW",
    "EXIT_APPROVAL",
    "EXIT_BLOCK",
    "EXIT_ERROR",
    "CheckOutcome",
    "DuplicateProposal",
    "PolicyErrors",
    "RetentionResult",
    "Rotation",
    "RotationRefused",
    "Session",
    "apply_retention",
    "check_proposal",
    "open_session",
    "open_signer",
    "open_store",
    "plan_retention",
    "rotate_signing_key",
    "settle",
]

logger = logging.getLogger("qed.runtime")

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

    def close(self, *, settle_chain: bool = True) -> None:
        """Close the store, draining anything this process queued first.

        ``settle_chain=False`` for a caller that will drain on its own
        schedule -- the API's leader loop does, and a per-request drain there
        would undo the whole point of deferring.
        """
        if settle_chain:
            try:
                settle(self)
            except Exception as exc:  # pragma: no cover - never block a close
                logger.warning("could not settle the chain on close: %s", exc)
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


def open_signer(config: QedConfig, directory: Path) -> FileSigner:
    """The evidence signing key, from `evidence.signing_key` or the state dir.

    Two paths because the key and the chain want different storage. On a
    laptop they live together and `qed keys init` puts them there. In a
    container the chain is on a writable volume (or in Postgres) while the key
    arrives from a secret mounted read-only, and nesting that mount inside the
    writable one to satisfy a fixed filename is the sort of arrangement that
    works until a kubelet orders the mounts differently.

    So `evidence.signing_key` names the private key wherever it is. Only the
    private key: the public half is derived from it, and the `public/`
    directory exists for `qed-verify`, which reads an export rather than a
    running instance.
    """
    configured = config.evidence.signing_key
    if not configured:
        return load_signer(directory)
    path = Path(configured).expanduser()
    if path.is_dir():
        # A directory is the laptop layout, so accept it rather than making
        # somebody read this function to find out which one is meant.
        return load_signer(path)
    return FileSigner.load(path)


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

    # Before the policy is read, because loading it lints every rule's control
    # references against the catalogues (SPEC 11) -- and a rule linted against
    # the shipped catalogues would then export against the imported ones. An
    # import lives in the state directory, so each session points the catalogue
    # loader at its own.
    use_imported(installed_dir(directory))

    store = open_store(config, directory)
    # Everything from here on can fail — a missing signing key, a chain that
    # belongs to another instance, a policy error. The store has to be closed on
    # every one of those paths or the CLI leaks a file handle per invocation.
    try:
        signer = open_signer(config, directory)
        writer = ChainWriter(
            store,
            signer,
            instance_id=config.instance_id,
            dev=dev,
            masking=config.evidence.masking,
            # Postgres exists for more than one replica, and more than one
            # direct writer forks the chain -- so the backend decides, not a
            # flag somebody has to remember to set. SQLite is one process
            # writing for itself and has nothing to coordinate.
            write_mode="deferred" if config.evidence.is_postgres else "direct",
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
    # An unsigned control catalogue is a property of the *evidence* this bundle
    # will produce, not of the rules, which is why it rides here: every verdict
    # points at this record, and the control labels an auditor reads come from
    # those catalogues.
    unsigned = unsigned_catalogues()
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
            # SPEC §11. False in the ordinary case, and present either way:
            # a field that appears only when something is wrong is a field an
            # auditor cannot tell from one this build never wrote.
            "unsigned": bool(unsigned),
            **({"unsigned_catalogues": list(unsigned)} if unsigned else {}),
        },
        ts=now,
    )


#: Exit codes for the commands that carry a verdict (SPEC §12.5). Named
#: because a CI job branches on them, and because the numbers are a contract:
#: changing one silently turns somebody's `if [ $? -eq 3 ]` into the opposite
#: of what they wrote.
#:
#: 1 is kept for "QED could not decide" -- a missing key, an unreadable
#: proposal, a broken bundle -- so a pipeline can tell a refusal from a
#: malfunction. Conflating them would let a misconfigured runner look like a
#: policy that allows everything.
EXIT_ALLOW: Final = 0
EXIT_ERROR: Final = 1
EXIT_BLOCK: Final = 2
EXIT_APPROVAL: Final = 3


#: Used when no rule named a timeout. Long enough for somebody to look, short
#: enough that an unanswered request stops blocking an agent for a whole shift.
APPROVAL_TIMEOUT_DEFAULT = timedelta(minutes=15)


@dataclass
class CheckOutcome:
    verdict: Verdict
    #: False when the service runs in shadow mode: the decision is recorded but
    #: the adapter is told to proceed (ADR-003).
    enforced: bool
    records: list[Appended]

    @property
    def effective_decision(self) -> Decision:
        return self.verdict.decision if self.enforced else Decision.ALLOW

    @property
    def exit_code(self) -> int:
        """SPEC §12.5: 0 ALLOW, 2 BLOCK, 3 REQUIRE_APPROVAL.

        Shadow mode always exits 0, because `effective_decision` is ALLOW
        there: a pipeline that failed in shadow mode would make shadow mode
        useless as a way to find out what a policy would do.
        """
        return {
            Decision.ALLOW: EXIT_ALLOW,
            Decision.BLOCK: EXIT_BLOCK,
            Decision.REQUIRE_APPROVAL: EXIT_APPROVAL,
        }[self.effective_decision]


def _resolve_approval(
    session: Session,
    proposal: ActionProposal,
    verdict: Verdict,
    *,
    key: str,
    now: datetime,
) -> tuple[Verdict, list[Appended]]:
    """Turn a REQUIRE_APPROVAL into whatever it actually is (SPEC §9.2).

    Four outcomes, in the order they are checked:

    * an open window for this exact action -> ALLOW, `via_approval` set;
    * a recent denial -> BLOCK, because an agent told no should not be able to
      ask again and have the second request look fresh to whoever sees it;
    * a pending request for the same action -> link to it rather than filing a
      copy, so the human sees one request instead of forty;
    * otherwise -> open a new request.
    """
    records: list[Appended] = []
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

    records: list[Appended] = []
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


def settle(session: Session) -> int:
    """Chain anything this process queued, if nobody else is doing it.

    A one-shot command -- `qed check`, `qed approve`, `qed mandate sign` --
    enqueues and exits. Without this the record would sit in the outbox until
    a server happened to run, so a CLI-only Postgres deployment would have a
    chain that never advanced. That is not a trade worth making for a latency
    benefit only a server needs.

    If the lock is held, a server *is* running and will drain it; this returns
    0 and the record is chained within that server's tick. Either way the
    record is durable from the moment it was enqueued.

    A no-op in direct mode, where the record was chained on the way in.
    """
    if not session.writer.deferred:
        return 0
    store = session.store
    claim = getattr(store, "try_become_leader", None)
    if claim is None or not claim():  # pragma: no cover - direct mode returns above
        return 0
    try:
        from qed.infra.chain_drain import drain_until_empty

        return drain_until_empty(session.writer).chained
    finally:
        resign = getattr(store, "resign_leadership", None)
        if resign is not None:
            resign()


class RotationRefused(RuntimeError):
    """Rotation would have raced another writer."""


@dataclass(frozen=True)
class Rotation:
    """What a completed rotation did, for the CLI to report."""

    old_key_id: str
    new_key_id: str
    #: Signed by the *retiring* key. That signature is what makes the chain
    #: verifiable across the rotation.
    record: EvidenceRecord
    retired_public_key: Path


def rotate_signing_key(session: Session, *, now: datetime | None = None) -> Rotation:
    """Rotate the evidence signing key (SPEC §10.5, ADR-0010).

    The order is load-bearing, and is why this is one function rather than a
    CLI command calling three:

    1. generate the new key and write it where a crash cannot lose it;
    2. append `key_rotated`, **signed by the retiring key**;
    3. activate the new key, which overwrites the old private key.

    (3) before (2) would leave the chain on the old key with the next record
    signed by the new one and nothing in between saying so -- a discontinuity
    indistinguishable from a forged chain. (1) after (2) would mean a crash
    between them left a chain expecting a key that was never written down.
    """
    from qed.infra.keys.rotation import finish_rotation, stage_rotation

    stamp = now if now is not None else utcnow()
    released = _hold_the_chain_alone(session)
    try:
        plan = stage_rotation(session.directory)
        record = session.writer.append_direct(
            type_=EvidenceType.key_rotated,
            assurance=Assurance.kernel,
            payload=plan.payload,
            ts=stamp,
        )
        finish_rotation(plan)
    finally:
        if released is not None:
            released()

    session.store.upsert_signing_key(
        SigningKeyInfo(
            key_id=plan.new.key_id,
            public_pem=plan.new.public_pem,
            created_at=stamp,
        )
    )
    session.store.retire_signing_key(plan.old.key_id, at=stamp)
    # Swap the in-memory signer too. A caller that kept using this session
    # would otherwise go on signing with a key the chain has just retired, and
    # the continuity check has already been satisfied for this process.
    session.writer.signer = plan.new
    session.signer = plan.new

    return Rotation(
        old_key_id=plan.old.key_id,
        new_key_id=plan.new.key_id,
        record=record,
        retired_public_key=(
            session.directory / PUBLIC_DIR_NAME / public_key_filename(plan.old.key_id)
        ),
    )


def _hold_the_chain_alone(session: Session) -> Callable[[], None] | None:
    """Make this process the only writer, or refuse.

    On SQLite there is nothing to arrange: one process writes for itself. On
    the deferred path the chain leader is appending concurrently, and a
    `key_rotated` written beside it could land after a record the new key had
    already signed -- which is the one ordering that makes the chain
    unverifiable.

    A running server holds the lock for its lifetime, so this refuses rather
    than waiting. Rotation there is an admin operation on the instance
    (SPEC §13's `POST /admin/keys:rotate`), not something a second process
    does behind its back.
    """
    if not session.writer.deferred:
        return None
    claim = getattr(session.store, "try_become_leader", None)
    resign = getattr(session.store, "resign_leadership", None)
    if claim is None or resign is None:  # pragma: no cover - deferred implies both
        return None
    if not claim():
        raise RotationRefused(
            "another process is appending to this chain -- almost certainly a running "
            "`qed serve`. Rotating from here could place the `key_rotated` record after a "
            "record the new key had already signed, which no verifier can accept. Stop the "
            "server and rotate, or rotate through the instance."
        )
    # Anything already queued belongs before the rotation: those records were
    # signed by the old key, and chaining them afterwards would put them
    # after the record that retired it.
    settle(session)
    return cast("Callable[[], None]", resign)


@dataclass(frozen=True)
class RetentionResult:
    """What a retention pass did. Empty when there was nothing to do."""

    purged: int
    plan: PurgePlan
    #: The `admin_action` record documenting the purge, when one was written.
    record: EvidenceRecord | None = None

    @property
    def acted(self) -> bool:
        return self.purged > 0


def plan_retention(session: Session, *, now: datetime | None = None) -> PurgePlan:
    """What a purge would clear, without clearing it.

    Reported by `qed doctor`. Separate from applying it because a retention
    policy is a thing an operator should be able to read the consequences of
    before it runs -- the whole point is that it destroys evidence on purpose.
    """
    policy = session.config.retention.policy()
    if not policy.active:
        return PurgePlan()
    return plan_purge(session.store.iter_evidence(), policy=policy, now=now or utcnow())


def apply_retention(session: Session, *, now: datetime | None = None) -> RetentionResult:
    """Clear the payloads the policy has expired, and record that it happened.

    The `admin_action` record is the point. A NULL payload with nothing saying
    why is indistinguishable from data loss, and "we delete after seven years"
    is a claim an auditor will want evidence of rather than a sentence in a
    policy document. SPEC §17: qed governs its own admin operations.

    Appended *after* the purge, so the record is outside the set it describes
    and cannot purge itself in the same pass -- and `admin_action` is in
    `NEVER_PURGE` anyway, because erasing the record of what was erased is the
    one thing retention must not do.
    """
    stamp = now if now is not None else utcnow()
    plan = plan_retention(session, now=stamp)
    if plan.empty:
        return RetentionResult(purged=0, plan=plan)

    purged = session.store.purge_payload_seqs(plan.seqs)
    appended = session.writer.append(
        type_=EvidenceType.admin_action,
        assurance=Assurance.kernel,
        payload={
            "action": "retention_purge",
            "policy": session.config.retention.policy().describe(),
            "purged": purged,
            **plan.summary(),
        },
        ts=stamp,
    )
    logger.info("retention purged %d payload(s): %s", purged, plan.summary().get("by_type"))
    return RetentionResult(purged=purged, plan=plan, record=appended.record)


def chain_status(session: Session) -> dict[str, object]:
    """Small posture summary used by the CLI."""
    last = session.store.last_seq()
    checkpoint = session.store.last_checkpoint()
    return {
        "instance_id": session.config.instance_id,
        "records": session.store.count_evidence(),
        "last_seq": last,
        "store": session.store.dialect.name,
        "retention": session.config.retention.policy().describe(),
        # SPEC §18's `qed_chain_lag_records`, reported here until there is a
        # /metrics endpoint to carry it. Always 0 on the direct path: the
        # record was chained before the caller got an answer, so there is
        # nothing that could lag.
        "write_mode": "deferred" if session.writer.deferred else "direct",
        "chain_lag_records": session.store.outbox_depth() if session.writer.deferred else 0,
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
