"""Produce the frozen evidence-format 1.0 conformance fixture. Run once, ever.

This script is committed because the fixture it produced has to be explicable:
an auditor, or anyone writing a second verifier, should be able to see how the
records were made rather than take a blob of JSON on trust. It is **not** run by
the test suite, and re-running it is a mistake -- the fixture is the frozen
artefact, and regenerating it would make the test assert that today's code
agrees with today's code, which is precisely what a format freeze exists to
rule out (SPEC §25.6, ADR-0015).

The one time it should run again is for a *new* `schema_version`, writing a
*new* directory beside this one. `tests/evidence/test_frozen_format.py` verifies
every directory it finds, so 1.0 goes on being checked after 1.1 exists.

Usage (deliberately awkward, because it should not be convenient):

    python tests/evidence/fixtures/generate_1_0.py --i-mean-it
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from qed.core.approval.model import DecisionKind, decide  # noqa: E402
from qed.core.evidence.export.jsonl import to_jsonl  # noqa: E402
from qed.core.evidence.hashing import principal_hash  # noqa: E402
from qed.core.schemas import ActionProposal, Assurance, EvidenceType  # noqa: E402
from qed.infra.keys.file import init_keys  # noqa: E402
from qed.infra.maintenance import maintain  # noqa: E402
from qed.runtime import (  # noqa: E402
    Session,
    apply_retention,
    check_proposal,
    open_session,
    rotate_signing_key,
)

#: Fixed, so the fixture is a story rather than a pile of records. Everything in
#: it is dated relative to this.
NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)

#: Not `qed-local`. The genesis `prev_hash` binds the chain to this string, so
#: the fixture demonstrates that binding only if the value is distinctive.
INSTANCE = "qed-conformance-1.0"

CONFIG = """\
# The instance that produced the frozen 1.0 conformance fixture.
instance_id: qed-conformance-1.0
mode: enforce
environment_profile: prod

retention:
  # Long enough that the two recent proposals keep their payloads and the
  # five-day-old one does not. One purged payload in the fixture is the point:
  # a record whose payload is gone still has to verify, forever.
  by_type:
    proposal: 2d
"""


def build(out: Path) -> None:
    work = out.parent / ".work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    init_keys(work)
    (work / "qed.yaml").write_text(CONFIG, encoding="utf-8")
    session = open_session(directory=work, config_path=work / "qed.yaml", strict_policy=False)

    story: list[str] = []
    try:
        # Three real proposals from `examples/proposals/` -- the same files the
        # README and the onboarding guide tell a reader to run.
        schedule = [
            ("github-read.json", NOW - timedelta(days=5)),
            ("prod-db-drop.json", NOW - timedelta(hours=1)),
            ("open-ingress.json", NOW - timedelta(minutes=30)),
        ]
        for name, stamp in schedule:
            document = (ROOT / "examples" / "proposals" / name).read_text(encoding="utf-8")
            proposal = ActionProposal.model_validate_json(document)
            outcome = check_proposal(session, proposal, now=stamp)
            story.append(f"{name}: {outcome.verdict.decision.value}")

            if outcome.verdict.approval_id is not None:
                _approve(session, outcome.verdict.approval_id, stamp, story)

        # A rotation in the middle of the chain. Without one the fixture never
        # exercises the rule that makes rotation verifiable -- the record is
        # signed by the *retiring* key -- and an auditor handed two public keys
        # would have no way to know this fixture would have caught a breach of
        # it.
        rotation = rotate_signing_key(session, now=NOW - timedelta(minutes=20))
        story.append(f"rotated {rotation.old_key_id} -> {rotation.new_key_id}")

        # Checkpoint, purge, checkpoint again: the second one covers the
        # `admin_action` the purge wrote, so every record in the fixture sits
        # under exactly one Merkle root.
        # `maintain` is checkpoint-then-retention in that order on purpose: a
        # root is fixed before any payload under it stops being readable. So
        # the purge happens inside this call, and the `apply_retention` below
        # finds nothing left to do -- which is worth recording rather than
        # hiding, because it is the ordering guarantee working.
        first = maintain(session, force_checkpoint=True, now=NOW - timedelta(minutes=10))
        story.append(f"checkpoint {_seq(first)}; purged {first.purged} payload(s)")

        purge = apply_retention(session, now=NOW - timedelta(minutes=5))
        story.append(f"second retention pass purged {purge.purged} (nothing left: correct)")

        second = maintain(session, force_checkpoint=True, now=NOW)
        story.append(f"checkpoint {_seq(second)}; purged {second.purged} payload(s)")

        records = list(session.store.iter_evidence())
        jsonl = to_jsonl(records)
        keys = {info.key_id: info.public_pem for info in session.store.signing_keys()}
    finally:
        session.close()

    if out.exists():
        shutil.rmtree(out)
    (out / "public").mkdir(parents=True)
    _write(out / "chain.jsonl", jsonl)
    for key_id, pem in sorted(keys.items()):
        _write(out / "public" / f"{key_id.replace(':', '_')}.pem", pem)

    manifest = {
        "schema_version": "1.0",
        "instance_id": INSTANCE,
        "records": len(records),
        "types": sorted({record.type.value for record in records}),
        "purged_seqs": [record.seq for record in records if record.payload is None],
        "head_seq": records[-1].seq,
        "head_hash": records[-1].hash,
        "key_ids": sorted(keys),
    }
    _write(out / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(work)

    print("\n".join(story))
    print(json.dumps(manifest, indent=2, sort_keys=True))


def _write(path: Path, text: str) -> None:
    """Write LF, whatever platform this runs on.

    `Path.write_text` goes through the default newline translation, so on
    Windows it turns every `\\n` into `\\r\\n`. The fixture is hashed byte for
    byte by `test_frozen_format.py`, and `.gitattributes` checks it out as LF
    everywhere -- so a fixture generated on Windows would carry a digest that
    matched on the machine that made it and nowhere else. CI would have failed
    on the pin and read as a format regression.

    That is the same platform asymmetry as the Windows-only docs test in week
    11, in the worse direction: that one failed locally and passed in CI.
    """
    path.write_bytes(text.encode("utf-8"))


def _seq(result: object) -> str:
    record = getattr(result, "checkpoint", None)
    return "not written" if record is None else f"at seq {record.seq}"


def _approve(session: Session, approval_id: str, stamp: datetime, story: list[str]) -> None:
    """Decide the approval the way `qed approve` does, by a different human."""
    request = session.store.load_approval(approval_id)
    if request is None:  # pragma: no cover - generator
        raise SystemExit("a REQUIRE_APPROVAL opened no request; the fixture would be misleading")
    decision = decide(
        request,
        kind=DecisionKind.approve_once,
        approver_hash=principal_hash("oncall@example.com"),
        approver_subject="oncall@example.com",
        # The first group the rule named. Separation of duties is enforced in
        # `decide`, not reported, so a generator that invented a group would
        # have produced no approval at all -- which is the correct behaviour
        # and would have made a quietly wrong fixture.
        approver_groups=list(request.approvers[:1]),
        now=stamp + timedelta(minutes=4),
        reason="Change window CHG-4471; reviewed the diff.",
    )
    if not session.store.apply_decision(decision):  # pragma: no cover - generator
        raise SystemExit(f"approval {approval_id} was already decided")
    session.writer.append(
        type_=EvidenceType.approval_decided,
        assurance=Assurance.kernel,
        payload={
            "approval_id": request.id,
            "kind": decision.kind.value,
            "approver_hash": decision.approver_hash,
            "identity": "oidc:https://login.example.com",
            "reason": decision.reason,
        },
        approval_id=request.id,
        ts=decision.decided_at,
    )
    story.append("approved by a second human")


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate a frozen fixture. Read the module.")
    parser.add_argument("--i-mean-it", action="store_true", help="Required. Read the docstring.")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "evidence-format-1.0")
    args = parser.parse_args()
    if not args.i_mean_it:
        parser.error("this overwrites a frozen fixture; pass --i-mean-it if that is really meant")
    build(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
