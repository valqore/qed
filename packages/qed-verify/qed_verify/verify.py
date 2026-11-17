"""Independent chain verification (SPEC §10.7).

This package imports nothing from `qed`. That is the whole point: an auditor
runs it against a JSONL export and a set of public keys, and nothing the
instance under audit can do affects the result. It depends on the standard
library and `cryptography`, and it reimplements canonicalisation and the record
hash from the written format rather than sharing code with the producer -- a
shared helper would mean a bug in the producer verifies cleanly.

Checks, in order:

1. ``seq`` starts at 0 and is contiguous.
2. ``prev_hash`` of record *n* equals ``hash`` of record *n-1*; record 0's
   ``prev_hash`` matches ``sha256(GENESIS_DOMAIN + instance_id)`` when the
   instance id is known.

   Check 2 is the only one that ties these records to a *particular* instance,
   and it is the only one that can be skipped. Everything else here is
   self-referential: a chain generated on a laptop five minutes ago, signed
   with a key generated at the same time, satisfies checks 1 and 3 through 7
   exactly as well as a real one. So when no instance id is supplied the report
   says which check did not run rather than reporting an unqualified pass --
   ``Report.genesis_bound_to`` and ``Report.unchecked`` carry it, and
   ``summary()`` prints it on the result line.

   The instance id must reach the verifier **from outside the file under
   review**. It is also in the genesis payload, so reading it out of the export
   and passing it back proves nothing: the forger chose both. The same applies
   to the public keys. A contract, an engagement letter, or the operator's
   published instance identity is the source; the export never is.
3. ``hash`` recomputes from the record's own fields. Uses ``payload_hash``, not
   the payload, so a record whose payload was purged under retention still
   verifies.
4. ``payload_hash`` recomputes from the payload, when the payload is present.
5. The signature verifies under the key named by ``key_id``.
6. Each ``key_rotated`` record is signed by the *old* key, which is what makes
   rotation a continuous chain rather than two chains.
7. Each ``checkpoint`` record's Merkle root recomputes over the range it claims.
8. Each anchor supplied from outside the export matches the export: the record
   it names is present, is byte-identical, and its Merkle root recomputes over
   the records in range.

   Check 8 is the only one that can detect a chain that *stops early*, and like
   check 2 it is skipped when its input is absent. Checks 1 and 3 through 7 are
   satisfied by any prefix of a chain: drop the last thousand records, and what
   remains is contiguous, correctly linked, correctly signed and internally
   consistent. Nothing inside an export can establish that it is the whole
   export, because the thing that would say so is the part that was removed.

   An anchor is a checkpoint record the instance published somewhere it cannot
   afterwards revise -- an object-locked S3 key, a GCS bucket with a locked
   retention policy, a signed git tag. Comparing one against the export turns
   truncation into a missing record, and an anchor only covers the records it
   names: everything after the newest one supplied is still unanchored, and the
   report says so rather than reporting an unqualified pass.

   Like the instance id, an anchor must reach the verifier **from outside the
   export**. One read out of the file under review proves nothing: the forger
   chose both.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from qed_verify import jcs

__all__ = ["CHAIN_FORMAT", "GENESIS_DOMAIN", "Problem", "Report", "verify_records"]

SEPARATOR = b"\x1f"

#: Format constants, spelled out here rather than imported from ``qed``: this
#: package verifies the written format, and sharing the constant with the
#: producer would mean a typo in the producer verifies cleanly. ADR-0006 explains
#: why the product name is deliberately absent from them;
#: ``tests/evidence/test_format_constants.py`` in the kernel repo checks that the
#: two copies still agree.
CHAIN_FORMAT = "evidence-chain/1"
GENESIS_DOMAIN = f"{CHAIN_FORMAT}:genesis:"


@dataclass(frozen=True)
class Problem:
    seq: int | None
    code: str
    detail: str

    def __str__(self) -> str:
        where = "chain" if self.seq is None else f"seq {self.seq}"
        return f"{where}: {self.code}: {self.detail}"


@dataclass
class Report:
    records: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    checkpoints: int = 0
    purged: int = 0
    keys_used: list[str] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    #: The instance id record 0 was successfully bound to, or ``None`` when the
    #: binding was not checked. Never populated from the export itself.
    genesis_bound_to: str | None = None
    #: How many externally supplied anchors were matched against this export.
    anchors: int = 0
    #: How many were *supplied*, matched or not. The two are different
    #: questions and one counter cannot answer both: an anchor that was
    #: supplied and failed left `anchors` at zero, and the summary then read
    #: "no anchor supplied" on the very run where the anchor caught a
    #: truncation. The worst thing a verifier can do is understate the
    #: evidence it was handed.
    anchors_supplied: int = 0
    #: The highest ``to_seq`` an anchor covered, or ``None`` when no anchor was
    #: supplied. Records after it are in the export on the export's own word.
    anchored_through: int | None = None
    #: Checks that did not run, in words an auditor can put in a working paper.
    #: A non-empty list does not make ``ok`` false -- nothing failed -- but it
    #: does mean the pass is narrower than it reads.
    unchecked: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def complete(self) -> bool:
        """Every check ran *and* passed. Weaker than ``ok`` is not enough."""
        return self.ok and not self.unchecked

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "complete": self.complete,
            "records": self.records,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "checkpoints": self.checkpoints,
            "purged_payloads": self.purged,
            "keys_used": sorted(self.keys_used),
            "genesis_bound_to": self.genesis_bound_to,
            "anchors": self.anchors,
            "anchors_supplied": self.anchors_supplied,
            "anchored_through": self.anchored_through,
            "unchecked": list(self.unchecked),
            "problems": [{"seq": p.seq, "code": p.code, "detail": p.detail} for p in self.problems],
        }

    def summary(self) -> str:
        bound = f"instance {self.genesis_bound_to!r}" if self.genesis_bound_to else "NOTHING"
        if self.anchors:
            anchored = f"{self.anchors} anchor(s), covering seq 0..{self.anchored_through}"
            if self.anchors_supplied > self.anchors:
                failed = self.anchors_supplied - self.anchors
                anchored += f" ({failed} further anchor(s) supplied did not verify)"
        elif self.anchors_supplied:
            anchored = (
                f"NOTHING -- {self.anchors_supplied} anchor(s) supplied, none of which "
                "verified against this export; see the problems below"
            )
        else:
            anchored = "NOTHING -- no anchor supplied"
        lines = [
            f"records   : {self.records} (seq {self.first_seq}..{self.last_seq})",
            f"keys      : {', '.join(sorted(self.keys_used)) or 'none'}",
            f"checkpoint: {self.checkpoints}",
            f"purged    : {self.purged} payload(s) removed under retention",
            f"bound to  : {bound}",
            f"anchored  : {anchored}",
        ]
        if not self.ok:
            lines.append(f"result    : FAILED -- {len(self.problems)} problem(s)")
            lines += [f"  - {p}" for p in self.problems]
        elif self.complete:
            lines.append(
                "result    : OK -- chain is contiguous, unmodified, signed, bound "
                "to the instance id supplied, and anchored to its last record"
            )
        else:
            lines.append(
                f"result    : OK SO FAR -- chain is contiguous, unmodified and signed, "
                f"but {len(self.unchecked)} check(s) did not run"
            )
            lines += [f"  ! {note}" for note in self.unchecked]
        return "\n".join(lines)


def _record_hash(record: dict[str, Any]) -> str:
    parts = [
        str(record["schema_version"]).encode(),
        str(record["seq"]).encode(),
        str(record["ts"]).encode(),
        str(record["type"]).encode(),
        str(record["payload_hash"]).encode(),
        str(record["prev_hash"]).encode(),
    ]
    return hashlib.sha256(SEPARATOR.join(parts)).hexdigest()


def _b64u_decode(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _merkle_root(leaves: Sequence[str]) -> str:
    level = [bytes.fromhex(h) for h in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def _genesis_prev_hash(instance_id: str) -> str:
    return hashlib.sha256(f"{GENESIS_DOMAIN}{instance_id}".encode()).hexdigest()


def verify_records(
    records: Iterable[dict[str, Any]],
    public_keys: dict[str, Ed25519PublicKey],
    *,
    instance_id: str | None = None,
    anchors: Sequence[dict[str, Any]] | None = None,
) -> Report:
    report = Report()
    previous: dict[str, Any] | None = None
    hashes: dict[int, str] = {}
    key_ids: set[str] = set()

    for record in records:
        seq = record.get("seq")
        if not isinstance(seq, int):
            report.problems.append(Problem(None, "malformed", "record has no integer seq"))
            continue
        report.records += 1
        if report.first_seq is None:
            report.first_seq = seq
        report.last_seq = seq
        hashes[seq] = str(record.get("hash", ""))
        key_id = str(record.get("key_id", ""))
        key_ids.add(key_id)

        if previous is None:
            if seq != 0:
                report.problems.append(
                    Problem(seq, "not_from_genesis", "export does not start at seq 0")
                )
            elif instance_id is not None:
                expected = _genesis_prev_hash(instance_id)
                if record.get("prev_hash") != expected:
                    report.problems.append(
                        Problem(
                            seq,
                            "genesis_mismatch",
                            f"prev_hash does not match instance id {instance_id!r}",
                        )
                    )
                else:
                    report.genesis_bound_to = instance_id
            else:
                report.unchecked.append(
                    "genesis binding: no instance id was supplied, so nothing ties these "
                    "records to a particular instance -- a chain generated anywhere, with "
                    "any key, verifies exactly like this one. Re-run with --instance-id, "
                    "taking the id from the engagement letter or the operator's published "
                    "identity, never from this file"
                )
        else:
            if seq != previous["seq"] + 1:
                report.problems.append(
                    Problem(
                        seq,
                        "sequence_gap",
                        f"follows seq {previous['seq']}; a record is missing or reordered",
                    )
                )
            if record.get("prev_hash") != previous.get("hash"):
                report.problems.append(
                    Problem(seq, "broken_link", "prev_hash does not match the previous hash")
                )

        recomputed = _record_hash(record)
        if recomputed != record.get("hash"):
            report.problems.append(
                Problem(seq, "hash_mismatch", "hash does not match the record's own fields")
            )

        payload = record.get("payload")
        if payload is None:
            report.purged += 1
        elif isinstance(payload, dict):
            if jcs.sha256_hex(payload) != record.get("payload_hash"):
                report.problems.append(
                    Problem(seq, "payload_tampered", "payload_hash does not match the payload")
                )
        else:
            report.problems.append(Problem(seq, "malformed", "payload is not an object"))

        _check_signature(record, seq, public_keys, previous, report)

        if record.get("type") == "checkpoint":
            report.checkpoints += 1
            _check_checkpoint(record, seq, hashes, report)

        previous = record

    if report.records == 0:
        report.problems.append(Problem(None, "empty", "no records to verify"))
    report.keys_used = sorted(k for k in key_ids if k)
    _check_anchors(anchors, hashes, public_keys, report)
    return report


def _check_anchors(
    anchors: Sequence[dict[str, Any]] | None,
    hashes: dict[int, str],
    public_keys: dict[str, Ed25519PublicKey],
    report: Report,
) -> None:
    """Compare externally published checkpoints against this export (check 8).

    This is the only check here that can fail on something the export does not
    contain, which is the point: every other check reads the export and asks
    whether it is self-consistent, and a truncated chain is perfectly
    self-consistent. The anchor is the one input that knows a record existed.
    """
    if not anchors:
        report.unchecked.append(
            "chain completeness: no anchor was supplied, so a chain that stops early "
            "verifies exactly like a complete one -- drop the last N records and what "
            "remains is contiguous, linked, signed and internally consistent. Re-run "
            "with --anchor, pointing at a checkpoint the instance published somewhere "
            "it cannot revise (an object-locked S3 key, a locked-retention GCS bucket, "
            "a signed tag), fetched from that target and never from this file"
        )
        return

    report.anchors_supplied = len(anchors)
    covered_to: list[int] = []
    for position, anchor in enumerate(anchors):
        label = f"anchor {position + 1}"
        seq = anchor.get("seq")
        payload = anchor.get("payload")
        if not isinstance(seq, int) or not isinstance(payload, dict):
            report.problems.append(
                Problem(None, "malformed_anchor", f"{label} is not a checkpoint record")
            )
            continue
        try:
            start = int(payload["from_seq"])
            end = int(payload["to_seq"])
            claimed = str(payload["merkle_root"])
        except (KeyError, TypeError, ValueError):
            report.problems.append(
                Problem(seq, "malformed_anchor", f"{label} has no from_seq/to_seq/merkle_root")
            )
            continue

        # The anchor is evidence only if it is itself intact and signed. An
        # anchor nobody checked is a second file to forge, not a control.
        try:
            recomputed = _record_hash(anchor)
        except KeyError:
            report.problems.append(
                Problem(seq, "malformed_anchor", f"{label} is missing fields the hash covers")
            )
            continue
        if recomputed != anchor.get("hash"):
            report.problems.append(
                Problem(seq, "anchor_hash_mismatch", f"{label}'s hash does not match its fields")
            )
            continue
        _check_signature(anchor, seq, public_keys, None, report)

        # The record the anchor names has to be in the export, and has to be
        # the same record. Absent is the truncation case: the instance
        # published a checkpoint at this seq and then handed over an export
        # that ends before it.
        present = hashes.get(seq)
        if present is None:
            report.problems.append(
                Problem(
                    seq,
                    "anchor_not_in_export",
                    f"{label} was published for seq {seq}, which this export does not "
                    f"contain (it ends at {report.last_seq}) -- the chain is truncated "
                    "or the anchor belongs to another instance",
                )
            )
            continue
        matched = True
        if present != anchor.get("hash"):
            matched = False
            report.problems.append(
                Problem(
                    seq,
                    "anchor_mismatch",
                    f"{label} and the export disagree about the record at seq {seq}; "
                    "the export was rewritten after the anchor was published",
                )
            )

        # And the range it vouches for has to recompute. Checked even when the
        # record above already disagreed, because the two answer different
        # questions -- *that* the export was rewritten, and *where* -- and an
        # auditor reading one problem code should not have to guess the other.
        in_range = [hashes[s] for s in range(start, end + 1) if s in hashes]
        if len(in_range) != end - start + 1:
            matched = False
            report.problems.append(
                Problem(
                    seq,
                    "anchor_range_missing",
                    f"{label} covers seq {start}..{end}; this export does not contain all of them",
                )
            )
        elif _merkle_root(in_range) != claimed:
            matched = False
            report.problems.append(
                Problem(
                    seq,
                    "anchor_root_mismatch",
                    f"{label}'s published Merkle root does not match the records at "
                    f"seq {start}..{end} in this export",
                )
            )

        if not matched:
            continue
        report.anchors += 1
        # Both halves count. The Merkle root vouches for `start..end`, and the
        # hash comparison above vouches for the checkpoint record itself, which
        # sits at `seq` -- one past `end` in every checkpoint the kernel
        # writes. Without this a chain whose last record is its own anchored
        # checkpoint would always report an unanchored tail of one.
        covered_to.append(max(end, seq))

    if not covered_to:
        return
    report.anchored_through = max(covered_to)
    if report.last_seq is not None and report.last_seq > report.anchored_through:
        tail = report.last_seq - report.anchored_through
        report.unchecked.append(
            f"chain completeness past the newest anchor: seq "
            f"{report.anchored_through + 1}..{report.last_seq} ({tail} record(s)) are "
            "after everything anchored, so they are present on this export's own word "
            "and truncation of that tail would not show here. An anchor covers the "
            "records it names and nothing later"
        )


def _check_signature(
    record: dict[str, Any],
    seq: int,
    public_keys: dict[str, Ed25519PublicKey],
    previous: dict[str, Any] | None,
    report: Report,
) -> None:
    # A rotation record must be signed by the retiring key, not the new one;
    # that is what ties the two key eras into one verifiable chain.
    signing_key_id = str(record.get("key_id", ""))
    if record.get("type") == "key_rotated" and previous is not None:
        expected = str(previous.get("key_id", ""))
        if signing_key_id != expected:
            report.problems.append(
                Problem(
                    seq,
                    "rotation_discontinuity",
                    f"key_rotated is signed by {signing_key_id} but the chain was on {expected}",
                )
            )
    key = public_keys.get(signing_key_id)
    if key is None:
        report.problems.append(
            Problem(seq, "unknown_key", f"no public key supplied for {signing_key_id!r}")
        )
        return
    try:
        key.verify(_b64u_decode(str(record.get("sig", ""))), bytes.fromhex(_record_hash(record)))
    except (InvalidSignature, ValueError):
        report.problems.append(
            Problem(seq, "bad_signature", f"signature does not verify under {signing_key_id}")
        )


def _check_checkpoint(
    record: dict[str, Any], seq: int, hashes: dict[int, str], report: Report
) -> None:
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return  # purged checkpoint payload; the hash chain still covers it
    try:
        start = int(payload["from_seq"])
        end = int(payload["to_seq"])
        claimed = str(payload["merkle_root"])
    except (KeyError, TypeError, ValueError):
        report.problems.append(
            Problem(seq, "malformed_checkpoint", "checkpoint payload is incomplete")
        )
        return
    covered = [hashes[s] for s in range(start, end + 1) if s in hashes]
    if len(covered) != end - start + 1:
        report.problems.append(
            Problem(
                seq,
                "checkpoint_range_missing",
                f"records {start}..{end} are not all present in this export",
            )
        )
        return
    if _merkle_root(covered) != claimed:
        report.problems.append(
            Problem(seq, "checkpoint_mismatch", "Merkle root does not match records in range")
        )


def load_jsonl(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            raise ValueError("every JSONL line must be an object")
        out.append(parsed)
    return out
