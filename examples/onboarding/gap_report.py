"""How far is this chain from `mode: enforce`?

Reads an exported chain on stdin and reports, per shadow rule, how often
promoting it would have changed an outcome:

    qed export --dir ./state --config qed.yaml | python examples/onboarding/gap_report.py

Every verdict carries two decisions. `decision` is what QED did; in shadow mode
that is effectively always ALLOW. `would_decision` is what QED would have
decided had every matching rule been enforcing. The records where they differ
are exactly the work between an operator and enforce, which is the whole reason
shadow mode exists -- see `docs/onboarding-shadow-to-enforce.md`.

Stdlib only, and it reads an export rather than the instance: the same file an
auditor is given, with no access to the database that produced it.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Iterable, Iterator
from typing import Any

#: Severity order, so the summary can say which way a promotion would move.
_RANK = {"ALLOW": 0, "REQUIRE_APPROVAL": 1, "BLOCK": 2}


def verdicts(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Yield each verdict payload, skipping everything else in the chain.

    A chain holds proposals, execution results, checkpoints and admin actions
    as well as verdicts, and a malformed line is skipped rather than fatal: an
    operator running this against a truncated export wants the report for the
    records that *are* there.
    """
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("type") != "verdict":
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        verdict = payload.get("verdict")
        if isinstance(verdict, dict):
            yield verdict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "chain",
        nargs="?",
        type=argparse.FileType("r", encoding="utf-8"),
        default=sys.stdin,
        help="exported chain as JSONL; stdin by default",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    gaps: collections.Counter[str] = collections.Counter()
    moves: dict[str, tuple[str, str]] = {}
    decided = 0
    gapped = 0

    for verdict in verdicts(args.chain):
        decided += 1
        decision = str(verdict.get("decision", ""))
        would = str(verdict.get("would_decision", ""))
        if decision == would:
            continue
        gapped += 1
        for hit in verdict.get("hits", []):
            if isinstance(hit, dict) and hit.get("mode") == "shadow":
                rule_id = str(hit.get("rule_id", "?"))
                gaps[rule_id] += 1
                moves[rule_id] = (decision, str(hit.get("verdict", would)))

    if args.json:
        json.dump(
            {
                "verdicts": decided,
                "verdicts_with_a_gap": gapped,
                "rules": [
                    {"rule_id": r, "count": c, "from": moves[r][0], "to": moves[r][1]}
                    for r, c in gaps.most_common()
                ],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    print(f"{decided} verdict(s); {gapped} would have decided differently under enforce\n")
    if not gaps:
        # Not the same as "you are ready": it can also mean the chain is too
        # short, or that nothing has exercised the shadow rules yet.
        print("No shadow rule changed an outcome in this chain.")
        print("Either the rules fit, or there is not enough traffic yet. Check the record count.")
        return 0

    print(f"{'COUNT':>6}  {'RULE':<16} WOULD MOVE")
    for rule_id, count in gaps.most_common():
        was, to = moves[rule_id]
        arrow = "->" if _RANK.get(to, 0) > _RANK.get(was, 0) else "~>"
        print(f"{count:>6}  {rule_id:<16} {was} {arrow} {to}")
    print("\nTo enforce one of these, write your own rule with your own id:")
    print("an override may only soften or narrow (ADR-002.4). See")
    print("docs/onboarding-shadow-to-enforce.md, stage 3.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
