"""`qed-verify` command line (SPEC §10.7).

Plain `argparse`, no Typer: the fewer dependencies an auditor has to install,
the more likely they actually run it.

Exit codes: 0 verified, 1 one or more problems, 2 usage error.

`--instance-id` is optional and that is a trap, so this module works to make the
omission impossible to miss: without it the genesis binding does not run, the
result line says so, and a note goes to stderr. `--require-complete` turns the
omission into exit 1, which is what a pipeline should use -- a pipeline reads the
exit code and never the summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from qed_verify.verify import load_jsonl, verify_records


def _load_keys(paths: list[Path]) -> dict[str, Ed25519PublicKey]:
    import hashlib

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    files: list[Path] = []
    for path in paths:
        files.extend(sorted(path.glob("*.pem")) if path.is_dir() else [path])

    keys: dict[str, Ed25519PublicKey] = {}
    for file in files:
        loaded = load_pem_public_key(file.read_bytes())
        if not isinstance(loaded, Ed25519PublicKey):
            print(f"warning: {file} is not an Ed25519 public key, ignored", file=sys.stderr)
            continue
        raw = loaded.public_bytes(Encoding.Raw, PublicFormat.Raw)
        keys[f"ed25519:{hashlib.sha256(raw).hexdigest()[:16]}"] = loaded
    return keys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qed-verify",
        description="Verify a qed evidence chain without trusting the instance that wrote it.",
    )
    parser.add_argument("records", type=Path, help="JSONL export of evidence records")
    parser.add_argument(
        "--keys",
        type=Path,
        action="append",
        required=True,
        help="public key PEM file, or a directory of them (repeatable)",
    )
    parser.add_argument(
        "--instance-id",
        help=(
            "the instance this chain is supposed to belong to, obtained from outside "
            "this file (contract, engagement letter, the operator's published identity) "
            "and never read out of the export. Without it, nothing ties these records "
            "to any instance and a chain forged elsewhere verifies identically"
        ),
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="exit 1 unless every check ran, not merely every check that ran passed",
    )
    parser.add_argument("--json", action="store_true", help="emit the machine-readable report")
    parser.add_argument(
        "--range",
        metavar="FROM:TO",
        help="verify only this seq range (linkage to the record before FROM is not checked)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        records = load_jsonl(args.records.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"qed-verify: cannot read {args.records}: {exc}", file=sys.stderr)
        return 2

    if args.range:
        try:
            low_text, high_text = args.range.split(":", 1)
            low, high = int(low_text), int(high_text)
        except ValueError:
            print("qed-verify: --range must look like FROM:TO", file=sys.stderr)
            return 2
        records = [r for r in records if low <= int(r.get("seq", -1)) <= high]

    keys = _load_keys(args.keys)
    if not keys:
        print("qed-verify: no usable public keys supplied", file=sys.stderr)
        return 2

    report = verify_records(records, keys, instance_id=args.instance_id)
    print(json.dumps(report.to_dict(), indent=2) if args.json else report.summary())

    for note in report.unchecked:
        print(f"qed-verify: not checked -- {note}", file=sys.stderr)

    if not report.ok:
        return 1
    if args.require_complete and not report.complete:
        print(
            "qed-verify: --require-complete was given and not every check ran",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
