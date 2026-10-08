"""JSONL and CSV export (SPEC §10.8).

JSONL is the format `gate-verify` consumes, so the field names and the string
forms here *are* the on-the-wire evidence format. Keep them in step with
``docs/evidence-format.md``; a change to either is a ``schema_version`` change.

OSCAL 1.1.2 ``assessment-results`` export is week 2.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable

from gate.core.schemas import EvidenceRecord

__all__ = ["CSV_COLUMNS", "record_to_dict", "to_csv", "to_jsonl"]


def record_to_dict(record: EvidenceRecord) -> dict[str, object]:
    """The exact shape written to JSONL."""
    return record.model_dump(mode="json")


def to_jsonl(records: Iterable[EvidenceRecord]) -> str:
    # separators without spaces: the file is machine input, and the bytes are
    # what an auditor archives.
    return "".join(
        json.dumps(record_to_dict(r), separators=(",", ":"), sort_keys=True) + "\n" for r in records
    )


CSV_COLUMNS = (
    "seq",
    "ts",
    "type",
    "assurance",
    "mode",
    "enforcement",
    "dev",
    "key_id",
    "payload_hash",
    "prev_hash",
    "hash",
)


def to_csv(records: Iterable[EvidenceRecord]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for record in records:
        row = record_to_dict(record)
        writer.writerow({column: row.get(column, "") for column in CSV_COLUMNS})
    return buffer.getvalue()
