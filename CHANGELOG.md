# Changelog

All notable changes to this project. Format: [Keep a Changelog]. Versioning:
semver, with `schema_version` of `ActionProposal` / `EvidenceRecord` tracked
independently (SPEC §25.6).

## [Unreleased]

### Added — week 1 (SPEC §22)

- Repo skeleton, `ruff` + `mypy --strict` + `pytest` in CI, no-network and
  no-LLM import guards on `gate.core`.
- `gate/core/schemas.py`: full SPEC §3 domain model on Pydantic v2, frozen and
  `extra="forbid"`. Timestamps are RFC 3339 UTC at millisecond precision with a
  deterministic serializer.
- `gate/core/jcs.py`: RFC 8785 canonical JSON, used for every hash.
- `gate/core/evidence/`: record construction, SPEC §10.2 hash, Ed25519
  signatures, Merkle checkpoints, secret/PII masking at write.
- `gate/infra/storage/sqlite.py` + forward-only migrations: the evidence ledger
  and the SPEC §15 tables week 1 needs.
- `gate/infra/keys/file.py`: file-backed Ed25519 keys, `gate keys init`.
- `gate/core/policy/`: loader (rules, overrides, disables), linter (all SPEC
  §4.3 error classes), predicate evaluator (SPEC §4.4), engine (SPEC §5),
  deterministic blast-radius table.
- `gate/core/policy/packs/agent-baseline/`: 15 baseline rules.
- `packages/gate-verify/`: standalone verifier, `cryptography` only.
- CLI: `keys init`, `check`, `policy lint|explain`, `export`, `verify`.
- 62 golden policy cases; chain, Merkle, masking, JCS, lint and CLI suites.

### Deliberately not added

- No `LICENSE` file and no `license` metadata. See
  `PATENT-AND-LICENCE-GATE.md` — SPEC §24.2 (patent scope) must close first
  because the Apache-2.0 patent grant is irrevocable once distributed.

### Changed from the spec

- `gate/core/policy/blast_radius.py` is **written fresh**, not ported from
  Valqore `governance/blast_radius.py`. See `docs/adr/0001-blast-radius-table.md`.
