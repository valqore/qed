"""Bundle loading and linting (SPEC §4.1–4.3, ADR-002.4, ADR-002.7).

A bundle is every rule from every file, resolved (overrides and disables
applied), sorted by ``rule_id``, canonicalised and hashed.

Two things worth knowing:

* ``policy_hash`` covers ``default_verdict`` as well as the rules. SPEC §4.6
  defines it over the rules alone, but ``default_verdict`` decides the outcome
  of every proposal that matches no rule, so a bundle hash that ignores it would
  let the effective policy change without the recorded hash changing — exactly
  what the hash exists to prevent. See ``docs/adr/0004-bundle-hash.md``.
* A rule's ``source`` file is excluded from the hash, so splitting or merging
  policy files is a no-op for the chain.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

import yaml
from pydantic import ValidationError

from qed.compliance.loader import canonical_framework
from qed.core import jcs
from qed.core.policy.model import (
    HASHED_RULE_FIELDS,
    LintFinding,
    LintSeverity,
    PolicyBundle,
    Rule,
    RuleOverride,
)
from qed.core.policy.predicates import validate_predicate
from qed.core.schemas import Decision, Frozen, Mode

__all__ = ["LoadResult", "bundle_hash", "load_bundle", "read_entries"]

_SOFTENING_ORDER = {Decision.BLOCK: 2, Decision.REQUIRE_APPROVAL: 1, Decision.ALLOW: 0}

#: Predicate findings that are warnings rather than errors. The rule loads and
#: evaluates; it just probably does not mean what its author thinks. An error
#: here would refuse the whole bundle, and a character class is a legal glob
#: feature -- rarely the intended one, but not something to forbid.
_PREDICATE_WARNINGS = frozenset({"suspicious_glob"})


class LoadResult(Frozen):
    bundle: PolicyBundle
    findings: list[LintFinding]

    @property
    def errors(self) -> list[LintFinding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def ok(self) -> bool:
        return not self.errors


def _yaml_files(paths: Sequence[Path]) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            out.extend(sorted(p for p in path.rglob("*.yaml") if p.is_file()))
        elif path.is_file():
            out.append(path)
    return out


def read_entries(paths: Sequence[Path]) -> list[tuple[str, dict[str, object]]]:
    """Read every rule-ish mapping from the given files or directories.

    Files are visited in sorted order so that two runs over the same tree see
    the same sequence; rule resolution is order-independent regardless, and a
    golden test shuffles the order to prove it.
    """
    entries: list[tuple[str, dict[str, object]]] = []
    for file in _yaml_files(paths):
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        if data is None:
            continue
        items: Iterable[object]
        if isinstance(data, dict):
            raw = data.get("rules", [])
            items = raw if isinstance(raw, list) else []
        elif isinstance(data, list):
            items = data
        else:
            items = []
        source = file.name
        for item in items:
            if isinstance(item, dict):
                entries.append((source, {str(k): v for k, v in item.items()}))
    return entries


def _rule_hash_payload(rule: Rule) -> dict[str, object]:
    dumped = rule.model_dump(mode="json", by_alias=True)
    return {field: dumped[field] for field in HASHED_RULE_FIELDS}


def bundle_hash(rules: Sequence[Rule], default_verdict: Decision) -> str:
    payload = {
        "default_verdict": default_verdict.value,
        "rules": [_rule_hash_payload(r) for r in sorted(rules, key=lambda r: r.rule_id)],
    }
    return jcs.sha256_hex(payload)


def _lint_rule(rule: Rule) -> list[LintFinding]:
    def finding(code: str, message: str, severity: LintSeverity = "error") -> LintFinding:
        return LintFinding(
            code=code,
            message=message,
            severity=severity,
            rule_id=rule.rule_id,
            source=rule.source,
        )

    findings: list[LintFinding] = []
    if rule.verdict is Decision.ALLOW:
        findings.append(
            finding(
                "allow_rule",
                "rules may only restrict (BLOCK or REQUIRE_APPROVAL); to exempt a case, "
                "narrow applies_to or disable the rule with a reason",
            )
        )
    if rule.disabled and not rule.reason:
        findings.append(
            finding(
                "disabled_without_reason",
                "`disabled: true` requires `reason:` so an auditor can see why",
            )
        )
    if rule.when is not None:
        findings += [
            finding(code, message, "warning" if code in _PREDICATE_WARNINGS else "error")
            for code, message in validate_predicate(rule.when)
        ]
    if rule.verdict is Decision.REQUIRE_APPROVAL and (
        rule.approval is None or not rule.approval.approvers
    ):
        findings.append(
            finding(
                "approval_without_approvers",
                "REQUIRE_APPROVAL without `approval.approvers` can never be approved",
                "warning",
            )
        )
    findings += [
        finding(
            "unknown_framework",
            f"unknown compliance framework {ref.framework!r}",
            "warning",
        )
        for ref in rule.compliance
        if canonical_framework(ref.framework) is None
    ]
    return findings


def _apply_override(rule: Rule, override: RuleOverride, source: str) -> tuple[Rule, list[str]]:
    """Return the overridden rule plus the names of any hardening attempts."""
    hardening: list[str] = []
    changes: dict[str, object] = {"source": source}

    if override.verdict is not None:
        if _SOFTENING_ORDER[override.verdict] > _SOFTENING_ORDER[rule.verdict]:
            hardening.append(f"verdict {rule.verdict.value} -> {override.verdict.value}")
        elif override.verdict is Decision.ALLOW:
            hardening.append("verdict -> ALLOW (use `disabled: true` with a reason)")
        else:
            changes["verdict"] = override.verdict

    if override.mode is not None:
        if rule.mode is Mode.shadow and override.mode is Mode.enforce:
            hardening.append("mode shadow -> enforce")
        else:
            changes["mode"] = override.mode

    if override.applies_to is not None:
        if not override.applies_to.narrows(rule.applies_to):
            hardening.append("applies_to widens the rule")
        else:
            changes["applies_to"] = override.applies_to

    if override.approval is not None:
        changes["approval"] = override.approval
    if override.severity is not None:
        changes["severity"] = override.severity

    return rule.model_copy(update=changes), hardening


def load_bundle(
    paths: Sequence[Path],
    *,
    default_verdict: Decision = Decision.ALLOW,
    default_mode: Mode = Mode.enforce,
    version: str | None = None,
) -> LoadResult:
    """Load, resolve and lint a bundle. Always returns a bundle; check ``ok``."""
    findings: list[LintFinding] = []
    rules: dict[str, Rule] = {}
    overrides: list[tuple[str, str, RuleOverride]] = []
    disables: list[tuple[str, str, str | None, str | None]] = []

    for source, entry in read_entries(paths):
        rule_id = entry.get("rule_id")
        if not isinstance(rule_id, str):
            findings.append(
                LintFinding(code="missing_rule_id", message="entry has no `rule_id`", source=source)
            )
            continue

        if "override" in entry:
            try:
                overrides.append((source, rule_id, RuleOverride.model_validate(entry["override"])))
            except ValidationError as exc:
                findings.append(
                    LintFinding(
                        code="invalid_override",
                        message=_compact(exc),
                        rule_id=rule_id,
                        source=source,
                    )
                )
            continue

        if set(entry) <= {"rule_id", "disabled", "reason", "disabled_by"}:
            reason = entry.get("reason")
            by = entry.get("disabled_by")
            disables.append(
                (
                    source,
                    rule_id,
                    reason if isinstance(reason, str) else None,
                    by if isinstance(by, str) else None,
                )
            )
            continue

        if rule_id in rules:
            findings.append(
                LintFinding(
                    code="duplicate_rule_id",
                    message=f"already defined in {rules[rule_id].source}",
                    rule_id=rule_id,
                    source=source,
                )
            )
            continue
        payload = dict(entry)
        payload.setdefault("mode", default_mode)
        payload["source"] = source
        try:
            rules[rule_id] = Rule.model_validate(payload)
        except ValidationError as exc:
            findings.append(
                LintFinding(
                    code="invalid_rule", message=_compact(exc), rule_id=rule_id, source=source
                )
            )

    for source, rule_id, override in overrides:
        target = rules.get(rule_id)
        if target is None:
            findings.append(
                LintFinding(
                    code="override_target_missing",
                    message="no rule with this id is defined in the bundle",
                    rule_id=rule_id,
                    source=source,
                )
            )
            continue
        updated, hardening = _apply_override(target, override, source)
        rules[rule_id] = updated
        findings += [
            LintFinding(
                code="override_hardening",
                message=f"an override may only soften or narrow: {item}",
                rule_id=rule_id,
                source=source,
            )
            for item in hardening
        ]

    for source, rule_id, reason, by in disables:
        target = rules.get(rule_id)
        if target is None:
            findings.append(
                LintFinding(
                    code="override_target_missing",
                    message="cannot disable a rule that is not defined in the bundle",
                    rule_id=rule_id,
                    source=source,
                )
            )
            continue
        rules[rule_id] = target.model_copy(
            update={"disabled": True, "reason": reason, "disabled_by": by, "source": source}
        )

    resolved = sorted(rules.values(), key=lambda r: r.rule_id)
    for rule in resolved:
        findings += _lint_rule(rule)

    bundle = PolicyBundle(
        rules=resolved,
        hash=bundle_hash(resolved, default_verdict),
        default_verdict=default_verdict,
        version=version,
        sources=sorted({r.source for r in resolved if r.source}),
    )
    return LoadResult(bundle=bundle, findings=findings)


def _compact(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
    )


def baseline_pack_dir() -> Path:
    """Directory of the shipped ``agent-baseline`` pack."""
    return Path(__file__).parent / "packs" / "agent-baseline"
