"""Linting (SPEC §4.3, ADR-002.4, ADR-002.7).

Every lint error class in the spec gets a case, plus the ones the spec implies:
an ALLOW rule (ADR-002.3) and a REQUIRE_APPROVAL rule with nobody who can
approve it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

from qed.core.policy.loader import bundle_hash, load_bundle
from qed.core.policy.predicates import validate_predicate
from qed.core.schemas import Decision

GOOD: dict[str, Any] = {
    "rule_id": "TT-AAA-001",
    "name": "Test rule",
    "message": "Test message.",
    "verdict": "BLOCK",
    "when": {"field": "context.environment", "equals": "prod"},
}


def write(tmp_path: Path, *entries: dict[str, Any], name: str = "rules.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(list(entries), sort_keys=False), encoding="utf-8")
    return path


def codes(tmp_path: Path, *entries: dict[str, Any]) -> list[str]:
    result = load_bundle([write(tmp_path, *entries)])
    return [f.code for f in result.findings]


def test_a_good_rule_lints_clean(tmp_path: Path) -> None:
    assert codes(tmp_path, GOOD) == []


def test_duplicate_rule_id(tmp_path: Path) -> None:
    assert "duplicate_rule_id" in codes(tmp_path, GOOD, {**GOOD, "name": "Other"})


def test_duplicate_rule_id_keeps_the_first_definition(tmp_path: Path) -> None:
    result = load_bundle([write(tmp_path, GOOD, {**GOOD, "message": "second"})])
    rule = result.bundle.by_id("TT-AAA-001")
    assert rule is not None and rule.message == "Test message."


def test_invalid_rule_id_shape(tmp_path: Path) -> None:
    assert "invalid_rule" in codes(tmp_path, {**GOOD, "rule_id": "lowercase-001"})


def test_missing_rule_id(tmp_path: Path) -> None:
    entry = {k: v for k, v in GOOD.items() if k != "rule_id"}
    assert "missing_rule_id" in codes(tmp_path, entry)


def test_invalid_regex(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "action.name", "regex": "([unclosed"}}
    assert "invalid_regex" in codes(tmp_path, rule)


def test_unknown_field_path(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "action.nmae", "equals": "x"}}
    assert "unknown_field_path" in codes(tmp_path, rule)


def test_free_form_parameter_paths_are_accepted(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "action.params_redacted.anything.nested", "exists": True}}
    assert codes(tmp_path, rule) == []


def test_derived_paths_are_accepted(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "derived.budget.steps_remaining", "lte": 1}}
    assert codes(tmp_path, rule) == []


def test_unknown_derived_path_is_rejected(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "derived.budget.wishes_remaining", "lte": 1}}
    assert "unknown_field_path" in codes(tmp_path, rule)


def test_two_operators_in_one_leaf(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "action.name", "equals": "a", "glob": "b"}}
    assert "invalid_predicate" in codes(tmp_path, rule)


def test_no_operator_in_a_leaf(tmp_path: Path) -> None:
    assert "invalid_predicate" in codes(tmp_path, {**GOOD, "when": {"field": "action.name"}})


def test_composite_must_be_the_only_key(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"any": [GOOD["when"]], "field": "action.name"}}
    assert "invalid_predicate" in codes(tmp_path, rule)


def test_empty_composite_list(tmp_path: Path) -> None:
    assert "invalid_predicate" in codes(tmp_path, {**GOOD, "when": {"all": []}})


def test_in_operand_must_be_a_list(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "context.environment", "in": "prod"}}
    assert "invalid_predicate" in codes(tmp_path, rule)


def test_exists_operand_must_be_a_boolean(tmp_path: Path) -> None:
    rule = {**GOOD, "when": {"field": "action.method", "exists": "yes"}}
    assert "invalid_predicate" in codes(tmp_path, rule)


def test_allow_rules_are_rejected(tmp_path: Path) -> None:
    assert "allow_rule" in codes(tmp_path, {**GOOD, "verdict": "ALLOW"})


def test_approval_without_approvers_is_a_warning(tmp_path: Path) -> None:
    result = load_bundle([write(tmp_path, {**GOOD, "verdict": "REQUIRE_APPROVAL"})])
    warning = next(f for f in result.findings if f.code == "approval_without_approvers")
    assert warning.severity == "warning"
    assert result.ok, "a warning must not stop the bundle from loading"


def test_unknown_compliance_framework_is_a_warning(tmp_path: Path) -> None:
    rule = {**GOOD, "compliance": [{"framework": "made_up_act", "control": "1"}]}
    result = load_bundle([write(tmp_path, rule)])
    assert [f.code for f in result.findings] == ["unknown_framework"]
    assert result.ok


def test_known_framework_aliases_are_accepted(tmp_path: Path) -> None:
    rule = {**GOOD, "compliance": [{"framework": "EU AI Act", "control": "Art. 14"}]}
    assert codes(tmp_path, rule) == []


class TestDisable:
    def test_disabling_without_a_reason_is_an_error(self, tmp_path: Path) -> None:
        found = codes(tmp_path, GOOD, {"rule_id": GOOD["rule_id"], "disabled": True})
        assert "disabled_without_reason" in found

    def test_disabling_with_a_reason_is_accepted(self, tmp_path: Path) -> None:
        entry = {
            "rule_id": GOOD["rule_id"],
            "disabled": True,
            "reason": "we do not run anything in prod yet",
            "disabled_by": "platform-team",
        }
        result = load_bundle([write(tmp_path, GOOD, entry)])
        assert result.ok
        rule = result.bundle.by_id(GOOD["rule_id"])
        assert rule is not None and rule.disabled
        assert rule.disabled_by == "platform-team"
        assert result.bundle.active_rules() == []

    def test_disabling_a_rule_that_does_not_exist(self, tmp_path: Path) -> None:
        entry = {"rule_id": "TT-ZZZ-999", "disabled": True, "reason": "typo"}
        assert "override_target_missing" in codes(tmp_path, entry)

    def test_disabling_changes_the_bundle_hash(self, tmp_path: Path) -> None:
        plain = load_bundle([write(tmp_path, GOOD, name="a.yaml")]).bundle
        entry = {"rule_id": GOOD["rule_id"], "disabled": True, "reason": "not needed"}
        off = load_bundle([write(tmp_path, GOOD, entry, name="b.yaml")]).bundle
        assert plain.hash != off.hash


class TestOverride:
    def test_missing_target(self, tmp_path: Path) -> None:
        entry = {"rule_id": "TT-ZZZ-999", "override": {"verdict": "REQUIRE_APPROVAL"}}
        assert "override_target_missing" in codes(tmp_path, entry)

    def test_softening_block_to_approval_is_allowed(self, tmp_path: Path) -> None:
        entry = {
            "rule_id": GOOD["rule_id"],
            "override": {
                "verdict": "REQUIRE_APPROVAL",
                "approval": {"approvers": ["sec-team"]},
            },
        }
        result = load_bundle([write(tmp_path, GOOD, entry)])
        assert result.ok, [f.format() for f in result.findings]
        rule = result.bundle.by_id(GOOD["rule_id"])
        assert rule is not None
        assert rule.verdict is Decision.REQUIRE_APPROVAL
        assert rule.approval is not None and rule.approval.approvers == ["sec-team"]

    def test_hardening_approval_to_block_is_rejected(self, tmp_path: Path) -> None:
        soft = {**GOOD, "verdict": "REQUIRE_APPROVAL", "approval": {"approvers": ["a"]}}
        entry = {"rule_id": GOOD["rule_id"], "override": {"verdict": "BLOCK"}}
        found = codes(tmp_path, soft, entry)
        assert "override_hardening" in found

    def test_overriding_to_allow_is_rejected(self, tmp_path: Path) -> None:
        entry = {"rule_id": GOOD["rule_id"], "override": {"verdict": "ALLOW"}}
        result = load_bundle([write(tmp_path, GOOD, entry)])
        assert "override_hardening" in [f.code for f in result.findings]
        rule = result.bundle.by_id(GOOD["rule_id"])
        # The attempt is reported and not applied.
        assert rule is not None and rule.verdict is Decision.BLOCK

    def test_narrowing_applies_to_is_allowed(self, tmp_path: Path) -> None:
        broad = {**GOOD, "applies_to": {"environments": ["dev", "staging", "prod"]}}
        entry = {
            "rule_id": GOOD["rule_id"],
            "override": {"applies_to": {"environments": ["staging"]}},
        }
        result = load_bundle([write(tmp_path, broad, entry)])
        assert result.ok, [f.format() for f in result.findings]
        rule = result.bundle.by_id(GOOD["rule_id"])
        assert rule is not None and rule.applies_to.environments == ["staging"]

    def test_widening_applies_to_is_rejected(self, tmp_path: Path) -> None:
        narrow = {**GOOD, "applies_to": {"environments": ["staging"]}}
        entry = {
            "rule_id": GOOD["rule_id"],
            "override": {"applies_to": {"environments": ["staging", "prod"]}},
        }
        assert "override_hardening" in codes(tmp_path, narrow, entry)

    def test_dropping_a_constraint_is_rejected_as_widening(self, tmp_path: Path) -> None:
        narrow = {**GOOD, "applies_to": {"environments": ["staging"], "kinds": ["http"]}}
        entry = {
            "rule_id": GOOD["rule_id"],
            "override": {"applies_to": {"environments": ["staging"]}},
        }
        assert "override_hardening" in codes(tmp_path, narrow, entry)

    def test_enforce_to_shadow_is_softening(self, tmp_path: Path) -> None:
        entry = {"rule_id": GOOD["rule_id"], "override": {"mode": "shadow"}}
        result = load_bundle([write(tmp_path, GOOD, entry)])
        assert result.ok
        rule = result.bundle.by_id(GOOD["rule_id"])
        assert rule is not None and rule.mode.value == "shadow"

    def test_shadow_to_enforce_is_hardening(self, tmp_path: Path) -> None:
        shadow = {**GOOD, "mode": "shadow"}
        entry = {"rule_id": GOOD["rule_id"], "override": {"mode": "enforce"}}
        assert "override_hardening" in codes(tmp_path, shadow, entry)

    def test_an_invalid_override_body_is_reported(self, tmp_path: Path) -> None:
        entry = {"rule_id": GOOD["rule_id"], "override": {"verdict": "MAYBE"}}
        assert "invalid_override" in codes(tmp_path, entry)


class TestBundleHash:
    def test_hash_ignores_rule_order(self, tmp_path: Path) -> None:
        second = {**GOOD, "rule_id": "TT-BBB-002"}
        one = load_bundle([write(tmp_path, GOOD, second, name="a.yaml")]).bundle
        two = load_bundle([write(tmp_path, second, GOOD, name="b.yaml")]).bundle
        assert one.hash == two.hash

    def test_hash_ignores_which_file_a_rule_came_from(self, tmp_path: Path) -> None:
        second = {**GOOD, "rule_id": "TT-BBB-002"}
        together = tmp_path / "together"
        together.mkdir()
        (together / "all.yaml").write_text(yaml.safe_dump([GOOD, second]), encoding="utf-8")
        apart = tmp_path / "apart"
        apart.mkdir()
        (apart / "one.yaml").write_text(yaml.safe_dump([GOOD]), encoding="utf-8")
        (apart / "two.yaml").write_text(yaml.safe_dump([second]), encoding="utf-8")
        assert load_bundle([together]).bundle.hash == load_bundle([apart]).bundle.hash

    def test_hash_covers_the_default_verdict(self, tmp_path: Path) -> None:
        path = write(tmp_path, GOOD)
        allow = load_bundle([path], default_verdict=Decision.ALLOW).bundle
        approve = load_bundle([path], default_verdict=Decision.REQUIRE_APPROVAL).bundle
        assert allow.hash != approve.hash

    def test_hash_changes_when_a_message_changes(self, tmp_path: Path) -> None:
        a = load_bundle([write(tmp_path, GOOD, name="a.yaml")]).bundle
        b = load_bundle([write(tmp_path, {**GOOD, "message": "Different."}, name="b.yaml")]).bundle
        assert a.hash != b.hash

    def test_helper_matches_the_loaded_bundle(self, tmp_path: Path) -> None:
        bundle = load_bundle([write(tmp_path, GOOD)]).bundle
        assert bundle_hash(bundle.rules, bundle.default_verdict) == bundle.hash


def test_empty_and_comment_only_files_are_tolerated(tmp_path: Path) -> None:
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    (tmp_path / "comment.yaml").write_text("# nothing here\n", encoding="utf-8")
    result = load_bundle([tmp_path])
    assert result.ok and result.bundle.rules == []


def test_a_mapping_file_with_a_rules_key_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "pack.yaml").write_text(
        yaml.safe_dump({"version": "1", "rules": [GOOD]}), encoding="utf-8"
    )
    result = load_bundle([tmp_path])
    assert result.ok and len(result.bundle.rules) == 1


class TestASuspiciousGlob:
    """``fnmatch`` reads ``[`` as a character class, not a literal bracket.

    ``*://[fd00:ec2::254]*`` does not look for that IPv6 literal. It matches
    any target whose host starts with one of ``f d 0 2 4 5 c e :``, which is
    most of the internet -- and a rule written that way reads correct while
    firing on traffic nobody meant it to, in the direction that blocks real
    work. The first live run of ``qed proxy`` was refused a CONNECT to
    example.com by exactly this.
    """

    def test_a_bracket_in_a_glob_is_reported(self) -> None:
        findings = validate_predicate({"field": "action.target", "glob": "*://[fd00::254]*"})
        assert [code for code, _ in findings] == ["suspicious_glob"]

    def test_the_message_names_the_escape_and_the_alternative(self) -> None:
        _, message = validate_predicate({"field": "action.target", "glob": "*://[fd00::254]*"})[0]
        assert "[[]" in message
        assert "contains" in message

    def test_an_escaped_bracket_is_accepted(self) -> None:
        """A literal bracket is still expressible, so the finding names the
        escape rather than forbidding the character."""
        assert validate_predicate({"field": "action.target", "glob": "*[[]fd00::254[]]*"}) == []

    def test_a_list_of_globs_is_checked_element_by_element(self) -> None:
        findings = validate_predicate(
            {"field": "action.target", "glob": ["*.amazonaws.com*", "*://[fd00::254]*"]}
        )
        assert len(findings) == 1

    def test_an_ordinary_glob_is_quiet(self) -> None:
        assert validate_predicate({"field": "action.target", "glob": "*.amazonaws.com*"}) == []

    def test_it_is_a_warning_and_not_an_error(self, tmp_path: Path) -> None:
        """A character class is a legal glob feature. Refusing the bundle
        would forbid it; the rule loads and the author is told."""
        pack = tmp_path / "p.yaml"
        rule = dict(GOOD)
        rule["when"] = {"field": "action.target", "glob": "*://[fd00::254]*"}
        pack.write_text(yaml.safe_dump([rule]), encoding="utf-8")
        result = load_bundle([pack])
        assert [f.code for f in result.findings] == ["suspicious_glob"]
        assert [f.severity for f in result.findings] == ["warning"]
        assert len(result.bundle.rules) == 1


class TestACatastrophicRegexShape:
    """A repeat whose body also repeats is where backtracking explodes.

    ``(a+)+`` against a long near-match can split the input between the inner
    and outer repeat in exponentially many ways. ADR-0017 and ADR-0018 bound
    the damage at runtime -- retried, then capped at the decision's whole regex
    allowance -- so this costs a skipped rule rather than a hung kernel. The
    lint finding exists to tell the author instead of the operator.

    Every case below is parameterised on the *shape*, not the text, because
    the check reads the parse tree: ``(a+)+`` and ``(?:a{1,}){2,}`` have to be
    one finding and a ``+`` inside a character class has to be none.
    """

    @pytest.mark.parametrize(
        "pattern",
        [
            r"(a+)+$",
            r"(a*)*b",
            r"(\w+\s?)*$",
            r"(?:\d+)+x",
            r"([a-z]+)*!",
            r"(a{1,}){2,}",
            r"(x+x+)+y",
            r"((a+))+z",
        ],
        ids=lambda p: p,
    )
    def test_a_nested_unbounded_repeat_is_reported(self, pattern: str) -> None:
        findings = validate_predicate({"field": "action.params_redacted.body", "regex": pattern})
        assert [code for code, _ in findings] == ["catastrophic_regex"]

    @pytest.mark.parametrize(
        "pattern",
        [
            r"^arn:aws:iam::\d{12}:role/.+$",
            r"(?:prod|staging)-[a-z0-9-]+",
            r"\bDROP\s+TABLE\b",
            r"[+*]+",
            r"^(a|b|c)+$",
            r"(ab)+",
            r"a+b+c+",
            r"(?:x+)?y",
            r"(a{1,3}){1,3}",
        ],
        ids=lambda p: p,
    )
    def test_an_ordinary_pattern_is_quiet(self, pattern: str) -> None:
        """The false-positive half, and the half that decides whether this can
        ship: a heuristic that fires on real policy regexes would train authors
        to ignore it."""
        assert validate_predicate({"field": "action.params_redacted.body", "regex": pattern}) == []

    def test_a_small_bounded_nesting_is_allowed(self) -> None:
        """``(a{1,3}){1,3}`` is nine repetitions, not an explosion, and the
        bound is a judgement written down in `_unbounded` rather than a
        measurement."""
        assert (
            validate_predicate({"field": "action.params_redacted.body", "regex": r"(a{1,3}){1,3}"})
            == []
        )

    def test_the_message_says_what_to_do(self) -> None:
        _, message = validate_predicate(
            {"field": "action.params_redacted.body", "regex": r"(a+)+$"}
        )[0]
        assert "bound the outer repeat" in message
        assert "(a+)+$" in message, "the finding does not quote the pattern"

    def test_one_finding_per_predicate_not_one_per_site(self) -> None:
        """One mistake, one finding, so a bundle report stays readable.

        The pattern is two *independent* nested repeats in separate branches,
        chosen on purpose. ``((a+)+)+`` would pass this test with or without
        the cap, because the walk stops at the first hit inside one branch --
        it asserts something true on both sides of the change and so proves
        nothing. An alternation reaches the second site, which is what makes
        this discriminating.
        """
        findings = validate_predicate(
            {"field": "action.params_redacted.body", "regex": r"(a+)+x|(b+)+y"}
        )
        assert len(findings) == 1, (
            "two nested-repeat sites produced two findings; one predicate is one mistake to fix"
        )
        assert findings[0][0] == "catastrophic_regex"

    def test_nesting_inside_nesting_is_also_one_finding(self) -> None:
        findings = validate_predicate(
            {"field": "action.params_redacted.body", "regex": r"((a+)+)+$"}
        )
        assert len(findings) == 1

    def test_an_invalid_regex_reports_only_that(self) -> None:
        """The shape check runs on the `else` of the compile, so a pattern that
        does not compile is not also reported for its shape -- one broken thing
        should produce one finding."""
        findings = validate_predicate({"field": "action.params_redacted.body", "regex": r"(a+)+["})
        assert [code for code, _ in findings] == ["invalid_regex"]

    def test_it_is_a_warning_and_not_an_error(self, tmp_path: Path) -> None:
        """ADR-0018's reasoning, as a test. Whether a pattern backtracks
        catastrophically on *some* input is not a question a linter settles, so
        this one recognises a shape and is wrong in both directions. Refusing
        the bundle would let a heuristic disable a correct BLOCK, and a
        disabled BLOCK is worse than a slow one."""
        pack = tmp_path / "p.yaml"
        rule = dict(GOOD)
        rule["when"] = {"field": "action.params_redacted.body", "regex": r"(a+)+$"}
        pack.write_text(yaml.safe_dump([rule]), encoding="utf-8")
        result = load_bundle([pack])
        assert [f.code for f in result.findings] == ["catastrophic_regex"]
        assert [f.severity for f in result.findings] == ["warning"]
        assert len(result.bundle.rules) == 1, "the rule was refused, not warned about"

    def test_the_runtime_bound_is_what_actually_protects_the_kernel(self) -> None:
        """The thing this finding is *not*. A pattern it does not flag can
        still meet the input that defeats it, so the guarantee has to come from
        ADR-0018's allowance rather than from a clean lint. Asserted here so
        that deleting the allowance does not leave the lint looking sufficient.
        """
        from qed.core.regex_budget import BUDGET, POOL

        assert POOL > BUDGET > 0

    def test_a_pattern_the_stdlib_cannot_parse_is_skipped_not_guessed(self) -> None:
        """`regex` accepts constructs `re` does not, such as its `(?V1)` flag.

        The check must not raise on those and must not invent a finding. What
        it returns is deliberately not asserted beyond that: silence here means
        "not examined", never "safe", and pinning the answer would turn a
        documented blind spot into a promise.
        """
        findings = validate_predicate(
            {"field": "action.params_redacted.body", "regex": r"(?V1)(?:a+)+"}
        )
        assert isinstance(findings, list)
        assert all(code != "invalid_regex" for code, _ in findings), (
            "regex compiled it, so it must not be reported as invalid"
        )


class TestTheDocumentationMatchesTheLinter:
    """`docs/policy-language.md` lists the codes and shows a worked fix.

    Both are hand-written next to code that can change without them, which is
    the shape that keeps producing stale claims here. These tie the page to
    the linter: a code that becomes a warning without the page saying so, and
    a documented before/after that stops being true, both fail here.

    The missing `suspicious_glob` is why this exists -- the page listed the
    warnings and had never mentioned it.
    """

    PAGE: ClassVar[Path] = Path(__file__).resolve().parents[2] / "docs" / "policy-language.md"

    def page(self) -> str:
        return self.PAGE.read_text(encoding="utf-8")

    def test_every_predicate_warning_is_documented_as_one(self) -> None:
        from qed.core.policy.loader import _PREDICATE_WARNINGS

        page = self.page()
        warnings_section = page[page.index("as **errors**") :]
        undocumented = [
            code for code in sorted(_PREDICATE_WARNINGS) if f"`{code}`" not in warnings_section
        ]
        assert not undocumented, (
            f"{undocumented} are warnings in the loader and are not listed as warnings on the page"
        )

    def _documented_examples(self) -> list[str]:
        """The regex operands from the page's fix example, in order."""
        page = self.page()
        section = page[page.index("### `catastrophic_regex`") :]
        return re.findall(r'regex:\s*"(.*?)"\s*\}', section)

    def test_the_example_it_calls_flagged_is_flagged(self) -> None:
        examples = self._documented_examples()
        assert len(examples) == 2, f"the page's fix example no longer has two regexes: {examples}"
        bad = examples[0].replace("\\\\", "\\")
        findings = validate_predicate({"field": "action.params_redacted.body", "regex": bad})
        assert [code for code, _ in findings] == ["catastrophic_regex"], (
            f"the page shows {bad!r} as the flagged pattern and it is not flagged"
        )

    def test_the_fix_it_recommends_is_actually_clean(self) -> None:
        """The half that matters more. Telling an author to rewrite a pattern
        into something that is also flagged would send them in a circle."""
        good = self._documented_examples()[1].replace("\\\\", "\\")
        findings = validate_predicate({"field": "action.params_redacted.body", "regex": good})
        assert findings == [], (
            f"the page recommends {good!r} as the fix and the linter reports "
            f"{[code for code, _ in findings]}"
        )


def test_the_shipped_baseline_pack_lints_clean() -> None:
    from qed.core.policy.loader import baseline_pack_dir

    result = load_bundle([baseline_pack_dir()])
    assert result.findings == [], [f.format() for f in result.findings]
    assert len(result.bundle.rules) == 46


@pytest.mark.parametrize("rule_id", ["AG", "ag-blr-001", "AG_BLR_001", "A-1"])
def test_rule_id_pattern_rejects_bad_shapes(tmp_path: Path, rule_id: str) -> None:
    assert "invalid_rule" in codes(tmp_path, {**GOOD, "rule_id": rule_id})
