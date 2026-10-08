"""Predicate operators and field resolution (SPEC §4.4)."""

from __future__ import annotations

import pytest

from gate.core.policy.predicates import (
    MISSING,
    PredicateError,
    evaluate_predicate,
    resolve_field,
)

PROPOSAL: dict[str, object] = {
    "action": {
        "kind": "http",
        "name": "POST /things",
        "target": "https://api.github.com/x",
        "method": None,
        "params_redacted": {"sql": "SELECT 1", "n": 5, "tags": ["a", "b"]},
    },
    "context": {"environment": "prod", "tags": ["migration"]},
}
DERIVED: dict[str, object] = {"blast_radius": 55, "budget": {"steps_remaining": 3}}


def check(node: dict[str, object]) -> bool:
    return evaluate_predicate(node, PROPOSAL, DERIVED)


class TestResolveField:
    def test_nested_path(self) -> None:
        assert resolve_field("action.kind", PROPOSAL, DERIVED) == "http"

    def test_derived_prefix_reads_the_derived_tree(self) -> None:
        assert resolve_field("derived.blast_radius", PROPOSAL, DERIVED) == 55

    def test_missing_leaf(self) -> None:
        assert resolve_field("action.nope", PROPOSAL, DERIVED) is MISSING

    def test_missing_branch(self) -> None:
        assert resolve_field("nope.nope.nope", PROPOSAL, DERIVED) is MISSING

    def test_descending_into_a_scalar(self) -> None:
        assert resolve_field("action.kind.deeper", PROPOSAL, DERIVED) is MISSING

    def test_explicit_null_is_not_missing(self) -> None:
        assert resolve_field("action.method", PROPOSAL, DERIVED) is None

    def test_list_indexing_is_not_supported(self) -> None:
        assert resolve_field("context.tags.0", PROPOSAL, DERIVED) is MISSING


class TestOperators:
    @pytest.mark.parametrize(
        ("node", "expected"),
        [
            ({"field": "action.kind", "equals": "http"}, True),
            ({"field": "action.kind", "equals": "shell"}, False),
            ({"field": "action.kind", "not_equals": "shell"}, True),
            ({"field": "action.kind", "in": ["http", "shell"]}, True),
            ({"field": "action.kind", "in": ["shell"]}, False),
            ({"field": "action.kind", "not_in": ["shell"]}, True),
            ({"field": "action.target", "glob": "https://*.github.com/*"}, True),
            ({"field": "action.target", "glob": ["no", "https://api.*"]}, True),
            ({"field": "action.target", "glob": "https://gitlab*"}, False),
            ({"field": "action.name", "regex": "(?i)^post "}, True),
            ({"field": "action.name", "regex": "^GET"}, False),
            ({"field": "derived.blast_radius", "gt": 54}, True),
            ({"field": "derived.blast_radius", "gt": 55}, False),
            ({"field": "derived.blast_radius", "gte": 55}, True),
            ({"field": "derived.blast_radius", "lt": 56}, True),
            ({"field": "derived.blast_radius", "lte": 55}, True),
            ({"field": "action.kind", "exists": True}, True),
            ({"field": "action.method", "exists": True}, False),
            ({"field": "action.method", "exists": False}, True),
            ({"field": "action.nope", "exists": False}, True),
            ({"field": "action.params_redacted.sql", "contains": "SELECT"}, True),
            ({"field": "action.params_redacted.tags", "contains": "a"}, True),
            ({"field": "action.params_redacted.tags", "contains": "z"}, False),
        ],
    )
    def test_operator(self, node: dict[str, object], expected: bool) -> None:
        assert check(node) is expected

    def test_numeric_comparison_against_a_string_is_false(self) -> None:
        assert check({"field": "action.kind", "gt": 1}) is False

    def test_booleans_are_not_numbers(self) -> None:
        proposal: dict[str, object] = {"a": True}
        assert evaluate_predicate({"field": "a", "gt": 0}, proposal, {}) is False

    def test_contains_on_a_number_is_false(self) -> None:
        assert check({"field": "action.params_redacted.n", "contains": "5"}) is False


class TestMissingSemantics:
    """ADR note: absence is falsy for everything except ``exists``."""

    @pytest.mark.parametrize(
        "op_value",
        [
            {"equals": "x"},
            {"not_equals": "x"},
            {"in": ["x"]},
            {"not_in": ["x"]},
            {"glob": "*"},
            {"regex": ".*"},
            {"gt": 0},
            {"lte": 999},
            {"contains": "x"},
        ],
    )
    def test_missing_field_is_false(self, op_value: dict[str, object]) -> None:
        assert check({"field": "action.absent", **op_value}) is False

    def test_not_makes_absence_expressible(self) -> None:
        assert check({"not": {"field": "action.absent", "equals": "x"}}) is True


class TestComposites:
    def test_any(self) -> None:
        assert check(
            {
                "any": [
                    {"field": "action.kind", "equals": "shell"},
                    {"field": "action.kind", "equals": "http"},
                ]
            }
        )

    def test_all(self) -> None:
        assert not check(
            {
                "all": [
                    {"field": "action.kind", "equals": "http"},
                    {"field": "context.environment", "equals": "dev"},
                ]
            }
        )

    def test_not(self) -> None:
        assert check({"not": {"field": "context.environment", "equals": "dev"}})

    def test_nesting(self) -> None:
        assert check(
            {
                "all": [
                    {"field": "context.environment", "equals": "prod"},
                    {
                        "any": [
                            {"field": "derived.blast_radius", "gt": 100},
                            {"not": {"field": "action.method", "exists": True}},
                        ]
                    },
                ]
            }
        )


class TestErrors:
    def test_unknown_key_in_a_leaf(self) -> None:
        with pytest.raises(PredicateError, match="unknown predicate keys"):
            check({"field": "action.kind", "equels": "http"})

    def test_two_operators(self) -> None:
        with pytest.raises(PredicateError, match="exactly one operator"):
            check({"field": "action.kind", "equals": "a", "glob": "b"})

    def test_missing_field_key(self) -> None:
        with pytest.raises(PredicateError, match="string 'field'"):
            check({"equals": "a"})

    def test_composite_needs_a_list(self) -> None:
        with pytest.raises(PredicateError, match="list of predicates"):
            check({"any": {"field": "action.kind", "equals": "http"}})

    def test_regex_operand_must_be_a_string(self) -> None:
        with pytest.raises(PredicateError, match="regex operand"):
            check({"field": "action.kind", "regex": 5})

    def test_runaway_nesting(self) -> None:
        node: dict[str, object] = {"field": "action.kind", "equals": "http"}
        for _ in range(30):
            node = {"not": node}
        with pytest.raises(PredicateError, match="nested"):
            check(node)
