"""The blast-radius table (docs/blast-radius.md, docs/adr/0001)."""

from __future__ import annotations

import pytest

from gate.core.policy.blast_radius import explain, score
from tests.conftest import make_proposal


def s(patch: dict[str, object]) -> int:
    return score(make_proposal(patch))


@pytest.mark.parametrize(
    ("scope", "expected"),
    [("single_resource", 10), ("multi_resource", 30), ("account", 60), ("global", 80)],
)
def test_scope_is_the_base(scope: str, expected: int) -> None:
    assert s({"context": {"blast_radius_hints": {"scope": scope}}}) == expected


@pytest.mark.parametrize(("environment", "expected"), [("dev", 10), ("staging", 15), ("prod", 25)])
def test_environment_adds(environment: str, expected: int) -> None:
    assert s({"context": {"environment": environment}}) == expected


def test_writes_and_deletes_stack() -> None:
    assert s({"context": {"blast_radius_hints": {"writes": True}}}) == 20
    assert s({"context": {"blast_radius_hints": {"deletes": True}}}) == 35
    assert s({"context": {"blast_radius_hints": {"writes": True, "deletes": True}}}) == 45


def test_shell_is_riskier_than_an_mcp_tool() -> None:
    assert s({"action": {"kind": "shell", "name": "bash", "target": "host:a"}}) == 20
    assert s({"action": {"kind": "skill", "name": "Skill:x", "target": "skill:x"}}) == 15
    assert s({}) == 10


def test_sensitive_surface_in_the_target() -> None:
    assert s({"action": {"target": "aws:iam:role/admin"}}) == 25


def test_sensitive_surface_tolerates_underscore_naming() -> None:
    """`\\btoken\\b` does not match GITHUB_TOKEN; the table must."""
    assert s({"action": {"name": "env.set", "target": "env:GITHUB_TOKEN"}}) == 25


def test_destructive_verb_in_the_name() -> None:
    assert s({"action": {"name": "ec2.terminate_instances"}}) == 25


def test_a_verb_embedded_in_a_longer_word_does_not_count() -> None:
    assert s({"action": {"name": "dropbox.list_files", "target": "saas:dropbox"}}) == 10


def test_destructive_verb_only_in_the_parameters() -> None:
    """The gap that made Valqore's gateway score `execute_sql` as low risk."""
    assert (
        s({"action": {"name": "postgres.execute_sql", "params_redacted": {"sql": "DROP TABLE t"}}})
        == 25
    )


def test_a_signal_in_both_places_counts_once() -> None:
    both = s(
        {
            "action": {
                "name": "postgres.drop_table",
                "params_redacted": {"sql": "DROP TABLE t"},
            }
        }
    )
    assert both == 25


def test_the_score_is_clamped_at_one_hundred() -> None:
    assert (
        s(
            {
                "action": {"name": "aws.delete_all_roles", "target": "aws:iam:*"},
                "context": {
                    "environment": "prod",
                    "blast_radius_hints": {
                        "writes": True,
                        "deletes": True,
                        "scope": "global",
                    },
                },
            }
        )
        == 100
    )


def test_the_score_is_a_pure_function_of_the_proposal() -> None:
    proposal = make_proposal({"context": {"environment": "prod"}})
    assert {score(proposal) for _ in range(20)} == {score(proposal)}


def test_explain_sums_to_the_score_before_clamping() -> None:
    proposal = make_proposal(
        {"context": {"environment": "prod", "blast_radius_hints": {"writes": True}}}
    )
    assert sum(points for _, points in explain(proposal)) == score(proposal)


def test_explain_names_every_contribution() -> None:
    proposal = make_proposal(
        {
            "action": {"target": "aws:iam:role/x"},
            "context": {"environment": "prod", "blast_radius_hints": {"writes": True}},
        }
    )
    reasons = [reason for reason, _ in explain(proposal)]
    assert reasons == [
        "scope=single_resource",
        "environment=prod",
        "writes",
        "touches identity/secrets/audit surface",
    ]


def test_parameter_scanning_is_bounded() -> None:
    """A 1 MB parameter blob must not make scoring the slowest step."""
    proposal = make_proposal(
        {"action": {"params_redacted": {"body": "x" * 1_000_000 + " DROP TABLE t"}}}
    )
    # The destructive verb sits past the scan limit, so it is not counted. The
    # policy rules still read the field directly; only the score is capped.
    assert score(proposal) == 10
