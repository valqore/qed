"""Target derivation (``qed/adapters/mcp/targets.py``).

``action.target`` is what ``target_globs`` in a policy rule matches on, and the
values come from tool arguments, which are attacker-influenced. The two things
that matter here are that a template resolves the way its author expects, and
that no argument value can reshape the target to match a glob it should not.
"""

from __future__ import annotations

import pytest

from qed.adapters.mcp.targets import (
    DEFAULT_TEMPLATE,
    MISSING,
    TemplateError,
    derive_target,
    validate_template,
)


def target(template: str, arguments: object, *, env: str = "prod") -> str:
    return derive_target(
        server="orders",
        tool="execute_sql",
        arguments=arguments,
        environment=env,
        template=template,
    )


class TestTemplates:
    def test_the_default_is_server_and_tool(self) -> None:
        assert target(DEFAULT_TEMPLATE, {}) == "orders:execute_sql"

    def test_arguments_fill_placeholders(self) -> None:
        assert target("db:{env}/{args.table}", {"table": "payments"}) == "db:prod/payments"

    def test_a_dotted_path_walks_in(self) -> None:
        assert target("k8s:{args.filter.namespace}", {"filter": {"namespace": "kube-system"}}) == (
            "k8s:kube-system"
        )

    def test_a_list_index_resolves(self) -> None:
        assert target("x:{args.names[1]}", {"names": ["a", "b"]}) == "x:b"

    def test_numbers_and_booleans_become_strings(self) -> None:
        assert target("x:{args.id}", {"id": 7}) == "x:7"
        assert target("x:{args.force}", {"force": True}) == "x:true"

    def test_every_placeholder_kind_at_once(self) -> None:
        got = target("{server}/{tool}/{env}/{args.table}", {"table": "orders"})
        assert got == "orders/execute_sql/prod/orders"


class TestMissingArguments:
    def test_a_missing_argument_is_marked_not_guessed(self) -> None:
        """One absent argument must not take the call out of the chain."""
        assert target("db:{env}/{args.table}", {}) == f"db:prod/{MISSING}"

    @pytest.mark.parametrize(
        "arguments", [{}, {"table": None}, {"other": 1}, [], "a string", None, {"names": []}]
    )
    def test_nothing_raises(self, arguments: object) -> None:
        assert MISSING in target("db:{args.table}", arguments)

    def test_the_marker_survives_sanitising_unchanged(self) -> None:
        """It is built from characters the sanitiser leaves alone."""
        assert target("db:{args.nope}", {}).endswith(MISSING)

    def test_an_out_of_range_index_is_missing(self) -> None:
        assert target("x:{args.names[9]}", {"names": ["a"]}) == f"x:{MISSING}"

    def test_a_dict_valued_argument_is_missing_rather_than_a_repr(self) -> None:
        """``{'a': 1}`` in a target would be noise no glob could match."""
        assert target("x:{args.body}", {"body": {"a": 1}}) == f"x:{MISSING}"


class TestArgumentsCannotReshapeTheTarget:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("orders; drop", "orders__drop"),
            ("a b", "a_b"),
            ("tab\there", "tab_here"),
            ("new\nline", "new_line"),
            ("quote'd", "quote_d"),
            ("brace{x}", "brace_x_"),
            ("star*", "star_"),
            ("question?", "question_"),
        ],
    )
    def test_unsafe_characters_are_replaced(self, value: str, expected: str) -> None:
        assert target("db:{args.table}", {"table": value}) == f"db:{expected}"

    def test_glob_metacharacters_cannot_come_from_an_argument(self) -> None:
        """A target carrying ``*`` would be a resource claiming to be a pattern.

        ``target_globs`` is matched with ``fnmatch``, where the *pattern* side
        holds the wildcards. A value that smuggled one in would not widen the
        match -- fnmatch does not treat the subject as a pattern -- but it would
        put a string in the chain that reads like a wildcard to a human, and an
        approver should not have to wonder.
        """
        got = target("db:{args.table}", {"table": "orders*"})
        assert "*" not in got

    def test_dots_and_slashes_survive_because_targets_are_paths(self) -> None:
        """``repo:acme/payments`` and ``A.5.34`` need both characters.

        A traversal-looking value is left intact on purpose. It cannot escape a
        glob: ``fnmatch("db:prod/../x", "db:prod/*")`` still matches, because
        ``*`` spans separators. The target is a policy-matching string, not a
        filesystem path, and nothing opens it.
        """
        assert target("db:{args.table}", {"table": "../../etc/passwd"}) == ("db:../../etc/passwd")

        from fnmatch import fnmatch

        assert fnmatch("db:prod/../../etc/passwd", "db:prod/*")

    def test_a_value_cannot_inject_another_placeholder(self) -> None:
        """A substituted value is never re-scanned for placeholders."""
        assert target("db:{args.table}", {"table": "{args.secret}"}) == "db:_args.secret_"

    def test_a_very_long_value_is_cut(self) -> None:
        got = target("db:{args.table}", {"table": "x" * 500})
        assert len(got) < 200

    def test_an_empty_value_becomes_the_marker(self) -> None:
        """An empty segment would make ``db:prod/`` match ``db:prod/*``."""
        assert target("db:{env}/{args.table}", {"table": ""}) == f"db:prod/{MISSING}"


class TestValidation:
    def test_a_good_template_passes(self) -> None:
        validate_template("db:{env}/{args.table}")

    @pytest.mark.parametrize(
        "template",
        ["", "   ", "db:{enviroment}", "db:{args}", "db:{", "db:}", "db:{Args.table}"],
    )
    def test_a_bad_template_is_refused_at_startup(self, template: str) -> None:
        """A typo in qed.yaml must not be found halfway through a session."""
        with pytest.raises(TemplateError):
            validate_template(template)

    def test_a_template_with_no_placeholders_is_allowed(self) -> None:
        """A fixed target is a legitimate choice for a single-purpose server."""
        validate_template("db:prod/orders")
        assert target("db:prod/orders", {"table": "x"}) == "db:prod/orders"
