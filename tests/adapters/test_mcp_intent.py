"""Tool-call classification (``gate/adapters/mcp/intent.py``).

The module exists because of one bug, so the first class of tests is that bug:
a mild verb in the tool name with a destructive statement in the arguments must
not come out read-only. The rest pins the tables, the scope heuristic and the
refusal to guess.
"""

from __future__ import annotations

import pytest

from gate.adapters.mcp.intent import classify


class TestTheCarriedForwardBug:
    """`execute_sql` + `DROP TABLE` (week 1 review, SPEC Appendix B)."""

    def test_a_mild_verb_with_a_destructive_payload_is_a_delete(self) -> None:
        intent = classify("postgres.execute_sql", {"sql": "DROP TABLE orders_archive;"})
        assert intent.deletes is True
        assert intent.writes is True
        assert intent.change_type == "delete"
        assert "destructive statement in arguments" in intent.reasons

    def test_the_tool_name_alone_would_not_have_been_enough(self) -> None:
        """Proves the test above is testing the arguments and not the name."""
        intent = classify("postgres.execute_sql", {"sql": "SELECT 1"})
        assert intent.deletes is False
        assert intent.writes is True, "`execute` is a mutating verb on its own"

    @pytest.mark.parametrize(
        "sql",
        [
            "DROP TABLE orders",
            "drop table orders",
            "  TRUNCATE orders_archive;",
            "DELETE FROM orders WHERE 1=1",
            "DROP DATABASE prod",
            "drop_table('orders')",
        ],
    )
    def test_destructive_sql_in_any_shape(self, sql: str) -> None:
        assert classify("db.query", {"sql": sql}).deletes is True

    @pytest.mark.parametrize(
        "command",
        [
            "rm -rf /var/lib/data",
            "git push --force origin main",
            "git push -u origin main --force",
            "git reset --hard origin/main",
            "helm uninstall payments",
        ],
    )
    def test_destructive_shell_in_arguments(self, command: str) -> None:
        assert classify("shell.run", {"command": command}).deletes is True

    def test_a_nested_argument_is_read_too(self) -> None:
        intent = classify("api.call", {"body": {"statements": ["DROP TABLE t"]}})
        assert intent.deletes is True


class TestVerbTables:
    @pytest.mark.parametrize(
        "tool",
        [
            "k8s.delete_pod",
            "helm.uninstall",
            "argo.rollback",
            "aws.terminate_instances",
            "db.drop_table",
            "fs.rm",
            "node.drain",
            "iam.revoke_grant",
        ],
    )
    def test_destructive_tool_names(self, tool: str) -> None:
        intent = classify(tool, {})
        assert intent.deletes is True
        assert intent.change_type == "delete"

    @pytest.mark.parametrize(
        "tool",
        ["k8s.apply", "github.create_issue", "aws.put_role_policy", "k8s.scale", "argo.sync"],
    )
    def test_mutating_tool_names(self, tool: str) -> None:
        intent = classify(tool, {})
        assert intent.writes is True
        assert intent.deletes is False

    @pytest.mark.parametrize(
        "tool", ["github.list_issues", "k8s.get_pods", "db.describe_table", "fs.read_file"]
    )
    def test_reading_tool_names(self, tool: str) -> None:
        intent = classify(tool, {})
        assert intent.read_only
        assert intent.change_type == "read"

    def test_underscores_do_not_hide_a_verb(self) -> None:
        """``\\b`` treats ``_`` as a word character; the splitter must not."""
        assert classify("aws.terminate_instances", {}).deletes is True

    def test_a_substring_is_not_a_verb(self) -> None:
        """``dropbox`` is not ``drop`` and ``getter`` is not ``get``."""
        assert classify("dropbox.upload_file", {}).deletes is False
        assert classify("dropbox.upload_file", {}).writes is True

    def test_create_is_distinguished_from_update(self) -> None:
        assert classify("github.create_issue", {}).change_type == "create"
        assert classify("github.update_issue", {}).change_type == "update"

    def test_an_unknown_verb_is_not_guessed_as_safe(self) -> None:
        """Guessing "read" here would be a guess in the agent's favour."""
        intent = classify("weather.frobnicate", {})
        assert intent.change_type == "unknown"
        assert intent.writes is False
        assert "no known verb" in intent.reasons[0]


class TestScope:
    def test_no_arguments_is_a_single_resource(self) -> None:
        assert classify("db.list_tables", {}).scope == "single_resource"

    def test_one_named_resource_is_a_single_resource(self) -> None:
        assert classify("db.delete_row", {"table": "orders", "id": 7}).scope == "single_resource"

    @pytest.mark.parametrize("key", ["selector", "label_selector", "filter", "where", "prefix"])
    def test_a_bulk_selector_is_multi_resource(self, key: str) -> None:
        assert classify("k8s.delete", {key: "app=payments"}).scope == "multi_resource"

    def test_a_list_of_targets_is_multi_resource(self) -> None:
        intent = classify("k8s.delete", {"names": ["a", "b", "c"]})
        assert intent.scope == "multi_resource"
        assert "names' names 3 resources" in " ".join(intent.reasons)

    def test_a_single_item_list_is_not_multi_resource(self) -> None:
        assert classify("k8s.delete", {"names": ["only-one"]}).scope == "single_resource"

    @pytest.mark.parametrize(
        "value", ["*", "%", "prod-*", "buckets/*", "orders_%", "arn:aws:s3:::acme:*"]
    )
    def test_a_wildcard_value_is_multi_resource(self, value: str) -> None:
        assert classify("s3.delete_objects", {"key": value}).scope == "multi_resource"

    def test_select_star_is_not_a_wildcard_target(self) -> None:
        """``SELECT * FROM orders`` is one query against one table.

        Matching ``*`` anywhere in the flattened arguments would escalate the
        scope of the single most common SQL statement there is.
        """
        assert classify("db.query", {"sql": "SELECT * FROM orders"}).scope == "single_resource"

    @pytest.mark.parametrize("key", ["account", "account_id", "organization", "tenant"])
    def test_an_account_level_argument_is_account_scope(self, key: str) -> None:
        assert classify("aws.delete_everything", {key: "123456789012"}).scope == "account"

    def test_scope_never_claims_to_be_global(self) -> None:
        """A proxy cannot know that from one JSON object.

        ``AG-BLR-001`` BLOCKs account-or-global scope in prod at CRITICAL. A
        hint that guessed ``global`` would make every wildcard call a critical
        block on the adapter's say-so.
        """
        for arguments in ({"selector": "*"}, {"account": "*"}, {"all": True}):
            assert classify("aws.nuke", arguments).scope != "global"

    def test_a_falsy_selector_is_not_a_selector(self) -> None:
        """``{"all": false}`` is the caller saying no."""
        assert classify("k8s.delete", {"all": False}).scope == "single_resource"
        assert classify("k8s.delete", {"selector": ""}).scope == "single_resource"
        assert classify("k8s.delete", {"selector": "   "}).scope == "single_resource"


class TestBoundedWork:
    def test_a_huge_argument_does_not_slow_classification(self) -> None:
        """The scan budget is the same as the kernel's, for the same reason."""
        intent = classify("db.query", {"sql": "x" * 200_000 + " DROP TABLE orders"})
        # The destructive verb is past the scan budget, so it is not found. The
        # kernel's blast-radius table has the same limit and the same blind
        # spot; what matters is that classification stays O(budget).
        assert intent.deletes is False

    def test_a_destructive_verb_inside_the_budget_is_found(self) -> None:
        intent = classify("db.query", {"sql": "DROP TABLE orders" + "x" * 200_000})
        assert intent.deletes is True

    def test_deeply_nested_arguments_terminate(self) -> None:
        nested: dict[str, object] = {"a": "DROP TABLE t"}
        for _ in range(50):
            nested = {"a": nested}
        assert classify("api.call", nested).deletes is False, "below the depth limit, not found"

    def test_non_dict_arguments_are_tolerated(self) -> None:
        """MCP says arguments are an object, but a client can send anything."""
        for arguments in (None, [], "DROP TABLE t", 7):
            intent = classify("db.query", arguments)
            assert intent.scope == "single_resource"


def test_classification_is_a_pure_function() -> None:
    arguments = {"sql": "DROP TABLE orders", "table": "orders"}
    first = classify("db.execute_sql", arguments)
    second = classify("db.execute_sql", arguments)
    assert first == second
    assert arguments == {"sql": "DROP TABLE orders", "table": "orders"}, "arguments were mutated"
