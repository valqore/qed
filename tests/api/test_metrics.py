"""``GET /metrics`` and the registry behind it (SPEC §18).

The output is **parsed**, not string-matched. A metrics endpoint that is
nearly-valid is worse than one that is absent: Prometheus drops the whole
scrape on a parse error and reports it in its own logs, not in yours, so a
missing `# TYPE` line shows up as an instance that silently has no metrics.

Two things get as much attention as the format.

**Labels are bounded.** Every label value comes from an enum, a configured id
or a fixed set -- never from a proposal's own strings. A metric labelled with
`action.target` is a cardinality explosion an agent can trigger on purpose,
and the first symptom is the monitoring system falling over.

**Recording cannot fail a request.** A metric is a report. One that raises
turns an observability concern into an outage.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from qed.api.observe import record_decision
from qed.api.routers.metrics import METRICS, WAIT_BUCKETS
from qed.core.policy.engine import PREDICATE_FAILED, SYNTHETIC_RULES
from qed.core.schemas import Decision, RuleHit, Verdict
from qed.infra.metrics import LATENCY_BUCKETS, MetricsRegistry
from qed.runtime import CheckOutcome
from tests.api.conftest import Signer
from tests.conftest import BASE_PROPOSAL, deep_merge, make_proposal

PROD_DROP: dict[str, object] = {
    "action": {
        "name": "postgres.execute_sql",
        "target": "db:prod/orders",
        "params_redacted": {"sql": "DROP TABLE orders_archive;"},
    },
    "context": {
        "environment": "prod",
        "blast_radius_hints": {"writes": True, "deletes": True, "scope": "single_resource"},
    },
}


# --------------------------------------------------------------------------
# The exposition format
# --------------------------------------------------------------------------


def parse(text: str) -> dict[str, dict[str, object]]:
    """A minimal Prometheus text-format parser.

    Deliberately strict about the things a scraper is strict about: a sample
    line before its `# TYPE`, a type that is not a known one, a line that is
    neither a comment nor `name{labels} value`.
    """
    metrics: dict[str, dict[str, object]] = {}
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("# HELP "):
            name, _, help_text = line[len("# HELP ") :].partition(" ")
            metrics.setdefault(name, {})["help"] = help_text
            continue
        if line.startswith("# TYPE "):
            name, _, kind = line[len("# TYPE ") :].partition(" ")
            assert kind in {"counter", "gauge", "histogram", "summary", "untyped"}, kind
            metrics.setdefault(name, {})["type"] = kind
            continue
        assert not line.startswith("#"), f"unexpected comment: {line}"

        series, _, value = line.rpartition(" ")
        assert series, line
        float(value)  # raises if it is not a number
        base = series.split("{", 1)[0]
        family = base
        for suffix in ("_bucket", "_sum", "_count"):
            if base.endswith(suffix):
                family = base[: -len(suffix)]
                break
        declared = family if family in metrics else base
        assert declared in metrics, f"{base} appeared before its # TYPE line"
        metrics[declared].setdefault("samples", []).append(series)  # type: ignore[union-attr]
    return metrics


class TestTheOutputParses:
    def test_it_is_served_as_the_text_format(self, client: TestClient) -> None:
        response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "version=0.0.4" in response.headers["content-type"]

    def test_every_sample_has_a_type_line(self, signed: Signer, client: TestClient) -> None:
        signed.post("/v1/proposals", BASE_PROPOSAL)
        parsed = parse(client.get("/metrics").text)
        for name, entry in parsed.items():
            assert entry.get("type"), f"{name} has samples and no # TYPE"

    def test_the_body_ends_with_a_newline(self, client: TestClient) -> None:
        """Required by the format, and a scraper that is strict about it fails
        with an unhelpful parse error rather than a missing-newline one."""
        assert client.get("/metrics").text.endswith("\n")

    def test_it_answers_before_anything_has_happened(self, client: TestClient) -> None:
        """An instance with no decisions yet still has gauges, and a scrape
        that 500s on a fresh instance is an alert nobody wants at startup."""
        parsed = parse(client.get("/metrics").text)
        assert "qed_records_total" in parsed


class TestItIsOpen:
    def test_no_signature_is_needed(self, client: TestClient) -> None:
        """A scraper is not an adapter and has no signing secret. The
        alternative -- a bearer token in every Prometheus config -- is the
        arrangement that ends with monitoring switched off."""
        assert client.get("/metrics").status_code == 200

    def test_it_exposes_no_principal_target_or_payload(
        self, signed: Signer, client: TestClient
    ) -> None:
        """Counts, latencies and queue depths. The point of a metric is that
        it is safe to ship to a system with different access controls."""
        signed.post("/v1/proposals", deep_merge(BASE_PROPOSAL, PROD_DROP))
        body = client.get("/metrics").text
        assert "db:prod/orders" not in body
        assert "orders_archive" not in body
        assert "postgres.execute_sql" not in body


# --------------------------------------------------------------------------
# What SPEC §18 asks for
# --------------------------------------------------------------------------


class TestTheMetricSet:
    @pytest.mark.parametrize(
        "name",
        [
            "qed_decisions_total",
            "qed_decision_latency_seconds",
            "qed_approvals_total",
            "qed_approval_wait_seconds",
            "qed_budget_exhausted_total",
            "qed_chain_lag_records",
            "qed_chain_last_checkpoint_age_seconds",
            "qed_ungated_windows_total",
            "qed_no_rule_matched_ratio",
        ],
    )
    def test_spec_18_names_it(self, name: str) -> None:
        assert name in METRICS, f"SPEC 18 names {name} and it is not declared"

    def test_every_declared_metric_has_help_text(self) -> None:
        for name, (kind, help_text) in METRICS.items():
            assert kind in {"counter", "gauge", "histogram"}, name
            assert help_text.endswith("."), f"{name}: help text reads as a sentence"

    def test_counters_end_in_total(self) -> None:
        """A convention scrapers and dashboards rely on, so it is part of the
        name rather than something a query has to know."""
        for name, (kind, _) in METRICS.items():
            if kind == "counter":
                assert name.endswith("_total"), name


class TestDecisionsAreCounted:
    def test_a_decision_increments_the_counter(self, signed: Signer, client: TestClient) -> None:
        signed.post("/v1/proposals", BASE_PROPOSAL)
        body = client.get("/metrics").text
        assert "qed_decisions_total{" in body
        assert 'decision="ALLOW"' in body or 'decision="BLOCK"' in body

    def test_the_labels_are_the_four_spec_18_names(
        self, signed: Signer, client: TestClient
    ) -> None:
        signed.post("/v1/proposals", BASE_PROPOSAL)
        line = next(
            line
            for line in client.get("/metrics").text.splitlines()
            if line.startswith("qed_decisions_total{")
        )
        labels = line.split("{", 1)[1].split("}", 1)[0]
        assert set(part.split("=")[0] for part in labels.split(",")) == {
            "adapter_kind",
            "decision",
            "environment",
            "mode",
        }

    def test_the_effective_decision_is_what_is_counted(
        self, signed: Signer, client: TestClient
    ) -> None:
        """In shadow mode a BLOCK becomes an ALLOW, and what a dashboard is
        being asked is what the adapter was told. `mode` is a label so the two
        can still be told apart."""
        signed.post("/v1/proposals", deep_merge(BASE_PROPOSAL, PROD_DROP))
        body = client.get("/metrics").text
        assert 'decision="ALLOW"' in body
        assert 'mode="shadow"' in body

    def test_the_latency_histogram_is_cumulative(self, signed: Signer, client: TestClient) -> None:
        """Prometheus histograms are cumulative: each bucket includes the ones
        below it, and a monotonic failure here makes every quantile wrong."""
        signed.post("/v1/proposals", BASE_PROPOSAL)
        buckets = [
            (line.split('le="')[1].split('"')[0], float(line.rsplit(" ", 1)[1]))
            for line in client.get("/metrics").text.splitlines()
            if line.startswith("qed_decision_latency_seconds_bucket")
        ]
        assert buckets
        counts = [count for _, count in buckets]
        assert counts == sorted(counts), counts
        assert buckets[-1][0] == "+Inf"

    def test_the_buckets_straddle_the_target(self) -> None:
        """SPEC §18 targets p95 < 50 ms, so 0.05 has to be a bucket edge --
        otherwise the number the target is about can only be interpolated."""
        assert 0.05 in LATENCY_BUCKETS
        assert sum(1 for edge in LATENCY_BUCKETS if edge < 0.05) >= 3

    def test_a_skipped_rule_is_counted(self) -> None:
        """`qed_decisions_rule_skipped_total`. A rule whose predicate could not
        be evaluated was skipped (ADR-0016), so this decision was taken with
        less policy than the bundle holds. It is in the evidence either way;
        the counter is what makes it alertable instead of archaeology."""
        assert self._skipped_counter(SYNTHETIC_RULES[PREDICATE_FAILED].hit()) == 1.0

    def test_an_ordinary_decision_does_not_move_that_counter(self) -> None:
        assert self._skipped_counter(SYNTHETIC_RULES["AG-DEF-001"].hit()) == 0.0

    @staticmethod
    def _skipped_counter(*hits: RuleHit) -> float:
        proposal = make_proposal()
        verdict = Verdict(
            proposal_id=proposal.id,
            decision=Decision.ALLOW,
            would_decision=Decision.ALLOW,
            hits=list(hits),
            blast_radius=0,
            policy_hash="0" * 64,
        )
        registry = MetricsRegistry()
        record_decision(
            registry,
            proposal=proposal,
            outcome=CheckOutcome(verdict=verdict, enforced=True, records=[]),
            seconds=0.001,
        )
        return registry.counter("qed_decisions_rule_skipped_total")

    def test_approval_waits_use_their_own_buckets(self) -> None:
        """Minutes to hours, not milliseconds. The latency buckets would put
        almost every approval in `+Inf`."""
        assert min(WAIT_BUCKETS) >= 10.0
        assert max(WAIT_BUCKETS) >= 3600.0

    def test_an_approval_is_counted_when_it_is_requested(
        self, api_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import yaml

        from qed.api.app import create_app
        from tests.api.conftest import ADAPTER_ID, SECRET, SECRET_ENV

        monkeypatch.setenv(SECRET_ENV, SECRET)
        config = tmp_path / "enforce.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "mode": "enforce",
                    "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV}],
                }
            ),
            encoding="utf-8",
        )
        with TestClient(create_app(directory=api_dir, config_path=config)) as client:
            Signer(client).post("/v1/proposals", deep_merge(BASE_PROPOSAL, PROD_DROP))
            body = client.get("/metrics").text
        assert 'qed_approvals_total{decision="requested"}' in body


class TestTheGauges:
    def test_the_record_count_is_read_at_scrape_time(
        self, signed: Signer, client: TestClient
    ) -> None:
        """Not pushed. Queue depth and record count are questions with a
        current answer, and a copy updated on some other schedule is a number
        that is right most of the time."""
        before = _gauge(client.get("/metrics").text, "qed_records_total")
        signed.post("/v1/proposals", BASE_PROPOSAL)
        after = _gauge(client.get("/metrics").text, "qed_records_total")
        assert after > before

    def test_no_checkpoint_is_minus_one_and_not_zero(self, client: TestClient) -> None:
        """A chain with no checkpoint is a different state from one
        checkpointed a moment ago, and an alert on "age > 2h" must not be
        satisfied by the absence of the thing it watches."""
        assert _gauge(client.get("/metrics").text, "qed_chain_last_checkpoint_age_seconds") == -1

    def test_the_lag_is_zero_on_the_direct_path(self, client: TestClient) -> None:
        assert _gauge(client.get("/metrics").text, "qed_chain_lag_records") == 0

    def test_the_no_rule_ratio_is_zero_before_any_decision(self, client: TestClient) -> None:
        """Not 1, which would read as "everything fell through" on an instance
        that has decided nothing."""
        assert _gauge(client.get("/metrics").text, "qed_no_rule_matched_ratio") == 0


def _gauge(body: str, name: str) -> float:
    line = next(line for line in body.splitlines() if line.startswith(name + " "))
    return float(line.rsplit(" ", 1)[1])


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------


class TestTheRegistry:
    def test_a_counter_starts_at_zero(self) -> None:
        assert MetricsRegistry().counter("nothing") == 0.0

    def test_label_order_does_not_make_two_series(self) -> None:
        registry = MetricsRegistry()
        registry.increment("m", labels={"a": "1", "b": "2"})
        registry.increment("m", labels={"b": "2", "a": "1"})
        assert registry.counter("m", {"a": "1", "b": "2"}) == 2.0

    def test_a_label_value_with_a_quote_is_escaped(self) -> None:
        """An adapter id is operator-configured and could contain anything. An
        unescaped quote makes the rest of the scrape unparseable."""
        registry = MetricsRegistry()
        registry.increment("m", labels={"id": 'a"b\\c'})
        body = registry.render(descriptions={"m": ("counter", "x.")})
        assert r'id="a\"b\\c"' in body

    def test_a_newline_in_help_text_is_escaped(self) -> None:
        registry = MetricsRegistry()
        registry.increment("m")
        body = registry.render(descriptions={"m": ("counter", "one\ntwo")})
        assert "one\\ntwo" in body
        assert len([line for line in body.splitlines() if line.startswith("# HELP")]) == 1

    def test_integers_render_without_a_decimal_point(self) -> None:
        registry = MetricsRegistry()
        registry.increment("m", by=3)
        assert "m 3\n" in registry.render(descriptions={"m": ("counter", "x.")})

    def test_a_histogram_sums_and_counts(self) -> None:
        registry = MetricsRegistry()
        for value in (0.001, 0.02, 7.0):
            registry.observe("h", value)
        body = registry.render(descriptions={"h": ("histogram", "x.")})
        assert "h_count 3" in body
        assert "h_sum 7.021" in body

    def test_a_value_past_the_last_bucket_lands_in_inf(self) -> None:
        registry = MetricsRegistry()
        registry.observe("h", 10_000.0)
        body = registry.render(descriptions={"h": ("histogram", "x.")})
        assert 'h_bucket{le="+Inf"} 1' in body
        assert 'h_bucket{le="10"} 0' in body

    def test_an_empty_registry_renders_a_newline(self) -> None:
        """Not an empty body: a zero-length response is ambiguous between "no
        metrics" and "the handler returned nothing"."""
        assert MetricsRegistry().render(descriptions={}) == "\n"

    def test_a_metric_with_no_description_is_untyped_rather_than_absent(self) -> None:
        """A metric somebody forgot to declare should still be visible. Absent
        would hide the omission; `untyped` reports it."""
        registry = MetricsRegistry()
        registry.increment("undeclared")
        body = registry.render(descriptions={})
        assert "# TYPE undeclared untyped" in body

    def test_two_registries_do_not_share_numbers(self) -> None:
        """On the state and not a module global, so a test can make a fresh
        one and two instances in one process stay separate."""
        first, second = MetricsRegistry(), MetricsRegistry()
        first.increment("m")
        assert second.counter("m") == 0.0

    def test_it_is_safe_from_several_threads(self) -> None:
        """The decision path and the scrape are different threads, and a lost
        increment would be a silently wrong number."""
        from concurrent.futures import ThreadPoolExecutor

        registry = MetricsRegistry()
        with ThreadPoolExecutor(max_workers=8) as pool:
            for _ in range(800):
                pool.submit(registry.increment, "m")
        assert registry.counter("m") == 800.0

    def test_the_snapshot_is_json_shaped(self) -> None:
        import json

        registry = MetricsRegistry()
        registry.increment("m", labels={"a": "1"})
        registry.observe("h", 0.01)
        registry.set_gauge("g", 2)
        json.dumps(registry.snapshot())
