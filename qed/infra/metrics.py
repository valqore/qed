"""Prometheus metrics (SPEC §18).

Hand-rolled, and the reason is worth stating because reaching for
`prometheus_client` would be the obvious call. Three things decided against it:
the metric set is fixed by SPEC §18 and small, so there is no API to grow into;
a client library registers process and GC collectors in a global default
registry at import time, which means `/metrics` on a policy kernel starts
reporting the interpreter's internals unless somebody remembers to stop it; and
every dependency in this repo is a line in a trust argument.

What that trades away is a library's correctness about the text format, so the
format is the part this module is careful about. `tests/api/test_metrics.py`
parses what comes out rather than string-matching it.

**Nothing here can fail a request.** A counter that raised would turn an
observability concern into an outage, so every path is a dict update under a
lock with no allocation that can fail meaningfully. Unknown label values are
accepted rather than validated: a metric is a report, and a report that refuses
unfamiliar input reports nothing.

**Labels are bounded by construction.** Every label this module records comes
from an enum, a configured adapter id, or a fixed set -- never from a proposal's
own strings. A metric labelled with agent-supplied text is a cardinality
explosion an attacker can trigger on purpose.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

__all__ = [
    "LATENCY_BUCKETS",
    "MetricsRegistry",
    "render",
]

#: Seconds. Chosen around SPEC §18's p95 < 50 ms target, so the bucket
#: boundaries sit either side of the number that matters: 0.05 is a bucket
#: edge, and there are three below it to tell 5 ms from 25 ms. The long tail
#: goes to 10 s because a decision that slow is a timeout somewhere and it
#: should still land in a bucket rather than only in `+Inf`.
LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.001,
    0.005,
    0.010,
    0.025,
    0.050,
    0.100,
    0.250,
    0.500,
    1.0,
    2.5,
    5.0,
    10.0,
)

Labels = tuple[tuple[str, str], ...]


def _key(labels: Mapping[str, str] | None) -> Labels:
    """Labels as a stable, hashable key. Sorted, so two orders are one series."""
    if not labels:
        return ()
    return tuple(sorted((str(name), str(value)) for name, value in labels.items()))


@dataclass
class _Histogram:
    buckets: tuple[float, ...]
    counts: list[int] = field(default_factory=list)
    total: float = 0.0
    observations: int = 0

    def __post_init__(self) -> None:
        if not self.counts:
            self.counts = [0] * (len(self.buckets) + 1)

    def observe(self, value: float) -> None:
        self.total += value
        self.observations += 1
        for index, edge in enumerate(self.buckets):
            if value <= edge:
                self.counts[index] += 1
                return
        self.counts[-1] += 1

    def cumulative(self) -> list[int]:
        """Prometheus histograms are cumulative: each bucket includes the ones
        below it. Stored as disjoint counts and summed on render, because the
        disjoint form is what makes `observe` one increment."""
        running = 0
        out = []
        for count in self.counts:
            running += count
            out.append(running)
        return out


class MetricsRegistry:
    """Every metric this instance reports. One per process.

    Deliberately not a module-level singleton: the API owns one on its state,
    which means a test can make a fresh one and two instances in one process do
    not share numbers.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, Labels], float] = {}
        self._histograms: dict[tuple[str, Labels], _Histogram] = {}
        #: Gauges are read at scrape time from whoever knows the answer rather
        #: than pushed, because every one of them -- queue depth, checkpoint
        #: age -- is a question with a current answer and no history worth
        #: keeping in here.
        self._gauges: dict[str, float] = {}

    # ------------------------------------------------------------- recording

    def increment(
        self, name: str, *, labels: Mapping[str, str] | None = None, by: float = 1.0
    ) -> None:
        with self._lock:
            key = (name, _key(labels))
            self._counters[key] = self._counters.get(key, 0.0) + by

    def observe(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, str] | None = None,
        buckets: tuple[float, ...] = LATENCY_BUCKETS,
    ) -> None:
        with self._lock:
            key = (name, _key(labels))
            histogram = self._histograms.get(key)
            if histogram is None:
                histogram = _Histogram(buckets=buckets)
                self._histograms[key] = histogram
            histogram.observe(value)

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    # --------------------------------------------------------------- reading

    def counter(self, name: str, labels: Mapping[str, str] | None = None) -> float:
        """For tests and for `/v1/status`. Zero for a series never touched."""
        with self._lock:
            return self._counters.get((name, _key(labels)), 0.0)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "counters": {
                    f"{name}{_label_text(labels)}": value
                    for (name, labels), value in sorted(self._counters.items())
                },
                "gauges": dict(sorted(self._gauges.items())),
                "histograms": {
                    f"{name}{_label_text(labels)}": {
                        "count": histogram.observations,
                        "sum": round(histogram.total, 6),
                    }
                    for (name, labels), histogram in sorted(self._histograms.items())
                },
            }

    def render(self, *, descriptions: Mapping[str, tuple[str, str]]) -> str:
        """The Prometheus text exposition format.

        `descriptions` maps a metric name to `(type, help)`. Passed in rather
        than registered up front so that a metric is declared in one place --
        `qed/api/routers/metrics.py` -- next to what reads it.
        """
        with self._lock:
            counters = dict(self._counters)
            histograms = {
                key: (h.cumulative(), h.total, h.observations)
                for key, h in self._histograms.items()
            }
            gauges = dict(self._gauges)
            bucket_edges = {key: h.buckets for key, h in self._histograms.items()}

        lines: list[str] = []
        emitted: set[str] = set()

        def header(name: str) -> None:
            if name in emitted:
                return
            emitted.add(name)
            kind, help_text = descriptions.get(name, ("untyped", ""))
            if help_text:
                lines.append(f"# HELP {name} {_escape_help(help_text)}")
            lines.append(f"# TYPE {name} {kind}")

        for (name, labels), value in sorted(counters.items()):
            header(name)
            lines.append(f"{name}{_label_text(labels)} {_number(value)}")

        for name, value in sorted(gauges.items()):
            header(name)
            lines.append(f"{name} {_number(value)}")

        for (name, labels), (cumulative, total, count) in sorted(histograms.items()):
            header(name)
            edges = bucket_edges[(name, labels)]
            for edge, running in zip(edges, cumulative, strict=False):
                lines.append(f"{name}_bucket{_label_text(labels, le=_number(edge))} {running}")
            lines.append(f"{name}_bucket{_label_text(labels, le='+Inf')} {cumulative[-1]}")
            lines.append(f"{name}_sum{_label_text(labels)} {_number(total)}")
            lines.append(f"{name}_count{_label_text(labels)} {count}")

        # A trailing newline is required by the format, and a scraper that is
        # strict about it fails with an unhelpful parse error rather than a
        # missing-newline one.
        return "\n".join(lines) + "\n" if lines else "\n"


def render(registry: MetricsRegistry, *, descriptions: Mapping[str, tuple[str, str]]) -> str:
    return registry.render(descriptions=descriptions)


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------


def _label_text(labels: Labels, **extra: str) -> str:
    pairs: list[str] = [f'{name}="{_escape_label(value)}"' for name, value in labels]
    pairs.extend(f'{name}="{_escape_label(value)}"' for name, value in extra.items())
    return "{" + ",".join(pairs) + "}" if pairs else ""


def _escape_label(value: str) -> str:
    """Backslash, double quote and newline, per the exposition format.

    In that order: escaping the backslash second would escape the backslashes
    the other two replacements just introduced.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _number(value: float) -> str:
    """A number Prometheus will parse.

    Integers without a decimal point, because `qed_decisions_total 3` reads
    better than `3.0` and both are valid; everything else with enough
    precision to be useful and not so much that a float's binary expansion
    shows through.
    """
    if value == int(value) and abs(value) < 2**53:
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")
