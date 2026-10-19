"""Tests for `windowed.py`, the thing that decides whether a timing gate goes red.

**Not marked `perf`.** There is no timing in this file: the "measurements" are
a list of numbers written down from the 2026-10-18 incident. That is the point
-- the logic that decides whether a build fails should be checked on every
matrix cell, not only in the one CI job that has a database attached.

The load-bearing test is `test_the_old_single_window_gate_would_have_failed`.
Without it every other test here would pass equally well against the code this
replaced, and a guard that holds on both sides of a change proves nothing about
the change. That trap has caught this project repeatedly, so it gets an
explicit test rather than a comment.
"""

from __future__ import annotations

from collections.abc import Callable

from tests.perf.windowed import WINDOWS, until_one_meets

#: p95 in milliseconds, from the three CI runs of commit b3c4294 against a
#: 50 ms gate. Real numbers, so this file fails if the helper stops handling
#: the case it was written for.
STALLED = 62.24
GREEN = 3.77
ALSO_GREEN = 8.71

BUDGET = 50.0


def sequence(*values: float) -> Callable[[], float]:
    """A fake measurement that returns the given numbers in order."""
    remaining = list(values)
    return lambda: remaining.pop(0)


def under_budget(value: float) -> bool:
    return value < BUDGET


class TestOneStallDoesNotFailTheBuild:
    def test_a_stalled_first_window_is_retried(self) -> None:
        attempt = until_one_meets(sequence(STALLED, GREEN), under_budget)
        assert attempt.ok
        assert attempt.windows == [STALLED, GREEN]

    def test_the_old_single_window_gate_would_have_failed(self) -> None:
        """The same sequence, measured the way it was measured before this
        change. It fails -- which is what makes the test above a statement
        about the fix rather than about arithmetic."""
        attempt = until_one_meets(sequence(STALLED, GREEN), under_budget, windows=1)
        assert not attempt.ok
        assert attempt.windows == [STALLED]

    def test_two_stalls_in_a_row_still_pass_on_the_third(self) -> None:
        attempt = until_one_meets(sequence(STALLED, STALLED, GREEN), under_budget)
        assert attempt.ok
        assert len(attempt.windows) == WINDOWS


class TestARealRegressionStillFails:
    def test_every_window_slow_fails(self) -> None:
        """The whole value of the gate. If this ever passes, the gate has
        stopped being a gate and the three windows are just three ways of
        not failing."""
        attempt = until_one_meets(sequence(STALLED, 70.1, 65.0), under_budget)
        assert not attempt.ok
        assert len(attempt.windows) == WINDOWS

    def test_it_gives_up_rather_than_measuring_forever(self) -> None:
        """A fourth window would have been green. It is never measured: a gate
        that keeps going until it gets the answer it wants is not a gate, and
        on metered CI minutes it is also a bill."""
        attempt = until_one_meets(sequence(STALLED, 70.1, 65.0, GREEN), under_budget)
        assert not attempt.ok
        assert len(attempt.windows) == WINDOWS


class TestTheGreenPathCostsNothingExtra:
    def test_a_passing_run_measures_once(self) -> None:
        """Three windows would have tripled the time of a perf suite that
        already dominates the `postgres` job. It does not, because the second
        window is only measured after the first has missed."""
        calls = 0

        def measure_once() -> float:
            nonlocal calls
            calls += 1
            return GREEN

        attempt = until_one_meets(measure_once, under_budget)
        assert attempt.ok
        assert calls == 1, "a green run paid for windows it did not need"


class TestTheReport:
    def test_a_single_window_reads_as_it_always_did(self) -> None:
        attempt = until_one_meets(sequence(GREEN), under_budget)
        assert attempt.report(lambda value: f"p95={value:.2f}ms") == "p95=3.77ms"

    def test_every_window_is_named_when_there_were_several(self) -> None:
        """So the spread is in the log even on a pass. A gate that hides the
        stall it tolerated would turn a host problem into an invisible one,
        and the host problem is worth knowing about."""
        attempt = until_one_meets(sequence(STALLED, ALSO_GREEN), under_budget)
        report = attempt.report(lambda value: f"p95={value:.2f}ms")
        assert "window 1: p95=62.24ms" in report
        assert "window 2: p95=8.71ms" in report
        assert "the host stalled" in report

    def test_a_failure_says_that_every_window_missed(self) -> None:
        attempt = until_one_meets(sequence(STALLED, 70.1, 65.0), under_budget)
        assert "all 3 windows missed the budget" in attempt.report(lambda v: f"{v}ms")
