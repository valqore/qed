"""The shared regex budget: one number, one retry, two callers.

The retry is the only mechanism that can answer the question a wall-clock
budget cannot -- was it this input, or was it this machine? These tests assert
that it asks, that it gives up, and that both callers ask the same way. They
are built from a fake unit of work rather than from real patterns, because a
test that needs a catastrophic pattern to fail is a test that spends a second
of CI proving a library works.
"""

from __future__ import annotations

import time

import pytest

from qed.core.regex_budget import ATTEMPTS, BUDGET, under_budget


def test_a_stall_that_does_not_recur_is_not_a_failure() -> None:
    """The whole point. One timeout is a question, not an answer."""
    calls = 0

    def work(remaining: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("descheduled")
        return "finished"

    assert under_budget(work) == "finished"
    assert calls == 2, "the first timeout should have been retried, not reported"


def test_a_pattern_that_always_times_out_is_still_reported() -> None:
    """Failing closed is kept. The retry delays the verdict, it does not remove it."""
    calls = 0

    def work(remaining: object) -> str:
        nonlocal calls
        calls += 1
        raise TimeoutError("catastrophic")

    with pytest.raises(TimeoutError):
        under_budget(work)
    assert calls == ATTEMPTS, f"expected {ATTEMPTS} attempts before giving up, got {calls}"


def test_each_attempt_starts_a_whole_fresh_budget() -> None:
    """A retry given the leftovers of the attempt that stalled would be no retry."""
    seen: list[float] = []

    def work(remaining: object) -> str:
        assert callable(remaining)
        seen.append(remaining())
        raise TimeoutError

    with pytest.raises(TimeoutError):
        under_budget(work)
    assert len(seen) == ATTEMPTS
    for budget in seen:
        assert budget > BUDGET * 0.9, (
            f"an attempt opened with {budget:.3f}s of a {BUDGET}s budget -- the attempts "
            "are sharing one deadline, so a stall in the first one spends the retry that "
            "exists to tell a stall from a pattern"
        )


def test_the_budget_bounds_the_attempt_and_not_each_regex_inside_it() -> None:
    """A budget spent inside a loop is a budget per iteration.

    The constant then names something no caller experiences: the redactor
    granted it per pattern, so sixteen patterns at 100 ms was a 1.6 s worst
    case for one string -- and widening the number multiplied it.

    Uses the clock in the safe direction only. The slices are tenths of a
    second against scheduling noise measured in microseconds, and a slower
    host makes the deadline bind sooner, so load can only strengthen this.
    """
    slices: list[int] = []

    def work(remaining: object) -> str:
        assert callable(remaining)
        count = 0
        while True:
            remaining()
            count += 1
            if count > 50:  # a pattern set this size would be its own problem
                slices.append(count)
                return "never bound"
            time.sleep(BUDGET / 5)

    with pytest.raises(TimeoutError):
        under_budget(work)
    assert not slices, (
        "the deadline never bound: each call drew a new clock rather than drawing down "
        "one, so the budget is per regex and scales with the pattern count"
    )


def test_a_spent_budget_raises_rather_than_reading_as_unbounded() -> None:
    """``regex`` treats a non-positive timeout as *no* timeout.

    Returning the exhausted budget would drop the guard at the one moment it
    is working, and the failure would be a hang instead of a refusal.
    """
    captured: list[object] = []

    def work(remaining: object) -> str:
        assert callable(remaining)
        captured.append(remaining)
        time.sleep(BUDGET * 1.1)
        remaining()  # must raise, not return <= 0
        return "unbounded"

    with pytest.raises(TimeoutError):
        under_budget(work)


def test_both_regex_callers_draw_on_this_one_budget() -> None:
    """The bug this module exists to prevent, asserted as an import.

    ADR-0016's reasoning was about the library's clock, so it governed every
    caller of it; it was applied to the policy engine and not to the redactor,
    which kept the 100 ms the ADR had already found too narrow. Two numbers
    meant to be one will drift, so there is now one number and this test fails
    if either caller grows its own again.
    """
    from qed.core.evidence.masking import _TIMEOUT
    from qed.core.policy.predicates import REGEX_TIMEOUT

    assert REGEX_TIMEOUT == BUDGET
    assert _TIMEOUT == BUDGET


class TestTheCallersActuallyRetry:
    """Both callers, exercised through their own public surface.

    The tests above prove `under_budget` retries. These prove the callers use
    it -- which is the half that was wrong before, when the mechanism existed
    on one side and the other kept its own copy of the number.
    """

    def test_masking_survives_one_stall_instead_of_eating_the_payload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A single stall must not reach the chain as `[masked:timeout]`.

        That substitution happens before `payload_hash`, so the record
        verifies against its own hash and the content is gone with nothing
        reporting it.

        Stands a fake rule in for the pattern set rather than monkeypatching a
        compiled pattern, whose `sub` is read-only.
        """
        import qed.core.evidence.masking as m

        stalls = {"left": 1}

        class StallsOnce:
            def sub(self, repl: object, text: str, timeout: float | None = None) -> str:
                assert timeout is not None and timeout > 0
                if stalls["left"]:
                    stalls["left"] -= 1
                    raise TimeoutError("descheduled")
                return text

        monkeypatch.setattr(m, "_RULES", [(StallsOnce(), "[masked:x]")])
        assert m.mask_text("mcp-proxy/0.1.0") == "mcp-proxy/0.1.0", (
            "one stall in one pattern replaced the whole string -- the redactor is not "
            "retrying, so host load still corrupts evidence permanently"
        )
        assert stalls["left"] == 0, "the stall was never triggered; the test proves nothing"

    def test_a_predicate_survives_one_stall_instead_of_skipping_its_rule(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A single stall must not cost a rule its coverage.

        ADR-0016 makes an unevaluable `when` skip its rule and record
        `AG-PRD-001`. That is the right handling for a pattern that cannot be
        evaluated and the wrong outcome for a busy machine.
        """
        import qed.core.policy.predicates as p

        stalls = {"left": 1}
        real_search = p.regex.search

        def flaky(pattern: str, text: str, timeout: float | None = None) -> object:
            if stalls["left"]:
                stalls["left"] -= 1
                raise TimeoutError("descheduled")
            return real_search(pattern, text, timeout=timeout)

        monkeypatch.setattr(p.regex, "search", flaky)
        assert p._regex("prod-delete", "^prod-") is True, (
            "one stall made a predicate unevaluable, so the engine skipped a rule and "
            "recorded AG-PRD-001 because the machine was busy, not because the pattern was"
        )
        assert stalls["left"] == 0, "the stall was never triggered; the test proves nothing"
