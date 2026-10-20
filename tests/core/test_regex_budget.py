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


class TestOnePoolPerDecision:
    """`under_budget` bounds one call; the pool bounds a loop of them.

    Without it a bundle of N unevaluable patterns costs N * ATTEMPTS * BUDGET,
    because each rule starts a fresh allowance. The engine's loop is the one
    that matters -- it sits in the request path.
    """

    def test_a_loop_of_timeouts_is_bounded_however_long_the_loop_is(self) -> None:
        """The bound holds at 4 iterations and at 400, which is the whole point."""
        from qed.core.regex_budget import POOL, PoolSpent, pooled

        def spend_and_fail(remaining: object) -> None:
            assert callable(remaining)
            time.sleep(POOL / 10)
            raise TimeoutError("slow pattern")

        attempted = 0
        started = time.monotonic()
        with pooled(total=POOL / 5):
            for _ in range(400):
                try:
                    attempted += 1
                    under_budget(spend_and_fail)
                except PoolSpent:
                    break
                except TimeoutError:
                    continue
        elapsed = time.monotonic() - started

        assert attempted < 400, (
            "400 iterations each got their own allowance, so the cost of a loop is the "
            "loop length times the per-call worst case -- which for a policy bundle is "
            "every rule paying for the first bad pattern all over again"
        )
        assert elapsed < POOL, (
            f"the pool was meant to cap this well under {POOL}s, took {elapsed:.1f}s"
        )

    def test_an_exhausted_pool_is_a_distinct_failure_from_a_bad_pattern(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`PoolSpent`, not a bare timeout.

        The two are different operator problems: this pattern spending its
        budget is a fault in this rule, while an empty pool means an earlier
        call spent it and this one never ran. A report that calls them the same
        thing blames every innocent rule behind the bad one.

        Shrinks `BUDGET` rather than the pool, because a pool below one budget
        funds no attempts at all and every call would be a refusal -- correct
        behaviour, and not what is being tested here.
        """
        import qed.core.regex_budget as rb

        monkeypatch.setattr(rb, "BUDGET", 0.05)

        def spends_its_budget(remaining: object) -> None:
            assert callable(remaining)
            time.sleep(rb.BUDGET * 1.2)
            raise TimeoutError("slow pattern")

        with rb.pooled(total=rb.BUDGET * ATTEMPTS):
            with pytest.raises(TimeoutError) as first:
                under_budget(spends_its_budget)
            assert not isinstance(first.value, rb.PoolSpent), (
                "the first call was refused by the pool rather than spending its own "
                "attempts, so the two causes cannot be told apart in a verdict"
            )
            with pytest.raises(rb.PoolSpent):
                under_budget(spends_its_budget)

        assert issubclass(rb.PoolSpent, TimeoutError), (
            "every existing caller catches TimeoutError; a pool refusal that is not one "
            "would escape the engine as a 500 instead of skipping a rule"
        )

    def test_an_attempt_is_funded_whole_or_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No slivers. Every attempt that runs gets a full budget.

        A pool handing out its last fraction of a second funds an attempt that
        cannot succeed, and the caller is then blamed for a pattern that was
        never fairly tried -- which also made the attribution depend on where
        the arithmetic landed, so the same bundle could report different rules
        on two machines.
        """
        import qed.core.regex_budget as rb

        monkeypatch.setattr(rb, "BUDGET", 0.05)
        handed: list[float] = []

        def record(remaining: object) -> None:
            assert callable(remaining)
            handed.append(remaining())
            time.sleep(rb.BUDGET * 1.2)
            raise TimeoutError

        with rb.pooled(total=rb.BUDGET * 1.5):
            with pytest.raises(TimeoutError):
                under_budget(record)
            with pytest.raises(rb.PoolSpent):
                under_budget(record)

        assert len(handed) == 1, f"expected one funded attempt from a 1.5x pool, got {len(handed)}"
        assert handed[0] > rb.BUDGET * 0.9, (
            f"an attempt was funded with {handed[0]:.4f}s of a {rb.BUDGET}s budget -- a "
            "sliver is not a test of anything and times out instantly"
        )

    def test_no_pool_means_no_bound_which_is_the_default(self) -> None:
        """Outside a `pooled` block nothing changes.

        `evaluate_predicate` is called by the linter and by tests with no
        evaluation around it, and the redactor deliberately never pools.
        """
        from qed.core.regex_budget import POOL

        calls = 0

        def always_stalls(remaining: object) -> None:
            nonlocal calls
            calls += 1
            raise TimeoutError

        with pytest.raises(TimeoutError):
            under_budget(always_stalls)
        assert calls == ATTEMPTS
        assert POOL >= ATTEMPTS * BUDGET, (
            f"a pool of {POOL}s cannot give one pattern its {ATTEMPTS} full attempts of "
            f"{BUDGET}s, so the bound would quietly undo the retry it sits on top of"
        )

    def test_concurrent_decisions_do_not_spend_each_other_s_pool(self) -> None:
        """One pool per decision, not one per process."""
        import threading

        from qed.core.regex_budget import PoolSpent, pooled

        refused: list[bool] = []

        def decide() -> None:
            def slow(remaining: object) -> None:
                assert callable(remaining)
                time.sleep(0.01)
                raise TimeoutError

            with pooled(total=BUDGET * ATTEMPTS):
                try:
                    under_budget(slow)
                    refused.append(False)
                except PoolSpent:
                    refused.append(True)
                except TimeoutError:
                    refused.append(False)

        threads = [threading.Thread(target=decide) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert refused == [False] * 4, (
            "a decision was refused by a pool it did not open -- the allowance is shared "
            "across threads, so one slow decision starves every concurrent one"
        )
