"""Token buckets (SPEC §13). Pure, so the boundaries need no sleeping.

The API side is in `tests/api/test_rate_limit.py`. What this file pins down is
the arithmetic and the decisions around it -- including the ones that are about
*not* being clever:

* a refusal from the adapter bucket must not also spend a principal's token;
* a clock that went backwards must not remove tokens;
* `Retry-After` must never be zero when the bucket is empty;
* a config reload must not reset somebody's allowance;
* `0` means off, not "refuse everything".
"""

from __future__ import annotations

from qed.core.ratelimit import (
    BURST_SECONDS,
    DEFAULT_PER_ADAPTER_RPS,
    DEFAULT_PER_PRINCIPAL_RPS,
    IDLE_EVICT_SECONDS,
    Bucket,
    Limiter,
)


#: Written as `rps * BURST_SECONDS` throughout rather than as a number, so
#: these tests say *the relationship* they depend on. An earlier version
#: hard-coded capacity == rps, and every one of them broke the day the burst
#: factor arrived -- which was the right failure, and a slow way to learn it.
def capacity(rps: float) -> float:
    return rps * BURST_SECONDS


class TestTheDefaults:
    def test_they_are_the_numbers_the_spec_names(self) -> None:
        assert DEFAULT_PER_ADAPTER_RPS == 100.0
        assert DEFAULT_PER_PRINCIPAL_RPS == 20.0


class TestOneBucket:
    def test_a_full_bucket_spends_its_burst(self) -> None:
        bucket = Bucket.full(10.0, now=0.0)
        spent = sum(1 for _ in range(int(capacity(10.0))) if bucket.take(0.0))
        assert spent == capacity(10.0)
        assert not bucket.take(0.0)

    def test_the_burst_is_more_than_one_second(self) -> None:
        """SPEC §13's per-principal limit is 20/s, and an agent that makes
        thirty tool calls while deciding what to do next is an ordinary agent.
        A one-second bucket would refuse it, and on `fail: closed` a refusal is
        a blocked action -- the limiter stopping the work it protects."""
        assert BURST_SECONDS > 1
        bucket = Bucket.full(20.0, now=0.0)
        assert sum(1 for _ in range(30) if bucket.take(0.0)) == 30

    def test_it_refills_continuously(self) -> None:
        """A float, not an int. At 100/s a request 3 ms after the last is owed
        0.3 of a token, and rounding that to zero would make the limit 1/s for
        a fast caller."""
        bucket = Bucket(rps=100.0, tokens=0.0, last_seen=0.0)
        assert not bucket.take(0.003)
        assert bucket.tokens == 0.3
        assert bucket.take(0.02)

    def test_it_never_exceeds_its_capacity(self) -> None:
        """An idle hour does not buy an hour's worth of burst."""
        bucket = Bucket(rps=10.0, tokens=0.0, last_seen=0.0)
        bucket.take(3600.0)
        assert bucket.tokens == capacity(10.0) - 1

    def test_a_backwards_clock_does_not_remove_tokens(self) -> None:
        """SPEC §17 already says the clock may be wrong. A limiter that
        punished a caller for it would turn a clock problem into an outage."""
        bucket = Bucket.full(10.0, now=100.0)
        assert bucket.take(50.0)
        assert bucket.tokens == capacity(10.0) - 1

    def test_retry_after_is_never_zero_when_empty(self) -> None:
        """A `Retry-After: 0` is an invitation to retry immediately, which is
        the thundering herd this is meant to prevent."""
        bucket = Bucket(rps=1.0, tokens=0.0, last_seen=0.0)
        assert bucket.retry_after(0.0) >= 0.1

    def test_retry_after_is_the_time_until_one_token(self) -> None:
        """Computed, not guessed. A caller told to wait one second when the
        bucket needs three is a caller who will be refused again."""
        bucket = Bucket(rps=0.5, tokens=0.0, last_seen=0.0)
        assert bucket.retry_after(0.0) == 2.0

    def test_retry_after_is_zero_when_there_is_a_token(self) -> None:
        assert Bucket.full(5.0, now=0.0).retry_after(0.0) == 0.0


class TestTheLimiter:
    def test_it_allows_within_the_limit(self) -> None:
        limiter = Limiter(per_adapter_rps=5.0, per_principal_rps=5.0)
        for _ in range(int(capacity(5.0))):
            assert limiter.check(adapter="a", principal="p", now=0.0).allowed

    def test_the_adapter_limit_names_itself(self) -> None:
        """An operator raising the wrong limit is a specific, common waste of
        an afternoon."""
        limiter = Limiter(per_adapter_rps=1.0, per_principal_rps=100.0)
        for _ in range(int(capacity(1.0))):
            assert limiter.check(adapter="a", principal="p", now=0.0).allowed
        verdict = limiter.check(adapter="a", principal="p", now=0.0)
        assert not verdict.allowed
        assert verdict.scope == "adapter"
        assert verdict.key == "a"
        assert verdict.limit_rps == 1.0

    def test_the_principal_limit_names_itself(self) -> None:
        limiter = Limiter(per_adapter_rps=100.0, per_principal_rps=1.0)
        for _ in range(int(capacity(1.0))):
            assert limiter.check(adapter="a", principal="p", now=0.0).allowed
        verdict = limiter.check(adapter="a", principal="p", now=0.0)
        assert not verdict.allowed
        assert verdict.scope == "principal"
        assert verdict.key == "p"

    def test_a_refused_adapter_does_not_drain_its_principals(self) -> None:
        """Otherwise fixing the adapter limit would leave the principal limit
        refusing you for reasons that no longer exist."""
        limiter = Limiter(per_adapter_rps=1.0, per_principal_rps=10.0)
        for _ in range(int(capacity(1.0))):
            limiter.check(adapter="a", principal="p", now=0.0)
        spent_by_the_adapter_bucket = capacity(10.0) - limiter.principals["p"].tokens
        for _ in range(5):
            assert not limiter.check(adapter="a", principal="p", now=0.0).allowed
        assert capacity(10.0) - limiter.principals["p"].tokens == spent_by_the_adapter_bucket

    def test_two_adapters_have_separate_allowances(self) -> None:
        limiter = Limiter(per_adapter_rps=1.0, per_principal_rps=0.0)
        for _ in range(int(capacity(1.0))):
            assert limiter.check(adapter="a", principal=None, now=0.0).allowed
        assert not limiter.check(adapter="a", principal=None, now=0.0).allowed
        assert limiter.check(adapter="b", principal=None, now=0.0).allowed

    def test_a_missing_key_is_not_limited(self) -> None:
        """A proposal with no human principal still has an adapter, and vice
        versa on the paths where only one is known."""
        limiter = Limiter(per_adapter_rps=1.0, per_principal_rps=1.0)
        for _ in range(50):
            assert limiter.check(adapter=None, principal=None, now=0.0).allowed

    def test_zero_means_off(self) -> None:
        """Zero reads as "no limit" to everyone who has ever written a config
        file. A kernel that refused every proposal because somebody typed 0
        would be an outage with a plausible cause."""
        limiter = Limiter(per_adapter_rps=0.0, per_principal_rps=0.0)
        assert not limiter.enabled
        for _ in range(100):
            assert limiter.check(adapter="a", principal="p", now=0.0).allowed

    def test_one_limit_set_is_still_enabled(self) -> None:
        assert Limiter(per_adapter_rps=0.0, per_principal_rps=5.0).enabled

    def test_refusals_are_counted_by_scope(self) -> None:
        """For `/metrics`. The chain deliberately gets none of this: recording
        every refusal would let a flood fill the evidence instead of the
        queue."""
        limiter = Limiter(per_adapter_rps=1.0, per_principal_rps=100.0)
        for _ in range(int(capacity(1.0)) + 2):
            limiter.check(adapter="a", principal="p", now=0.0)
        assert limiter.refused == {"adapter": 2}

    def test_a_reload_with_a_new_limit_does_not_reset_the_allowance(self) -> None:
        """Otherwise reloading the config is a way to buy a fresh burst."""
        limiter = Limiter(per_adapter_rps=5.0, per_principal_rps=0.0)
        for _ in range(int(capacity(5.0))):
            limiter.check(adapter="a", principal=None, now=0.0)
        assert not limiter.check(adapter="a", principal=None, now=0.0).allowed

        limiter.per_adapter_rps = 50.0
        assert not limiter.check(adapter="a", principal=None, now=0.0).allowed

    def test_lowering_a_limit_clamps_a_held_allowance(self) -> None:
        limiter = Limiter(per_adapter_rps=50.0, per_principal_rps=0.0)
        limiter.check(adapter="a", principal=None, now=0.0)
        limiter.per_adapter_rps = 2.0
        limiter.check(adapter="a", principal=None, now=0.0)
        assert limiter.adapters["a"].tokens <= capacity(2.0)


class TestEviction:
    def test_an_idle_bucket_is_forgotten(self) -> None:
        """Keyed by principal, the key space is "everyone who ever called", so
        something has to drop them."""
        limiter = Limiter(per_adapter_rps=0.0, per_principal_rps=5.0)
        limiter.check(adapter=None, principal="p", now=0.0)
        assert "p" in limiter.principals
        limiter.check(adapter=None, principal="q", now=IDLE_EVICT_SECONDS + 1)
        assert "p" not in limiter.principals

    def test_eviction_cannot_grant_extra_capacity(self) -> None:
        """A bucket idle for longer than it takes to refill is already full, so
        dropping it and recreating it full are the same thing."""
        limiter = Limiter(per_adapter_rps=0.0, per_principal_rps=5.0)
        for _ in range(int(capacity(5.0))):
            limiter.check(adapter=None, principal="p", now=0.0)
        assert not limiter.check(adapter=None, principal="p", now=0.0).allowed
        # Long enough to refill many times over, so being forgotten changes
        # nothing an operator could exploit.
        assert limiter.check(adapter=None, principal="p", now=IDLE_EVICT_SECONDS + 1).allowed

    def test_a_busy_bucket_is_kept(self) -> None:
        limiter = Limiter(per_adapter_rps=0.0, per_principal_rps=5.0)
        for tick in range(10):
            limiter.check(adapter=None, principal="p", now=float(tick))
        assert "p" in limiter.principals


class TestWhatItReports:
    def test_describe_says_the_scope_is_one_process(self) -> None:
        """Four replicas with `per_adapter_rps: 100` admit 400/s between them,
        and an operator sizing a limit has to know that. A shared limiter would
        need Redis, or the database on every request -- which costs more than
        the work it protects."""
        described = Limiter().describe()
        assert described["scope"] == "this process only; multiply by your replica count"

    def test_describe_carries_the_counts(self) -> None:
        limiter = Limiter(per_adapter_rps=1.0, per_principal_rps=0.0)
        for _ in range(int(capacity(1.0)) + 1):
            limiter.check(adapter="a", principal=None, now=0.0)
        described = limiter.describe()
        assert described["refused"] == {"adapter": 1}
        assert described["tracked"] == {"adapters": 1, "principals": 0}
