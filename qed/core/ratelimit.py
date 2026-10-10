"""Token buckets for the API's rate limits (SPEC §13). Pure.

SPEC §13: *"Rate limits: per adapter 100 proposals/s default; per principal
20/s. 429 with `Retry-After`."*

**A rate limit on a gate is a kill switch under load, and that is the whole
reason this file is careful.** Every other service answers a 429 by making
somebody wait. Here, an adapter in `fail: closed` that cannot reach a decision
treats it as a refusal, so throttling the kernel stops the agent's work. The
defaults are therefore high enough that nothing legitimate reaches them, and
the limit exists for the case it is actually for: one misbehaving adapter, or
one principal in a loop, consuming the capacity every other adapter needs.

Three decisions.

**Token bucket, not a fixed window.** A fixed window lets a caller spend its
whole allowance in the last millisecond of one window and again in the first of
the next, so a "100/s" limit passes 200 requests in two milliseconds.

The capacity is **three** seconds' worth rather than one (:data:`BURST_SECONDS`).
An agent that makes thirty tool calls while working out what to do next is an
ordinary agent, and SPEC §13's per-principal limit is 20/s -- so a one-second
bucket would refuse it, and on `fail: closed` a refusal is a blocked action.
The sustained rate stays exactly what the spec says; only the first burst is
free.

**A refusal costs nothing but a counter.** A throttled proposal never became a
decision, so nothing goes in the chain. Recording every refusal would let the
attack this exists to stop -- a caller flooding the API -- fill the evidence
chain instead of the request queue, which is strictly worse: the chain is the
thing that must stay readable, and `admin_action` aside, it is the expensive
place to write. The refusals are counted for `/metrics` and reported by
`qed status`.

**`Retry-After` is computed, not guessed.** A caller told to retry after one
second when the bucket needs three is a caller who will be refused again, and
three clients doing that in lockstep is a thundering herd of qed's own making.
:meth:`Bucket.retry_after` returns the time until one token exists.

Pure: no clock, no storage, no asyncio. The caller passes `now` and keeps the
buckets, which is what makes the boundary conditions here testable without
sleeping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

__all__ = [
    "DEFAULT_PER_ADAPTER_RPS",
    "DEFAULT_PER_PRINCIPAL_RPS",
    "Bucket",
    "Decision",
    "Limiter",
]

#: SPEC §13's defaults. High on purpose: see the module docstring on why a
#: rate limit on a gate is not like a rate limit on a web service.
DEFAULT_PER_ADAPTER_RPS: Final = 100.0
DEFAULT_PER_PRINCIPAL_RPS: Final = 20.0

#: How much of a burst a bucket absorbs, as a multiple of the sustained rate.
#:
#: Capacity equal to `rps` -- one second's worth -- is the textbook token
#: bucket and the wrong default *here*. SPEC §13's per-principal limit is 20/s,
#: and an agent that makes thirty tool calls while deciding what to do next is
#: an ordinary agent, not an abusive one. With a one-second bucket those thirty
#: calls are refused, and on an adapter in `fail: closed` a refusal is a
#: blocked action: the limiter would be stopping the work it exists to protect.
#:
#: Three seconds' worth absorbs that and leaves the **sustained** rate exactly
#: what the spec says, which is the number that matters for abuse. A caller
#: that keeps pushing still settles at `rps`; only the first burst is free.
BURST_SECONDS: Final = 3.0

#: How long a bucket may sit unused before it is worth forgetting. Keyed by
#: principal, the key space is "every human and agent that ever called", so
#: something has to drop them or an instance running for a year holds a bucket
#: per principal for a year. Two minutes is far longer than any bucket needs to
#: refill, so forgetting one can never grant more than its full burst.
IDLE_EVICT_SECONDS: Final = 120.0


@dataclass
class Bucket:
    """One caller's allowance.

    `tokens` is a float because refill is continuous: at 100/s a request
    arriving 3 ms after the last one is owed 0.3 of a token, and rounding that
    to zero would make the limit 1/s for a fast caller.
    """

    rps: float
    tokens: float
    last_seen: float

    @classmethod
    def full(cls, rps: float, *, now: float) -> Bucket:
        return cls(rps=rps, tokens=rps * BURST_SECONDS, last_seen=now)

    @property
    def capacity(self) -> float:
        """The burst. See :data:`BURST_SECONDS`."""
        return self.rps * BURST_SECONDS

    def _refill(self, now: float) -> None:
        # `max(0, ...)` because a clock that went backwards must not *remove*
        # tokens: SPEC §17 already says the clock may be wrong, and a limiter
        # that punished a caller for it would turn a clock problem into an
        # outage. The worst a backwards clock can do here is delay a refill.
        elapsed = max(0.0, now - self.last_seen)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rps)
        self.last_seen = now

    def take(self, now: float) -> bool:
        """Spend one token if there is one."""
        self._refill(now)
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True

    def retry_after(self, now: float) -> float:
        """Seconds until one token exists, rounded up to the next tenth.

        Never zero when the bucket is empty: a `Retry-After: 0` is an
        invitation to retry immediately, which is the thundering herd this is
        supposed to prevent.
        """
        self._refill(now)
        if self.tokens >= 1.0 or self.rps <= 0:
            return 0.0
        needed = (1.0 - self.tokens) / self.rps
        return max(0.1, round(needed + 0.049, 1))


@dataclass(frozen=True)
class Decision:
    """Whether this request proceeds, and what to tell the caller."""

    allowed: bool
    #: Which limit refused it -- `adapter` or `principal` -- for the problem
    #: detail and for the metric label. An operator raising the wrong one is a
    #: specific, common waste of an afternoon.
    scope: str = ""
    key: str = ""
    retry_after: float = 0.0
    limit_rps: float = 0.0


@dataclass
class Limiter:
    """The buckets, by scope and key. Not thread-safe; the caller serialises.

    **In-process, which means per replica.** Four replicas with
    `per_adapter_rps: 100` admit 400/s between them. A shared limiter would
    need Redis, or the database on every request -- and a limiter that writes
    to PostgreSQL per proposal spends more than the work it is protecting. So
    this is honest about being local, `qed doctor` says so, and an operator
    sizing a limit divides by their replica count.
    """

    per_adapter_rps: float = DEFAULT_PER_ADAPTER_RPS
    per_principal_rps: float = DEFAULT_PER_PRINCIPAL_RPS
    adapters: dict[str, Bucket] = field(default_factory=dict)
    principals: dict[str, Bucket] = field(default_factory=dict)
    #: Refusals since start, by scope. The chain deliberately has none of this.
    refused: dict[str, int] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        """A limit of 0 is off, not "refuse everything".

        Zero reads as "no limit" to everyone who has ever written a config
        file, and a kernel that refused every proposal because somebody typed 0
        would be an outage with a plausible-looking cause.
        """
        return self.per_adapter_rps > 0 or self.per_principal_rps > 0

    def check(self, *, adapter: str | None, principal: str | None, now: float) -> Decision:
        """Spend a token from each applicable bucket.

        The adapter bucket is checked first because it is the coarser one: when
        a single adapter is flooding, saying so is more useful than naming
        whichever principal happened to arrive at the moment the bucket
        emptied.

        **A refusal from the first bucket does not spend from the second.**
        Otherwise a throttled adapter would also drain its principals' buckets,
        and a caller fixing the adapter limit would find the principal limit
        refusing them for reasons that no longer existed.
        """
        self._evict(now)
        for scope, key, rps, buckets in (
            ("adapter", adapter, self.per_adapter_rps, self.adapters),
            ("principal", principal, self.per_principal_rps, self.principals),
        ):
            if key is None or rps <= 0:
                continue
            bucket = buckets.get(key)
            if bucket is None:
                bucket = Bucket.full(rps, now=now)
                buckets[key] = bucket
            elif bucket.rps != rps:
                # The config was reloaded with a different limit. Keep the
                # tokens rather than refilling: a reload must not be a way to
                # reset somebody's allowance.
                bucket.rps = rps
                bucket.tokens = min(bucket.tokens, bucket.capacity)
            if not bucket.take(now):
                self.refused[scope] = self.refused.get(scope, 0) + 1
                return Decision(
                    allowed=False,
                    scope=scope,
                    key=key,
                    retry_after=bucket.retry_after(now),
                    limit_rps=rps,
                )
        return Decision(allowed=True)

    def _evict(self, now: float) -> None:
        """Forget buckets nobody has used for a while.

        Keyed by principal, the key space is unbounded over an instance's
        lifetime. Eviction cannot grant extra capacity: a bucket idle for
        longer than it takes to refill is already full, so dropping it and
        recreating it full are the same thing.
        """
        for buckets in (self.adapters, self.principals):
            stale = [
                key
                for key, bucket in buckets.items()
                if now - bucket.last_seen > IDLE_EVICT_SECONDS
            ]
            for key in stale:
                del buckets[key]

    def describe(self) -> dict[str, object]:
        """What `qed status` and `qed doctor` report."""
        return {
            "per_adapter_rps": self.per_adapter_rps,
            "per_principal_rps": self.per_principal_rps,
            "burst_seconds": BURST_SECONDS,
            "enabled": self.enabled,
            "scope": "this process only; multiply by your replica count",
            "refused": dict(sorted(self.refused.items())),
            "tracked": {"adapters": len(self.adapters), "principals": len(self.principals)},
        }
