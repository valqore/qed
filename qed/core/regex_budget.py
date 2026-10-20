"""One wall-clock budget for every regex this kernel runs (SPEC §17, ADR-0017).

Two callers match untrusted text against a fixed pattern set: the policy
engine's ``regex`` predicate and the evidence redactor. Both need the same
guard against a pattern that will not finish, both get it from the ``regex``
module's ``timeout=``, and both had their own copy of the number. That is how
ADR-0016 came to be applied to one of them -- its reasoning was about the
library's clock, which governs every caller of it, and the other kept a budget
the ADR had already found too narrow. Four days later a loaded runner masked a
fifteen-character string as ``[masked:timeout]`` inside an evidence record.

So the budget lives here, once, and the two callers import it.

Why a retry
-----------

``timeout=`` is **wall clock**, not work. It cannot tell the two things apart
that it is asked to distinguish:

* a pattern that backtracks catastrophically on this input, which is a
  property of the pattern and the input, and
* a thread the host descheduled mid-match, which is a property of the
  neighbours.

No budget separates them. Widen it and a pathological pattern costs more
before it is caught; narrow it and ordinary text fails on a busy machine. The
only thing that *does* separate them is running it again: a pathological
pattern blows every budget it is given, and a stall does not recur. So a
timeout is treated as a question rather than an answer, and asked
:data:`ATTEMPTS` times before the caller is told it failed.

The cost is the worst case: a pattern that really cannot be evaluated now
takes ``ATTEMPTS * BUDGET`` to say so instead of ``BUDGET``. That is the right
trade for both callers, because both treat a timeout as a failure with
consequences -- a skipped rule recorded as ``AG-PRD-001``, or a payload
replaced by ``[masked:timeout]`` *before* it is hashed, which is permanent and
reports nothing. Paying three times the budget to avoid either is cheap.

One pool per decision
---------------------

:func:`under_budget` bounds one call. A caller that runs it in a loop
multiplies the worst case by the loop count, which for the policy engine meant
a bundle of 46 unevaluable patterns costing ``46 * ATTEMPTS * BUDGET``. So a
caller can open a :func:`pooled` block, and every attempt inside it draws from
one shared allowance of regex time (ADR-0018).

The pool measures *regex* time and not wall time, so nothing else happening in
the loop can spend it. When it is gone, further matching fails immediately
rather than being attempted, which is what makes the bound hold however many
rules there are.

The redactor deliberately does **not** use one. Its loop is over the strings in
a payload, and a shared allowance would let one stalled string spend the budget
that the fields after it need -- turning one stall into a record full of
``[masked:timeout]``. Per-string is the right granularity there precisely
because the failure is per-string.

What this does not do
---------------------

It does not make a timeout impossible, and nothing here should be read as
claiming that. Three stalls in a row are unlikely, not excluded.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Final

__all__ = ["ATTEMPTS", "BUDGET", "POOL", "PoolSpent", "Remaining", "pooled", "under_budget"]

#: Seconds, per attempt. One second, which is absurd next to the microseconds
#: a legitimate pattern spends and is meant to be: the budget is wall clock, so
#: it has to stand far enough above a real match that scheduling noise cannot
#: spend it. ADR-0016 raised it here from 100 ms after a CI runner spent that
#: on a pattern matching in 219 microseconds.
BUDGET: Final = 1.0

#: How many times a timeout is retried before the caller is told. Three,
#: because the retry is a test of whether the input or the host caused it and
#: two answers cannot break a tie: a stall that happens to recur once looks
#: exactly like a pattern that always fails.
ATTEMPTS: Final = 3

#: Seconds of regex evaluation one :func:`pooled` block may spend in total,
#: however many times it matches. Since an attempt is funded with a whole
#: :data:`BUDGET` or refused, this is also the number of attempts a block gets:
#: five. That is :data:`ATTEMPTS` plus two, so a single pattern that genuinely
#: cannot be evaluated still gets its three full attempts -- any less and this
#: bound would quietly undo the retry it sits on top of -- with enough left to
#: start showing that a second pattern is bad too. It is about a hundred
#: thousand times what a real bundle spends, so a bundle whose patterns all
#: work can never reach it.
POOL: Final = 5.0

#: What a unit of work calls to get the timeout to hand to ``regex``. Calling
#: it again after some work has been done returns less, because one deadline
#: is being drawn down rather than a new clock started per pattern.
Remaining = Callable[[], float]


class PoolSpent(TimeoutError):
    """The shared allowance is gone, so this match was never attempted.

    A subclass of ``TimeoutError`` so that every caller's existing handling
    still applies -- the policy engine skips the rule, the redactor masks the
    string. It is a distinct type because the two causes are different operator
    problems and must not read as one: *this* pattern spending its budget is a
    fault in this rule, while the pool being empty means some *earlier* call
    spent it and this one never got to run. Blaming forty-four innocent rules
    for the one bad pattern ahead of them is how a report stops being useful.

    Raised only when **no** attempt was made. A call whose own first attempt
    timed out and then found the pool empty spent the missing time itself, so
    it gets the ordinary timeout its pattern earned; pointing at the pool there
    would point an operator at the wrong rule.
    """


@dataclass
class _Pool:
    allowance: float
    spent: float = 0.0

    def remaining(self) -> float:
        return self.allowance - self.spent


_POOL: ContextVar[_Pool | None] = ContextVar("qed_regex_pool", default=None)


@contextmanager
def pooled(total: float | None = None) -> Iterator[None]:
    """Make every :func:`under_budget` call inside this block share one allowance.

    Scoped to the context, so concurrent decisions on separate threads or
    tasks each get their own pool and cannot spend each other's.

    Reads :data:`POOL` at entry rather than capturing it at import, so a test
    can shrink it and watch the bound hold without spending five seconds.
    """
    token = _POOL.set(_Pool(allowance=POOL if total is None else total))
    try:
        yield
    finally:
        _POOL.reset(token)


def under_budget[T](work: Callable[[Remaining], T]) -> T:
    """Run ``work`` under a deadline, retrying a timeout, and re-raise it last.

    ``work`` is called with a :data:`Remaining` callable and must be **pure**:
    it is run up to :data:`ATTEMPTS` times and only the last result is kept, so
    anything it mutates would be mutated repeatedly. Both callers build a new
    string or return a bool, which is why this is safe for them.

    Each attempt gets a whole fresh :data:`BUDGET`. The deadline bounds the
    attempt, not each regex inside it -- a budget spent inside a loop is a
    budget *per iteration*, and the constant then names something no caller
    experiences. That is not hypothetical: the redactor granted it per pattern,
    so sixteen patterns at 100 ms was a 1.6 s worst case for one string, and
    widening the number to survive a loaded host multiplied the worst case by
    the same factor and halved four-session throughput.
    """
    pool = _POOL.get()
    failure: TimeoutError | None = None
    for _ in range(ATTEMPTS):
        # A whole BUDGET or nothing. Handing out whatever is left would fund an
        # attempt with a sliver -- a tenth of a millisecond is not a test of
        # anything, it times out instantly, and the call then looks like a
        # pattern that failed on its own rather than one that was never given a
        # chance. It also made the outcome depend on where in the pool the
        # arithmetic happened to land, which is a verdict that varies with the
        # clock. Up to one budget of the pool goes unused; exactness is not
        # worth a misattributed rule.
        if pool is not None and pool.remaining() < BUDGET:
            if failure is None:
                # Nothing was attempted, so nothing here is at fault: an
                # earlier call spent the allowance and this one never ran.
                raise PoolSpent("the shared regex allowance for this call is gone")
            # This call has already had an attempt time out, so it spent what
            # is missing and the fault is its own. Reporting the pool would
            # point an operator at the wrong rule.
            break
        started = time.monotonic()
        deadline = started + BUDGET

        def remaining(deadline: float = deadline) -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                # `regex` reads a non-positive timeout as *no* timeout, so
                # handing it the spent budget would drop the guard at the one
                # moment it is doing something, and the failure would be a
                # hang rather than a refusal.
                raise TimeoutError("regex budget spent")
            return left

        try:
            return work(remaining)
        except TimeoutError as exc:
            failure = exc
        finally:
            if pool is not None:
                # Charged whether the attempt succeeded or timed out. A pool
                # that only counted failures would let a pattern which is
                # merely slow run unbounded, and slow is the thing being
                # bounded.
                pool.spent += time.monotonic() - started
    assert failure is not None  # ATTEMPTS >= 1, so the loop either returns or sets this
    raise failure
