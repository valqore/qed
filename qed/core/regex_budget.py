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

What this does not do
---------------------

It does not make a timeout impossible, and nothing here should be read as
claiming that. Three stalls in a row are unlikely, not excluded. It also does
not bound anything above a single call: a caller that runs this in a loop --
the redactor over a payload's strings, the engine over a bundle's rules --
multiplies the worst case by the loop count, and bounding *that* is the
caller's business, not this module's.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

__all__ = ["ATTEMPTS", "BUDGET", "Remaining", "under_budget"]

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

#: What a unit of work calls to get the timeout to hand to ``regex``. Calling
#: it again after some work has been done returns less, because one deadline
#: is being drawn down rather than a new clock started per pattern.
Remaining = Callable[[], float]


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
    failure: TimeoutError | None = None
    for _ in range(ATTEMPTS):
        deadline = time.monotonic() + BUDGET

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
    assert failure is not None  # ATTEMPTS >= 1, so the loop either returns or sets this
    raise failure
