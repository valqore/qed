"""Whether this machine's clock can be believed (SPEC §17). Pure.

SPEC §17: *"Clock: warn if NTP drift > 5 s; `seq` guarantees order regardless of
`ts`."* Both halves matter, and the second one is why this warns rather than
refusing: a record's position in the chain comes from `seq` and `prev_hash`, so
a wrong clock makes timestamps misleading and the chain is still sound. Halting
decisions over a clock would be trading a cosmetic problem for an outage.

**What is actually measured, and what is not.** This does not query an NTP
server. The kernel is offline by design -- invariant §1.7 is "zero bytes out by
default" -- and a governance component that reached for the network to decide
whether to trust itself would be a new dependency in the decision path and a
new thing for an auditor to think about.

What it measures instead is the chain against the system clock: **the newest
record's timestamp against now**. That catches the failure that matters, which
is the clock going *backwards* -- after which a later record carries an earlier
timestamp, and a reader who sorts the export by `ts` sees an order that is not
the order things happened. It is a weaker signal than NTP's own, and it is a
local one: no network, no daemon, no second opinion needed.

So the name is `drift` with the measurement named next to it, rather than
`ntp_drift`, which would claim a source this never asks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

__all__ = ["TOLERANCE_SECONDS", "ClockReport", "assess_clock"]

#: SPEC §17's number. Five seconds is loose enough that a virtual machine
#: coming back from a snapshot does not cry wolf, and tight enough that a
#: clock which has jumped is visible.
TOLERANCE_SECONDS: Final = 5.0


@dataclass(frozen=True)
class ClockReport:
    """What `qed status` and `qed doctor` say about the clock."""

    #: Seconds the newest record's timestamp is *ahead* of now. Negative is the
    #: ordinary case: records are written in the past.
    ahead_seconds: float
    tolerance_seconds: float = TOLERANCE_SECONDS

    @property
    def suspect(self) -> bool:
        """True when the newest record is in the future beyond the tolerance.

        Only that direction. A record written an hour ago is not evidence of
        anything -- an idle instance looks exactly like a stopped one -- and
        warning about it would make the check noise on every laptop that was
        closed overnight.
        """
        return self.ahead_seconds > self.tolerance_seconds

    def describe(self) -> dict[str, object]:
        return {
            "newest_record_ahead_seconds": round(self.ahead_seconds, 3),
            "tolerance_seconds": self.tolerance_seconds,
            "suspect": self.suspect,
            "measured": "newest record ts vs system clock; no NTP query",
        }

    def message(self) -> str:
        """The sentence an operator reads, or empty when there is nothing to say."""
        if not self.suspect:
            return ""
        return (
            f"the newest record is timestamped {self.ahead_seconds:.1f}s in the future, "
            f"which is past the {self.tolerance_seconds:.0f}s tolerance. The clock has "
            "most likely gone backwards since it was written. The chain is unaffected -- "
            "`seq` and `prev_hash` fix the order, not `ts` (SPEC 17) -- but an export "
            "sorted by timestamp will not read in the order things happened, so fix the "
            "clock before giving one to an auditor."
        )


def assess_clock(
    newest_record_ts: datetime | None, *, now: datetime, tolerance: float = TOLERANCE_SECONDS
) -> ClockReport:
    """Compare the newest record's timestamp with the system clock.

    `None` for an empty chain, which reports zero rather than nothing: a caller
    that had to handle None would have two code paths for "the clock is fine".
    """
    if newest_record_ts is None:
        return ClockReport(ahead_seconds=0.0, tolerance_seconds=tolerance)
    return ClockReport(
        ahead_seconds=(newest_record_ts - now).total_seconds(), tolerance_seconds=tolerance
    )
