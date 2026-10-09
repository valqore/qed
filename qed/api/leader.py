"""The chain's background loop (SPEC §10.3, §10.4, §10.6, §104).

Two jobs, and which of them applies depends on the backend.

**Draining the outbox** is the HA path only. Every replica serves the API and
decides; exactly one drains into the chain, and this is the task that tries to
be that one.

**Maintenance** -- checkpoint, publish the root, purge expired payloads --
applies on both. Nothing was doing it: `writer.checkpoint()` was reachable only
from `qed checkpoint`, so an instance nobody ran that command against had a
chain with no anchors, and SPEC §10.4's "every 1,000 records or 3,600 s" was a
threshold with no clock behind it.

The two are in one loop because maintenance appends to the chain, so it has the
same requirement the drain does: **exactly one writer.** On the HA path that
means holding the lock, which the drain already arranges; on SQLite it is true
by construction. Splitting them into two loops would mean the second asking the
first whether it was allowed to run.

**The loop owns its own database connection, on its own thread.** A `sqlite3`
connection may only be used by the thread that created it, and the API's was
created by the event loop at startup -- so a tick running anywhere else fails
with `ProgrammingError: SQLite objects created in a thread can only be used in
that same thread`. (`asyncio.to_thread` makes that certain rather than likely:
it uses a pool, so successive ticks can land on different threads.) Giving the
loop its own session keeps the API's connection single-threaded, which is what
everything else here assumes.

Two writers against one SQLite file is the arrangement week 1 designed for:
`append_evidence` re-reads the sequence number inside `BEGIN IMMEDIATE` and
raises rather than guessing, so the loser of a race fails loudly and the next
tick retries.

It is deliberately dull. It wakes up, tries the lock, drains if it got it, and
goes back to sleep. There is no election protocol, no term number and no
heartbeat, because PostgreSQL already provides the only hard part: a
session-scoped lock that is released when the holder's connection dies. A
replica that is killed does not have to notice, announce, or hand over —
its connection drops and the next tick somewhere else succeeds.

Two properties worth stating because they are easy to lose:

**It never blocks on the lock.** ``pg_try_advisory_lock``, not
``pg_advisory_lock``. A follower that blocked would hold a task and a
connection waiting for a leader to die, and would then wake up holding the
lock with no idea how long it had been waiting.

**It re-checks leadership every tick** rather than remembering it. The lock can
be lost without this process being told — a connection reset, a failover, an
administrator calling ``pg_advisory_unlock_all``. A remembered "I am the
leader" would be a replica appending to a chain somebody else is also
appending to, which is the one failure the lock exists to prevent.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from typing import Final

from qed.infra.chain_drain import drain_until_empty
from qed.infra.maintenance import maintain
from qed.runtime import Session

__all__ = ["MAINTENANCE_SECONDS", "STOP_TIMEOUT", "TICK_SECONDS", "LeaderLoop"]

logger = logging.getLogger("qed.api.leader")

#: How often a follower tries the lock, and a leader looks for work.
#:
#: SPEC §104 promises a replacement "within seconds". Two is inside that and
#: cheap: the try is one round trip and the drain does nothing when the queue
#: is empty. Shorter would turn an idle cluster into a steady stream of lock
#: attempts for no benefit.
TICK_SECONDS: Final = 2.0

#: How often the loop asks whether a checkpoint, a publication or a purge is
#: due. Thirty seconds, against SPEC §10.4's thresholds of 1,000 records or an
#: hour: fine enough that neither drifts noticeably, coarse enough that an idle
#: instance is not reading its own chain tip every two seconds to be told no.
MAINTENANCE_SECONDS: Final = 30.0

#: How long shutdown waits for a tick in progress. Longer than the git
#: publisher's own 60s timeout would be, so a slow anchor does not turn into a
#: container that will not stop; shorter than a container runtime's usual
#: SIGKILL grace, so the join is the thing that gives up rather than the
#: orchestrator.
STOP_TIMEOUT: Final = 15.0


class LeaderLoop:
    """Drains the outbox for as long as this replica holds the chain lock."""

    def __init__(
        self,
        session: Session,
        *,
        tick: float = TICK_SECONDS,
        maintenance: float = MAINTENANCE_SECONDS,
        own_session: Callable[[], Session] | None = None,
    ) -> None:
        #: The session a *synchronous* `tick_once` uses -- the one a test or
        #: `qed checkpoint` hands over. The background thread does not use it.
        self.session = session
        #: How the background thread gets a session of its own. Required by
        #: `start()`: a session is a database connection, and a `sqlite3`
        #: connection belongs to the thread that made it.
        self._own_session = own_session
        self.tick = tick
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        #: Reported by `/v1/status` so an operator can see which replica is
        #: appending. Advisory: it is what this process last observed.
        self.leading = False
        self.chained = 0
        self.checkpoints = 0
        self.purged = 0
        self.last_error = ""
        #: Maintenance is checked on its own, slower schedule. The tick is two
        #: seconds because a replacement leader has to be found in seconds
        #: (SPEC §104); asking whether a checkpoint is due that often would be
        #: a read of the chain tip every two seconds for the life of the
        #: process, to answer "not yet" almost every time.
        self.maintenance_interval = maintenance
        self._next_maintenance = 0.0

    @property
    def drains(self) -> bool:
        """Whether this deployment has an outbox to drain.

        Only the deferred path does. On SQLite the decider chains its own
        records on the way in, so there is nothing queued and no lock to hold.
        """
        return self.session.writer.deferred and hasattr(self.session.store, "try_become_leader")

    @property
    def applicable(self) -> bool:
        """Whether the loop has anything to do.

        Always, now. Maintenance runs on both backends -- a SQLite instance
        still needs checkpoints, anchors and retention, and before this loop
        existed it got them only if somebody ran `qed checkpoint` by hand.
        """
        return True

    def start(self) -> None:
        """Start the background thread. Idempotent.

        Requires `own_session`. Sharing the caller's session would work on
        PostgreSQL and fail on SQLite with `ProgrammingError: SQLite objects
        created in a thread can only be used in that same thread` -- an error
        that appears only on the default backend, only once the thread does
        its first database read, and in a log rather than a test. Refusing up
        front is the difference between a mistake that is impossible and one
        that is merely unlikely.
        """
        if not self.applicable or self._thread is not None:
            return
        if self._own_session is None:
            raise ValueError(
                "LeaderLoop.start() needs `own_session`: the loop runs on its own thread "
                "and a database connection belongs to the thread that opened it. Pass a "
                "callable that opens a session, or call `tick_once()` synchronously."
            )
        self._stopping.clear()
        # A thread and not a task: every tick is blocking database work, and
        # one dedicated thread is also what lets the loop keep a connection of
        # its own. `daemon=False` because `stop()` joins it -- a daemon thread
        # killed mid-transaction is a half-written chain.
        self._thread = threading.Thread(target=self._run, name="qed-chain-loop", daemon=False)
        self._thread.start()
        logger.info(
            "chain loop started; tick %.1fs, maintenance every %.0fs",
            self.tick,
            self.maintenance_interval,
        )

    async def stop(self) -> None:
        """Stop the thread and resign, so a handover takes milliseconds.

        Resigning is not required for correctness -- closing the connection
        releases the lock -- but a replica that resigns on the way out does not
        make the next one wait for the server to notice a dead connection.

        Awaited from the app's shutdown, and the join is run in a thread so a
        tick in progress does not block the event loop while it finishes.
        """
        self._stopping.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            await asyncio.to_thread(thread.join, STOP_TIMEOUT)
            if thread.is_alive():  # pragma: no cover - a publisher hung past its timeout
                logger.error(
                    "the chain loop did not stop within %.0fs; leaving it to finish",
                    STOP_TIMEOUT,
                )
        self.leading = False

    def _run(self) -> None:
        """The thread body. Opens its own session, ticks until told to stop."""
        assert self._own_session is not None, "start() checked this"
        try:
            owned = self._own_session()
        except Exception as exc:
            # No loop, and the API carries on. A chain that is not being
            # checkpointed is worse than one that is, and far better than an
            # instance that refuses to decide because a background task could
            # not start.
            self.last_error = f"could not open a session for the chain loop: {exc}"
            logger.error("%s", self.last_error)
            return
        session = owned

        try:
            while not self._stopping.is_set():
                try:
                    self.tick_once(session=session)
                except Exception as exc:
                    # Logged and counted, never swallowed silently: a loop that
                    # stopped working without saying so looks exactly like a
                    # cluster with nothing to do, and the only symptom would be
                    # a queue depth nobody was watching.
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    logger.error("chain loop tick failed: %s", self.last_error)
                self._stopping.wait(self.tick)
        finally:
            if self.leading:
                resign = getattr(session.store, "resign_leadership", None)
                if resign is not None:
                    try:
                        resign()
                    except Exception as exc:  # pragma: no cover - the socket may be gone
                        logger.debug("could not resign cleanly: %s", exc)
                self.leading = False
            # Its own session, so its own close -- and no settle, because
            # draining is what this loop was doing until a moment ago.
            owned.close(settle_chain=False)

    def tick_once(self, *, session: Session | None = None) -> int:
        """One attempt. Returns how many records were chained.

        `session` is the loop thread's own when it is running, and the one
        passed to the constructor when a test or a command calls this directly.
        Both halves are transactions rather than something to interleave with
        request handling, which is why this is synchronous.
        """
        active = session if session is not None else self.session
        if self.drains:
            store = active.store
            claim = getattr(store, "try_become_leader", None)
            if claim is None:  # pragma: no cover - `drains` checked this
                return 0
            # Asked every tick, not remembered. The lock can be lost without
            # this process being told.
            self.leading = bool(claim())
            if not self.leading:
                # Not the writer, so neither the drain nor the maintenance may
                # append. A follower that checkpointed would be a second
                # writer, which is the whole thing the lock prevents.
                return 0
        else:
            # One process, one chain, no election.
            self.leading = True

        chained = self._drain(active)
        self._maintain(active)
        return chained

    def _drain(self, session: Session) -> int:
        if not self.drains:
            return 0
        result = drain_until_empty(session.writer)
        if result.skipped:
            self.last_error = result.skipped
            logger.error("drain stopped: %s", result.skipped)
        elif result.chained:
            self.last_error = ""
            self.chained += result.chained
        return result.chained

    def _maintain(self, session: Session) -> None:
        """Checkpoint, publish, purge -- each when its own threshold says so.

        Run every tick because deciding whether anything is due is cheap: the
        checkpoint thresholds are a count and a timestamp comparison, and
        retention plans nothing at all when no policy is configured.
        """
        if self._next_maintenance > time.monotonic():
            return
        self._next_maintenance = time.monotonic() + self.maintenance_interval
        result = maintain(session)
        self.checkpoints += 1 if result.checkpoint is not None else 0
        self.purged += result.purged
        if result.errors:
            self.last_error = "; ".join(result.errors)
