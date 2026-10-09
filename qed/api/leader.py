"""The chain leader's loop (SPEC §10.3, §104).

Every replica serves the API and decides; exactly one drains the outbox into
the chain. This is the task that tries to be that one.

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
from contextlib import suppress
from typing import Final

from qed.infra.chain_drain import drain_until_empty
from qed.runtime import Session

__all__ = ["TICK_SECONDS", "LeaderLoop"]

logger = logging.getLogger("qed.api.leader")

#: How often a follower tries the lock, and a leader looks for work.
#:
#: SPEC §104 promises a replacement "within seconds". Two is inside that and
#: cheap: the try is one round trip and the drain does nothing when the queue
#: is empty. Shorter would turn an idle cluster into a steady stream of lock
#: attempts for no benefit.
TICK_SECONDS: Final = 2.0


class LeaderLoop:
    """Drains the outbox for as long as this replica holds the chain lock."""

    def __init__(self, session: Session, *, tick: float = TICK_SECONDS) -> None:
        self.session = session
        self.tick = tick
        self._task: asyncio.Task[None] | None = None
        #: Reported by `/v1/status` so an operator can see which replica is
        #: appending. Advisory: it is what this process last observed.
        self.leading = False
        self.chained = 0
        self.last_error = ""

    @property
    def applicable(self) -> bool:
        """Whether this deployment needs a leader at all.

        Only the deferred path does. On SQLite the decider chains its own
        records on the way in, so a drain loop would be a task with nothing to
        do and a lock that does not exist.
        """
        return self.session.writer.deferred and hasattr(self.session.store, "try_become_leader")

    def start(self) -> None:
        if not self.applicable or self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="qed-chain-leader")
        logger.info("chain leader loop started; tick %.1fs", self.tick)

    async def stop(self) -> None:
        """Cancel the loop and resign, so a handover takes milliseconds.

        Resigning is not required for correctness -- closing the connection
        releases the lock -- but a replica that resigns on the way out does not
        make the next one wait for the server to notice a dead connection.
        """
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            # Suppressing broadly on purpose: this runs during shutdown, and a
            # drain that failed on the way out has already been logged by
            # `_run`. Re-raising here would turn a tidy stop into a traceback
            # and skip the resignation below.
            with suppress(BaseException):
                await task
        if self.leading:
            resign = getattr(self.session.store, "resign_leadership", None)
            if resign is not None:
                try:
                    resign()
                except Exception as exc:  # pragma: no cover - the socket may be gone
                    logger.debug("could not resign cleanly: %s", exc)
            self.leading = False

    async def _run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.tick_once)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Logged and counted, never swallowed silently: a leader that
                # stopped draining without saying so would look exactly like a
                # cluster with nothing to do, and the only symptom would be an
                # outbox depth nobody was watching.
                self.last_error = f"{type(exc).__name__}: {exc}"
                logger.error("chain leader tick failed: %s", self.last_error)
            await asyncio.sleep(self.tick)

    def tick_once(self) -> int:
        """One attempt. Returns how many records were chained.

        Synchronous and run in a thread: the store's connection belongs to
        whichever thread uses it, and the drain is a transaction rather than
        something to interleave with request handling.
        """
        store = self.session.store
        claim = getattr(store, "try_become_leader", None)
        if claim is None:  # pragma: no cover - `applicable` checked this
            return 0

        # Asked every tick, not remembered. The lock can be lost without this
        # process being told.
        self.leading = bool(claim())
        if not self.leading:
            return 0

        result = drain_until_empty(self.session.writer)
        if result.skipped:
            self.last_error = result.skipped
            logger.error("drain stopped: %s", result.skipped)
        elif result.chained:
            self.last_error = ""
            self.chained += result.chained
        return result.chained
