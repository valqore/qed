"""Shipping OCSF events to a SIEM (SPEC §18).

A webhook, or stdout. Both are deliberately crude, because the chain is the
record and this is a copy: an event that is never delivered changes nothing
about what was decided or what was recorded, and the one thing this must never
do is make a decision wait for a log shipper.

So the design is a **bounded queue and a background thread**:

* ``send`` appends to a deque with a maximum length and returns. It never
  blocks, never retries inline, and never raises;
* when the queue is full the **oldest** event is dropped, and a counter says
  how many. Dropping the newest would mean a burst hid itself; dropping the
  oldest means the queue holds what is happening now, which is what somebody
  reading a SIEM during an incident wants;
* a single worker thread posts them. One, so events arrive roughly in order
  and a slow endpoint cannot open fifty connections.

Failures are counted and logged, not retried forever. A webhook that has been
down for an hour has lost an hour of events and the operator needs to know
that, which a `qed_siem_dropped_total` on `/metrics` says and an infinite retry
queue does not.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from collections.abc import Callable
from typing import Final

from qed.core.evidence.export.ocsf import to_ocsf
from qed.core.schemas import EvidenceRecord

__all__ = ["QUEUE_MAX", "SiemShipper", "SiemStats"]

logger = logging.getLogger("qed.siem")

#: Events held while the endpoint is slow or down. 10,000 is about a minute of
#: a busy instance; past that the oldest go, because an unbounded queue in
#: front of a dead webhook is a memory leak with a plausible excuse.
QUEUE_MAX: Final = 10_000

#: Seconds. Short: a SIEM is not on the decision path, and a slow one must not
#: hold the worker thread long enough for the queue to back up behind it.
TIMEOUT: Final = 5.0


class SiemStats:
    """Counters, for `/metrics` and `qed doctor`."""

    __slots__ = ("dropped", "failed", "sent")

    def __init__(self) -> None:
        self.sent = 0
        self.failed = 0
        #: Events discarded because the queue was full. The number that
        #: matters: it is the gap in somebody's SIEM.
        self.dropped = 0

    def as_dict(self) -> dict[str, int]:
        return {"sent": self.sent, "failed": self.failed, "dropped": self.dropped}


class SiemShipper:
    """Converts records to OCSF and ships them, out of the request's way."""

    def __init__(
        self,
        *,
        instance_id: str,
        webhook: str | None = None,
        to_stdout: bool = False,
        timeout: float = TIMEOUT,
        post: Callable[[str, bytes, float], int] | None = None,
    ) -> None:
        self.instance_id = instance_id
        self.webhook = webhook
        self.to_stdout = to_stdout
        self.timeout = timeout
        self.stats = SiemStats()
        #: Injectable so a test can assert what would have gone over the wire
        #: without one. Default is httpx, imported lazily: an instance with no
        #: SIEM configured should not pay for the import.
        self._post = post or _post_with_httpx
        self._queue: deque[dict[str, object]] = deque(maxlen=QUEUE_MAX)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def active(self) -> bool:
        return bool(self.webhook) or self.to_stdout

    def describe(self) -> str:
        """One line for `qed doctor`. The host, never a query string.

        A webhook URL often carries a token in its path or query -- Splunk HEC
        and Slack both do -- and `qed doctor` output ends up in a support
        ticket.
        """
        if not self.active:
            return "siem: not configured"
        parts = []
        if self.webhook:
            parts.append(f"webhook {_redact(self.webhook)}")
        if self.to_stdout:
            parts.append("stdout")
        return "siem: " + ", ".join(parts)

    # ---------------------------------------------------------------- sending

    def send(self, record: EvidenceRecord, *, principal_hash: str | None = None) -> None:
        """Queue one record. Never blocks, never raises.

        Called from the request path, so everything that could go wrong --
        serialisation, a full queue, a dead endpoint -- is handled here or
        counted and forgotten.
        """
        if not self.active:
            return
        try:
            event = to_ocsf(record, instance_id=self.instance_id, principal_hash=principal_hash)
        except Exception as exc:  # pragma: no cover - mapping is pure and total
            logger.error("could not map record %s to OCSF: %s", record.seq, exc)
            return
        with self._lock:
            if len(self._queue) == QUEUE_MAX:
                # The deque drops the oldest itself; counting it is the point.
                self.stats.dropped += 1
            self._queue.append(event)
        self._wake.set()

    def start(self) -> None:
        if not self.active or self._thread is not None:
            return
        self._stopping.clear()
        self._thread = threading.Thread(target=self._run, name="qed-siem", daemon=False)
        self._thread.start()
        logger.info("%s", self.describe())

    def stop(self, *, timeout: float = 5.0) -> None:
        """Stop, after one last attempt to drain what is queued.

        A best effort, not a guarantee: a shutdown that waited for a dead
        webhook would be a container that will not stop.
        """
        self._stopping.set()
        self._wake.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout)
        if self._queue:
            logger.warning(
                "%d SIEM event(s) were still queued at shutdown and were not sent",
                len(self._queue),
            )

    # ----------------------------------------------------------------- worker

    def _run(self) -> None:
        while True:
            self._wake.wait(1.0)
            self._wake.clear()
            self._drain()
            if self._stopping.is_set():
                self._drain()
                return

    def _drain(self) -> None:
        while True:
            with self._lock:
                if not self._queue:
                    return
                event = self._queue.popleft()
            self._deliver(event)

    def _deliver(self, event: dict[str, object]) -> None:
        body = json.dumps(event, separators=(",", ":")).encode("utf-8")
        if self.to_stdout:
            # One JSON object per line: what every log collector reads, and
            # what `docker logs | jq` reads too.
            print(body.decode("utf-8"), flush=True)
        if not self.webhook:
            self.stats.sent += 1
            return
        try:
            status = self._post(self.webhook, body, self.timeout)
        except Exception as exc:
            self.stats.failed += 1
            logger.warning("SIEM webhook failed: %s: %s", type(exc).__name__, exc)
            return
        if 200 <= status < 300:
            self.stats.sent += 1
        else:
            self.stats.failed += 1
            logger.warning("SIEM webhook answered %d", status)


def _post_with_httpx(url: str, body: bytes, timeout: float) -> int:
    import httpx

    response = httpx.post(
        url, content=body, headers={"content-type": "application/json"}, timeout=timeout
    )
    return int(response.status_code)


def _redact(url: str) -> str:
    """Scheme, host and port. Nothing else.

    A webhook URL often carries a token in its path or query -- Splunk HEC and
    Slack both do -- and this string goes into logs and `qed doctor` output.
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:  # pragma: no cover - urlsplit is forgiving
        return "<unparseable>"
    if not parts.hostname:
        return "<no host>"
    port = f":{parts.port}" if parts.port else ""
    # ASCII: this is printed by `qed doctor`, and a Windows console at the
    # default code page cannot encode an ellipsis -- a week-1 bug worth not
    # reintroducing.
    return f"{parts.scheme}://{parts.hostname}{port}/..."
