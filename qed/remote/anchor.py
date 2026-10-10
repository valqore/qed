"""The transparency-log anchor client (SPEC §10.4, §16, invariant §1.7).

A checkpoint is a Merkle root over a range of the chain, signed and appended
like any other record. On its own it proves only that the instance was
internally consistent at the moment an auditor read it: an operator who rewrote
the chain could recompute every root and every signature. Publishing the root
somewhere outside the instance's control is what closes that, and this is the
publisher that sends it to a log run by somebody else.

**What goes out is the narrow part, and it is the whole design here.**

The other three publishers copy the entire checkpoint record, because they copy
it into infrastructure the operator owns: their own bucket, their own
repository, their own volume. This one sends it to a third party, and SPEC
§1.7's promise is "carries no customer data (hashes/signatures only)". The
record is not that: a checkpoint payload includes the **previous checkpoint's
receipts**, and a receipt's `target` is an `s3://bucket/key` or a git remote.
Posting the record to an anchor service would hand it a list of the operator's
bucket names, which is exactly the kind of inventory nobody consented to
publish.

So this sends one small document -- the record's `hash`, its signature, its key
id, its sequence number and the Merkle root -- and nothing else. A test asserts
that no bucket name, path or receipt from the record appears in the body.

The consequence is honest and worth stating: **the log cannot verify the
signature covers a meaningful payload**, because it never sees the payload. It
does not need to. A transparency log's job is "this value existed at this
time", and the value is a hash whose preimage the auditor already holds in
their export. The log is a witness, not a verifier.

`log_id` is the second privacy decision, and it is **required**. A log has to
scope entries somehow, and qed has nothing to offer: `instance_id` is a
customer-chosen string -- `acme-prod-qed` names a company and an environment --
and the checkpoint record does not even carry it, which is itself a good sign.
Deriving one from the signing key was the other option and is worse: a key
rotation would silently move an instance's entries to a different scope,
splitting its own history in somebody else's log.

So the operator writes the name their entries carry in a third party's log.
That is their decision to make, and a default would have made it for them.

Not built: the log itself. SPEC §22 week 9 asks for the client with a server
stub, and the server is `qed-cloud`'s (SPEC §24.2, the proprietary side). The
stub this is tested against is in `tests/evidence/test_anchor_client.py`.
"""

from __future__ import annotations

from typing import Any, Final

from qed.core.schemas import EvidenceRecord
from qed.infra.publishers.model import PublicationError, Receipt

__all__ = ["AnchorPublisher"]

#: Seconds to wait for the log. Short on purpose: this runs inside the
#: maintenance tick that also drains the outbox, and a log that has gone away
#: must cost one checkpoint's latency rather than the chain's progress. A
#: failed publication is a receipt with `ok=False`, which is durable -- the
#: next checkpoint carries it, so nothing is lost by giving up quickly.
DEFAULT_TIMEOUT_S: Final = 5.0


#: Hosts where plain http is allowed, because the request never leaves the
#: machine and there is no path for anything to observe or substitute the root.
#:
#: The exemption is here because the guard was doing real harm without it: a
#: local relay or sidecar is a legitimate deployment -- one process that holds
#: the log credential and talks https onward -- and an operator blocked from
#: `http://127.0.0.1` turns the publisher off instead, which is strictly worse
#: than anchoring through a relay. Matched on the literal host, so no DNS name
#: can resolve its way in.
LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})


def _is_loopback(url: str) -> bool:
    from urllib.parse import urlsplit

    if not url.startswith("http://"):
        return False
    host = urlsplit(url).hostname or ""
    return host in LOOPBACK_HOSTS


class AnchorPublisher:
    """POST a checkpoint's root to a transparency log.

    Opt-in, outbound-only, and absent unless configured -- an instance with no
    `qed-anchor` publisher opens no socket and sends nothing.
    """

    kind = "qed-anchor"

    def __init__(
        self,
        *,
        url: str,
        log_id: str,
        timeout: float = DEFAULT_TIMEOUT_S,
        token_env: str = "",
    ) -> None:
        self.url = url.rstrip("/")
        self.log_id = log_id
        self.timeout = timeout
        self.token_env = token_env

    @classmethod
    def from_config(cls, options: dict[str, object]) -> AnchorPublisher:
        url = str(options.get("url", "")).strip()
        if not url:
            raise PublicationError(
                "the `qed-anchor` publisher needs a `url`. Without one there is no log "
                "to anchor to, and a publisher that was configured and does nothing is "
                "an anchor the operator believes exists."
            )
        if not url.startswith("https://") and not _is_loopback(url):
            # Not pedantry: the body is the one thing that proves a chain was
            # not rewritten, and over http an observer can see every root and a
            # middlebox can replace them.
            raise PublicationError(
                f"the `qed-anchor` url must be https, and this is {url!r}. The root is "
                "the evidence that the chain was not rewritten; sending it in clear "
                "lets anything on the path substitute it. Plain http is allowed only "
                "to loopback, where the body never leaves the machine."
            )
        log_id = str(options.get("log_id", "") or "").strip()
        if not log_id:
            raise PublicationError(
                "the `qed-anchor` publisher needs a `log_id`: the name your entries "
                "carry in somebody else's log. There is no default on purpose -- "
                "`instance_id` is a customer-chosen string that names a company and an "
                "environment, and deriving one from the signing key would move your "
                "entries to a new scope at the next rotation, splitting your own "
                "history in that log."
            )
        if "token" in options or "secret" in options:
            raise PublicationError(
                "put the anchor token in an environment variable and name it with "
                "`token_env`, not in `qed.yaml`. SPEC 16: secrets are never in the "
                "config file, only env names or secret-store references."
            )
        return cls(
            url=url,
            log_id=log_id,
            timeout=float(options.get("timeout_seconds", DEFAULT_TIMEOUT_S)),  # type: ignore[arg-type]
            token_env=str(options.get("token_env", "") or ""),
        )

    # ------------------------------------------------------------------ body

    def body(self, record: EvidenceRecord) -> dict[str, object]:
        """What is sent. Deliberately not the record.

        Five values, each of which an auditor already holds: the record hash
        and the Merkle root they can recompute from their export, the signature
        and key id they already verify with, and the sequence number. Nothing
        from the payload -- which carries the previous checkpoint's receipts,
        and so the operator's bucket names and git remotes.
        """
        payload = record.payload or {}
        return {
            "log_id": self.log_id,
            "seq": record.seq,
            "hash": record.hash,
            "merkle_root": str(payload.get("merkle_root", "")),
            "key_id": record.key_id,
            "sig": record.sig,
        }

    # --------------------------------------------------------------- publish

    def publish(self, record: EvidenceRecord) -> Receipt:
        """Send it. Returns a receipt; never raises (SPEC §10.4)."""
        import os

        import httpx

        target = f"{self.url}/v1/anchors"
        headers = {"content-type": "application/json"}
        if self.token_env:
            token = os.environ.get(self.token_env, "")
            if not token:
                return Receipt(
                    publisher=self.kind,
                    target=target,
                    ok=False,
                    error=(
                        f"{self.token_env} is empty, so the log would refuse this anyway. "
                        "Nothing was sent."
                    ),
                )
            headers["authorization"] = f"Bearer {token}"

        try:
            response = httpx.post(
                target, json=self.body(record), headers=headers, timeout=self.timeout
            )
        except httpx.HTTPError as exc:
            # The message, not the exception: a connection error's string can
            # include the URL, and the URL is not a secret, but a stack trace
            # in the chain is noise an auditor has to read past.
            return Receipt(
                publisher=self.kind,
                target=target,
                ok=False,
                error=f"could not reach the anchor log: {type(exc).__name__}: {exc}",
            )

        if response.status_code >= 400:
            return Receipt(
                publisher=self.kind,
                target=target,
                ok=False,
                error=f"the anchor log answered {response.status_code}: {_short(response.text)}",
            )

        return Receipt(publisher=self.kind, target=target, ok=True, proof=_proof(response))

    def describe(self) -> str:
        """One line for `qed doctor`, with no credential in it."""
        auth = f", token from ${self.token_env}" if self.token_env else ", no token"
        return f"{self.kind}: {self.url} as {self.log_id}{auth}"


#: Characters of a log's error body kept in a receipt. The receipt goes into
#: the chain, and an HTML error page would put a kilobyte of markup in it.
ERROR_CHARS: Final = 200


def _short(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= ERROR_CHARS:
        return collapsed
    return collapsed[:ERROR_CHARS] + "..."


def _proof(response: Any) -> dict[str, object]:
    """The log's own attestation, kept as given.

    A transparency log's answer is the part worth storing -- an index, an
    inclusion proof, a signed timestamp -- and qed does not interpret it. What
    it does do is refuse to store something unbounded: a receipt lands in the
    chain, which is immutable, so a log answering with a megabyte would put a
    megabyte there for good.
    """
    try:
        document = response.json()
    except Exception:
        return {"status": int(response.status_code)}
    if not isinstance(document, dict):
        return {"status": int(response.status_code)}
    kept = {
        key: value
        for key, value in document.items()
        if key in {"log_index", "log_id", "inclusion_proof", "signed_timestamp", "tree_size"}
    }
    return {"status": int(response.status_code), **kept}
