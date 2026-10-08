"""Fetching and caching an issuer's signing keys (SPEC §6.1 step 1).

The only part of delegation that touches the network, and it is built so that
the network is an optimisation rather than a dependency:

* every successful fetch is written to disk, and
* a fetch that fails falls back to that copy without ceremony.

An install that has run once can therefore keep verifying tokens through an
outage, and an air-gapped install can be seeded by copying the cache file in
and never fetching at all. The alternative — treating a JWKS fetch as a
precondition — makes the identity provider a single point of failure for a
gate whose entire purpose is to keep deciding.

What this module will **not** do is fetch a key it was not configured to trust.
``kid`` selects among the keys of a configured issuer; it never names a URL.
A token that could point at its own key server would be a token that signs
itself.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
from joserfc.jwk import KeySet

from gate.core.delegation.claims import TokenVerificationError

__all__ = ["JwksCache", "JwksError", "discover_jwks_uri"]

#: How long a fetched set is reused before another fetch is attempted. Short
#: enough that a rotated key is picked up within the hour, long enough that a
#: busy gate is not hammering its IdP.
DEFAULT_TTL = timedelta(minutes=15)

#: A key that has just appeared is not refetched more than this often, so an
#: unknown `kid` — which is what a rotation looks like from here — cannot be
#: turned into a request amplifier by anyone who can mint junk tokens.
MIN_REFETCH_INTERVAL = timedelta(seconds=30)

HTTP_TIMEOUT = 5.0


class JwksError(TokenVerificationError):
    """No usable key set, from the network or from the cache."""


def discover_jwks_uri(issuer: str, *, client: httpx.Client | None = None) -> str:
    """Resolve an issuer to its ``jwks_uri`` via OIDC discovery."""
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    owned = client is None
    http = client or httpx.Client(timeout=HTTP_TIMEOUT)
    try:
        response = http.get(url)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise JwksError(f"could not discover {issuer}: {exc}") from exc
    finally:
        if owned:
            http.close()
    uri = document.get("jwks_uri")
    if not isinstance(uri, str) or not uri:
        raise JwksError(f"{url} carries no jwks_uri")
    return uri


@dataclass
class _Entry:
    keyset: KeySet
    fetched_at: float
    kids: frozenset[str]


@dataclass
class JwksCache:
    """Key sets per issuer, in memory and on disk.

    ``directory`` is where the on-disk copies live; passing ``None`` keeps the
    cache in memory only, which is what the tests and a read-only container
    root want.
    """

    directory: Path | None = None
    ttl: timedelta = DEFAULT_TTL
    client: httpx.Client | None = None
    offline: bool = False
    _entries: dict[str, _Entry] = field(default_factory=dict, repr=False)
    #: Only unknown-`kid` refetches are recorded here. A scheduled TTL refresh
    #: must not consume the rotation budget, or the first legitimate rotation
    #: after a refresh waits out the interval for no reason.
    _last_kid_miss: dict[str, float] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ disk

    def _cache_path(self, issuer: str) -> Path | None:
        if self.directory is None:
            return None
        safe = "".join(c if c.isalnum() else "_" for c in issuer)
        return self.directory / "jwks" / f"{safe}.json"

    def _read_disk(self, issuer: str) -> dict[str, Any] | None:
        path = self._cache_path(issuer)
        if path is None or not path.exists():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return loaded if isinstance(loaded, dict) else None

    def _write_disk(self, issuer: str, document: dict[str, Any]) -> None:
        path = self._cache_path(issuer)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Written whole and moved into place: a half-written cache file is
            # worse than none, because it fails exactly when the network is
            # also down and the fallback is all there is.
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(document), encoding="utf-8")
            temporary.replace(path)
        except OSError:
            return

    # --------------------------------------------------------------- fetching

    def _fetch(self, jwks_uri: str) -> dict[str, Any]:
        owned = self.client is None
        http = self.client or httpx.Client(timeout=HTTP_TIMEOUT)
        try:
            response = http.get(jwks_uri)
            response.raise_for_status()
            document = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise JwksError(f"could not fetch {jwks_uri}: {exc}") from exc
        finally:
            if owned:
                http.close()
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise JwksError(f"{jwks_uri} did not return a JWK Set")
        return document

    @staticmethod
    def _to_keyset(document: dict[str, Any]) -> tuple[KeySet, frozenset[str]]:
        try:
            keyset = KeySet.import_key_set(document)
        except Exception as exc:  # joserfc raises several unrelated types here
            raise JwksError(f"key set could not be parsed: {exc}") from exc
        kids = frozenset(
            str(key.get("kid")) for key in document["keys"] if key.get("kid") is not None
        )
        return keyset, kids

    # ------------------------------------------------------------------- api

    def get(self, issuer: str, jwks_uri: str, *, kid: str | None = None) -> KeySet:
        """The key set for ``issuer``, fetching only when it has to.

        A ``kid`` that is not in the cached set forces one refetch, bounded by
        :data:`MIN_REFETCH_INTERVAL`: that is what a key rotation looks like
        from this side, and waiting out the TTL would mean every token signed
        with the new key is refused until it expires.
        """
        now = time.monotonic()
        entry = self._entries.get(issuer)

        fresh = entry is not None and (now - entry.fetched_at) < self.ttl.total_seconds()
        kid_miss = False
        if entry is not None and kid is not None and kid not in entry.kids:
            last = self._last_kid_miss.get(issuer)
            if last is None or (now - last) >= MIN_REFETCH_INTERVAL.total_seconds():
                kid_miss = True
                fresh = False

        if entry is not None and fresh:
            return entry.keyset

        if not self.offline:
            if kid_miss:
                self._last_kid_miss[issuer] = now
            try:
                document = self._fetch(jwks_uri)
            except JwksError:
                document = None  # type: ignore[assignment]
            else:
                keyset, kids = self._to_keyset(document)
                self._write_disk(issuer, document)
                self._entries[issuer] = _Entry(keyset, now, kids)
                return keyset

        if entry is not None:
            # The network failed and an in-memory set is already loaded. Serving
            # a stale key beats refusing every action until the IdP is back:
            # expiry still bounds every token this set can verify.
            return entry.keyset

        from_disk = self._read_disk(issuer)
        if from_disk is not None:
            keyset, kids = self._to_keyset(from_disk)
            self._entries[issuer] = _Entry(keyset, now, kids)
            return keyset

        raise JwksError(
            f"no key set for {issuer}: the fetch failed and nothing is cached on disk. "
            "For an air-gapped install, seed the cache file instead of fetching."
        )

    def seed(self, issuer: str, document: dict[str, Any]) -> None:
        """Install a key set directly, for air-gapped use and for tests."""
        keyset, kids = self._to_keyset(document)
        self._entries[issuer] = _Entry(keyset, time.monotonic(), kids)
        self._write_disk(issuer, document)
