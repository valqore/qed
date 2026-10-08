"""JWKS fetching and the offline fallback (SPEC §6.1 step 1).

The property under test throughout: the network is an optimisation, not a
dependency. A gate whose purpose is to keep deciding must not stop deciding
because its identity provider is unreachable.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from joserfc.jwk import RSAKey

from gate.infra.jwks import JwksCache, JwksError, discover_jwks_uri

ISSUER = "https://idp.example"
JWKS_URI = f"{ISSUER}/jwks"


def key_document(kid: str) -> dict[str, Any]:
    key = RSAKey.generate_key(2048, parameters={"kid": kid})
    return {"keys": [key.as_dict(private=False)]}


class Recorder:
    """An httpx transport that counts requests and can be told to fail."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document
        self.calls = 0
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.fail:
            raise httpx.ConnectError("network is down", request=request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"jwks_uri": JWKS_URI})
        return httpx.Response(200, json=self.document)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def recorder() -> Recorder:
    return Recorder(key_document("idp-1"))


class TestDiscovery:
    def test_the_jwks_uri_comes_from_the_discovery_document(self, recorder: Recorder) -> None:
        assert discover_jwks_uri(ISSUER, client=recorder.client()) == JWKS_URI

    def test_a_discovery_document_without_a_jwks_uri_is_an_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"issuer": ISSUER})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(JwksError, match="no jwks_uri"):
            discover_jwks_uri(ISSUER, client=client)

    def test_an_unreachable_issuer_is_an_error_not_a_crash(self, recorder: Recorder) -> None:
        recorder.fail = True
        with pytest.raises(JwksError, match="could not discover"):
            discover_jwks_uri(ISSUER, client=recorder.client())


class TestFetchAndCache:
    def test_the_first_call_fetches(self, recorder: Recorder) -> None:
        cache = JwksCache(client=recorder.client())
        cache.get(ISSUER, JWKS_URI)
        assert recorder.calls == 1

    def test_a_second_call_inside_the_ttl_does_not_fetch(self, recorder: Recorder) -> None:
        cache = JwksCache(client=recorder.client())
        cache.get(ISSUER, JWKS_URI)
        cache.get(ISSUER, JWKS_URI)
        assert recorder.calls == 1

    def test_an_expired_ttl_fetches_again(self, recorder: Recorder) -> None:
        cache = JwksCache(client=recorder.client(), ttl=timedelta(seconds=0))
        cache.get(ISSUER, JWKS_URI)
        cache.get(ISSUER, JWKS_URI)
        assert recorder.calls == 2

    def test_an_unknown_kid_forces_one_refetch(self, recorder: Recorder) -> None:
        """What a key rotation looks like from this side. Waiting out the TTL
        would refuse every token signed with the new key until it expired."""
        cache = JwksCache(client=recorder.client())
        cache.get(ISSUER, JWKS_URI)
        cache.get(ISSUER, JWKS_URI, kid="idp-2")
        assert recorder.calls == 2

    def test_a_known_kid_does_not_refetch(self, recorder: Recorder) -> None:
        cache = JwksCache(client=recorder.client())
        cache.get(ISSUER, JWKS_URI)
        cache.get(ISSUER, JWKS_URI, kid="idp-1")
        assert recorder.calls == 1

    def test_a_flood_of_unknown_kids_is_rate_limited(self, recorder: Recorder) -> None:
        """Otherwise anyone able to mint junk tokens turns this into a request
        amplifier pointed at the identity provider."""
        cache = JwksCache(client=recorder.client())
        cache.get(ISSUER, JWKS_URI)
        for n in range(50):
            cache.get(ISSUER, JWKS_URI, kid=f"forged-{n}")
        assert recorder.calls == 2


class TestOfflineFallback:
    def test_a_failed_fetch_falls_back_to_the_loaded_set(self, recorder: Recorder) -> None:
        cache = JwksCache(client=recorder.client(), ttl=timedelta(seconds=0))
        first = cache.get(ISSUER, JWKS_URI)
        recorder.fail = True
        assert cache.get(ISSUER, JWKS_URI) is first

    def test_a_cold_start_during_an_outage_reads_the_disk_copy(
        self, tmp_path: Path, recorder: Recorder
    ) -> None:
        """The case that matters: the process restarted while the IdP is down."""
        warm = JwksCache(directory=tmp_path, client=recorder.client())
        warm.get(ISSUER, JWKS_URI)

        recorder.fail = True
        cold = JwksCache(directory=tmp_path, client=recorder.client())
        assert cold.get(ISSUER, JWKS_URI) is not None

    def test_nothing_fetched_and_nothing_cached_is_an_honest_error(
        self, tmp_path: Path, recorder: Recorder
    ) -> None:
        recorder.fail = True
        cache = JwksCache(directory=tmp_path, client=recorder.client())
        with pytest.raises(JwksError, match="air-gapped"):
            cache.get(ISSUER, JWKS_URI)

    def test_an_air_gapped_install_can_be_seeded_without_a_fetch(
        self, tmp_path: Path, recorder: Recorder
    ) -> None:
        cache = JwksCache(directory=tmp_path, offline=True, client=recorder.client())
        cache.seed(ISSUER, recorder.document)
        assert cache.get(ISSUER, JWKS_URI) is not None
        assert recorder.calls == 0, "offline mode must not touch the network"

    def test_offline_mode_never_fetches_even_with_an_unknown_kid(
        self, tmp_path: Path, recorder: Recorder
    ) -> None:
        cache = JwksCache(directory=tmp_path, offline=True, client=recorder.client())
        cache.seed(ISSUER, recorder.document)
        cache.get(ISSUER, JWKS_URI, kid="idp-9")
        assert recorder.calls == 0


class TestBadInput:
    def test_a_response_that_is_not_a_jwk_set_is_refused(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"not": "a key set"})

        cache = JwksCache(client=httpx.Client(transport=httpx.MockTransport(handler)))
        with pytest.raises(JwksError):
            cache.get(ISSUER, JWKS_URI)

    def test_a_corrupt_disk_cache_does_not_crash_the_fetch_path(
        self, tmp_path: Path, recorder: Recorder
    ) -> None:
        path = tmp_path / "jwks"
        path.mkdir()
        (path / "https___idp_example.json").write_text("{ not json", encoding="utf-8")
        cache = JwksCache(directory=tmp_path, client=recorder.client())
        assert cache.get(ISSUER, JWKS_URI) is not None

    def test_the_disk_copy_is_written_whole(self, tmp_path: Path, recorder: Recorder) -> None:
        """A half-written cache file fails exactly when the network is also
        down and the fallback is all there is."""
        cache = JwksCache(directory=tmp_path, client=recorder.client())
        cache.get(ISSUER, JWKS_URI)
        written = next((tmp_path / "jwks").glob("*.json"))
        assert "keys" in json.loads(written.read_text(encoding="utf-8"))
        assert not list((tmp_path / "jwks").glob("*.tmp"))
