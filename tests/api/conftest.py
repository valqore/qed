"""Fixtures for the API tests.

The signing helper is the point of this file. Every ``/v1`` request has to carry
a real HMAC, so the tests sign the way an adapter does, through the same
``qed.api.auth`` functions. A test helper that computed the MAC its own way
would pass while the two sides disagreed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qed.api.app import create_app
from qed.api.auth import (
    HEADER_ADAPTER,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_string,
    sign,
)
from qed.core.schemas import rfc3339_ms, utcnow
from qed.infra.keys.file import init_keys

ADAPTER_ID = "adp_test"
SECRET_ENV = "QED_TEST_ADAPTER_SECRET"
SECRET = "s" * 48


class Signer:
    """Signs requests the way an adapter does, then sends them."""

    def __init__(self, client: TestClient, *, adapter_id: str = ADAPTER_ID) -> None:
        self.client = client
        self.adapter_id = adapter_id

    def headers(self, method: str, path: str, body: bytes, *, nonce: str = "") -> dict[str, str]:
        timestamp = rfc3339_ms(utcnow())
        canonical = canonical_string(
            method=method, path=path, timestamp=timestamp, nonce=nonce, body=body
        )
        return {
            HEADER_ADAPTER: self.adapter_id,
            HEADER_TIMESTAMP: timestamp,
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: sign(SECRET, canonical),
        }

    def post(self, path: str, payload: object, **kwargs: Any) -> Any:
        body = json.dumps(payload).encode("utf-8")
        headers = {**self.headers("POST", path, body), "content-type": "application/json"}
        headers.update(kwargs.pop("headers", {}))
        return self.client.post(path, content=body, headers=headers, **kwargs)

    def get(self, path: str, **kwargs: Any) -> Any:
        # The MAC covers the path without the query string, matching what the
        # server sees in `request.url.path`.
        base = path.split("?", 1)[0]
        headers = {**self.headers("GET", base, b"")}
        headers.update(kwargs.pop("headers", {}))
        return self.client.get(path, headers=headers, **kwargs)


@pytest.fixture
def qed_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(SECRET_ENV, SECRET)
    path = tmp_path / "qed.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "instance_id": "qed-local",
                "mode": "shadow",
                "adapters": [{"adapter_id": ADAPTER_ID, "secret_env": SECRET_ENV, "kind": "mcp"}],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def api_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "qed"
    init_keys(directory)
    return directory


@pytest.fixture
def app(api_dir: Path, qed_config: Path) -> FastAPI:
    return create_app(directory=api_dir, config_path=qed_config)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as started:
        yield started


@pytest.fixture
def signed(client: TestClient) -> Signer:
    return Signer(client)
