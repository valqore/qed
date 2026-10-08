"""Upstream servers for the proxy tests.

Deliberately raw. An ``httpx`` test server would answer requests, which is
not what needs checking: what needs checking is the exact bytes the proxy
forwards, and specifically which credential header arrives. So the echo
server hands the request head back as the response body and the tests read it.

The TCP server exists for the tunnel tests. A tunnel carries whatever the
client puts in it, so the thing to prove is that arbitrary bytes survive the
round trip and that the counters match -- not that TLS works, which is not the
proxy's job in ``host_path`` mode.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


@asynccontextmanager
async def echo_server() -> AsyncIterator[tuple[str, int]]:
    """An HTTP server whose 200 body is the request it received, as JSON."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        request_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
        body = b""
        length = int(headers.get("content-length", "0") or "0")
        if length:
            body = await reader.readexactly(length)
        payload = json.dumps(
            {
                "request_line": request_line,
                "headers": headers,
                "body": body.decode("utf-8", "replace"),
            }
        ).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(payload)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + payload
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    try:
        yield str(host), int(port)
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def tcp_echo() -> AsyncIterator[tuple[str, int]]:
    """A server that echoes raw bytes, for what goes through a tunnel."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while chunk := await reader.read(4096):
                writer.write(chunk)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    try:
        yield str(host), int(port)
    finally:
        server.close()
        await server.wait_closed()


async def closed_port() -> int:
    """A port with nothing listening on it, for the 502 path."""
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    server.close()
    await server.wait_closed()
    return port
