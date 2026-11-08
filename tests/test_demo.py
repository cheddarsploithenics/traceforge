"""scripts/demo.py: idempotent setup and a loopback-only service."""

from __future__ import annotations

import importlib.util
import socket
import threading
from pathlib import Path

import httpx
from fastapi import FastAPI

from tests.conftest import BASE_URL
from traceforge.client import TraceForgeClient

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "demo.py"
spec = importlib.util.spec_from_file_location("traceforge_demo", SCRIPT)
assert spec and spec.loader
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


async def test_prepare_is_idempotent(app: FastAPI) -> None:
    app.state.database.initialize()
    client = TraceForgeClient(
        BASE_URL,
        token_provider=lambda: app.state.api_token,
        transport=httpx.ASGITransport(app=app),
    )
    async with client:
        first_id, first_url = await demo.prepare(client)
        second_id, second_url = await demo.prepare(client)
        projects = await client.list_projects()
        rules = await client.list_scope(first_id)

    assert first_id == second_id
    assert [p.name for p in projects] == ["Local lab"]
    assert [(r.kind, r.value) for r in rules] == [("include", "127.0.0.1/32")]
    assert first_url.startswith("http://127.0.0.1:5173/#code=")
    assert first_url != second_url  # a fresh single-use code each time


def test_service_listens_on_loopback_only_and_sends_banner() -> None:
    server = demo.open_listener(0)
    host, port = server.getsockname()[:2]
    assert host == "127.0.0.1"
    thread = threading.Thread(target=demo.serve_banner, args=(server,), daemon=True)
    thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
        assert conn.recv(64) == demo.BANNER
    server.close()
    thread.join(timeout=2)
    assert not thread.is_alive()  # closing the listener stops the service
