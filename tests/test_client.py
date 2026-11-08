from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from tests.conftest import BASE_URL
from traceforge.client import (
    ApiError,
    AuthenticationError,
    BackendUnavailableError,
    TraceForgeClient,
    file_token_provider,
)
from traceforge.security.tokens import write_token_file


def asgi_client(app: FastAPI, token_provider=None) -> TraceForgeClient:
    app.state.database.initialize()  # ASGITransport does not run the lifespan
    return TraceForgeClient(
        BASE_URL, token_provider=token_provider, transport=httpx.ASGITransport(app=app)
    )


async def test_client_reads_health_from_real_app(app: FastAPI) -> None:
    async with asgi_client(app) as client:
        health = await client.health()
    assert health.status == "ok"


async def test_client_authenticates_with_token_file(app: FastAPI, tmp_path) -> None:
    token_file = tmp_path / "t" / "api.token"
    write_token_file(token_file, app.state.api_token)

    async with asgi_client(app, file_token_provider(token_file)) as client:
        project = await client.create_project("acme", "SOW-1")
        await client.add_scope_rule(project.id, "include", "10.0.0.0/24")
        check = await client.check_scope(project.id, ["10.0.0.1", "10.9.9.9"])
        projects = await client.list_projects()

    assert [d.allowed for d in check.decisions] == [True, False]
    assert projects[0].scope_rule_count == 1


async def test_client_rereads_rotated_token_after_401(app: FastAPI) -> None:
    tokens = iter(["stale-token-from-previous-server", app.state.api_token])
    async with asgi_client(app, lambda: next(tokens)) as client:
        assert await client.list_projects() == []


async def test_client_without_token_file_explains(app: FastAPI, tmp_path) -> None:
    async with asgi_client(app, file_token_provider(tmp_path / "missing")) as client:
        with pytest.raises(AuthenticationError, match="traceforge serve"):
            await client.list_projects()


async def test_client_with_wrong_token_raises(app: FastAPI) -> None:
    async with asgi_client(app, lambda: "wrong") as client:
        with pytest.raises(AuthenticationError, match="rejected"):
            await client.list_projects()


async def test_client_surfaces_scope_violation(app: FastAPI) -> None:
    async with asgi_client(app, lambda: app.state.api_token) as client:
        project = await client.create_project("acme", "SOW-1")
        with pytest.raises(ApiError) as excinfo:
            await client.launch_scan(project.id, "nmap", ["8.8.8.8"])
    assert excinfo.value.status_code == 403


async def test_client_raises_when_backend_unreachable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    async with TraceForgeClient(
        "http://127.0.0.1:9", transport=httpx.MockTransport(refuse)
    ) as client:
        with pytest.raises(BackendUnavailableError, match="cannot reach"):
            await client.health()


async def test_client_rejects_unexpected_status() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(500, text="boom"))

    async with TraceForgeClient("http://127.0.0.1:9", transport=transport) as client:
        with pytest.raises(BackendUnavailableError, match="HTTP 500"):
            await client.health()
