from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from tests.conftest import BASE_URL
from traceforge.client import TraceForgeClient
from traceforge.tui import TraceForgeApp
from traceforge.tui.widgets import HealthPanel, ProjectsPanel


async def test_tui_shows_healthy_backend_and_projects(app: FastAPI) -> None:
    app.state.database.initialize()
    app.state.executor.projects.create("acme", "SOW-42")
    client = TraceForgeClient(
        BASE_URL,
        token_provider=lambda: app.state.api_token,
        transport=httpx.ASGITransport(app=app),
    )
    tui = TraceForgeApp(client, poll_backend=False)

    async with tui.run_test() as pilot:
        await tui.workers.wait_for_complete()
        await pilot.pause()
        health = tui.query_one(HealthPanel)
        projects = tui.query_one(ProjectsPanel).render().plain

        assert "OK" in str(health.content)
        assert health.has_class("-ok")
        assert "acme" in projects and "SOW-42" in projects


async def test_tui_without_token_reports_authentication_problem(app: FastAPI) -> None:
    app.state.database.initialize()
    client = TraceForgeClient(
        BASE_URL, token_provider=lambda: None, transport=httpx.ASGITransport(app=app)
    )
    tui = TraceForgeApp(client, poll_backend=False)

    async with tui.run_test() as pilot:
        await tui.workers.wait_for_complete()
        await pilot.pause()
        panel = tui.query_one(ProjectsPanel)

        assert "no API token found" in panel.render().plain
        assert panel.has_class("-error")


async def test_tui_reports_unreachable_backend_and_can_refresh() -> None:
    calls = 0

    def refuse(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("connection refused", request=request)

    client = TraceForgeClient("http://127.0.0.1:9", transport=httpx.MockTransport(refuse))
    tui = TraceForgeApp(client, poll_backend=False)

    async with tui.run_test() as pilot:
        await tui.workers.wait_for_complete()
        await pilot.pause()
        panel = tui.query_one(HealthPanel)
        assert "UNREACHABLE" in str(panel.content)
        assert panel.has_class("-error")

        await pilot.press("r")
        await tui.workers.wait_for_complete()

    assert calls == 2


@pytest.mark.parametrize(
    "message",
    [
        "closing tag [/b] without opener",  # previously crashed the refresh worker
        "[@click=app.quit]click me[/]",  # must not become a clickable action
        "[red]styled[/red]",
    ],
)
async def test_tui_displays_untrusted_text_literally(message: str) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(message, request=request)

    client = TraceForgeClient("http://[::1]:8000", transport=httpx.MockTransport(refuse))
    tui = TraceForgeApp(client, poll_backend=False)

    async with tui.run_test() as pilot:
        await tui.workers.wait_for_complete()
        await pilot.pause()
        rendered = tui.query_one(HealthPanel).render().plain

    assert message in rendered
    assert "http://[::1]:8000" in rendered
