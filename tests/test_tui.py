from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from tests.conftest import BASE_URL
from traceforge.client import TraceForgeClient
from traceforge.tui import TraceForgeApp
from traceforge.tui.widgets import (
    AssetDetailPanel,
    AssetPortsTable,
    AssetsTable,
    ChangesTable,
    ComparisonSummaryPanel,
    HealthPanel,
    ObservationsTable,
    ProjectsPanel,
    ResultsTable,
    ScanDetail,
    ScansTable,
)


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


def seed_scan(app: FastAPI, product: str = "OpenSSH") -> int:
    from traceforge.execution.tools import HostResult, PortResult, ToolReport

    executor = app.state.executor
    project = executor.projects.create("acme", "SOW-42")
    scan_id = executor.scans.create(
        project["id"], "nmap", ["app.example.com"], scan_addresses=["93.184.216.34"]
    )
    executor.scans.mark_running(scan_id)
    report = ToolReport(
        hosts=(
            HostResult(
                "93.184.216.34",
                "ipv4",
                "up",
                ports=(
                    PortResult("tcp", 22, "open", service_name="ssh", service_product=product),
                    PortResult("tcp", 443, "filtered", service_name="https"),
                ),
            ),
        )
    )
    executor.results.store(scan_id, project["id"], report, {"93.184.216.34": ["app.example.com"]})
    executor.scans.finish(scan_id, "completed", exit_code=0)
    return scan_id


def asgi_tui(app: FastAPI) -> TraceForgeApp:
    client = TraceForgeClient(
        BASE_URL,
        token_provider=lambda: app.state.api_token,
        transport=httpx.ASGITransport(app=app),
    )
    return TraceForgeApp(client, poll_backend=False)


def plain_rows(table) -> list[list[str]]:
    return [[str(c) for c in table.get_row_at(i)] for i in range(table.row_count)]


async def test_tui_lists_scans_and_shows_results(app: FastAPI) -> None:
    app.state.database.initialize()
    scan_id = seed_scan(app)
    tui = asgi_tui(app)

    async with tui.run_test(size=(140, 45)) as pilot:
        await pilot.press("s")
        await tui.workers.wait_for_complete()
        await pilot.pause()
        await tui.workers.wait_for_complete()

        assert tui.query_one("#tabs").active == "scans"
        scans = tui.query_one(ScansTable)
        assert plain_rows(scans)[0][:5] == [str(scan_id), "completed", "1", "app.example.com", "1"]

        detail = tui.query_one(ScanDetail).render().plain
        assert "COMPLETED" in detail and "93.184.216.34" in detail

        results = plain_rows(tui.query_one(ResultsTable))
        assert results == [
            ["93.184.216.34 (app.example.com)", "22/tcp", "open", "ssh", "OpenSSH"],
            ["93.184.216.34 (app.example.com)", "443/tcp", "filtered", "https", ""],
        ]

        await pilot.press("o")
        assert tui.query_one("#tabs").active == "overview"


async def test_tui_scan_results_render_banners_literally(app: FastAPI) -> None:
    app.state.database.initialize()
    hostile = "[@click=app.quit]pwn[/] [red]x[/red] [/b]"
    seed_scan(app, product=hostile)
    tui = asgi_tui(app)

    async with tui.run_test(size=(140, 45)) as pilot:
        await pilot.press("s")
        await tui.workers.wait_for_complete()
        await pilot.pause()
        await tui.workers.wait_for_complete()
        row = plain_rows(tui.query_one(ResultsTable))[0]

    assert row[4] == hostile
    assert tui.return_code is None  # the embedded click action did not quit the app


async def test_tui_scans_tab_with_no_scans(app: FastAPI) -> None:
    app.state.database.initialize()
    tui = asgi_tui(app)
    async with tui.run_test() as pilot:
        await pilot.press("s")
        await tui.workers.wait_for_complete()
        await pilot.pause()
        assert tui.query_one(ScansTable).row_count == 0
        assert "Select a scan" in tui.query_one(ScanDetail).render().plain


# --- assets & comparisons (v0.3) ---------------------------------------------------


def seed_inventory(app: FastAPI, settings) -> tuple[int, int]:
    from tests.inventory_helpers import record_scan
    from tests.nmapxml import Host, Port, nmap_xml

    db = app.state.database
    db.initialize()
    settings.evidence_path.mkdir(parents=True, exist_ok=True)
    pid = app.state.executor.projects.create("acme", "SOW-42")["id"]
    before = nmap_xml(
        Host(
            "10.0.0.5",
            [
                Port(22, service="ssh", product="OpenSSH", version="9.6p1"),
                Port(8080, service="http-proxy", method="table"),
            ],
        ),
        services="22,8080",
    )
    after = nmap_xml(
        Host(
            "10.0.0.5",
            [Port(22, service="ssh", product="OpenSSH", version="9.7p1")],
            extraports=[("closed", 1, "8080")],
        ),
        services="22,8080",
        offset=60,
    )
    first = record_scan(db, settings.evidence_path, pid, before)
    second = record_scan(db, settings.evidence_path, pid, after)
    return first, second


async def test_tui_lists_assets_and_shows_details(app: FastAPI, settings) -> None:
    seed_inventory(app, settings)
    tui = asgi_tui(app)

    async with tui.run_test(size=(160, 50)) as pilot:
        await pilot.press("a")
        await tui.workers.wait_for_complete()
        await pilot.pause()
        await tui.workers.wait_for_complete()

        assert tui.query_one("#tabs").active == "assets"
        (row,) = plain_rows(tui.query_one(AssetsTable))
        assert row[0] == "10.0.0.5" and row[3] == "1" and row[4] == "22/ssh"
        ports = plain_rows(tui.query_one(AssetPortsTable))
        assert ports[0][:5] == ["22/tcp", "open", "ssh", "detected", "OpenSSH 9.7p1"]
        assert ports[1][:4] == ["8080/tcp", "closed", "http-proxy", "port label"]
        observations = plain_rows(tui.query_one(ObservationsTable))
        assert [o[0] for o in observations] == ["#2", "#1"]
        assert observations[0][3] == "10.0.0.0/24 → 10.0.0.5"
        assert "ast_" in tui.query_one(AssetDetailPanel).render().plain


async def test_tui_compares_highlighted_scan_with_previous(app: FastAPI, settings) -> None:
    first, second = seed_inventory(app, settings)
    tui = asgi_tui(app)

    async with tui.run_test(size=(160, 50)) as pilot:
        await tui.workers.wait_for_complete()
        await pilot.press("s")
        await pilot.pause()
        await pilot.press("c")  # newest scan is highlighted: compare with the previous one
        await tui.workers.wait_for_complete()
        await pilot.pause()

        assert tui.query_one("#tabs").active == "compare"
        assert tui.query_one("#baseline").value == str(first)
        assert tui.query_one("#comparison").value == str(second)
        rows = plain_rows(tui.query_one(ChangesTable))
        assert [r[:5] for r in rows] == [
            ["-", "removed", "10.0.0.5", "8080/tcp", "port closed"],
            ["~", "changed", "10.0.0.5", "22/tcp", "version changed"],
        ]
        assert "+0 added" in tui.query_one(ComparisonSummaryPanel).render().plain


async def test_tui_compare_reports_api_errors(app: FastAPI, settings) -> None:
    first, _ = seed_inventory(app, settings)
    tui = asgi_tui(app)
    async with tui.run_test(size=(160, 50)) as pilot:
        await pilot.press("d")
        await pilot.press(*str(first), "tab", *str(first), "enter")
        await tui.workers.wait_for_complete()
        await pilot.pause()
        text = tui.query_one(ComparisonSummaryPanel).render().plain
    assert "Cannot compare" in text and "two different scans" in text
