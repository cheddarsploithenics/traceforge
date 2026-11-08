"""TraceForge terminal interface."""

from __future__ import annotations

from typing import ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane

from traceforge import __version__
from traceforge.client import (
    ApiError,
    AuthenticationError,
    BackendUnavailableError,
    TraceForgeClient,
)
from traceforge.tui.widgets import (
    HealthPanel,
    ProjectsPanel,
    ResultsTable,
    ScanDetail,
    ScansTable,
)

REFRESH_INTERVAL_SECONDS = 10.0
CLIENT_ERRORS = (AuthenticationError, ApiError, BackendUnavailableError)


class TraceForgeApp(App[None]):
    """Backend status, projects, and scan history with results."""

    TITLE = "TraceForge"
    SUB_TITLE = f"v{__version__}"
    CSS_PATH = "app.tcss"
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("o", "show_tab('overview')", "Overview"),
        Binding("s", "show_tab('scans')", "Scans"),
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, client: TraceForgeClient, *, poll_backend: bool = True) -> None:
        super().__init__()
        self.client = client
        self.poll_backend = poll_backend

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="overview", id="tabs"):
            with TabPane("Overview", id="overview"), Vertical(id="main"):
                yield Static(
                    "Evidence-driven penetration testing orchestration.\n"
                    "Start scans with [b]traceforge scan run[/b] or the web dashboard; "
                    "press [b]s[/b] to browse results.",
                    id="intro",
                )
                yield HealthPanel(id="health")
                yield ProjectsPanel(id="projects")
            with TabPane("Scans", id="scans"):
                yield ScansTable(id="scan-list")
                yield ScanDetail(id="scan-detail")
                yield ResultsTable(id="scan-results")
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh()
        if self.poll_backend:
            self.set_interval(REFRESH_INTERVAL_SECONDS, self.action_refresh)

    def action_show_tab(self, tab: str) -> None:
        if tab == "scans":
            self.query_one(TabbedContent).active = tab
            self.query_one(ScansTable).focus()
            return
        # Drop focus first: otherwise it moves to the next table in the hidden
        # pane and TabbedContent switches back to the pane holding focus.
        self.set_focus(None)
        self.query_one(TabbedContent).active = tab

    @work(exclusive=True, group="refresh")
    async def action_refresh(self) -> None:
        health_panel = self.query_one(HealthPanel)
        projects_panel = self.query_one(ProjectsPanel)
        detail = self.query_one(ScanDetail)
        try:
            health = await self.client.health()
        except BackendUnavailableError as exc:
            health_panel.show_error(str(exc))
            projects_panel.show_error("backend unreachable")
            detail.show_error("backend unreachable")
            return
        health_panel.show_health(health, self.client.base_url)

        try:
            projects_panel.show_projects(await self.client.list_projects())
            scans = await self.client.list_scans(limit=200)
        except CLIENT_ERRORS as exc:
            projects_panel.show_error(str(exc))
            detail.show_error(str(exc))
            return
        table = self.query_one(ScansTable)
        table.show_scans(scans)
        if (scan_id := table.selected_scan_id) is not None:
            self.load_results(scan_id)

    @on(DataTable.RowHighlighted, "#scan-list")
    def _scan_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value is not None:
            self.load_results(int(event.row_key.value))

    @work(exclusive=True, group="results")
    async def load_results(self, scan_id: int) -> None:
        detail = self.query_one(ScanDetail)
        try:
            results = await self.client.get_scan_results(scan_id)
        except CLIENT_ERRORS as exc:
            detail.show_error(str(exc))
            return
        detail.show_scan(results.scan, len(results.hosts))
        self.query_one(ResultsTable).show_results(results)

    async def on_unmount(self) -> None:
        await self.client.aclose()
