"""TraceForge terminal interface."""

from __future__ import annotations

from typing import ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    TabbedContent,
    TabPane,
)

from traceforge import __version__
from traceforge.client import (
    ApiError,
    AuthenticationError,
    BackendUnavailableError,
    TraceForgeClient,
)
from traceforge.schemas import Scan
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

REFRESH_INTERVAL_SECONDS = 10.0
CLIENT_ERRORS = (AuthenticationError, ApiError, BackendUnavailableError)


class TraceForgeApp(App[None]):
    """Backend status, projects, scans, assets and scan comparisons."""

    TITLE = "TraceForge"
    SUB_TITLE = f"v{__version__}"
    CSS_PATH = "app.tcss"
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("o", "show_tab('overview')", "Overview"),
        Binding("s", "show_tab('scans')", "Scans"),
        Binding("a", "show_tab('assets')", "Assets"),
        Binding("d", "show_tab('compare')", "Compare"),
        Binding("c", "compare_highlighted", "Compare with previous"),
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, client: TraceForgeClient, *, poll_backend: bool = True) -> None:
        super().__init__()
        self.client = client
        self.poll_backend = poll_backend
        self.scans: list[Scan] = []

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
            with TabPane("Assets", id="assets"):
                yield AssetsTable(id="asset-list")
                yield AssetDetailPanel(id="asset-detail")
                yield AssetPortsTable(id="asset-ports")
                yield ObservationsTable(id="asset-observations")
            with TabPane("Compare", id="compare"):
                with Horizontal(id="compare-form"):
                    yield Input(placeholder="baseline scan id", id="baseline", type="integer")
                    yield Input(placeholder="comparison scan id", id="comparison", type="integer")
                    yield Button("Compare", id="compare-button", variant="primary")
                yield ComparisonSummaryPanel(id="compare-summary")
                yield ChangesTable(id="compare-changes")
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh()
        if self.poll_backend:
            self.set_interval(REFRESH_INTERVAL_SECONDS, self.action_refresh)

    FOCUS_ON_OPEN: ClassVar[dict[str, str]] = {
        "scans": "#scan-list",
        "assets": "#asset-list",
        "compare": "#baseline",
    }

    def action_show_tab(self, tab: str) -> None:
        if tab in self.FOCUS_ON_OPEN:
            self.query_one(TabbedContent).active = tab
            self.query_one(self.FOCUS_ON_OPEN[tab]).focus()
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
        self.scans = scans
        table = self.query_one(ScansTable)
        table.show_scans(scans)
        if (scan_id := table.selected_scan_id) is not None:
            self.load_results(scan_id)
        try:
            assets = await self.client.list_assets()
        except CLIENT_ERRORS as exc:
            self.query_one(AssetDetailPanel).show_error(str(exc))
            return
        asset_table = self.query_one(AssetsTable)
        asset_table.show_assets(assets)
        if (uid := asset_table.selected_uid) is not None:
            self.load_asset(uid)

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

    @on(DataTable.RowHighlighted, "#asset-list")
    def _asset_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value is not None:
            self.load_asset(event.row_key.value)

    @work(exclusive=True, group="asset")
    async def load_asset(self, uid: str) -> None:
        panel = self.query_one(AssetDetailPanel)
        try:
            asset = await self.client.get_asset(uid)
        except CLIENT_ERRORS as exc:
            panel.show_error(str(exc))
            return
        panel.show_asset(asset)
        self.query_one(AssetPortsTable).show_ports(asset)
        self.query_one(ObservationsTable).show_observations(asset)

    # -- comparisons ---------------------------------------------------------------

    def action_compare_highlighted(self) -> None:
        """Compare the highlighted scan with the previous completed scan of its project."""
        scan_id = self.query_one(ScansTable).selected_scan_id
        current = next((s for s in self.scans if s.id == scan_id), None)
        summary = self.query_one(ComparisonSummaryPanel)
        self.action_show_tab("compare")
        if current is None:
            summary.show_error("highlight a scan on the Scans tab first")
            return
        previous = [
            s
            for s in self.scans
            if s.project_id == current.project_id and s.status == "completed" and s.id < current.id
        ]
        if not previous:
            summary.show_error(f"scan #{current.id} has no earlier completed scan in its project")
            return
        baseline = max(previous, key=lambda s: s.id)
        self.query_one("#baseline", Input).value = str(baseline.id)
        self.query_one("#comparison", Input).value = str(current.id)
        self.run_comparison(baseline.id, current.id)

    @on(Button.Pressed, "#compare-button")
    @on(Input.Submitted, "#baseline, #comparison")
    def _compare_requested(self) -> None:
        summary = self.query_one(ComparisonSummaryPanel)
        try:
            baseline = int(self.query_one("#baseline", Input).value)
            comparison = int(self.query_one("#comparison", Input).value)
        except ValueError:
            summary.show_error("enter two scan ids")
            return
        self.run_comparison(baseline, comparison)

    @work(exclusive=True, group="compare")
    async def run_comparison(self, baseline: int, comparison: int) -> None:
        summary = self.query_one(ComparisonSummaryPanel)
        try:
            scan = await self.client.get_scan(baseline)
            if scan.project_id is None:
                summary.show_error(f"scan #{baseline} has no project")
                return
            result = await self.client.compare_scans(scan.project_id, baseline, comparison)
        except CLIENT_ERRORS as exc:
            detail = exc.detail if isinstance(exc, ApiError) else str(exc)
            summary.show_error(str(detail))
            self.query_one(ChangesTable).clear()
            return
        summary.show_comparison(result)
        self.query_one(ChangesTable).show_changes(result)

    async def on_unmount(self) -> None:
        await self.client.aclose()
