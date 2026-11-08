"""TraceForge terminal interface."""

from __future__ import annotations

from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Footer, Header, Static

from traceforge import __version__
from traceforge.client import (
    ApiError,
    AuthenticationError,
    BackendUnavailableError,
    TraceForgeClient,
)
from traceforge.tui.widgets import HealthPanel, ProjectsPanel

REFRESH_INTERVAL_SECONDS = 10.0


class TraceForgeApp(App[None]):
    """Minimal dashboard showing backend status."""

    TITLE = "TraceForge"
    SUB_TITLE = f"v{__version__}"
    CSS_PATH = "app.tcss"
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, client: TraceForgeClient, *, poll_backend: bool = True) -> None:
        super().__init__()
        self.client = client
        self.poll_backend = poll_backend

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="main"):
            yield Static(
                "Evidence-driven penetration testing orchestration.\n"
                "Scanning is not available in v0.1.",
                id="intro",
            )
            yield HealthPanel(id="health")
            yield ProjectsPanel(id="projects")
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh()
        if self.poll_backend:
            self.set_interval(REFRESH_INTERVAL_SECONDS, self.action_refresh)

    @work(exclusive=True, group="refresh")
    async def action_refresh(self) -> None:
        health_panel = self.query_one(HealthPanel)
        projects_panel = self.query_one(ProjectsPanel)
        try:
            health = await self.client.health()
        except BackendUnavailableError as exc:
            health_panel.show_error(str(exc))
            projects_panel.show_error("backend unreachable")
            return
        health_panel.show_health(health, self.client.base_url)

        try:
            projects_panel.show_projects(await self.client.list_projects())
        except (AuthenticationError, ApiError, BackendUnavailableError) as exc:
            projects_panel.show_error(str(exc))

    async def on_unmount(self) -> None:
        await self.client.aclose()
