"""Reusable widgets for the terminal interface."""

from __future__ import annotations

from textual.markup import escape
from textual.widgets import Static

from traceforge.schemas import HealthResponse, Project


class HealthPanel(Static):
    """Displays the most recent backend health check.

    Every value that originates outside this module (API responses, URLs,
    exception messages) is passed through :func:`escape` so it is shown
    literally instead of being parsed as Textual markup.
    """

    DEFAULT_CLASSES = "panel"

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__("Checking backend…", id=id)
        self.border_title = "Backend health"

    def show_health(self, health: HealthResponse, base_url: str) -> None:
        self.set_class(health.status == "ok", "-ok")
        self.set_class(health.status != "ok", "-error")
        self.update(
            f"Status:    [b]{escape(health.status.upper())}[/b]\n"
            f"Version:   {escape(health.version)}\n"
            f"Database:  {escape(health.database)}\n"
            f"Endpoint:  {escape(base_url)}"
        )

    def show_error(self, message: str) -> None:
        self.remove_class("-ok")
        self.add_class("-error")
        self.update(
            f"Status:    [b]UNREACHABLE[/b]\n{escape(message)}\n\n"
            "Start the API with:  [b]traceforge serve[/b]"
        )


class ProjectsPanel(Static):
    """Lists projects and their authorized scope size (requires the API token)."""

    DEFAULT_CLASSES = "panel"

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__("Loading projects…", id=id)
        self.border_title = "Projects"

    def show_projects(self, projects: list[Project]) -> None:
        self.remove_class("-error")
        if not projects:
            self.update(
                "No projects yet. Create one with:\n"
                "  [b]traceforge project create NAME --authorization-ref REF[/b]"
            )
            return
        lines = [
            f"#{p.id}  {escape(p.name)}  —  {p.scope_rule_count} scope rule(s)  "
            f"[dim]({escape(p.authorization_ref)})[/dim]"
            for p in projects
        ]
        self.update("\n".join(lines))

    def show_error(self, message: str) -> None:
        self.add_class("-error")
        self.update(f"[b]Unavailable:[/b] {escape(message)}")
