"""Reusable widgets for the terminal interface."""

from __future__ import annotations

from rich.text import Text
from textual.markup import escape
from textual.widgets import DataTable, Static

from traceforge.schemas import HealthResponse, Project, Scan, ScanResults


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


# --- scans ---------------------------------------------------------------------------

STATUS_STYLES = {
    "queued": "yellow",
    "running": "bold cyan",
    "completed": "green",
    "failed": "bold red",
    "cancelled": "dim",
}


def cell(value: object, style: str = "") -> Text:
    """A table cell rendered literally.

    DataTable parses plain ``str`` cells as markup, and scan results contain
    text chosen by the scanned host (service banners), so every cell is a
    :class:`Text` instance, which is never interpreted.
    """
    return Text("" if value is None else str(value), style=style)


class ScansTable(DataTable):
    """Scan history, newest first. Highlighting a row loads its results."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=True)
        self.border_title = "Scans"
        self.add_columns("ID", "Status", "Project", "Targets", "Open", "Created")

    def show_scans(self, scans: list[Scan]) -> None:
        selected = self.selected_scan_id
        self.clear()
        for s in scans:
            self.add_row(
                cell(s.id),
                cell(s.status, STATUS_STYLES.get(s.status, "")),
                cell(s.project_id),
                cell(", ".join(s.targets)),
                cell(s.open_ports),
                cell(f"{s.created_at:%Y-%m-%d %H:%M}"),
                key=str(s.id),
            )
        if selected is not None and str(selected) in self.rows:
            self.move_cursor(row=self.get_row_index(str(selected)))

    @property
    def selected_scan_id(self) -> int | None:
        if not self.row_count:
            return None
        try:
            key = self.coordinate_to_cell_key(self.cursor_coordinate).row_key
        except Exception:
            return None
        return int(key.value) if key.value is not None else None


class ScanDetail(Static):
    """Summary of the selected scan."""

    DEFAULT_CLASSES = "panel"

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__("Select a scan to see its results.", id=id)
        self.border_title = "Scan"

    def show_scan(self, scan: Scan, host_count: int) -> None:
        lines = [
            f"#{scan.id}  {escape(scan.tool or '')}  [b]{escape(scan.status.upper())}[/b]"
            f"  — project {scan.project_id}, by {escape(scan.actor or '?')}",
            f"Targets:  {escape(', '.join(scan.targets))}",
            f"Scanned:  {escape(', '.join(scan.scan_addresses))}",
            f"Started:  {scan.started_at or '—'}   Finished: {scan.finished_at or '—'}",
            f"Hosts:    {host_count} ({scan.hosts_up} up), {scan.open_ports} open port(s)",
        ]
        if scan.error:
            lines.append(f"Error:    {escape(scan.error)}")
        if scan.evidence:
            lines.append(f"Evidence: {escape(scan.evidence.file)}")
        self.set_class(scan.status == "failed", "-error")
        self.set_class(scan.status == "completed", "-ok")
        self.update("\n".join(lines))

    def show_error(self, message: str) -> None:
        self.add_class("-error")
        self.update(f"[b]Unavailable:[/b] {escape(message)}")


class ResultsTable(DataTable):
    """Ports and services discovered by the selected scan."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=True)
        self.border_title = "Results"
        self.add_columns("Host", "Port", "State", "Service", "Version")

    def show_results(self, results: ScanResults) -> None:
        self.clear()
        for host in results.hosts:
            label = host.address + (f" ({', '.join(host.hostnames)})" if host.hostnames else "")
            if not host.ports:
                self.add_row(cell(label), cell("—"), cell(host.state), cell(""), cell(""))
            for p in host.ports:
                version = " ".join(
                    v for v in (p.service_product, p.service_version, p.service_extrainfo) if v
                )
                self.add_row(
                    cell(label),
                    cell(f"{p.port}/{p.protocol}"),
                    cell(p.state, "green" if p.state == "open" else "dim"),
                    cell(p.service_name),
                    cell(version),
                )
