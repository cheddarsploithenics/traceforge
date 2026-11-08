"""Reusable widgets for the terminal interface."""

from __future__ import annotations

from rich.text import Text
from textual.markup import escape
from textual.widgets import DataTable, Static

from traceforge.schemas import (
    AssetDetail,
    AssetSummary,
    ComparisonSide,
    HealthResponse,
    Project,
    Scan,
    ScanComparison,
    ScanResults,
)


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


# --- assets & comparisons (v0.3) ---------------------------------------------------

IDENTIFICATION_LABELS = {"detected": "detected", "port-label": "port label"}
CHANGE_STYLES = {
    "added": ("+", "green"),
    "removed": ("-", "red"),
    "changed": ("~", "yellow"),
    "inconclusive": ("?", "dim"),
}


class AssetsTable(DataTable):
    """The asset inventory. Highlighting a row loads the asset's details."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=True)
        self.border_title = "Assets"
        self.add_columns("Address", "Hostnames", "Project", "Open", "Services", "Last seen")

    def show_assets(self, assets: list[AssetSummary]) -> None:
        selected = self.selected_uid
        self.clear()
        for a in assets:
            services = ", ".join(f"{s.port}/{s.service_name or '?'}" for s in a.services)
            self.add_row(
                cell(a.address),
                cell(", ".join(a.hostnames)),
                cell(a.project_name),
                cell(a.open_ports, "bold" if a.open_ports else "dim"),
                cell(services),
                cell(f"{a.last_seen:%Y-%m-%d %H:%M}"),
                key=a.uid,
            )
        if selected is not None and selected in self.rows:
            self.move_cursor(row=self.get_row_index(selected))

    @property
    def selected_uid(self) -> str | None:
        if not self.row_count:
            return None
        try:
            key = self.coordinate_to_cell_key(self.cursor_coordinate).row_key
        except Exception:
            return None
        return key.value


class AssetDetailPanel(Static):
    DEFAULT_CLASSES = "panel"

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__("Select an asset to see its ports and history.", id=id)
        self.border_title = "Asset"

    def show_asset(self, asset: AssetDetail) -> None:
        names = f"  ({escape(', '.join(asset.hostnames))})" if asset.hostnames else ""
        self.remove_class("-error")
        self.update(
            f"[b]{escape(asset.address)}[/b]{names}   {escape(asset.uid)}\n"
            f"Project:    {escape(asset.project_name)}\n"
            f"First seen: {asset.first_seen:%Y-%m-%d %H:%M:%S}   "
            f"Last seen: {asset.last_seen:%Y-%m-%d %H:%M:%S}\n"
            f"Open ports: {asset.open_ports}   Observations: {len(asset.observations)}"
        )

    def show_error(self, message: str) -> None:
        self.add_class("-error")
        self.update(f"[b]Unavailable:[/b] {escape(message)}")


class AssetPortsTable(DataTable):
    """Current state of each port, with how the service was identified."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=True)
        self.border_title = "Ports"
        self.add_columns("Port", "State", "Service", "Identified by", "Version", "Last checked")

    def show_ports(self, asset: AssetDetail) -> None:
        self.clear()
        for p in asset.ports:
            version = " ".join(v for v in (p.service_product, p.service_version) if v)
            self.add_row(
                cell(f"{p.port}/{p.protocol}"),
                cell(p.state, "green" if p.state == "open" else "dim"),
                cell(p.service_name),
                cell(IDENTIFICATION_LABELS.get(p.identification or "", "")),
                cell(version),
                cell(f"{p.last_seen:%Y-%m-%d %H:%M} (scan #{p.state_scan_id})"),
            )


class ObservationsTable(DataTable):
    """Every observation of the asset, with its provenance."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=True)
        self.border_title = "Observations (provenance)"
        self.add_columns("Scan", "Observed", "Tool", "Requested → scanned", "Open", "Evidence")

    def show_observations(self, asset: AssetDetail) -> None:
        self.clear()
        for o in asset.observations:
            prov = o.provenance
            evidence = f"{prov.evidence.sha256[:12]}… {prov.evidence.file}" if prov.evidence else ""
            self.add_row(
                cell(f"#{o.scan_id}"),
                cell(f"{o.observed_at:%Y-%m-%d %H:%M:%S}"),
                cell(f"{prov.tool or ''} {prov.tool_version or ''}".strip()),
                cell(f"{', '.join(prov.requested_targets) or '-'} → {prov.scanned_address}"),
                cell(sum(1 for p in o.ports if p.state == "open")),
                cell(evidence),
            )


class ComparisonSummaryPanel(Static):
    DEFAULT_CLASSES = "panel"

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(
            "Highlight a scan on the Scans tab and press [b]c[/b] to compare it with the previous "
            "completed scan of its project, or enter two scan ids below.",
            id=id,
        )
        self.border_title = "Comparison"

    def show_comparison(self, result: ScanComparison) -> None:
        self.remove_class("-error")
        s = result.summary

        def side(label: str, x: ComparisonSide) -> str:
            ports = ", ".join(f"{k} {v}" for k, v in (x.ports_scanned or {}).items()) or "unknown"
            flags = [
                f for f, on in (("-Pn", not x.host_discovery), ("-sV", x.service_detection)) if on
            ]
            return f"{label} #{x.scan_id}  ports {escape(ports)}  {' '.join(flags)}"

        lines = [
            side("Baseline:  ", result.baseline),
            side("Comparison:", result.comparison),
            f"[green]+{s.added} added[/]  [red]-{s.removed} removed[/]  "
            f"[yellow]~{s.changed} changed[/]  [dim]?{s.inconclusive} inconclusive[/]  "
            f"{s.unchanged_open_ports} open port(s) unchanged",
        ]
        lines += [f"[dim]note:[/dim] {escape(note)}" for note in result.notes]
        self.update("\n".join(lines))

    def show_error(self, message: str) -> None:
        self.add_class("-error")
        self.update(f"[b]Cannot compare:[/b] {escape(message)}")


class ChangesTable(DataTable):
    """Comparison results. Category is shown as a symbol and a word, not only a color."""

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id, cursor_type="row", zebra_stripes=True)
        self.border_title = "Differences"
        self.add_columns("", "Category", "Host", "Port", "Change", "Detail")

    def show_changes(self, result: ScanComparison) -> None:
        self.clear()
        for c in result.changes:
            symbol, style = CHANGE_STYLES[c.category]
            self.add_row(
                cell(symbol, style),
                cell(c.category, style),
                cell(c.address),
                cell(f"{c.port}/{c.protocol}" if c.port is not None else ""),
                cell(c.kind.replace("_", " ")),
                cell(c.detail),
            )
