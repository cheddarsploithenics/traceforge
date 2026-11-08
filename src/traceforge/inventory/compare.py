"""Compare two completed scans of the same project.

Results are calculated on demand from the stored observations (never cached),
so they always reflect the same rules as the asset inventory.

Every difference falls into one category:

* ``added`` / ``removed`` / ``changed`` — **confirmed**: both scans actually
  observed the thing in question and the observations differ;
* ``inconclusive`` — one side has no observation (port not scanned, host
  timed out, coverage unknown, target not in scope of that scan), or the
  observation is ambiguous (``filtered`` means "no answer", not "closed"; a
  port-number label is not a detected service).

A port that scan A saw open and scan B never probed is reported as *not
checked*, never as closed.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from traceforge.inventory.model import OPEN, HostObservation, PortObservation, ScanContext
from traceforge.inventory.store import load_observations, load_scan, port_view


class ComparisonError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Change:
    category: str  # added | removed | changed | inconclusive
    kind: str
    address: str
    detail: str
    asset_uid: str | None = None
    hostnames: tuple[str, ...] = ()
    protocol: str | None = None
    port: int | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "kind": self.kind,
            "address": self.address,
            "asset_uid": self.asset_uid,
            "hostnames": list(self.hostnames),
            "protocol": self.protocol,
            "port": self.port,
            "before": self.before,
            "after": self.after,
            "detail": self.detail,
        }


def _side(scan: ScanContext, observations: list[HostObservation]) -> dict[str, Any]:
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "created_at": scan.created_at,
        "finished_at": scan.finished_at,
        "tool": scan.tool,
        "tool_version": scan.tool_version,
        "targets": list(scan.targets),
        "scan_addresses": list(scan.scan_addresses),
        "ports_scanned": (
            {proto: str(ports) for proto, ports in scan.coverage.items()}
            if scan.coverage is not None
            else None
        ),
        "host_discovery": scan.host_discovery,
        "service_detection": scan.service_detection,
        "hosts_responsive": sum(1 for o in observations if o.responsive),
        "evidence": scan.evidence,
    }


def _no_response(scan: ScanContext) -> str:
    return (
        "did not respond to host discovery"
        if scan.host_discovery
        else "no port answered (-Pn: host assumed up)"
    )


def _port_entry(reading_state: str | None, port: PortObservation | None) -> dict[str, Any]:
    if port is not None:
        return port_view(port)
    return {"state": reading_state}


def _service_changes(
    a: PortObservation, b: PortObservation, base: dict[str, Any], scans: tuple[ScanContext, ...]
) -> list[Change]:
    a_id, b_id = a.identification, b.identification
    if not a_id and not b_id:
        return []
    before, after = port_view(a), port_view(b)
    if a_id == "detected" and b_id == "detected":
        if a.service_name != b.service_name:
            return [
                Change(
                    "changed",
                    "service_changed",
                    detail=f"service detected as {a.service_name}, now {b.service_name}",
                    before=before,
                    after=after,
                    **base,
                )
            ]
        a_version, b_version = a.version_text, b.version_text
        if a_version and b_version and a_version != b_version:
            return [
                Change(
                    "changed",
                    "version_changed",
                    detail=f"{a.service_name} version {a_version} → {b_version}",
                    before=before,
                    after=after,
                    **base,
                )
            ]
        if a_version and not b_version:
            return [
                Change(
                    "inconclusive",
                    "version_not_reported",
                    detail=f"{a.service_name} version {a_version} was not reported this time",
                    before=before,
                    after=after,
                    **base,
                )
            ]
        return []
    if a_id == "detected" and b_id != "detected":
        why = (
            "service detection (-sV) was not run"
            if not scans[1].service_detection
            else "the service was not identified by probing"
        )
        return [
            Change(
                "inconclusive",
                "service_not_checked",
                detail=f"previously detected as {a.service_name}; in this scan {why}",
                before=before,
                after=after,
                **base,
            )
        ]
    if b_id == "detected" and a_id != "detected" and a.service_name != b.service_name:
        label = f"only the port-number label {a.service_name!r}" if a.service_name else "no label"
        return [
            Change(
                "inconclusive",
                "service_identified",
                detail=f"detected as {b.service_name}; the baseline had {label}, not a detection",
                before=before,
                after=after,
                **base,
            )
        ]
    return []


def _compare_ports(
    a: HostObservation, b: HostObservation, base: dict[str, Any]
) -> tuple[list[Change], int]:
    changes: list[Change] = []
    unchanged = 0
    keys = sorted({*a.ports, *b.ports})
    for protocol, port in keys:
        ra, rb = a.port_state(protocol, port), b.port_state(protocol, port)
        pa, pb = a.ports.get((protocol, port)), b.ports.get((protocol, port))
        here = {**base, "protocol": protocol, "port": port}
        before, after = _port_entry(ra.state, pa), _port_entry(rb.state, pb)
        if ra.state == OPEN and rb.state == OPEN:
            found = (
                _service_changes(pa, pb, here, (a.scan, b.scan)) if pa and pb else []  # type: ignore[arg-type]
            )
            changes += found
            unchanged += not found
        elif rb.state == OPEN:
            if ra.observed:
                changes.append(
                    Change("added", "port_opened", detail=f"was {ra.state}, now open",
                           before=before, after=after, **here)
                )  # fmt: skip
            else:
                changes.append(
                    Change("inconclusive", "port_open_unverified",
                           detail=f"open now; not observed in the baseline ({ra.source})",
                           before=None, after=after, **here)
                )  # fmt: skip
        elif ra.state == OPEN:
            if rb.state == "closed":
                changes.append(
                    Change("removed", "port_closed", detail="was open, now confirmed closed",
                           before=before, after=after, **here)
                )  # fmt: skip
            elif rb.observed:
                changes.append(
                    Change("inconclusive", "port_unreachable",
                           detail=f"was open, now {rb.state}: no answer, which is not the same "
                           "as closed (firewall, rate limiting or host down)",
                           before=before, after=after, **here)
                )  # fmt: skip
            else:
                changes.append(
                    Change("inconclusive", "port_not_checked",
                           detail=f"was open; not observed in this scan ({rb.source})",
                           before=before, after=None, **here)
                )  # fmt: skip
    return changes, unchanged


def compare_scans(
    conn: sqlite3.Connection, project_id: int, baseline_id: int, comparison_id: int
) -> dict[str, Any]:
    if baseline_id == comparison_id:
        raise ComparisonError(422, "choose two different scans to compare")
    scans: list[ScanContext] = []
    for scan_id in (baseline_id, comparison_id):
        scan = load_scan(conn, scan_id)
        if scan is None or scan.project_id != project_id:
            # Same answer for "missing" and "other project": no cross-project probing.
            raise ComparisonError(404, f"scan {scan_id} not found in project {project_id}")
        if scan.status != "completed":
            raise ComparisonError(
                409,
                f"scan {scan_id} is {scan.status}; only completed scans can be compared "
                "(an incomplete scan would make missing observations look like changes)",
            )
        scans.append(scan)
    a_scan, b_scan = scans

    a_obs = {o.address: o for o in load_observations(conn, scan_id=baseline_id)}
    b_obs = {o.address: o for o in load_observations(conn, scan_id=comparison_id)}
    uids = {
        r["address"]: r["uid"]
        for r in conn.execute("SELECT address, uid FROM assets WHERE project_id = ?", (project_id,))
    }

    changes: list[Change] = []
    unchanged_ports = 0
    for address in sorted({*a_obs, *b_obs}, key=_address_key):
        a, b = a_obs.get(address), b_obs.get(address)
        a_up, b_up = bool(a and a.responsive), bool(b and b.responsive)
        names = tuple(dict.fromkeys([*(a.hostnames if a else ()), *(b.hostnames if b else ())]))
        base = {"address": address, "asset_uid": uids.get(address), "hostnames": names}

        if a_up and b_up:
            assert a and b
            if a.timed_out or b.timed_out:
                side = "baseline" if a.timed_out else "comparison"
                changes.append(
                    Change("inconclusive", "host_incomplete",
                           detail=f"host timed out in the {side} scan; its ports are not compared",
                           **base)
                )  # fmt: skip
                continue
            found, same = _compare_ports(a, b, base)
            changes += found
            unchanged_ports += same
        elif b_up:
            assert b
            open_now = {"open_ports": [port_view(p) for p in b.open_ports()]}
            if a_scan.targeted(address) and not (a and a.timed_out):
                changes.append(
                    Change("added", "host_appeared",
                           detail="responded in this scan; in the baseline it "
                           + _no_response(a_scan),
                           after=open_now, **base)
                )  # fmt: skip
            else:
                why = "timed out" if a and a.timed_out else "was not targeted"
                changes.append(
                    Change("inconclusive", "host_appeared_unverified",
                           detail=f"responded in this scan; in the baseline it {why}",
                           after=open_now, **base)
                )  # fmt: skip
        elif a_up:
            assert a
            open_before = {"open_ports": [port_view(p) for p in a.open_ports()]}
            if b_scan.targeted(address) and not (b and b.timed_out):
                changes.append(
                    Change("removed", "host_not_observed",
                           detail="responded in the baseline; in this scan it "
                           + _no_response(b_scan),
                           before=open_before, **base)
                )  # fmt: skip
            else:
                why = "timed out" if b and b.timed_out else "was not targeted"
                changes.append(
                    Change("inconclusive", "host_not_checked",
                           detail=f"responded in the baseline; in this scan it {why}",
                           before=open_before, **base)
                )  # fmt: skip

    notes = _notes(a_scan, b_scan)
    order = {"added": 0, "removed": 1, "changed": 2, "inconclusive": 3}
    changes.sort(key=lambda c: (order[c.category], _address_key(c.address), c.port or -1))
    summary = {cat: sum(1 for c in changes if c.category == cat) for cat in order}
    return {
        "project_id": project_id,
        "baseline": _side(a_scan, list(a_obs.values())),
        "comparison": _side(b_scan, list(b_obs.values())),
        "summary": {**summary, "unchanged_open_ports": unchanged_ports},
        "changes": [c.as_dict() for c in changes],
        "notes": notes,
    }


def _address_key(address: str) -> tuple[int, str]:
    import ipaddress

    try:
        ip = ipaddress.ip_address(address)
        return (ip.version, f"{int(ip):040d}")
    except ValueError:
        return (9, address)


def _notes(a: ScanContext, b: ScanContext) -> list[str]:
    notes = []
    for label, scan in (("baseline", a), ("comparison", b)):
        if scan.coverage is None:
            notes.append(
                f"The {label} scan's port coverage is unknown (its evidence could not be "
                "re-verified), so only ports it listed individually are compared."
            )
        if not scan.host_discovery:
            notes.append(
                f"The {label} scan used -Pn: hosts count as present only if a port answered."
            )
    if a.service_detection != b.service_detection:
        notes.append(
            "Only one of the scans ran service detection (-sV); service differences between "
            "them are reported as inconclusive."
        )
    if (a.finished_at or a.created_at) > (b.finished_at or b.created_at):
        notes.append("The baseline scan is newer than the comparison scan.")
    return notes
