"""Asset inventory persistence: ingesting scan results and deriving asset state.

Observations (``scan_hosts`` + ``scan_ports`` of *completed* scans) are the
source of truth. Everything on ``assets`` beyond identity, and all of
``asset_ports``, is derived from them by :func:`refresh_assets`, inside the
same transaction as the ingest, so the inventory never drifts and does not
depend on the order in which scans were ingested.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traceforge.db import Database
from traceforge.execution.tools import ExtraPorts, ToolReport
from traceforge.inventory.model import (
    OPEN,
    HostObservation,
    PortObservation,
    ScanContext,
    bulk_from_json,
    coverage_from_json,
)

logger = logging.getLogger("uvicorn.error")

# Bump when ingestion starts recording something new that older scans should
# be re-read for (see backfill_scans).
INGEST_VERSION = 1

_SCAN_COLUMNS = (
    "id, project_id, status, tool, tool_version, created_at, finished_at, targets, "
    "scan_addresses, hostnames, options, command, timeout_seconds, coverage, "
    "evidence_path, evidence_sha256, evidence_bytes"
)


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_asset_uid() -> str:
    return f"ast_{secrets.token_hex(8)}"


def _json(value: Any, default: Any) -> Any:
    return json.loads(value) if value else default


# --------------------------------------------------------------------------- loading


def scan_context(row: sqlite3.Row) -> ScanContext:
    evidence = None
    if row["evidence_path"] and row["evidence_sha256"]:
        evidence = {
            "file": row["evidence_path"],
            "sha256": row["evidence_sha256"],
            "size_bytes": row["evidence_bytes"] or 0,
        }
    return ScanContext(
        id=row["id"],
        project_id=row["project_id"],
        status=row["status"],
        tool=row["tool"],
        tool_version=row["tool_version"],
        created_at=row["created_at"],
        finished_at=row["finished_at"],
        targets=tuple(_json(row["targets"], [])),
        scan_addresses=tuple(_json(row["scan_addresses"], [])),
        hostnames=_json(row["hostnames"], {}),
        options=_json(row["options"], {}),
        command=tuple(_json(row["command"], [])),
        timeout_seconds=row["timeout_seconds"],
        coverage=coverage_from_json(_json(row["coverage"], None)),
        evidence=evidence,
    )


def load_scan(conn: sqlite3.Connection, scan_id: int) -> ScanContext | None:
    row = conn.execute(f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return scan_context(row) if row else None


def _port_observation(row: sqlite3.Row) -> PortObservation:
    return PortObservation(
        protocol=row["protocol"],
        port=row["port"],
        state=row["state"],
        reason=row["reason"],
        service_name=row["service_name"],
        service_product=row["service_product"],
        service_version=row["service_version"],
        service_extrainfo=row["service_extrainfo"],
        service_tunnel=row["service_tunnel"],
        service_method=row["service_method"],
        service_confidence=row["service_confidence"],
        cpe=tuple(_json(row["cpe"], [])),
    )


def load_observations(
    conn: sqlite3.Connection, *, scan_id: int | None = None, asset_id: int | None = None
) -> list[HostObservation]:
    """Host observations from completed scans, oldest first.

    Only scans of the asset's own project are joined, as a second line of
    defence for project isolation.
    """
    if (scan_id is None) == (asset_id is None):
        raise ValueError("pass exactly one of scan_id or asset_id")
    column, value = ("h.scan_id", scan_id) if scan_id is not None else ("h.asset_id", asset_id)
    rows = conn.execute(
        "SELECT h.id, h.scan_id, h.asset_id, h.state, h.reason, h.hostnames, h.observed_at, "
        "h.timed_out, h.extraports, a.address, s.finished_at, s.created_at "
        "FROM scan_hosts h JOIN assets a ON a.id = h.asset_id "
        "JOIN scans s ON s.id = h.scan_id AND s.project_id = a.project_id "
        f"WHERE {column} = ? AND s.status = 'completed'",
        (value,),
    ).fetchall()
    if not rows:
        return []

    host_ids = [r["id"] for r in rows]
    ports: dict[int, dict[tuple[str, int], PortObservation]] = {h: {} for h in host_ids}
    for chunk in range(0, len(host_ids), 500):
        ids = host_ids[chunk : chunk + 500]
        marks = ",".join("?" * len(ids))
        for p in conn.execute(f"SELECT * FROM scan_ports WHERE scan_host_id IN ({marks})", ids):
            ports[p["scan_host_id"]][(p["protocol"], p["port"])] = _port_observation(p)

    contexts: dict[int, ScanContext] = {}
    observations = []
    for r in rows:
        context = contexts.get(r["scan_id"])
        if context is None:
            context = contexts[r["scan_id"]] = load_scan(conn, r["scan_id"])  # type: ignore[assignment]
        observations.append(
            HostObservation(
                scan=context,
                scan_host_id=r["id"],
                asset_id=r["asset_id"],
                address=r["address"],
                state=r["state"],
                reason=r["reason"],
                hostnames=tuple(_json(r["hostnames"], [])),
                observed_at=r["observed_at"] or r["finished_at"] or r["created_at"],
                timed_out=bool(r["timed_out"]),
                bulk=bulk_from_json(_json(r["extraports"], [])),
                ports=ports[r["id"]],
            )
        )
    observations.sort(key=lambda o: (o.observed_at, o.scan.id))
    return observations


# --------------------------------------------------------------------------- ingest


def _extraports_json(groups: Iterable[ExtraPorts]) -> str:
    return json.dumps(
        [
            {
                "state": g.state,
                "count": g.count,
                "ports": dict(g.ports) if g.ports is not None else None,
            }
            for g in groups
        ]
    )


def ingest_report(
    conn: sqlite3.Connection,
    scan_id: int,
    project_id: int,
    report: ToolReport,
    hostnames: dict[str, list[str]] | None = None,
) -> list[int]:
    """Record a completed scan's findings and refresh the affected assets.

    Runs on the caller's connection so it commits or rolls back as one unit.
    Hosts the tool reported as down are not stored: "targeted but did not
    respond" is derived from the scan's targets instead, so no asset is ever
    created for an address that never answered.
    """
    hostnames = hostnames or {}
    now = utc_now()
    conn.execute(
        "UPDATE scans SET coverage = ?, ingest_version = ? WHERE id = ?",
        (json.dumps(dict(report.coverage)) if report.coverage else None, INGEST_VERSION, scan_id),
    )
    touched: list[int] = []
    for host in report.hosts:
        if host.state != "up":
            continue
        observed_at = host.observed_at or now
        names = list(dict.fromkeys([*hostnames.get(host.address, []), *host.hostnames]))
        conn.execute(
            "INSERT INTO assets (uid, project_id, address, addr_type, hostnames, first_seen, "
            "last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (project_id, address) DO NOTHING",
            (new_asset_uid(), project_id, host.address, host.addr_type, json.dumps(names),
             observed_at, observed_at),
        )  # fmt: skip
        asset_id = conn.execute(
            "SELECT id FROM assets WHERE project_id = ? AND address = ?",
            (project_id, host.address),
        ).fetchone()[0]
        cursor = conn.execute(
            "INSERT INTO scan_hosts (scan_id, asset_id, state, reason, hostnames, observed_at, "
            "timed_out, extraports) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, asset_id, host.state, host.reason, json.dumps(names), observed_at,
             int(host.timed_out), _extraports_json(host.extraports)),
        )  # fmt: skip
        conn.executemany(
            "INSERT OR REPLACE INTO scan_ports (scan_host_id, protocol, port, state, reason, "
            "service_name, service_product, service_version, service_extrainfo, service_tunnel, "
            "service_method, service_confidence, cpe) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (cursor.lastrowid, p.protocol, p.port, p.state, p.reason, p.service_name,
                 p.service_product, p.service_version, p.service_extrainfo, p.service_tunnel,
                 p.service_method, p.service_confidence, json.dumps(list(p.cpe)))
                for p in host.ports
            ],
        )  # fmt: skip
        touched.append(asset_id)
    refresh_assets(conn, touched)
    return touched


# --------------------------------------------------------------------------- derive


def refresh_assets(conn: sqlite3.Connection, asset_ids: Iterable[int]) -> None:
    for asset_id in dict.fromkeys(asset_ids):
        refresh_asset(conn, asset_id)


def refresh_asset(conn: sqlite3.Connection, asset_id: int) -> None:
    """Recompute an asset's derived state from all of its observations."""
    observations = load_observations(conn, asset_id=asset_id)
    if not observations:
        conn.execute("UPDATE assets SET confirmed = 0, open_ports = 0 WHERE id = ?", (asset_id,))
        conn.execute("DELETE FROM asset_ports WHERE asset_id = ?", (asset_id,))
        return

    responsive = [o for o in observations if o.responsive]
    basis = responsive or observations
    names: list[str] = []
    for o in observations:
        for name in (*o.scan.hostnames.get(o.address, []), *o.hostnames):
            if name not in names:
                names.append(name)

    keys = sorted({key for o in observations for key, p in o.ports.items() if p.state == OPEN})
    rows = []
    for protocol, port in keys:
        first = last = state = last_open = None
        state_scan = None
        service: tuple[PortObservation, int] | None = None
        for o in observations:
            reading = o.port_state(protocol, port)
            if not reading.observed:
                continue
            first = first or o.observed_at
            last, state, state_scan = o.observed_at, reading.state, o.scan.id
            if reading.state == OPEN:
                last_open = o.observed_at
                listed = o.ports.get((protocol, port))
                if listed is not None:
                    service = (listed, o.scan.id)
        svc = service[0] if service else None
        rows.append(
            (asset_id, protocol, port, state, state_scan, first, last, last_open,
             svc.service_name if svc else None, svc.service_product if svc else None,
             svc.service_version if svc else None, svc.service_extrainfo if svc else None,
             svc.service_method if svc else None, svc.service_confidence if svc else None,
             json.dumps(list(svc.cpe)) if svc else "[]", service[1] if service else None)
        )  # fmt: skip

    conn.execute("DELETE FROM asset_ports WHERE asset_id = ?", (asset_id,))
    conn.executemany(
        "INSERT INTO asset_ports (asset_id, protocol, port, state, state_scan_id, first_seen, "
        "last_seen, last_open_at, service_name, service_product, service_version, "
        "service_extrainfo, service_method, service_confidence, cpe, service_scan_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.execute(
        "UPDATE assets SET hostnames = ?, first_seen = ?, last_seen = ?, confirmed = ?, "
        "open_ports = ?, last_scan_id = ? WHERE id = ?",
        (
            json.dumps(names),
            basis[0].observed_at,
            basis[-1].observed_at,
            int(bool(responsive)),
            sum(1 for r in rows if r[3] == OPEN),
            basis[-1].scan.id,
            asset_id,
        ),
    )


# --------------------------------------------------------------------------- backfill


def _read_verified_evidence(evidence_dir: Path, name: str, sha256: str) -> bytes | None:
    """Evidence bytes, only if the file is ours and still matches its recorded hash."""
    if Path(name).name != name or name.startswith("."):
        return None
    try:
        fd = os.open(evidence_dir / name, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read()
    return data if hashlib.sha256(data).hexdigest() == sha256 else None


def backfill_scans(db: Database, evidence_dir: Path, parsers: dict[str, Any]) -> dict[str, int]:
    """Bring scans ingested by an older release up to this release's model.

    For each completed scan with an older ``ingest_version``, the raw evidence
    is re-read — only if its SHA-256 still matches the recorded hash — to
    recover coverage, bulk-reported ports and per-host timestamps. Scans whose
    evidence is missing or altered keep "coverage unknown", which comparisons
    treat conservatively. Nothing is deleted. Idempotent; one transaction per
    scan.
    """
    counts = {"scans": 0, "reparsed": 0, "unverifiable": 0}
    with db.connect() as conn:
        pending = conn.execute(
            "SELECT id, tool, evidence_path, evidence_sha256 FROM scans "
            "WHERE status = 'completed' AND ingest_version < ? ORDER BY id",
            (INGEST_VERSION,),
        ).fetchall()
    for scan in pending:
        report: ToolReport | None = None
        parser = parsers.get(scan["tool"] or "")
        if parser and scan["evidence_path"] and scan["evidence_sha256"]:
            data = _read_verified_evidence(
                evidence_dir, scan["evidence_path"], scan["evidence_sha256"]
            )
            if data is not None:
                try:
                    report = parser(data)
                except ValueError:
                    report = None
        with db.connect() as conn:
            if report is not None:
                conn.execute(
                    "UPDATE scans SET coverage = ? WHERE id = ?",
                    (json.dumps(dict(report.coverage)) if report.coverage else None, scan["id"]),
                )
                for host in report.hosts:
                    conn.execute(
                        "UPDATE scan_hosts SET observed_at = COALESCE(?, observed_at), "
                        "timed_out = ?, extraports = ? WHERE scan_id = ? AND asset_id = "
                        "(SELECT a.id FROM assets a JOIN scans s ON s.project_id = a.project_id "
                        " WHERE s.id = ? AND a.address = ?)",
                        (host.observed_at, int(host.timed_out), _extraports_json(host.extraports),
                         scan["id"], scan["id"], host.address),
                    )  # fmt: skip
                counts["reparsed"] += 1
            else:
                counts["unverifiable"] += 1
            conn.execute(
                "UPDATE scan_hosts SET observed_at = (SELECT COALESCE(finished_at, created_at) "
                "FROM scans WHERE id = ?) WHERE scan_id = ? AND observed_at IS NULL",
                (scan["id"], scan["id"]),
            )
            conn.execute(
                "UPDATE scans SET ingest_version = ? WHERE id = ?", (INGEST_VERSION, scan["id"])
            )
            asset_ids = [
                r[0]
                for r in conn.execute(
                    "SELECT asset_id FROM scan_hosts WHERE scan_id = ?", (scan["id"],)
                )
            ]
            refresh_assets(conn, asset_ids)
        counts["scans"] += 1
    return counts


# --------------------------------------------------------------------------- queries


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _asset_dict(row: sqlite3.Row) -> dict[str, Any]:
    asset = dict(row)
    asset["hostnames"] = _json(asset["hostnames"], [])
    asset["confirmed"] = bool(asset["confirmed"])
    return asset


def _port_dict(row: sqlite3.Row) -> dict[str, Any]:
    port = dict(row)
    port["cpe"] = _json(port["cpe"], [])
    if port.get("service_name"):
        port["identification"] = "detected" if port["service_method"] == "probed" else "port-label"
    else:
        port["identification"] = None
    return port


class AssetQueries:
    """Read-only views of the inventory, used by the API."""

    def __init__(self, db: Database) -> None:
        self.db = db

    _SELECT = (
        "SELECT a.id, a.uid, a.project_id, p.name AS project_name, a.address, a.addr_type, "
        "a.hostnames, a.first_seen, a.last_seen, a.confirmed, a.open_ports, a.last_scan_id "
        "FROM assets a JOIN projects p ON p.id = a.project_id"
    )

    def list(
        self,
        project_id: int | None = None,
        query: str | None = None,
        include_unconfirmed: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if project_id is not None:
            clauses.append("a.project_id = ?")
            params.append(project_id)
        if not include_unconfirmed:
            clauses.append("a.confirmed = 1")
        if query and query.strip():
            term = query.strip()
            like = _like(term)
            clauses.append(
                "(a.address LIKE ? ESCAPE '\\' OR a.hostnames LIKE ? ESCAPE '\\' OR a.uid = ? "
                "OR EXISTS (SELECT 1 FROM asset_ports ap WHERE ap.asset_id = a.id AND "
                "ap.state = 'open' AND (ap.service_name LIKE ? ESCAPE '\\' OR "
                "ap.service_product LIKE ? ESCAPE '\\' OR CAST(ap.port AS TEXT) = ?)))"
            )
            params += [like, like, term, like, like, term]
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as conn:
            rows = conn.execute(
                self._SELECT + where + " ORDER BY a.last_seen DESC, a.id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            assets = [_asset_dict(r) for r in rows]
            by_id = {a["id"]: a for a in assets}
            for a in assets:
                a["services"] = []
            if by_id:
                marks = ",".join("?" * len(by_id))
                for p in conn.execute(
                    "SELECT asset_id, protocol, port, service_name, service_method "
                    "FROM asset_ports WHERE state = 'open' "
                    f"AND asset_id IN ({marks}) ORDER BY port",
                    list(by_id),
                ):
                    by_id[p["asset_id"]]["services"].append(
                        {
                            "protocol": p["protocol"],
                            "port": p["port"],
                            "service_name": p["service_name"],
                            "identification": (
                                None
                                if not p["service_name"]
                                else "detected"
                                if p["service_method"] == "probed"
                                else "port-label"
                            ),
                        }
                    )
        return assets

    def stats(self, project_id: int | None = None) -> dict[str, int]:
        where, params = ("WHERE a.project_id = ?", (project_id,)) if project_id else ("", ())
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT "
                "COALESCE(SUM(a.confirmed), 0) AS assets, "
                "COALESCE(SUM(a.confirmed = 0), 0) AS unconfirmed, "
                "COALESCE(SUM(a.confirmed = 1 AND a.open_ports > 0), 0) AS assets_with_open_ports, "
                "COALESCE(SUM(CASE WHEN a.confirmed = 1 THEN a.open_ports ELSE 0 END), 0) "
                "  AS open_ports "
                f"FROM assets a {where}",
                params,
            ).fetchone()
            detected = conn.execute(
                "SELECT COUNT(*) FROM asset_ports ap JOIN assets a ON a.id = ap.asset_id "
                "WHERE ap.state = 'open' AND ap.service_method = 'probed' AND a.confirmed = 1"
                + (" AND a.project_id = ?" if project_id else ""),
                params,
            ).fetchone()[0]
        return {**dict(row), "detected_services": detected}

    def get(self, uid: str) -> dict[str, Any] | None:
        with self.db.connect() as conn:
            row = conn.execute(self._SELECT + " WHERE a.uid = ?", (uid,)).fetchone()
            if row is None:
                return None
            asset = _asset_dict(row)
            asset["ports"] = [
                _port_dict(p)
                for p in conn.execute(
                    "SELECT protocol, port, state, state_scan_id, first_seen, last_seen, "
                    "last_open_at, service_name, service_product, service_version, "
                    "service_extrainfo, service_method, service_confidence, cpe, service_scan_id "
                    "FROM asset_ports WHERE asset_id = ? ORDER BY protocol, port",
                    (asset["id"],),
                )
            ]
            observations = load_observations(conn, asset_id=asset["id"])
        asset["observations"] = [observation_dict(o) for o in reversed(observations)]
        asset["services"] = [
            {k: p[k] for k in ("protocol", "port", "service_name", "identification")}
            for p in asset["ports"]
            if p["state"] == OPEN
        ]
        return asset


def provenance(o: HostObservation) -> dict[str, Any]:
    scan = o.scan
    ports_scanned = (
        {proto: str(ports) for proto, ports in scan.coverage.items()}
        if scan.coverage is not None
        else None
    )
    return {
        "project_id": scan.project_id,
        "scan_id": scan.id,
        "tool": scan.tool,
        "tool_version": scan.tool_version,
        "observed_at": o.observed_at,
        "requested_targets": scan.requested_as(o.address),
        "scanned_address": o.address,
        "configuration": {
            "options": scan.options,
            "command": list(scan.command),
            "timeout_seconds": scan.timeout_seconds,
            "ports_scanned": ports_scanned,
            "host_discovery": scan.host_discovery,
            "service_detection": scan.service_detection,
        },
        "evidence": scan.evidence,
    }


def port_view(p: PortObservation) -> dict[str, Any]:
    return {
        "protocol": p.protocol,
        "port": p.port,
        "state": p.state,
        "reason": p.reason,
        "service_name": p.service_name,
        "service_product": p.service_product,
        "service_version": p.service_version,
        "service_extrainfo": p.service_extrainfo,
        "service_method": p.service_method,
        "identification": p.identification,
        "cpe": list(p.cpe),
    }


def observation_dict(o: HostObservation) -> dict[str, Any]:
    return {
        "scan_id": o.scan.id,
        "observed_at": o.observed_at,
        "state": o.state,
        "reason": o.reason,
        "responsive": o.responsive,
        "timed_out": o.timed_out,
        "hostnames": list(o.hostnames),
        "ports": [
            port_view(p) for p in sorted(o.ports.values(), key=lambda p: (p.protocol, p.port))
        ],
        "provenance": provenance(o),
    }


def scan_ids_in_project(conn: sqlite3.Connection, project_id: int, ids: Sequence[int]) -> set[int]:
    marks = ",".join("?" * len(ids))
    return {
        r[0]
        for r in conn.execute(
            f"SELECT id FROM scans WHERE project_id = ? AND id IN ({marks})", (project_id, *ids)
        )
    }
