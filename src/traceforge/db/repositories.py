"""Data access for projects, scope rules, scans and the audit log."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any

from traceforge.db.database import Database

if TYPE_CHECKING:
    from traceforge.execution.tools import ToolReport


class NotFoundError(LookupError):
    pass


class ConflictError(ValueError):
    pass


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


class ProjectRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    _SELECT = """
        SELECT p.*, (SELECT COUNT(*) FROM scope_rules r WHERE r.project_id = p.id)
               AS scope_rule_count
        FROM projects p
    """

    def create(
        self,
        name: str,
        authorization_ref: str,
        authorized_from: datetime | None = None,
        authorized_until: datetime | None = None,
    ) -> dict[str, Any]:
        try:
            with self.db.connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO projects (name, authorization_ref, authorized_from, "
                    "authorized_until) VALUES (?, ?, ?, ?)",
                    (name, authorization_ref, _iso(authorized_from), _iso(authorized_until)),
                )
                project_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"a project named {name!r} already exists") from exc
        return self.get(int(project_id or 0))

    def get(self, project_id: int) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = conn.execute(self._SELECT + " WHERE p.id = ?", (project_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"project {project_id} not found")
        return dict(row)

    def list_all(self) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            return [dict(r) for r in conn.execute(self._SELECT + " ORDER BY p.id")]


class ScopeRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, project_id: int, kind: str, value: str, note: str | None) -> dict[str, Any]:
        try:
            with self.db.connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO scope_rules (project_id, kind, value, note) VALUES (?, ?, ?, ?)",
                    (project_id, kind, value, note),
                )
                row = conn.execute(
                    "SELECT * FROM scope_rules WHERE id = ?", (cursor.lastrowid,)
                ).fetchone()
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"{kind} rule {value!r} already exists") from exc
        return dict(row)

    def list_all(self, project_id: int) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scope_rules WHERE project_id = ? ORDER BY id", (project_id,)
            )
            return [dict(r) for r in rows]

    def delete(self, project_id: int, rule_id: int) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM scope_rules WHERE id = ? AND project_id = ?", (rule_id, project_id)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"scope rule {rule_id} not found")
            conn.execute("DELETE FROM scope_rules WHERE id = ?", (rule_id,))
        return dict(row)


_NOW = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
_ACTIVE = "('queued', 'running')"


def _decode_scan(row: sqlite3.Row) -> dict[str, Any]:
    scan = dict(row)
    for key, empty in (
        ("targets", []),
        ("scan_addresses", []),
        ("hostnames", {}),
        ("options", {}),
        ("command", []),
    ):
        scan[key] = json.loads(scan[key]) if scan.get(key) else empty
    scan["evidence"] = (
        {
            "file": scan["evidence_path"],
            "sha256": scan["evidence_sha256"],
            "size_bytes": scan["evidence_bytes"] or 0,
        }
        if scan.get("evidence_path") and scan.get("evidence_sha256")
        else None
    )
    scan["ports_scanned"] = json.loads(scan["coverage"]) if scan.get("coverage") else None
    return scan


class ScanRepository:
    """Scan jobs. Status only moves forward: queued -> running -> terminal."""

    def __init__(self, db: Database) -> None:
        self.db = db

    _SELECT = """
        SELECT s.*,
          (SELECT COUNT(*) FROM scan_hosts h WHERE h.scan_id = s.id AND h.state = 'up')
            AS hosts_up,
          (SELECT COUNT(*) FROM scan_ports p JOIN scan_hosts h ON p.scan_host_id = h.id
            WHERE h.scan_id = s.id AND p.state = 'open') AS open_ports
        FROM scans s
    """

    def create(
        self,
        project_id: int,
        tool: str,
        targets: Sequence[str],
        *,
        scan_addresses: Sequence[str] = (),
        hostnames: dict[str, list[str]] | None = None,
        options: dict[str, Any] | None = None,
        command: Sequence[str] = (),
        actor: str | None = None,
        timeout_seconds: int | None = None,
    ) -> int:
        with self.db.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (project_id, tool, name, target, targets, scan_addresses, "
                "hostnames, options, command, actor, timeout_seconds, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued')",
                (
                    project_id,
                    tool,
                    f"{tool} scan",
                    ", ".join(targets),
                    json.dumps(list(targets)),
                    json.dumps(list(scan_addresses)),
                    json.dumps(hostnames or {}),
                    json.dumps(options or {}, sort_keys=True),
                    json.dumps(list(command)),
                    actor,
                    timeout_seconds,
                ),
            )
            return int(cursor.lastrowid or 0)

    def mark_running(self, scan_id: int) -> bool:
        """queued -> running. False if the scan is no longer queued (e.g. cancelled)."""
        with self.db.connect() as conn:
            cursor = conn.execute(
                f"UPDATE scans SET status = 'running', started_at = {_NOW} "
                "WHERE id = ? AND status = 'queued'",
                (scan_id,),
            )
            return cursor.rowcount == 1

    def finish(
        self,
        scan_id: int,
        status: str,
        *,
        exit_code: int | None = None,
        error: str | None = None,
        evidence_path: str | None = None,
        evidence_sha256: str | None = None,
        evidence_bytes: int | None = None,
        tool_version: str | None = None,
    ) -> bool:
        """Move an active scan to a terminal state. Terminal scans are never rewritten."""
        if status not in ("completed", "failed", "cancelled"):
            raise ValueError(f"{status!r} is not a terminal status")
        with self.db.connect() as conn:
            return self._finish(
                conn,
                scan_id,
                status,
                exit_code=exit_code,
                error=error,
                evidence_path=evidence_path,
                evidence_sha256=evidence_sha256,
                evidence_bytes=evidence_bytes,
                tool_version=tool_version,
            )

    @staticmethod
    def _finish(
        conn: sqlite3.Connection,
        scan_id: int,
        status: str,
        *,
        exit_code: int | None = None,
        error: str | None = None,
        evidence_path: str | None = None,
        evidence_sha256: str | None = None,
        evidence_bytes: int | None = None,
        tool_version: str | None = None,
    ) -> bool:
        from traceforge.inventory.store import refresh_assets

        cursor = conn.execute(
            f"UPDATE scans SET status = ?, finished_at = {_NOW}, exit_code = ?, error = ?, "
            "evidence_path = COALESCE(?, evidence_path), "
            "evidence_sha256 = COALESCE(?, evidence_sha256), "
            "evidence_bytes = COALESCE(?, evidence_bytes), "
            "tool_version = COALESCE(?, tool_version) "
            f"WHERE id = ? AND status IN {_ACTIVE}",
            (
                status,
                exit_code,
                error,
                evidence_path,
                evidence_sha256,
                evidence_bytes,
                tool_version,
                scan_id,
            ),
        )
        if cursor.rowcount != 1:
            return False
        if status == "completed":
            # Its observations now count: re-derive the assets it saw.
            refresh_assets(
                conn,
                [
                    r[0]
                    for r in conn.execute(
                        "SELECT asset_id FROM scan_hosts WHERE scan_id = ?", (scan_id,)
                    )
                ],
            )
        return True

    def fail_interrupted(self) -> list[int]:
        """Mark scans left active by a previous server process as failed."""
        with self.db.connect() as conn:
            ids = [
                int(r[0]) for r in conn.execute(f"SELECT id FROM scans WHERE status IN {_ACTIVE}")
            ]
            conn.execute(
                f"UPDATE scans SET status = 'failed', finished_at = {_NOW}, "
                "error = 'interrupted: the server stopped before this scan finished' "
                f"WHERE status IN {_ACTIVE}"
            )
        return ids

    def get(self, scan_id: int) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = conn.execute(self._SELECT + " WHERE s.id = ?", (scan_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"scan {scan_id} not found")
        return _decode_scan(row)

    def list_all(
        self,
        project_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if project_id is not None:
            clauses.append("s.project_id = ?")
            params.append(project_id)
        if status is not None:
            clauses.append("s.status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.db.connect() as conn:
            rows = conn.execute(
                self._SELECT + where + " ORDER BY s.id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        return [_decode_scan(r) for r in rows]


class ResultRepository:
    """Assets, hosts and ports/services discovered by scans."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def complete_with_results(
        self,
        scan_id: int,
        project_id: int,
        report: ToolReport,
        hostnames: dict[str, list[str]] | None,
        **finish: Any,
    ) -> bool:
        """Store a scan's results and mark it completed in one transaction.

        Either both happen or neither: a crash can never leave results of a
        scan that is not marked completed, or a completed scan without them.
        Returns False (storing nothing) if the scan is no longer active.
        """
        from traceforge.inventory.store import ingest_report

        with self.db.connect() as conn:
            active = conn.execute(
                "SELECT 1 FROM scans WHERE id = ? AND status IN ('queued', 'running')", (scan_id,)
            ).fetchone()
            if active is None:
                return False
            ingest_report(conn, scan_id, project_id, report, hostnames)
            return ScanRepository._finish(conn, scan_id, "completed", **finish)

    def store(
        self,
        scan_id: int,
        project_id: int,
        report: ToolReport,
        hostnames: dict[str, list[str]] | None = None,
    ) -> None:
        """Persist a parsed report atomically (asset state counts it once the
        scan is completed)."""
        from traceforge.inventory.store import ingest_report

        with self.db.connect() as conn:
            ingest_report(conn, scan_id, project_id, report, hostnames)

    def for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            hosts = conn.execute(
                "SELECT h.id, h.asset_id, a.uid AS asset_uid, a.address, a.addr_type, h.state, "
                "h.reason, h.hostnames, h.observed_at, h.timed_out "
                "FROM scan_hosts h JOIN assets a ON a.id = h.asset_id "
                "WHERE h.scan_id = ? ORDER BY h.id",
                (scan_id,),
            ).fetchall()
            ports = conn.execute(
                "SELECT p.* FROM scan_ports p JOIN scan_hosts h ON p.scan_host_id = h.id "
                "WHERE h.scan_id = ? ORDER BY p.protocol, p.port",
                (scan_id,),
            ).fetchall()
        by_host: dict[int, list[dict[str, Any]]] = {}
        for port in ports:
            entry = dict(port)
            entry["cpe"] = json.loads(entry["cpe"])
            by_host.setdefault(entry.pop("scan_host_id"), []).append(entry)
        return [
            {
                **{
                    k: h[k]
                    for k in ("asset_id", "asset_uid", "address", "addr_type", "state", "reason")
                },
                "observed_at": h["observed_at"],
                "timed_out": bool(h["timed_out"]),
                "hostnames": json.loads(h["hostnames"]),
                "ports": by_host.get(h["id"], []),
            }
            for h in hosts
        ]


class AuditRepository:
    """Append-only record of security-relevant events (scope changes, launches)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def record(self, actor: str, action: str, project_id: int | None = None, **detail: Any) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (actor, action, project_id, detail) VALUES (?, ?, ?, ?)",
                (actor, action, project_id, json.dumps(detail, default=str, sort_keys=True)),
            )

    def list_all(self, project_id: int | None = None) -> list[dict[str, Any]]:
        query, params = "SELECT * FROM audit_log", ()
        if project_id is not None:
            query, params = query + " WHERE project_id = ?", (project_id,)
        with self.db.connect() as conn:
            rows = conn.execute(query + " ORDER BY id", params).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]
