"""Data access for projects, scope rules, scans and the audit log."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from traceforge.db.database import Database


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


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, project_id: int, tool: str, targets: Sequence[str]) -> int:
        with self.db.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (project_id, tool, name, target, status) "
                "VALUES (?, ?, ?, ?, 'pending')",
                (project_id, tool, f"{tool} scan", ", ".join(targets)),
            )
            return int(cursor.lastrowid or 0)

    def set_status(self, scan_id: int, status: str) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))

    def get(self, scan_id: int) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"scan {scan_id} not found")
        return dict(row)


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
