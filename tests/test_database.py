from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from traceforge.db import Database
from traceforge.db.schema import SCHEMA_VERSION


def test_initialize_creates_file_and_parent_dirs(tmp_path: Path) -> None:
    db = Database(tmp_path / "nested" / "dir" / "traceforge.db")

    db.initialize()

    assert db.path.exists()
    assert db.schema_version() == SCHEMA_VERSION


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "traceforge.db")
    db.initialize()
    db.initialize()

    assert db.schema_version() == SCHEMA_VERSION


def test_scans_table_exists_and_enforces_status(tmp_path: Path) -> None:
    db = Database(tmp_path / "traceforge.db")
    db.initialize()

    with db.connect() as conn:
        conn.execute("INSERT INTO scans (name, target) VALUES (?, ?)", ("demo", "10.0.0.1"))
        row = conn.execute("SELECT name, target, status, created_at FROM scans").fetchone()

    assert row["name"] == "demo"
    assert row["status"] == "pending"
    assert row["created_at"]

    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint"), db.connect() as conn:
        conn.execute("INSERT INTO scans (name, target, status) VALUES ('x', 'y', 'bogus')")


def test_ping(tmp_path: Path) -> None:
    assert Database(tmp_path / "ok.db").ping() is True
    assert Database(tmp_path / "missing-dir" / "x.db").ping() is False


def test_migrates_v1_database_and_keeps_scan_history(tmp_path: Path) -> None:
    from traceforge.db.schema import MIGRATIONS

    db = Database(tmp_path / "old.db")
    with db.connect() as conn:  # a database created by TraceForge v0.1 (schema v1)
        conn.executescript(MIGRATIONS[0])
        conn.execute("PRAGMA user_version = 1")
        conn.execute("INSERT INTO scans (name, target) VALUES ('legacy', '10.0.0.1')")

    db.initialize()

    assert db.schema_version() == SCHEMA_VERSION
    with db.connect() as conn:
        row = conn.execute("SELECT name, project_id, tool FROM scans").fetchone()
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tuple(row) == ("legacy", None, None)
    assert {"projects", "scope_rules", "audit_log"} <= tables


def test_refuses_database_from_newer_version(tmp_path: Path) -> None:
    db = Database(tmp_path / "future.db")
    with db.connect() as conn:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(RuntimeError, match="newer"):
        db.initialize()


def test_deleting_project_cascades_to_scope(tmp_path: Path) -> None:
    db = Database(tmp_path / "t.db")
    db.initialize()
    with db.connect() as conn:
        conn.execute("INSERT INTO projects (name, authorization_ref) VALUES ('p', 'ref')")
        conn.execute("INSERT INTO scope_rules (project_id, kind, value) VALUES (1, 'include', 'x')")
        conn.execute("DELETE FROM projects")
        assert conn.execute("SELECT COUNT(*) FROM scope_rules").fetchone()[0] == 0
