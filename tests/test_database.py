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
    assert row["status"] == "queued"
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


def test_migrates_v2_scans_to_job_states(tmp_path: Path) -> None:
    from traceforge.db.schema import MIGRATIONS

    db = Database(tmp_path / "v2.db")
    with db.connect() as conn:  # schema v2 as shipped in TraceForge 0.1
        for migration in MIGRATIONS[:2]:
            conn.executescript(migration)
        conn.execute("PRAGMA user_version = 2")
        conn.execute("INSERT INTO projects (name, authorization_ref) VALUES ('p', 'ref')")
        conn.execute(
            "INSERT INTO scans (name, target, status, project_id, tool) "
            "VALUES ('old', '10.0.0.1', 'pending', 1, 'probe')"
        )
        conn.execute(
            "INSERT INTO scans (name, target, status, project_id, tool) "
            "VALUES ('done', '10.0.0.2', 'completed', 1, 'probe')"
        )

    db.initialize()

    with db.connect() as conn:
        rows = conn.execute("SELECT name, status, targets FROM scans ORDER BY id").fetchall()
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert [tuple(r) for r in rows] == [
        ("old", "queued", '["10.0.0.1"]'),
        ("done", "completed", '["10.0.0.2"]'),
    ]
    assert {"assets", "scan_hosts", "scan_ports"} <= tables


def test_scan_results_cascade_with_scan(tmp_path: Path) -> None:
    from traceforge.db.repositories import ResultRepository, ScanRepository
    from traceforge.execution.tools import HostResult, PortResult, ToolReport

    db = Database(tmp_path / "t.db")
    db.initialize()
    with db.connect() as conn:
        conn.execute("INSERT INTO projects (name, authorization_ref) VALUES ('p', 'ref')")
    scan_id = ScanRepository(db).create(1, "nmap", ["10.0.0.1"])
    report = ToolReport(
        hosts=(HostResult("10.0.0.1", "ipv4", "up", ports=(PortResult("tcp", 22, "open"),)),)
    )
    ResultRepository(db).store(scan_id, 1, report)
    with db.connect() as conn:
        conn.execute("DELETE FROM scans")
        assert conn.execute("SELECT COUNT(*) FROM scan_ports").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM scan_hosts").fetchone()[0] == 0
        # Assets are project inventory and outlive individual scans.
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1


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
