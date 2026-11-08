"""Thin wrapper around :mod:`sqlite3`.

A new connection is opened per unit of work. SQLite connections are cheap and
this keeps the layer safe to use from FastAPI's thread pool without sharing
connection objects across threads.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from traceforge.db.schema import MIGRATIONS, SCHEMA_VERSION


class Database:
    """Access point for the TraceForge SQLite database."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection that commits on success and rolls back on error."""
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the database file and apply any pending migrations."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            current = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema v{current} is newer than this TraceForge (v{SCHEMA_VERSION})"
            )
        for version in range(current + 1, SCHEMA_VERSION + 1):
            # executescript() manages its own transaction; wrap each migration
            # with its version bump so it applies atomically.
            script = MIGRATIONS[version - 1]
            with self.connect() as conn:
                conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {version};\nCOMMIT;")

    def schema_version(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])

    def ping(self) -> bool:
        """Return True if the database can be opened and queried."""
        try:
            with self.connect() as conn:
                conn.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True
