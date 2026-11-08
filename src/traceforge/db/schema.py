"""SQLite schema, applied as ordered migrations.

``PRAGMA user_version`` records how many migrations have run. Append new
migrations to ``MIGRATIONS``; never edit one that has been released.
"""

_TIMESTAMP = "(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"

MIGRATIONS: tuple[str, ...] = (
    # 1 — scan history
    f"""
    CREATE TABLE IF NOT EXISTS scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        target       TEXT    NOT NULL,
        status       TEXT    NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
        created_at   TEXT    NOT NULL DEFAULT {_TIMESTAMP},
        started_at   TEXT,
        finished_at  TEXT,
        notes        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at);
    """,
    # 2 — projects, authorized scope and audit trail
    f"""
    CREATE TABLE projects (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        name               TEXT NOT NULL UNIQUE,
        authorization_ref  TEXT NOT NULL CHECK (length(trim(authorization_ref)) > 0),
        authorized_from    TEXT,
        authorized_until   TEXT,
        created_at         TEXT NOT NULL DEFAULT {_TIMESTAMP}
    );
    CREATE TABLE scope_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id  INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
        kind        TEXT    NOT NULL CHECK (kind IN ('include', 'exclude')),
        value       TEXT    NOT NULL,
        note        TEXT,
        created_at  TEXT    NOT NULL DEFAULT {_TIMESTAMP},
        UNIQUE (project_id, kind, value)
    );
    ALTER TABLE scans ADD COLUMN project_id INTEGER REFERENCES projects (id);
    ALTER TABLE scans ADD COLUMN tool TEXT;
    CREATE TABLE audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at  TEXT    NOT NULL DEFAULT {_TIMESTAMP},
        actor       TEXT    NOT NULL,
        action      TEXT    NOT NULL,
        project_id  INTEGER,
        detail      TEXT    NOT NULL DEFAULT '{{}}'
    );
    CREATE INDEX idx_audit_project ON audit_log (project_id, created_at);
    """,
)

SCHEMA_VERSION = len(MIGRATIONS)
