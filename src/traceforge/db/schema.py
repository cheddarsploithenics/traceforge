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
    # 3 — scan jobs, assets, ports/services and evidence references.
    # SQLite cannot alter a CHECK constraint, so `scans` is rebuilt; legacy
    # 'pending' rows become 'queued'.
    f"""
    CREATE TABLE scans_v3 (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id       INTEGER REFERENCES projects (id),
        tool             TEXT,
        name             TEXT    NOT NULL,
        target           TEXT    NOT NULL,
        targets          TEXT    NOT NULL DEFAULT '[]',
        scan_addresses   TEXT    NOT NULL DEFAULT '[]',
        hostnames        TEXT    NOT NULL DEFAULT '{{}}',
        options          TEXT    NOT NULL DEFAULT '{{}}',
        command          TEXT    NOT NULL DEFAULT '[]',
        actor            TEXT,
        status           TEXT    NOT NULL DEFAULT 'queued'
                         CHECK (status IN ('queued', 'running', 'completed', 'failed',
                                           'cancelled')),
        timeout_seconds  INTEGER,
        created_at       TEXT    NOT NULL DEFAULT {_TIMESTAMP},
        started_at       TEXT,
        finished_at      TEXT,
        exit_code        INTEGER,
        error            TEXT,
        evidence_path    TEXT,
        evidence_sha256  TEXT,
        evidence_bytes   INTEGER,
        tool_version     TEXT,
        notes            TEXT
    );
    INSERT INTO scans_v3 (id, project_id, tool, name, target, targets, status, created_at,
                          started_at, finished_at, notes)
        SELECT id, project_id, tool, name, target, json_array(target),
               CASE status WHEN 'pending' THEN 'queued' ELSE status END,
               created_at, started_at, finished_at, notes
        FROM scans;
    DROP TABLE scans;
    ALTER TABLE scans_v3 RENAME TO scans;
    CREATE INDEX idx_scans_created_at ON scans (created_at);
    CREATE INDEX idx_scans_project ON scans (project_id, id);
    CREATE INDEX idx_scans_status ON scans (status);

    -- Hosts seen in a project, across scans.
    CREATE TABLE assets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id  INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
        address     TEXT    NOT NULL,
        addr_type   TEXT    NOT NULL,
        hostnames   TEXT    NOT NULL DEFAULT '[]',
        first_seen  TEXT    NOT NULL DEFAULT {_TIMESTAMP},
        last_seen   TEXT    NOT NULL DEFAULT {_TIMESTAMP},
        UNIQUE (project_id, address)
    );

    -- A host as observed by one scan.
    CREATE TABLE scan_hosts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
        asset_id    INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
        state       TEXT    NOT NULL,
        reason      TEXT,
        hostnames   TEXT    NOT NULL DEFAULT '[]',
        UNIQUE (scan_id, asset_id)
    );

    -- A port and the service identified on it, as observed by one scan.
    CREATE TABLE scan_ports (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_host_id       INTEGER NOT NULL REFERENCES scan_hosts (id) ON DELETE CASCADE,
        protocol           TEXT    NOT NULL,
        port               INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
        state              TEXT    NOT NULL,
        reason             TEXT,
        service_name       TEXT,
        service_product    TEXT,
        service_version    TEXT,
        service_extrainfo  TEXT,
        service_tunnel     TEXT,
        service_method     TEXT,
        service_confidence INTEGER,
        cpe                TEXT    NOT NULL DEFAULT '[]',
        UNIQUE (scan_host_id, protocol, port)
    );
    CREATE INDEX idx_scan_ports_host ON scan_ports (scan_host_id);
    """,
)

SCHEMA_VERSION = len(MIGRATIONS)
