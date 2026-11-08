"""Asset inventory: creation from Nmap XML, deduplication, updates, provenance, backfill."""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from tests.inventory_helpers import iso, ports_of, record_scan
from tests.nmapxml import Host, Port, nmap_xml
from traceforge.db import Database
from traceforge.db.repositories import ProjectRepository
from traceforge.execution.nmap import parse_nmap_xml
from traceforge.inventory.store import AssetQueries, backfill_scans

# --------------------------------------------------------------------------- creation


def test_asset_created_from_nmap_xml(db, evidence_dir, project) -> None:
    xml = nmap_xml(
        Host(
            "10.0.0.5",
            [
                Port(22, service="ssh", product="OpenSSH", version="9.6p1"),
                Port(8080, service="http-proxy", method="table"),
            ],
            extraports=[("closed", 998, "1-21,23-1000")],
        ),
        services="1-1000,8080",
        offset=10,
    )
    scan_id = record_scan(db, evidence_dir, project, xml)

    (summary,) = AssetQueries(db).list(project)
    assert re.fullmatch(r"ast_[0-9a-f]{16}", summary["uid"])
    assert summary["address"] == "10.0.0.5"
    assert summary["confirmed"] is True
    assert summary["open_ports"] == 2
    assert summary["first_seen"] == summary["last_seen"] == iso(10)
    assert summary["last_scan_id"] == scan_id

    asset = AssetQueries(db).get(summary["uid"])
    ports = ports_of(asset)
    assert ports[22]["state"] == "open"
    assert (ports[22]["service_name"], ports[22]["service_version"]) == ("ssh", "9.6p1")
    assert ports[22]["identification"] == "detected"
    # A port-number label is not a detection, and is labelled as such.
    assert ports[8080]["identification"] == "port-label"
    assert ports[22]["state_scan_id"] == ports[22]["service_scan_id"] == scan_id
    # Closed-in-bulk ports never seen open are not inventory.
    assert set(ports) == {22, 8080}


def test_down_hosts_and_unanswered_pn_hosts_are_not_inventory(db, evidence_dir, project) -> None:
    xml = nmap_xml(
        Host("10.0.0.6", state="down", reason="no-response"),
        Host("10.0.0.7", reason="user-set", extraports=[("filtered", 1000, None)]),
        services="1-1000",
    )
    record_scan(db, evidence_dir, project, xml, options={"skip_host_discovery": True})

    assert AssetQueries(db).list(project) == []
    hidden = AssetQueries(db).list(project, include_unconfirmed=True)
    # The down host is not stored at all; the -Pn host is stored, but unconfirmed.
    assert [(a["address"], a["confirmed"]) for a in hidden] == [("10.0.0.7", False)]
    assert AssetQueries(db).stats(project)["unconfirmed"] == 1


def test_pn_host_with_a_closed_port_counts_as_responsive(db, evidence_dir, project) -> None:
    # A TCP reset is an answer: the host is there even though -Pn skipped discovery.
    xml = nmap_xml(Host("10.0.0.8", [Port(25, state="closed")], reason="user-set"), services="25")
    record_scan(db, evidence_dir, project, xml, options={"skip_host_discovery": True})
    (asset,) = AssetQueries(db).list(project)
    assert asset["confirmed"] is True and asset["open_ports"] == 0


# --------------------------------------------------------------------------- duplicates & updates


def test_repeated_scans_do_not_duplicate_assets(db, evidence_dir, project) -> None:
    for offset in (0, 100, 200):
        record_scan(
            db,
            evidence_dir,
            project,
            nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")]), offset=offset),
        )

    (summary,) = AssetQueries(db).list(project)
    assert summary["first_seen"] == iso(0)
    assert summary["last_seen"] == iso(200)
    asset = AssetQueries(db).get(summary["uid"])
    assert len(asset["observations"]) == 3
    assert [o["observed_at"] for o in asset["observations"]] == [iso(200), iso(100), iso(0)]
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1


def test_asset_updates_across_scans(db, evidence_dir, project) -> None:
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")]), services="22,80"),
    )
    second = record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(
            Host(
                "10.0.0.5",
                [
                    Port(22, state="closed"),
                    Port(80, service="http", product="nginx", version="1.26"),
                ],
            ),
            services="22,80",
            offset=100,
        ),
    )

    asset = AssetQueries(db).get(AssetQueries(db).list(project)[0]["uid"])
    ports = ports_of(asset)
    assert ports[22]["state"] == "closed"
    assert ports[22]["state_scan_id"] == second
    assert ports[22]["last_open_at"] == iso(0)  # history kept
    assert ports[80]["state"] == "open" and ports[80]["service_version"] == "1.26"
    assert asset["open_ports"] == 1


def test_bulk_reported_closure_is_applied(db, evidence_dir, project) -> None:
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(Host("10.0.0.5", [Port(8080, service="http")]), services="8080"),
    )
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(
            Host(
                "10.0.0.5", [Port(8000, service="http")], extraports=[("closed", 100, "8001-8100")]
            ),
            services="8000-8100",
            offset=50,
        ),
    )
    ports = ports_of(AssetQueries(db).get(AssetQueries(db).list(project)[0]["uid"]))
    assert ports[8080]["state"] == "closed"


def test_a_port_not_rescanned_keeps_its_last_observed_state(db, evidence_dir, project) -> None:
    first = record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(Host("10.0.0.5", [Port(8080, service="http")]), services="8080"),
    )
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")]), services="22", offset=100),
    )
    ports = ports_of(AssetQueries(db).get(AssetQueries(db).list(project)[0]["uid"]))
    assert ports[8080]["state"] == "open"
    assert ports[8080]["last_seen"] == iso(0)  # last *observed*, not last scan
    assert ports[8080]["state_scan_id"] == first


def test_ingestion_order_does_not_matter(db, evidence_dir, project) -> None:
    # A later-observed scan ingested first (e.g. backfill) must not be overwritten.
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(Host("10.0.0.5", [Port(22, state="closed")]), services="22", offset=500),
    )
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")]), services="22", offset=0),
    )
    ports = ports_of(AssetQueries(db).get(AssetQueries(db).list(project)[0]["uid"]))
    assert ports[22]["state"] == "closed"


@pytest.mark.parametrize("outcome", ["failed", "cancelled"])
def test_failed_or_cancelled_scans_never_change_assets(db, evidence_dir, project, outcome) -> None:
    record_scan(db, evidence_dir, project, nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")])))
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(
            Host("10.0.0.5", [Port(22, state="closed"), Port(3306, service="mysql")]), offset=100
        ),
        outcome=outcome,
    )
    asset = AssetQueries(db).get(AssetQueries(db).list(project)[0]["uid"])
    assert ports_of(asset)[22]["state"] == "open"
    assert 3306 not in ports_of(asset)
    assert len(asset["observations"]) == 1


def test_results_and_completion_are_atomic(db, evidence_dir, project, monkeypatch) -> None:
    import traceforge.inventory.store as store

    def boom(conn, ids):
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "refresh_assets", boom)
    with pytest.raises(RuntimeError):
        record_scan(
            db, evidence_dir, project, nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")]))
        )
    with db.connect() as conn:
        assert conn.execute("SELECT status FROM scans").fetchone()[0] == "running"
        assert conn.execute("SELECT COUNT(*) FROM scan_hosts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


# --------------------------------------------------------------------------- provenance


def test_observations_carry_full_provenance(db, evidence_dir, project) -> None:
    xml = nmap_xml(
        Host("93.184.216.34", [Port(443, service="https", product="nginx")]),
        services="443",
        offset=7,
    )
    scan_id = record_scan(
        db,
        evidence_dir,
        project,
        xml,
        targets=("app.example.com", "10.0.0.0/24"),
        addresses=("93.184.216.34", "10.0.0.0/24"),
        hostnames={"93.184.216.34": ["app.example.com"]},
    )
    asset = AssetQueries(db).get(AssetQueries(db).list(project)[0]["uid"])
    assert asset["hostnames"] == ["app.example.com"]
    (observation,) = asset["observations"]
    prov = observation["provenance"]
    assert prov["project_id"] == project
    assert prov["scan_id"] == scan_id
    assert (prov["tool"], prov["tool_version"]) == ("nmap", "7.99")
    assert prov["observed_at"] == iso(7)
    assert prov["requested_targets"] == ["app.example.com"]
    assert prov["scanned_address"] == "93.184.216.34"
    config = prov["configuration"]
    assert config["ports_scanned"] == {"tcp": "443"}
    assert config["options"]["service_detection"] is True
    assert config["command"][0] == "/usr/bin/nmap"
    assert config["host_discovery"] is True
    # Evidence is referenced (one file per scan), and its hash still verifies.
    evidence = prov["evidence"]
    data = (evidence_dir / evidence["file"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == evidence["sha256"]
    assert len(list(evidence_dir.iterdir())) == 1


# --------------------------------------------------------------------------- isolation


def test_projects_are_isolated(db, evidence_dir) -> None:
    projects = ProjectRepository(db)
    first, second = projects.create("one", "A")["id"], projects.create("two", "B")["id"]
    record_scan(db, evidence_dir, first, nmap_xml(Host("10.0.0.5", [Port(22, service="ssh")])))
    record_scan(
        db, evidence_dir, second, nmap_xml(Host("10.0.0.5", [Port(3389, service="ms-wbt-server")]))
    )

    queries = AssetQueries(db)
    (a,), (b,) = queries.list(first), queries.list(second)
    assert a["uid"] != b["uid"]
    assert [s["port"] for s in a["services"]] == [22]
    assert [s["port"] for s in b["services"]] == [3389]
    for asset, project_id in ((queries.get(a["uid"]), first), (queries.get(b["uid"]), second)):
        assert {o["provenance"]["project_id"] for o in asset["observations"]} == {project_id}
    assert queries.stats(first)["open_ports"] == 1


def test_search(db, evidence_dir, project) -> None:
    record_scan(
        db,
        evidence_dir,
        project,
        nmap_xml(
            Host("10.0.0.5", [Port(22, service="ssh", product="OpenSSH")]),
            Host("10.0.0.6", [Port(8080, service="http", product="Jetty")]),
        ),
    )
    queries = AssetQueries(db)
    assert [a["address"] for a in queries.list(project, "jetty")] == ["10.0.0.6"]
    assert [a["address"] for a in queries.list(project, "8080")] == ["10.0.0.6"]
    assert [a["address"] for a in queries.list(project, "10.0.0.5")] == ["10.0.0.5"]
    # LIKE wildcards in user input are literal.
    assert queries.list(project, "%") == [] and queries.list(project, "_") == []


# --------------------------------------------------------------------------- v0.2 upgrade


def test_v02_database_is_upgraded_without_losing_anything(tmp_path, evidence_dir) -> None:
    """A database written by v0.2 (schema 3) gains the inventory on first start."""
    from traceforge.db.schema import MIGRATIONS

    db = Database(tmp_path / "v02.db")
    xml = nmap_xml(
        Host("10.0.0.5", [Port(22, service="ssh")], extraports=[("closed", 999, "1-21,23-1000")]),
        Host("10.0.0.9", state="down", reason="no-response"),
        services="1-1000",
    ).encode()
    good, tampered = "scan-1-nmap-a.xml", "scan-2-nmap-b.xml"
    (evidence_dir / good).write_bytes(xml)
    (evidence_dir / tampered).write_bytes(xml + b"<!-- edited -->")
    digest = hashlib.sha256(xml).hexdigest()
    with db.connect() as conn:  # exactly what v0.2 stored
        for migration in MIGRATIONS[:3]:
            conn.executescript(migration)
        conn.execute("PRAGMA user_version = 3")
        conn.execute("INSERT INTO projects (name, authorization_ref) VALUES ('legacy', 'X')")
        for scan_id, name in ((1, good), (2, tampered)):
            conn.execute(
                "INSERT INTO scans (id, project_id, tool, name, target, targets, scan_addresses, "
                "options, status, finished_at, evidence_path, evidence_sha256, evidence_bytes, "
                "tool_version) VALUES (?, 1, 'nmap', 'nmap scan', ?, ?, ?, ?, 'completed', "
                "?, ?, ?, ?, '7.99')",
                (
                    scan_id,
                    "10.0.0.0/24",
                    '["10.0.0.0/24"]',
                    '["10.0.0.0/24"]',
                    '{"service_detection": true}',
                    f"2026-11-0{scan_id}T10:00:00.000Z",
                    name,
                    digest,
                    len(xml),
                ),
            )
        conn.execute(
            "INSERT INTO assets (project_id, address, addr_type) VALUES (1, '10.0.0.5', 'ipv4'), "
            "(1, '10.0.0.9', 'ipv4')"
        )
        for scan_id in (1, 2):
            conn.execute(
                "INSERT INTO scan_hosts (scan_id, asset_id, state, reason) VALUES (?, 1, ?, ?)",
                (scan_id, "up", "conn-refused"),
            )
            conn.execute(
                "INSERT INTO scan_ports (scan_host_id, protocol, port, state, service_name, "
                "service_method) VALUES (?, 'tcp', 22, 'open', 'ssh', 'probed')",
                (scan_id,),
            )
        conn.execute(
            "INSERT INTO scan_hosts (scan_id, asset_id, state, reason) VALUES (1, 2, ?, ?)",
            ("down", "no-response"),
        )

    db.initialize()
    counts = backfill_scans(db, evidence_dir, {"nmap": parse_nmap_xml})
    assert counts == {"scans": 2, "reparsed": 1, "unverifiable": 1}
    assert backfill_scans(db, evidence_dir, {"nmap": parse_nmap_xml})["scans"] == 0  # idempotent

    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM scan_hosts").fetchone()[0] == 3
        coverage = dict(conn.execute("SELECT id, coverage FROM scans").fetchall())
        hashes = [r[0] for r in conn.execute("SELECT evidence_sha256 FROM scans")]
    assert json.loads(coverage[1]) == {"tcp": "1-1000"}
    assert coverage[2] is None  # altered evidence is never trusted: coverage stays unknown
    assert hashes == [digest, digest]  # recorded hashes untouched
    assert hashlib.sha256((evidence_dir / good).read_bytes()).hexdigest() == digest

    (asset,) = AssetQueries(db).list(1)  # the v0.2 "down" host is not inventory
    assert re.fullmatch(r"ast_[0-9a-f]{16}", asset["uid"])
    assert asset["open_ports"] == 1 and len(AssetQueries(db).get(asset["uid"])["observations"]) == 2
