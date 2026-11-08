"""Helpers for inventory and comparison tests: run a scan's lifecycle without a process."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from tests.nmapxml import BASE_TIME
from traceforge.db import Database
from traceforge.db.repositories import ResultRepository, ScanRepository
from traceforge.execution.nmap import parse_nmap_xml


def record_scan(
    db: Database,
    evidence_dir: Path,
    project_id: int,
    xml: str,
    *,
    targets: tuple[str, ...] = ("10.0.0.0/24",),
    addresses: tuple[str, ...] | None = None,
    hostnames: dict[str, list[str]] | None = None,
    options: dict | None = None,
    outcome: str = "completed",
) -> int:
    """Run a scan's whole lifecycle through the repositories, as the job manager does."""
    scans = ScanRepository(db)
    options = {
        "service_detection": True,
        "timing": 3,
        "skip_host_discovery": False,
        **(options or {}),
    }
    scan_id = scans.create(
        project_id,
        "nmap",
        list(targets),
        scan_addresses=list(addresses or targets),
        hostnames=hostnames or {},
        options=options,
        command=["/usr/bin/nmap", "-sT", "--", *(addresses or targets)],
        actor="cli",
        timeout_seconds=600,
    )
    scans.mark_running(scan_id)
    data = xml.encode()
    name = f"scan-{scan_id}-nmap-test.xml"
    (evidence_dir / name).write_bytes(data)
    evidence = {
        "evidence_path": name,
        "evidence_sha256": hashlib.sha256(data).hexdigest(),
        "evidence_bytes": len(data),
        "exit_code": 0,
    }
    report = parse_nmap_xml(data)
    if outcome == "completed":
        ResultRepository(db).complete_with_results(
            scan_id,
            project_id,
            report,
            hostnames or {},
            tool_version=report.tool_version,
            **evidence,
        )
    else:
        ResultRepository(db).store(scan_id, project_id, report, hostnames or {})
        scans.finish(scan_id, outcome, error="test", **evidence)
    return scan_id


def iso(offset: int) -> str:
    return datetime.fromtimestamp(BASE_TIME + offset, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ports_of(asset: dict) -> dict[int, dict]:
    return {p["port"]: p for p in asset["ports"]}
