"""Scan job manager: real subprocesses (the fake nmap), real timeouts and signals."""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.conftest import FakeNmap, fake_resolver
from traceforge.db import Database
from traceforge.execution.executor import Executor
from traceforge.execution.jobs import QueueFullError, ScanJobManager
from traceforge.execution.nmap import NmapAdapter
from traceforge.execution.scope import parse_scope_rule
from traceforge.execution.tools import ToolRegistry


async def eventually(condition: Callable[[], bool], timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        if asyncio.get_running_loop().time() > deadline:
            pytest.fail("condition not met in time")
        await asyncio.sleep(0.02)


def process_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "t.db")
    database.initialize()
    return database


@pytest.fixture
def make(db: Database, fake_nmap: FakeNmap, tmp_path: Path):
    """Build (executor, manager, project_id) wired to the fake nmap."""

    def build(**manager_options) -> tuple[Executor, ScanJobManager, int]:
        manager = ScanJobManager(db, evidence_dir=tmp_path / "evidence", **manager_options)
        executor = Executor(
            db,
            tools=ToolRegistry([NmapAdapter(fake_nmap.path)]),
            runner=manager,
            resolver=fake_resolver,
        )
        project = executor.projects.create(f"p{len(executor.projects.list_all())}", "SOW-1")
        for kind, value in (("include", "10.0.0.0/24"), ("include", "*.example.com")):
            rule = parse_scope_rule(kind, value)  # type: ignore[arg-type]
            executor.scope.add(project["id"], rule.kind, rule.value, None)
        return executor, manager, project["id"]

    return build


async def launch(executor: Executor, pid: int, targets=("10.0.0.5",), **kwargs) -> int:
    options = kwargs.pop("options", {"ports": "22,80"})
    result = await executor.launch(
        pid, "nmap", list(targets), actor="cli", options=options, **kwargs
    )
    return result.scan_id


async def test_completed_scan_stores_results_and_evidence(make, fake_nmap, tmp_path) -> None:
    executor, manager, pid = make()
    scan_id = await launch(executor, pid, ["10.0.0.5", "app.example.com"])
    await manager.wait_for(scan_id)

    scan = executor.scans.get(scan_id)
    assert scan["status"] == "completed", scan["error"]
    assert scan["exit_code"] == 0
    assert scan["started_at"] and scan["finished_at"]
    assert scan["tool_version"] == "7.99-fake"
    assert scan["hosts_up"] == 2 and scan["open_ports"] == 4
    assert scan["scan_addresses"] == ["10.0.0.5", "93.184.216.34"]  # hostname pinned

    hosts = executor.results.for_scan(scan_id)
    assert [h["address"] for h in hosts] == ["10.0.0.5", "93.184.216.34"]
    assert hosts[1]["hostnames"] == ["app.example.com"]
    ssh = hosts[0]["ports"][0]
    assert (ssh["port"], ssh["state"], ssh["service_name"], ssh["service_product"]) == (
        22,
        "open",
        "ssh",
        "OpenSSH",
    )

    evidence_dir = tmp_path / "evidence"
    evidence = evidence_dir / scan["evidence"]["file"]
    data = evidence.read_bytes()
    assert hashlib.sha256(data).hexdigest() == scan["evidence"]["sha256"]
    assert scan["evidence"]["size_bytes"] == len(data)
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    assert stat.S_IMODE(evidence_dir.stat().st_mode) == 0o700

    actions = [e["action"] for e in executor.audit.list_all(pid)]
    assert actions[-3:] == ["launch.authorized", "scan.started", "scan.completed"]


async def test_assets_accumulate_across_scans(make) -> None:
    executor, manager, pid = make()
    for _ in range(2):
        await manager.wait_for(await launch(executor, pid))
    with executor.scans.db.connect() as conn:
        assets = conn.execute("SELECT address, first_seen, last_seen FROM assets").fetchall()
    assert [a["address"] for a in assets] == ["10.0.0.5"]


async def test_tool_runs_with_a_minimal_environment(make, fake_nmap, monkeypatch) -> None:
    monkeypatch.setenv("TRACEFORGE_API_TOKEN_LEAK", "secret-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    executor, manager, pid = make()
    await manager.wait_for(await launch(executor, pid))

    assert set(fake_nmap.environment) <= {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE"}
    assert "secret-token" not in str(fake_nmap.environment)


@pytest.mark.parametrize(
    "mode, expected",
    [
        ("fail", "nmap exited with status 1: Failed to resolve given hostname/IP\nQUITTING!"),
        ("garbage", "unusable nmap output: malformed nmap XML"),
    ],
)
async def test_failures_are_recorded(make, fake_nmap, mode, expected) -> None:
    fake_nmap.set_scenario(mode)
    executor, manager, pid = make()
    scan_id = await launch(executor, pid)
    await manager.wait_for(scan_id)

    scan = executor.scans.get(scan_id)
    assert scan["status"] == "failed"
    assert scan["error"].startswith(expected)
    assert executor.audit.list_all(pid)[-1]["action"] == "scan.failed"


async def test_nmap_reported_error_fails_the_scan(make, fake_nmap) -> None:
    fake_nmap.set_scenario(
        "xml",
        xml='<nmaprun><runstats><finished exit="error" errormsg="boom"/></runstats></nmaprun>',
    )
    executor, manager, pid = make()
    scan_id = await launch(executor, pid)
    await manager.wait_for(scan_id)
    assert executor.scans.get(scan_id)["error"] == "nmap reported: boom"


async def test_timeout_kills_the_process(make, fake_nmap) -> None:
    fake_nmap.set_scenario("sleep")
    executor, manager, pid = make()
    executor.default_timeout_seconds = 1
    scan_id = await launch(executor, pid)
    await manager.wait_for(scan_id)

    scan = executor.scans.get(scan_id)
    assert scan["status"] == "failed"
    assert scan["error"] == "timed out after 1 s"
    assert process_gone(fake_nmap.pids[0])


async def test_cancel_running_scan_terminates_process(make, fake_nmap) -> None:
    fake_nmap.set_scenario("sleep")
    executor, manager, pid = make()
    scan_id = await launch(executor, pid)
    await eventually(lambda: bool(fake_nmap.pids))
    assert executor.scans.get(scan_id)["status"] == "running"

    assert await manager.cancel(scan_id) is True

    scan = executor.scans.get(scan_id)
    assert scan["status"] == "cancelled"
    assert scan["error"] == "cancelled by operator"
    assert scan["evidence"] is not None  # partial output is still referenced
    assert process_gone(fake_nmap.pids[0])
    assert executor.audit.list_all(pid)[-1]["action"] == "scan.cancelled"
    assert await manager.cancel(scan_id) is False  # already finished


async def test_process_ignoring_sigterm_is_killed(make, fake_nmap) -> None:
    fake_nmap.set_scenario("ignore-term")
    executor, manager, pid = make(kill_grace_seconds=0.3)
    scan_id = await launch(executor, pid)
    await eventually(lambda: bool(fake_nmap.pids))
    await asyncio.sleep(0.2)  # let it install its SIGTERM handler

    await manager.cancel(scan_id)

    assert executor.scans.get(scan_id)["status"] == "cancelled"
    assert process_gone(fake_nmap.pids[0])


async def test_concurrency_limit_queues_extra_scans(make, fake_nmap) -> None:
    fake_nmap.set_scenario("sleep")
    executor, manager, pid = make(max_concurrent=1)
    first = await launch(executor, pid)
    second = await launch(executor, pid)
    await eventually(lambda: len(fake_nmap.pids) == 1)
    await asyncio.sleep(0.2)

    assert executor.scans.get(first)["status"] == "running"
    assert executor.scans.get(second)["status"] == "queued"
    assert len(fake_nmap.calls) == 1

    await manager.cancel(first)
    await eventually(lambda: len(fake_nmap.pids) == 2)
    assert executor.scans.get(second)["status"] == "running"
    await manager.cancel(second)
    assert len(fake_nmap.calls) == 2


async def test_cancelling_a_queued_scan_never_starts_it(make, fake_nmap) -> None:
    fake_nmap.set_scenario("sleep")
    executor, manager, pid = make(max_concurrent=1)
    first = await launch(executor, pid)
    queued = await launch(executor, pid)
    await eventually(lambda: bool(fake_nmap.pids))

    await manager.cancel(queued)
    assert executor.scans.get(queued)["status"] == "cancelled"
    assert executor.scans.get(queued)["started_at"] is None

    await manager.cancel(first)
    assert len(fake_nmap.calls) == 1


async def test_queue_limit(make, fake_nmap) -> None:
    fake_nmap.set_scenario("sleep")
    executor, manager, pid = make(max_concurrent=1, max_queued=1)
    await launch(executor, pid)
    await launch(executor, pid)

    with pytest.raises(QueueFullError):
        await launch(executor, pid)
    rejected = executor.scans.list_all(pid)[0]
    assert rejected["status"] == "failed"
    assert rejected["error"].startswith("not started:")
    await manager.shutdown()


async def test_shutdown_cancels_everything(make, fake_nmap) -> None:
    fake_nmap.set_scenario("sleep")
    executor, manager, pid = make(max_concurrent=1)
    ids = [await launch(executor, pid) for _ in range(3)]
    await eventually(lambda: bool(fake_nmap.pids))

    await manager.shutdown()

    assert manager.active_count == 0
    for scan_id in ids:
        scan = executor.scans.get(scan_id)
        assert (scan["status"], scan["error"]) == ("cancelled", "server shutting down")
    assert process_gone(fake_nmap.pids[0])


async def test_output_limit_aborts_scan(make, fake_nmap) -> None:
    fake_nmap.set_scenario("huge")
    executor, manager, pid = make(max_output_bytes=4096)
    scan_id = await launch(executor, pid)
    await manager.wait_for(scan_id)

    scan = executor.scans.get(scan_id)
    assert scan["status"] == "failed"
    assert "exceeded 4096 bytes" in scan["error"]
    assert process_gone(fake_nmap.pids[0])


async def test_binary_disappearing_before_start_fails_cleanly(make, fake_nmap, tmp_path) -> None:
    executor, manager, pid = make(max_concurrent=1)
    fake_nmap.set_scenario("sleep")
    blocker = await launch(executor, pid)
    queued = await launch(executor, pid)
    await eventually(lambda: bool(fake_nmap.pids))
    fake_nmap.path.unlink()

    await manager.cancel(blocker)
    await manager.wait_for(queued)

    scan = executor.scans.get(queued)
    assert scan["status"] == "failed"
    assert scan["error"].startswith("could not start nmap")
    assert scan["evidence"] is None
    assert len(list((tmp_path / "evidence").iterdir())) == 1  # only the blocker's


async def test_recover_marks_interrupted_scans_failed(make, db) -> None:
    executor, manager, pid = make()
    scan_id = executor.scans.create(pid, "nmap", ["10.0.0.5"])
    executor.scans.mark_running(scan_id)

    assert manager.recover() == [scan_id]
    scan = executor.scans.get(scan_id)
    assert scan["status"] == "failed"
    assert "interrupted" in scan["error"]


def test_terminal_states_are_never_rewritten(make) -> None:
    executor, _, pid = make()
    scan_id = executor.scans.create(pid, "nmap", ["10.0.0.5"])
    assert executor.scans.finish(scan_id, "completed") is True
    assert executor.scans.finish(scan_id, "cancelled") is False
    assert executor.scans.mark_running(scan_id) is False
    assert executor.scans.get(scan_id)["status"] == "completed"
    with pytest.raises(ValueError):
        executor.scans.finish(scan_id, "running")
