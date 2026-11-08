"""The execution choke point: scope is enforced before any tool is launched."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.conftest import fake_resolver
from traceforge.db import Database
from traceforge.execution.executor import (
    AuthorizationWindowError,
    Executor,
    ToolUnavailableError,
    UnavailableRunner,
)
from traceforge.execution.jobs import ScanJob
from traceforge.execution.scope import (
    AuthorizedTargets,
    InvalidTargetError,
    ScopeViolationError,
    parse_scope_rule,
)
from traceforge.execution.tools import ToolCommand, ToolRegistry, ToolReport

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


class RecordingTool:
    name = "probe"

    def __init__(self) -> None:
        self.calls: list[AuthorizedTargets] = []

    def parse_options(self, raw):
        return dict(raw)

    def build_command(self, targets: AuthorizedTargets, options) -> ToolCommand:
        self.calls.append(targets)
        args = targets.as_arguments()
        return ToolCommand(argv=["probe", "--", *args], scan_addresses=args, options=options)

    def parse_output(self, data: bytes) -> ToolReport:
        return ToolReport()


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[int, list[str]]] = []
        self.jobs: list[ScanJob] = []

    async def submit(self, job: ScanJob) -> None:
        self.jobs.append(job)
        self.calls.append((job.scan_id, job.command.argv))


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "t.db")
    database.initialize()
    return database


@pytest.fixture
def tool() -> RecordingTool:
    return RecordingTool()


@pytest.fixture
def runner() -> RecordingRunner:
    return RecordingRunner()


@pytest.fixture
def executor(db: Database, tool: RecordingTool, runner: RecordingRunner) -> Executor:
    return Executor(
        db, tools=ToolRegistry([tool]), runner=runner, resolver=fake_resolver, clock=lambda: NOW
    )


def make_project(executor: Executor, *rules: tuple[str, str], **window) -> int:
    project = executor.projects.create("acme", "SOW-42", **window)
    for kind, value in rules:
        rule = parse_scope_rule(kind, value)  # type: ignore[arg-type]
        executor.scope.add(project["id"], rule.kind, rule.value, None)
    return project["id"]


async def test_in_scope_launch_reaches_tool_and_runner(executor, tool, runner) -> None:
    pid = make_project(executor, ("include", "10.0.0.0/24"))

    result = await executor.launch(pid, "probe", ["10.0.0.5", "10.0.0.6"], actor="cli")

    assert tool.calls[0].as_arguments() == ["10.0.0.5", "10.0.0.6"]
    assert runner.calls == [(result.scan_id, ["probe", "--", "10.0.0.5", "10.0.0.6"])]
    assert executor.scans.get(result.scan_id)["status"] == "queued"
    events = executor.audit.list_all(pid)
    assert events[-1]["action"] == "launch.authorized"
    assert events[-1]["detail"]["targets"] == ["10.0.0.5", "10.0.0.6"]


@pytest.mark.parametrize(
    "targets",
    [
        ["192.168.1.1"],
        ["10.0.0.5", "192.168.1.1"],  # one bad target blocks the whole launch
        ["10.0.0.0/23"],
        ["10.0.0.99"],  # excluded
        ["unknown.example.com"],
    ],
)
async def test_out_of_scope_launch_never_reaches_tool(executor, tool, runner, targets) -> None:
    pid = make_project(executor, ("include", "10.0.0.0/24"), ("exclude", "10.0.0.99"))

    with pytest.raises(ScopeViolationError):
        await executor.launch(pid, "probe", targets, actor="cli")

    assert tool.calls == []
    assert runner.calls == []
    denied = executor.audit.list_all(pid)[-1]
    assert denied["action"] == "launch.denied"
    assert denied["actor"] == "cli"
    assert denied["detail"]["targets"] == targets


async def test_project_without_scope_cannot_launch(executor, tool, runner) -> None:
    pid = make_project(executor)
    with pytest.raises(ScopeViolationError, match="no authorized scope"):
        await executor.launch(pid, "probe", ["10.0.0.1"], actor="cli")
    assert runner.calls == []


async def test_malformed_target_is_rejected_and_audited(executor, runner) -> None:
    pid = make_project(executor, ("include", "10.0.0.0/24"))
    with pytest.raises(InvalidTargetError):
        await executor.launch(pid, "probe", ["-oN /tmp/pwn"], actor="dashboard")
    assert runner.calls == []
    assert executor.audit.list_all(pid)[-1]["action"] == "launch.denied"


@pytest.mark.parametrize(
    "window",
    [
        {"authorized_from": NOW + timedelta(days=1)},
        {"authorized_until": NOW - timedelta(seconds=1)},
        {"authorized_from": NOW - timedelta(days=9), "authorized_until": NOW},
    ],
)
async def test_launch_outside_authorization_window_is_denied(executor, runner, window) -> None:
    pid = make_project(executor, ("include", "10.0.0.0/24"), **window)
    with pytest.raises(AuthorizationWindowError):
        await executor.launch(pid, "probe", ["10.0.0.5"], actor="cli")
    assert runner.calls == []


async def test_launch_inside_authorization_window_is_allowed(executor, runner) -> None:
    pid = make_project(
        executor,
        ("include", "10.0.0.0/24"),
        authorized_from=NOW - timedelta(days=1),
        authorized_until=NOW + timedelta(days=1),
    )
    await executor.launch(pid, "probe", ["10.0.0.5"], actor="cli")
    assert len(runner.calls) == 1


async def test_scope_is_checked_before_tool_lookup(executor, runner) -> None:
    pid = make_project(executor, ("include", "10.0.0.0/24"))
    # Unknown tool + out-of-scope target: the scope violation is what surfaces.
    with pytest.raises(ScopeViolationError):
        await executor.launch(pid, "does-not-exist", ["8.8.8.8"], actor="cli")
    with pytest.raises(ToolUnavailableError):
        await executor.launch(pid, "does-not-exist", ["10.0.0.5"], actor="cli")


async def test_scope_changes_apply_to_the_next_launch(executor, runner) -> None:
    pid = make_project(executor, ("include", "10.0.0.0/24"))
    await executor.launch(pid, "probe", ["10.0.0.5"], actor="cli")

    rule = parse_scope_rule("exclude", "10.0.0.5")
    executor.scope.add(pid, rule.kind, rule.value, "client asked us to stop")
    with pytest.raises(ScopeViolationError):
        await executor.launch(pid, "probe", ["10.0.0.5"], actor="cli")
    assert len(runner.calls) == 1


async def test_default_configuration_executes_nothing(db: Database) -> None:
    executor = Executor(db, resolver=fake_resolver)
    pid = make_project(executor, ("include", "10.0.0.0/24"))
    assert executor.tools.names == []
    with pytest.raises(ToolUnavailableError, match="available: none"):
        await executor.launch(pid, "nmap", ["10.0.0.5"], actor="cli")


async def test_unavailable_runner_refuses() -> None:
    with pytest.raises(ToolUnavailableError):
        await UnavailableRunner().submit(None)  # type: ignore[arg-type]


async def test_runner_failure_marks_scan_failed(db: Database, tool) -> None:
    class Boom:
        async def submit(self, job: ScanJob) -> None:
            raise RuntimeError("crashed")

    executor = Executor(db, tools=ToolRegistry([tool]), runner=Boom(), resolver=fake_resolver)
    pid = make_project(executor, ("include", "10.0.0.0/24"))
    with pytest.raises(RuntimeError):
        await executor.launch(pid, "probe", ["10.0.0.5"], actor="cli")
    scan_id = executor.audit.list_all(pid)[-1]["detail"]["scan_id"]
    assert executor.scans.get(scan_id)["status"] == "failed"
