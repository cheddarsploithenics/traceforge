"""The single choke point through which every tool launch must pass.

``Executor.launch`` performs, in order:

1. load the project and check its authorization window;
2. parse every target (malformed or option-like values are rejected);
3. enforce project scope, resolving hostnames — **before the tool is even
   looked up**, so scope is checked for every launch request — and pin the
   addresses each hostname resolved to;
4. validate the tool's options and build its argv from
   :class:`AuthorizedTargets` (pinned addresses, never re-resolved names);
5. record the decision in the audit log, create the scan as ``queued`` and
   hand it to the runner (the job manager), which executes it asynchronously.

Any failure in steps 1-4 raises, is audited, and nothing is launched.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from traceforge.db import Database
from traceforge.db.repositories import (
    AuditRepository,
    NotFoundError,
    ProjectRepository,
    ResultRepository,
    ScanRepository,
    ScopeRepository,
)
from traceforge.execution.jobs import ScanJob
from traceforge.execution.scope import (
    AuthorizedTargets,
    InvalidTargetError,
    Resolver,
    ScopeDecision,
    ScopePolicy,
    ScopeRule,
    ScopeViolationError,
    parse_scope_rule,
    parse_target,
    system_resolver,
)
from traceforge.execution.tools import InvalidOptionsError, ToolRegistry, ToolUnavailableError


class AuthorizationWindowError(PermissionError):
    """The project's authorization is not valid at this time."""


class Runner(Protocol):
    async def submit(self, job: ScanJob) -> None: ...


class UnavailableRunner:
    """Runner that refuses to execute anything (the default for a bare Executor)."""

    async def submit(self, job: ScanJob) -> None:
        raise ToolUnavailableError("tool execution is not configured")


@dataclass(frozen=True)
class LaunchResult:
    scan_id: int
    tool: str
    targets: list[str]
    scan_addresses: list[str]


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Executor:
    def __init__(
        self,
        db: Database,
        tools: ToolRegistry | None = None,
        runner: Runner | None = None,
        resolver: Resolver = system_resolver,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        default_timeout_seconds: int = 1800,
        max_timeout_seconds: int = 4 * 3600,
    ) -> None:
        self.projects = ProjectRepository(db)
        self.scope = ScopeRepository(db)
        self.scans = ScanRepository(db)
        self.results = ResultRepository(db)
        self.audit = AuditRepository(db)
        self.tools = tools or ToolRegistry()
        self.runner = runner or UnavailableRunner()
        self.resolver = resolver
        self.clock = clock
        self.default_timeout_seconds = default_timeout_seconds
        self.max_timeout_seconds = max_timeout_seconds

    def policy_for(self, project_id: int) -> ScopePolicy:
        self.projects.get(project_id)  # raises NotFoundError
        rules: list[ScopeRule] = [
            parse_scope_rule(row["kind"], row["value"]) for row in self.scope.list_all(project_id)
        ]
        return ScopePolicy(project_id, rules)

    async def check(self, project_id: int, raw_targets: Sequence[str]) -> list[ScopeDecision]:
        """Dry run: report the scope decision for each target without launching."""
        policy = self.policy_for(project_id)
        targets = [parse_target(t) for t in raw_targets]
        return await asyncio.to_thread(policy.evaluate_all, targets, self.resolver)

    def _check_window(self, project: dict) -> None:
        now = self.clock()
        start = _parse_time(project["authorized_from"])
        end = _parse_time(project["authorized_until"])
        if start and now < start:
            raise AuthorizationWindowError(f"authorization for this project starts at {start}")
        if end and now >= end:
            raise AuthorizationWindowError(f"authorization for this project ended at {end}")

    def _timeout(self, requested: int | None) -> int:
        if requested is None:
            return self.default_timeout_seconds
        if not 10 <= requested <= self.max_timeout_seconds:
            raise InvalidOptionsError(
                f"timeout_seconds must be between 10 and {self.max_timeout_seconds}"
            )
        return requested

    async def launch(
        self,
        project_id: int,
        tool_name: str,
        raw_targets: Sequence[str],
        *,
        actor: str,
        options: Mapping[str, Any] | None = None,
        timeout_seconds: int | None = None,
    ) -> LaunchResult:
        project = self.projects.get(project_id)
        timeout = self._timeout(timeout_seconds)

        def deny(reason: str) -> None:
            self.audit.record(
                actor,
                "launch.denied",
                project_id,
                tool=tool_name,
                targets=list(raw_targets),
                reason=reason,
            )

        try:
            self._check_window(project)
            targets = [parse_target(t) for t in raw_targets]
            policy = self.policy_for(project_id)
            authorized: AuthorizedTargets = await asyncio.to_thread(
                policy.authorize, targets, self.resolver
            )
        except (AuthorizationWindowError, ScopeViolationError, ValueError) as exc:
            deny(str(exc))
            raise

        tool = self.tools.get(tool_name)
        if tool is None:
            raise ToolUnavailableError(
                f"unknown tool {tool_name!r}; available: {', '.join(self.tools.names) or 'none'}"
            )
        try:
            parsed = tool.parse_options(options or {})
            command = tool.build_command(authorized, parsed)
        except (InvalidOptionsError, InvalidTargetError) as exc:
            deny(str(exc))
            raise

        names = authorized.as_arguments()
        scan_id = self.scans.create(
            project_id,
            tool_name,
            names,
            scan_addresses=command.scan_addresses,
            hostnames=command.hostnames,
            options=command.options,
            command=command.argv,
            actor=actor,
            timeout_seconds=timeout,
        )
        self.audit.record(
            actor,
            "launch.authorized",
            project_id,
            scan_id=scan_id,
            tool=tool_name,
            targets=names,
            scan_addresses=command.scan_addresses,
            options=command.options,
        )
        job = ScanJob(scan_id, project_id, tool, command, timeout)
        try:
            await self.runner.submit(job)
        except Exception as exc:
            self.scans.finish(scan_id, "failed", error=f"not started: {exc}")
            raise
        return LaunchResult(
            scan_id=scan_id, tool=tool_name, targets=names, scan_addresses=command.scan_addresses
        )


__all__ = [
    "AuthorizationWindowError",
    "Executor",
    "InvalidOptionsError",
    "LaunchResult",
    "NotFoundError",
    "Runner",
    "ToolUnavailableError",
    "UnavailableRunner",
]
