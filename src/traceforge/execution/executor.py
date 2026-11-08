"""The single choke point through which every tool launch must pass.

``Executor.launch`` performs, in order:

1. load the project and check its authorization window;
2. parse every target (malformed or option-like values are rejected);
3. enforce project scope, resolving hostnames — **before the tool is even
   looked up**, so scope is checked for every launch request;
4. record the decision in the audit log;
5. only then build the tool's argv from :class:`AuthorizedTargets` and hand
   it to the runner.

Any failure in steps 1-3 raises and nothing is launched.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from traceforge.db import Database
from traceforge.db.repositories import (
    AuditRepository,
    NotFoundError,
    ProjectRepository,
    ScanRepository,
    ScopeRepository,
)
from traceforge.execution.scope import (
    AuthorizedTargets,
    Resolver,
    ScopeDecision,
    ScopePolicy,
    ScopeRule,
    ScopeViolationError,
    parse_scope_rule,
    parse_target,
    system_resolver,
)
from traceforge.execution.tools import ToolRegistry


class AuthorizationWindowError(PermissionError):
    """The project's authorization is not valid at this time."""


class ToolUnavailableError(LookupError):
    pass


class Runner(Protocol):
    async def run(self, scan_id: int, argv: list[str]) -> None: ...


class UnavailableRunner:
    """Default runner: this version of TraceForge does not execute tools."""

    async def run(self, scan_id: int, argv: list[str]) -> None:
        raise ToolUnavailableError("tool execution is not available in this version")


@dataclass(frozen=True)
class LaunchResult:
    scan_id: int
    tool: str
    targets: list[str]


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
    ) -> None:
        self.projects = ProjectRepository(db)
        self.scope = ScopeRepository(db)
        self.scans = ScanRepository(db)
        self.audit = AuditRepository(db)
        self.tools = tools or ToolRegistry()
        self.runner = runner or UnavailableRunner()
        self.resolver = resolver
        self.clock = clock

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

    async def launch(
        self, project_id: int, tool_name: str, raw_targets: Sequence[str], *, actor: str
    ) -> LaunchResult:
        project = self.projects.get(project_id)
        try:
            self._check_window(project)
            targets = [parse_target(t) for t in raw_targets]
            policy = self.policy_for(project_id)
            authorized: AuthorizedTargets = await asyncio.to_thread(
                policy.authorize, targets, self.resolver
            )
        except (AuthorizationWindowError, ScopeViolationError, ValueError) as exc:
            self.audit.record(
                actor,
                "launch.denied",
                project_id,
                tool=tool_name,
                targets=list(raw_targets),
                reason=str(exc),
            )
            raise

        tool = self.tools.get(tool_name)
        if tool is None:
            raise ToolUnavailableError(
                f"unknown tool {tool_name!r}; available: {', '.join(self.tools.names) or 'none'}"
            )

        argv = tool.build_argv(authorized)
        names = authorized.as_arguments()
        scan_id = self.scans.create(project_id, tool_name, names)
        self.audit.record(
            actor, "launch.authorized", project_id, scan_id=scan_id, tool=tool_name, targets=names
        )
        try:
            self.scans.set_status(scan_id, "running")
            await self.runner.run(scan_id, argv)
        except Exception:
            self.scans.set_status(scan_id, "failed")
            raise
        return LaunchResult(scan_id=scan_id, tool=tool_name, targets=names)


__all__ = [
    "AuthorizationWindowError",
    "Executor",
    "LaunchResult",
    "NotFoundError",
    "Runner",
    "ToolUnavailableError",
    "UnavailableRunner",
]
