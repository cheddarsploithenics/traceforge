"""Asynchronous scan jobs: queueing, concurrency limits, timeouts, cancellation.

Lifecycle (persisted in ``scans.status``)::

    queued ──> running ──> completed
       │          ├──────> failed      (non-zero exit, timeout, bad output, …)
       └──────────┴──────> cancelled   (operator request or server shutdown)

Each job is an asyncio task. A semaphore caps how many tool processes run at
once; jobs beyond that wait in ``queued``. Processes are started with
:func:`asyncio.create_subprocess_exec` (an argument vector, never a shell) in a
new session, so cancelling or timing out kills the whole process group (Kali's
``nmap`` is a wrapper script around the real binary).

Tool processes get a minimal environment: TraceForge's own settings, tokens
and anything else in the server's environment are not inherited, so they can
never appear in tool output, evidence or stored errors.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import signal
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traceforge.db import Database
from traceforge.db.repositories import AuditRepository, ResultRepository, ScanRepository
from traceforge.execution.tools import ToolAdapter, ToolCommand
from traceforge.security.tokens import ensure_private_dir

# Same logger as the app factory, so scan lifecycle events appear in the server log.
logger = logging.getLogger("uvicorn.error")

SYSTEM_ACTOR = "system"
STDERR_TAIL_BYTES = 4096
MAX_ERROR_CHARS = 2000


class QueueFullError(RuntimeError):
    """Too many scans are already queued or running."""


@dataclass(frozen=True)
class ScanJob:
    scan_id: int
    project_id: int
    tool: ToolAdapter
    command: ToolCommand
    timeout_seconds: float


def minimal_environment() -> dict[str, str]:
    """Environment for tool processes: nothing from the server's environment
    except what is needed to find binaries and decode text."""
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _clean_text(data: bytes | str, limit: int = MAX_ERROR_CHARS) -> str:
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    text = "".join(ch if ch.isprintable() or ch == "\n" else "�" for ch in text).strip()
    return text[-limit:]


class ScanJobManager:
    """Runs scan jobs in the background. One instance per API process."""

    def __init__(
        self,
        db: Database,
        *,
        evidence_dir: Path,
        max_concurrent: int = 2,
        max_queued: int = 20,
        max_output_bytes: int = 64 * 1024 * 1024,
        kill_grace_seconds: float = 5.0,
    ) -> None:
        self.scans = ScanRepository(db)
        self.results = ResultRepository(db)
        self.audit = AuditRepository(db)
        self.evidence_dir = evidence_dir
        self.max_concurrent = max_concurrent
        self.max_queued = max_queued
        self.max_output_bytes = max_output_bytes
        self.kill_grace_seconds = kill_grace_seconds
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._cancel_reasons: dict[int, str] = {}
        # Evidence written so far, so cancelled scans still reference it.
        self._evidence: dict[int, dict[str, Any]] = {}
        self._semaphore: asyncio.Semaphore | None = None

    # -- lifecycle ----------------------------------------------------------------

    def recover(self) -> list[int]:
        """On startup: scans a previous process left active can never finish."""
        interrupted = self.scans.fail_interrupted()
        for scan_id in interrupted:
            self.audit.record(SYSTEM_ACTOR, "scan.failed", None, scan_id=scan_id, reason="restart")
        return interrupted

    async def shutdown(self) -> None:
        for scan_id in list(self._tasks):
            self._request_cancel(scan_id, "server shutting down")
        await self.wait_idle()

    async def wait_idle(self) -> None:
        while self._tasks:
            await asyncio.wait(list(self._tasks.values()))

    async def wait_for(self, scan_id: int) -> None:
        task = self._tasks.get(scan_id)
        if task is not None:
            await asyncio.wait({task})

    @property
    def active_count(self) -> int:
        return len(self._tasks)

    def is_tracked(self, scan_id: int) -> bool:
        return scan_id in self._tasks

    # -- public API ---------------------------------------------------------------

    async def submit(self, job: ScanJob) -> None:
        if len(self._tasks) >= self.max_concurrent + self.max_queued:
            raise QueueFullError(
                f"{len(self._tasks)} scans are already queued or running; try again later"
            )
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
        task = asyncio.create_task(self._run(job), name=f"traceforge-scan-{job.scan_id}")
        self._tasks[job.scan_id] = task
        task.add_done_callback(lambda t, j=job: self._on_done(j, t))

    async def cancel(self, scan_id: int, reason: str = "cancelled by operator") -> bool:
        """Cancel a queued or running job and wait until its process is gone."""
        task = self._request_cancel(scan_id, reason)
        if task is None:
            return False
        await asyncio.wait({task})
        return True

    def _request_cancel(self, scan_id: int, reason: str) -> asyncio.Task[None] | None:
        task = self._tasks.get(scan_id)
        if task is None or task.done():
            return None
        self._cancel_reasons.setdefault(scan_id, reason)
        task.cancel()
        return task

    def _on_done(self, job: ScanJob, task: asyncio.Task[None]) -> None:
        """Runs for every finished task. A task cancelled before it first ran
        never executes its body, so cancellation is recorded here, not in _run."""
        sid = job.scan_id
        self._tasks.pop(sid, None)
        evidence = self._evidence.pop(sid, {})
        reason = self._cancel_reasons.pop(sid, "cancelled")
        if task.cancelled() and self.scans.finish(sid, "cancelled", error=reason, **evidence):
            self.audit.record(
                SYSTEM_ACTOR, "scan.cancelled", job.project_id, scan_id=sid, reason=reason
            )
            logger.info("scan %d cancelled: %s", sid, reason)

    # -- job execution ------------------------------------------------------------

    async def _run(self, job: ScanJob) -> None:
        sid, pid = job.scan_id, job.project_id
        assert self._semaphore is not None
        try:
            async with self._semaphore:
                if not self.scans.mark_running(sid):
                    return
                self.audit.record(
                    SYSTEM_ACTOR, "scan.started", pid, scan_id=sid, tool=job.tool.name
                )
                logger.info("scan %d started (%s)", sid, job.tool.name)
                status, fields = await self._execute(job)
        except Exception as exc:
            logger.exception("scan %d crashed", sid)
            error = _clean_text(f"internal error: {type(exc).__name__}: {exc}")
            self.scans.finish(sid, "failed", error=error, **self._evidence.pop(sid, {}))
            self.audit.record(SYSTEM_ACTOR, "scan.failed", pid, scan_id=sid, reason=error)
            return
        self._evidence.pop(sid, None)
        self.scans.finish(sid, status, **fields)
        self.audit.record(
            SYSTEM_ACTOR,
            f"scan.{status}",
            pid,
            scan_id=sid,
            exit_code=fields.get("exit_code"),
            reason=fields.get("error"),
            evidence_sha256=fields.get("evidence_sha256"),
        )
        logger.info("scan %d %s", sid, status)

    def _open_evidence(self, job: ScanJob) -> tuple[Path, int]:
        ensure_private_dir(self.evidence_dir)
        name = f"scan-{job.scan_id}-{job.tool.name}-{secrets.token_hex(4)}.xml"
        path = self.evidence_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        return path, fd

    async def _execute(self, job: ScanJob) -> tuple[str, dict[str, Any]]:
        path, fd = self._open_evidence(job)
        digest = hashlib.sha256()
        size = 0
        overflow = False
        stderr_tail = bytearray()

        with os.fdopen(fd, "wb") as evidence:
            try:
                process = await asyncio.create_subprocess_exec(
                    *job.command.argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=minimal_environment(),
                    cwd=self.evidence_dir,
                    start_new_session=True,
                )
            except OSError as exc:
                path.unlink(missing_ok=True)
                error = _clean_text(f"could not start {job.tool.name}: {exc.strerror or exc}")
                return "failed", {"error": error}

            async def pump_stdout() -> None:
                nonlocal size, overflow
                assert process.stdout is not None
                while chunk := await process.stdout.read(65536):
                    if size + len(chunk) > self.max_output_bytes:
                        overflow = True
                        self._signal(process, signal.SIGKILL)
                        return
                    size += len(chunk)
                    evidence.write(chunk)
                    digest.update(chunk)

            async def pump_stderr() -> None:
                assert process.stderr is not None
                while chunk := await process.stderr.read(4096):
                    stderr_tail.extend(chunk)
                    del stderr_tail[:-STDERR_TAIL_BYTES]

            try:
                async with asyncio.timeout(job.timeout_seconds):
                    await asyncio.gather(pump_stdout(), pump_stderr())
                    returncode = await process.wait()
            except TimeoutError:
                returncode = None
            finally:
                await self._terminate(process)
                evidence.flush()
                os.fsync(evidence.fileno())
                self._evidence[job.scan_id] = {
                    "evidence_path": path.name,
                    "evidence_sha256": digest.hexdigest(),
                    "evidence_bytes": size,
                }

        fields: dict[str, Any] = {"exit_code": returncode, **self._evidence[job.scan_id]}
        name = job.tool.name
        if returncode is None:
            return "failed", {**fields, "error": f"timed out after {job.timeout_seconds:g} s"}
        if overflow:
            limit = self.max_output_bytes
            return "failed", {**fields, "error": f"{name} output exceeded {limit} bytes"}
        if returncode != 0:
            detail = _clean_text(bytes(stderr_tail)) or "no error output"
            return "failed", {
                **fields,
                "error": f"{name} exited with status {returncode}: {detail}",
            }

        data = await asyncio.to_thread(path.read_bytes)
        try:
            report = await asyncio.to_thread(job.tool.parse_output, data)
        except ValueError as exc:
            return "failed", {**fields, "error": _clean_text(f"unusable {name} output: {exc}")}
        fields["tool_version"] = report.tool_version
        if report.error:
            return "failed", {**fields, "error": _clean_text(f"{name} reported: {report.error}")}
        fields["tool_version"] = report.tool_version
        # Results and the "completed" status are committed together.
        await asyncio.to_thread(
            self.results.complete_with_results,
            job.scan_id,
            job.project_id,
            report,
            job.command.hostnames,
            **fields,
        )
        return "completed", fields

    @staticmethod
    def _signal(process: asyncio.subprocess.Process, sig: signal.Signals) -> None:
        # start_new_session=True makes the child a process-group leader.
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, sig)

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        """Stop the process group: SIGTERM, then SIGKILL after a grace period.

        Only signals while the leader is unreaped, so its process-group id
        cannot have been recycled for an unrelated process.
        """
        if process.returncode is not None:
            return
        self._signal(process, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), self.kill_grace_seconds)
        except TimeoutError:
            self._signal(process, signal.SIGKILL)
            await process.wait()
