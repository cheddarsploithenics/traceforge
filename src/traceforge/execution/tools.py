"""Tool adapter contract and registry.

An adapter turns :class:`AuthorizedTargets` plus validated options into an
argument vector (never a shell string) and parses the tool's raw output into a
:class:`ToolReport`. Adapters must follow the requirements in
``docs/THREAT_MODEL.md`` §8: no free-form arguments, no target discovery the
scope check has not seen, and resolved (pinned) addresses instead of hostnames.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from traceforge.execution.scope import AuthorizedTargets


class InvalidOptionsError(ValueError):
    """Tool options failed validation."""


class ToolUnavailableError(LookupError):
    """The tool is unknown, not installed, or execution is disabled."""


@dataclass(frozen=True)
class ToolCommand:
    """A fully-built, ready-to-execute command."""

    argv: list[str]
    # The exact addresses / networks handed to the tool (after DNS pinning).
    scan_addresses: list[str]
    # address -> hostnames it was authorized under, for labelling results.
    hostnames: dict[str, list[str]] = field(default_factory=dict)
    # Normalised options, as stored with the scan.
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PortResult:
    protocol: str
    port: int
    state: str
    reason: str | None = None
    service_name: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    service_extrainfo: str | None = None
    service_tunnel: str | None = None
    service_method: str | None = None
    service_confidence: int | None = None
    cpe: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExtraPorts:
    """Ports reported in bulk rather than one by one (Nmap's ``<extraports>``).

    ``ports`` lists them when the tool says which ports they are (as a port
    spec, keyed by protocol); ``None`` means only the count is known.
    """

    state: str
    count: int
    ports: tuple[tuple[str, str], ...] | None = None


@dataclass(frozen=True)
class HostResult:
    address: str
    addr_type: str
    state: str
    reason: str | None = None
    hostnames: tuple[str, ...] = ()
    ports: tuple[PortResult, ...] = ()
    # When the tool finished with this host (ISO 8601, UTC), if reported.
    observed_at: str | None = None
    # The tool gave up on this host, so its port data is incomplete.
    timed_out: bool = False
    extraports: tuple[ExtraPorts, ...] = ()


@dataclass(frozen=True)
class ToolReport:
    """Tool-agnostic findings parsed from raw output."""

    hosts: tuple[HostResult, ...] = ()
    tool_version: str | None = None
    # The tool reported failure in its own output (e.g. nmap's exit="error").
    error: str | None = None
    # Ports the tool was asked to scan, per protocol, as port specs. Empty
    # when the output does not say (coverage unknown).
    coverage: tuple[tuple[str, str], ...] = ()


class ToolAdapter(Protocol):
    name: str

    def parse_options(self, raw: Mapping[str, Any]) -> Any:
        """Validate client-supplied options; raise :class:`InvalidOptionsError`."""
        ...

    def build_command(self, targets: AuthorizedTargets, options: Any) -> ToolCommand:
        """Return the command to execute, as an argument vector."""
        ...

    def parse_output(self, data: bytes) -> ToolReport:
        """Parse the tool's raw (evidence) output."""
        ...


class ToolRegistry:
    def __init__(self, adapters: list[ToolAdapter] | None = None) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: ToolAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"tool {adapter.name!r} is already registered")
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ToolAdapter | None:
        return self._adapters.get(name)

    @property
    def names(self) -> list[str]:
        return sorted(self._adapters)
