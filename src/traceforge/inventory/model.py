"""What a scan actually observed — and what it did not.

Asset state and scan comparisons are both derived from these definitions, so
they can never disagree. The central rule: **a port's state is only known
where the scan looked.** A port the scan never covered, on a host that did not
respond or timed out, is *not observed* — never "closed".

How Nmap reports a port, and how it is read here:

* listed individually in ``<port>`` → that state;
* reported in bulk in ``<extraports>`` → that state, if the bulk group names
  its ports (``<extrareasons ports=…>``), or if it is the host's only bulk
  group (every unlisted, covered port then has that state);
* not mentioned → not observed.

Coverage — which ports a scan probed — comes from ``<scaninfo services=…>``.
Scans whose evidence could not be re-read (some v0.2 scans) have *unknown*
coverage: only individually listed ports count as observed.

Host discovery (``-Pn``): Nmap then reports every target as up with reason
``user-set``, even if nothing answered. Such a host only counts as responsive
if at least one port answered (open, or closed — a TCP reset is an answer).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from traceforge.execution.portset import PortSet

RESPONDING_STATES = frozenset({"open", "closed"})
OPEN = "open"


@dataclass(frozen=True)
class ScanContext:
    """The facts about one completed scan needed to interpret its results."""

    id: int
    project_id: int
    status: str
    tool: str | None
    tool_version: str | None
    created_at: str
    finished_at: str | None
    targets: tuple[str, ...]
    scan_addresses: tuple[str, ...]
    hostnames: dict[str, list[str]]
    options: dict[str, Any]
    command: tuple[str, ...]
    timeout_seconds: int | None
    # protocol -> ports probed; None when coverage is unknown (legacy scans).
    coverage: dict[str, PortSet] | None
    evidence: dict[str, Any] | None

    @property
    def host_discovery(self) -> bool:
        """False when the scan used -Pn (every target assumed up)."""
        return not self.options.get("skip_host_discovery", False)

    @property
    def service_detection(self) -> bool:
        return bool(self.options.get("service_detection", False))

    def _networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for value in self.scan_addresses:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        return networks

    def targeted(self, address: str) -> bool:
        """Whether this scan was pointed at ``address`` at all."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in self._networks())

    def requested_as(self, address: str) -> list[str]:
        """The operator-supplied targets that led the scan to ``address``."""
        names = set(self.hostnames.get(address, []))
        requested = []
        for target in self.targets:
            if target in names:
                requested.append(target)
                continue
            try:
                network = ipaddress.ip_network(target, strict=False)
                if ipaddress.ip_address(address) in network:
                    requested.append(target)
            except ValueError:
                continue
        return requested

    def ports_scanned(self, protocol: str = "tcp") -> PortSet | None:
        if self.coverage is None:
            return None
        return self.coverage.get(protocol, PortSet())


@dataclass(frozen=True)
class PortObservation:
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

    @property
    def identification(self) -> str | None:
        """'detected' when Nmap probed the service, 'port-label' when the name is
        only the conventional service for that port number."""
        if not self.service_name:
            return None
        return "detected" if self.service_method == "probed" else "port-label"

    @property
    def version_text(self) -> str:
        return " ".join(
            v for v in (self.service_product, self.service_version, self.service_extrainfo) if v
        )


@dataclass(frozen=True)
class BulkPorts:
    state: str
    count: int
    ports: dict[str, PortSet] | None  # None: the group does not say which ports


@dataclass(frozen=True)
class StateReading:
    """A port's state in one scan, or why it was not observed."""

    state: str | None
    source: str  # "listed", "bulk", or the reason it was not observed

    @property
    def observed(self) -> bool:
        return self.state is not None


@dataclass(frozen=True)
class HostObservation:
    """One host as reported by one completed scan."""

    scan: ScanContext
    scan_host_id: int
    asset_id: int
    address: str
    state: str
    reason: str | None
    hostnames: tuple[str, ...]
    observed_at: str
    timed_out: bool
    bulk: tuple[BulkPorts, ...]
    ports: dict[tuple[str, int], PortObservation] = field(default_factory=dict)

    @property
    def responsive(self) -> bool:
        """Positive evidence the host was there (see module docstring on -Pn)."""
        if self.state != "up":
            return False
        if self.reason != "user-set":
            return True
        if any(p.state in RESPONDING_STATES for p in self.ports.values()):
            return True
        return any(b.state in RESPONDING_STATES and b.count > 0 for b in self.bulk)

    def port_state(self, protocol: str, port: int) -> StateReading:
        if self.state != "up":
            return StateReading(None, "host did not respond")
        if self.timed_out:
            return StateReading(None, "host timed out before the scan finished")
        listed = self.ports.get((protocol, port))
        if listed is not None:
            return StateReading(listed.state, "listed")
        scanned = self.scan.ports_scanned(protocol)
        if scanned is None:
            return StateReading(None, "scan coverage unknown")
        if port not in scanned:
            return StateReading(None, "port not scanned")
        for group in self.bulk:
            if group.ports is not None and port in group.ports.get(protocol, PortSet()):
                return StateReading(group.state, "bulk")
        if len(self.bulk) == 1 and self.bulk[0].ports is None:
            return StateReading(self.bulk[0].state, "bulk")
        return StateReading(None, "state not reported")

    def open_ports(self) -> list[PortObservation]:
        return sorted(
            (p for p in self.ports.values() if p.state == OPEN), key=lambda p: (p.protocol, p.port)
        )


def bulk_from_json(groups: list[dict[str, Any]]) -> tuple[BulkPorts, ...]:
    parsed = []
    for group in groups:
        ports = group.get("ports")
        spec: dict[str, PortSet] | None = None
        if isinstance(ports, dict):
            spec = {}
            for proto, value in ports.items():
                parsed_ports = PortSet.parse_or_none(value)
                if parsed_ports is None:
                    spec = None
                    break
                spec[proto] = parsed_ports
        parsed.append(BulkPorts(str(group.get("state")), int(group.get("count") or 0), spec))
    return tuple(parsed)


def coverage_from_json(value: dict[str, str] | None) -> dict[str, PortSet] | None:
    if value is None:
        return None
    coverage = {}
    for proto, spec in value.items():
        ports = PortSet.parse_or_none(spec)
        if ports is None:
            return None  # malformed: treat the whole coverage as unknown
        coverage[proto] = ports
    return coverage
