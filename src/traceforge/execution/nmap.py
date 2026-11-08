"""Nmap tool adapter: argv construction and XML result parsing.

Meets the adapter requirements in ``docs/THREAT_MODEL.md`` §8:

* targets come only from :class:`AuthorizedTargets`; hostnames are replaced by
  the addresses they resolved to during the scope check (DNS pinning), and
  ``-n`` stops Nmap from doing any DNS of its own;
* the command is an argument vector built from :class:`NmapScanOptions`;
  clients cannot add flags, and targets follow ``--``;
* ``-sT`` (TCP connect) and ``--unprivileged`` mean no raw packets are sent,
  even when the binary is a wrapper that adds ``--privileged`` (as on Kali);
* XML goes to stdout (``-oX -``) so TraceForge, not Nmap, creates the
  evidence file; ``--noninteractive`` stops Nmap from reading the terminal.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from traceforge.execution.portset import PortSet
from traceforge.execution.scope import AuthorizedTargets, InvalidTargetError
from traceforge.execution.tools import (
    ExtraPorts,
    HostResult,
    InvalidOptionsError,
    PortResult,
    ToolCommand,
    ToolReport,
    ToolUnavailableError,
)
from traceforge.schemas import NmapScanOptions

MAX_XML_BYTES = 256 * 1024 * 1024
MAX_FIELD_CHARS = 1024


class NmapOutputError(ValueError):
    """Nmap's XML output is missing, malformed or unsafe to parse."""


def format_validation_error(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or 'options'}: {err['msg']}" for err in exc.errors()
    )


class NmapAdapter:
    name = "nmap"

    def __init__(self, binary: Path | str | None = None, *, max_addresses: int = 4096) -> None:
        self._binary = Path(binary) if binary else None
        self.max_addresses = max_addresses

    # -- binary -------------------------------------------------------------------

    def resolve_binary(self) -> str:
        if self._binary is not None:
            if not self._binary.is_absolute():
                raise ToolUnavailableError("the configured nmap path must be absolute")
            if not (self._binary.is_file() and os.access(self._binary, os.X_OK)):
                raise ToolUnavailableError(f"nmap is not executable at {self._binary}")
            return str(self._binary)
        found = shutil.which("nmap")
        if found is None:
            raise ToolUnavailableError(
                "nmap was not found on PATH; install it (apt install nmap) "
                "or set TRACEFORGE_NMAP_PATH"
            )
        return str(Path(found).absolute())

    # -- options ------------------------------------------------------------------

    def parse_options(self, raw: Mapping[str, Any]) -> NmapScanOptions:
        try:
            return NmapScanOptions.model_validate(dict(raw))
        except ValidationError as exc:
            raise InvalidOptionsError(format_validation_error(exc)) from exc

    # -- command ------------------------------------------------------------------

    def _scan_addresses(self, targets: AuthorizedTargets) -> tuple[list[str], dict, int]:
        """Pinned scan arguments, address->hostnames map, and the IP version."""
        explicit = [t.network for t in targets.targets if t.network is not None]
        versions = {n.version for n in explicit}
        if len(versions) > 1:
            raise InvalidTargetError(
                "nmap scans one address family per run; split IPv4 and IPv6 targets "
                "into separate scans"
            )

        pinned: dict[str, tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]] = {}
        for target in targets.targets:
            if target.hostname is None:
                continue
            addresses = targets.pinned_addresses(target.hostname)
            if not addresses:
                # Never let nmap resolve a name scope has not resolved and checked.
                raise InvalidTargetError(f"{target.hostname} was not resolved during authorization")
            pinned[target.hostname] = addresses

        if versions:
            version = versions.pop()
        else:
            all_pinned = [a for addrs in pinned.values() for a in addrs]
            version = 4 if any(a.version == 4 for a in all_pinned) else 6

        arguments: list[str] = []
        hostnames: dict[str, list[str]] = {}
        seen: set[str] = set()
        count = 0

        def add(argument: str, size: int) -> None:
            nonlocal count
            if argument not in seen:
                seen.add(argument)
                arguments.append(argument)
                count += size

        for target in targets.targets:
            if target.network is not None:
                single = target.network.num_addresses == 1
                add(
                    str(target.network.network_address if single else target.network),
                    target.network.num_addresses,
                )
                continue
            hostname = str(target.hostname)
            family = [a for a in pinned[hostname] if a.version == version]
            if not family:
                raise InvalidTargetError(
                    f"{hostname} has no IPv{version} address; scan it in a separate "
                    f"IPv{6 if version == 4 else 4} scan"
                )
            for address in family:
                add(str(address), 1)
                names = hostnames.setdefault(str(address), [])
                if hostname not in names:
                    names.append(hostname)

        if count > self.max_addresses:
            raise InvalidTargetError(
                f"scan covers {count} addresses; the limit is {self.max_addresses} "
                "(TRACEFORGE_SCAN_MAX_ADDRESSES)"
            )
        return arguments, hostnames, version

    def build_command(self, targets: AuthorizedTargets, options: NmapScanOptions) -> ToolCommand:
        addresses, hostnames, version = self._scan_addresses(targets)
        argv = [self.resolve_binary(), "-sT"]
        if options.service_detection:
            argv.append("-sV")
        argv += ["-n", "--unprivileged", "--noninteractive", f"-T{options.timing}"]
        if options.skip_host_discovery:
            argv.append("-Pn")
        if options.ports is not None:
            argv += ["-p", options.ports]
        elif options.top_ports is not None:
            argv += ["--top-ports", str(options.top_ports)]
        if version == 6:
            argv.append("-6")
        argv += ["-oX", "-", "--", *addresses]
        return ToolCommand(
            argv=argv,
            scan_addresses=addresses,
            hostnames=hostnames,
            options=options.model_dump(),
        )

    # -- output -------------------------------------------------------------------

    def parse_output(self, data: bytes) -> ToolReport:
        return parse_nmap_xml(data)


def _clean(value: str | None) -> str | None:
    """Make tool-supplied text safe to store and display.

    Service banners are controlled by the scanned host, so control characters
    (e.g. terminal escape sequences aimed at the TUI) are replaced and length
    is capped.
    """
    if value is None:
        return None
    cleaned = "".join(ch if ch.isprintable() else "�" for ch in value)
    return cleaned[:MAX_FIELD_CHARS]


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _parse_port(element: ET.Element) -> PortResult | None:
    port = _int(element.get("portid"))
    if port is None or not 0 <= port <= 65535:
        return None
    state = element.find("state")
    service = element.find("service")
    svc = service.attrib if service is not None else {}
    cpes = tuple(
        c
        for c in (_clean(e.text) for e in (service.findall("cpe") if service is not None else []))
        if c
    )
    return PortResult(
        protocol=_clean(element.get("protocol")) or "tcp",
        port=port,
        state=_clean(state.get("state")) if state is not None else "unknown",
        reason=_clean(state.get("reason")) if state is not None else None,
        service_name=_clean(svc.get("name")),
        service_product=_clean(svc.get("product")),
        service_version=_clean(svc.get("version")),
        service_extrainfo=_clean(svc.get("extrainfo")),
        service_tunnel=_clean(svc.get("tunnel")),
        service_method=_clean(svc.get("method")),
        service_confidence=_int(svc.get("conf")),
        cpe=cpes,
    )


def _iso_from_epoch(value: str | None) -> str | None:
    seconds = _int(value)
    if seconds is None or seconds <= 0:
        return None
    try:
        moment = datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _valid_spec(value: str | None) -> str | None:
    """A port spec from tool output, normalised; None if absent or malformed."""
    ports = PortSet.parse_or_none(value)
    return str(ports) if ports is not None else None


def _parse_extraports(element: ET.Element) -> ExtraPorts | None:
    state = _clean(element.get("state"))
    count = _int(element.get("count"))
    if not state or count is None or count < 0:
        return None
    reasons = element.findall("extrareasons")
    specs: dict[str, PortSet] = {}
    known = bool(reasons)
    for reason in reasons:
        proto = _clean(reason.get("proto")) or "tcp"
        ports = PortSet.parse_or_none(reason.get("ports"))
        if ports is None:
            known = False  # some of these ports are not identified
            break
        specs[proto] = specs[proto].union(ports) if proto in specs else ports
    listed = tuple(sorted((proto, str(ports)) for proto, ports in specs.items()))
    return ExtraPorts(state=state, count=count, ports=listed if known else None)


def _parse_host(element: ET.Element) -> HostResult | None:
    address = next(
        (a for a in element.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None
    )
    if address is None:
        return None
    try:
        addr = str(ipaddress.ip_address(address.get("addr", "")))
    except ValueError:
        return None
    status = element.find("status")
    hostnames = tuple(
        n for n in (_clean(h.get("name")) for h in element.findall("hostnames/hostname")) if n
    )
    ports = tuple(p for p in (_parse_port(e) for e in element.findall("ports/port")) if p)
    extraports = tuple(
        e for e in (_parse_extraports(x) for x in element.findall("ports/extraports")) if e
    )
    return HostResult(
        address=addr,
        addr_type=address.get("addrtype", "ipv4"),
        state=_clean(status.get("state")) if status is not None else "unknown",
        reason=_clean(status.get("reason")) if status is not None else None,
        hostnames=hostnames,
        ports=ports,
        observed_at=_iso_from_epoch(element.get("endtime") or element.get("starttime")),
        timed_out=element.get("timedout") == "true",
        extraports=extraports,
    )


def parse_nmap_xml(data: bytes) -> ToolReport:
    """Parse Nmap ``-oX`` output into a :class:`ToolReport`.

    Entity declarations are refused outright (Nmap never emits them), which
    rules out entity-expansion attacks; the standard library parser does not
    fetch external entities.
    """
    if not data.strip():
        raise NmapOutputError("nmap produced no XML output")
    if len(data) > MAX_XML_BYTES:
        raise NmapOutputError("nmap XML output is too large to parse")
    if b"<!ENTITY" in data:
        raise NmapOutputError("refusing to parse XML containing entity declarations")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise NmapOutputError(f"malformed nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapOutputError(f"unexpected XML root element <{root.tag}>")

    error = None
    finished = root.find("runstats/finished")
    if finished is not None and finished.get("exit") == "error":
        error = _clean(finished.get("errormsg")) or "nmap reported an error"

    hosts = tuple(h for h in (_parse_host(e) for e in root.findall("host")) if h)
    coverage: dict[str, PortSet] = {}
    for info in root.findall("scaninfo"):
        proto = _clean(info.get("protocol"))
        ports = PortSet.parse_or_none(info.get("services"))
        if proto and ports is not None:
            # Several <scaninfo> elements for one protocol are merged.
            coverage[proto] = coverage[proto].union(ports) if proto in coverage else ports
    return ToolReport(
        hosts=hosts,
        tool_version=_clean(root.get("version")),
        error=error,
        coverage=tuple(sorted((p, str(ports)) for p, ports in coverage.items())),
    )
