"""Build realistic Nmap XML documents for tests (structure as emitted by Nmap 7.99)."""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.sax.saxutils import quoteattr

BASE_TIME = 1794160000  # 2026-11-08T18:26:40Z


@dataclass
class Port:
    port: int
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    method: str = "probed"  # "probed" (detected) or "table" (port-number label)
    reason: str = "syn-ack"

    def xml(self) -> str:
        service = ""
        if self.service:
            attrs = {
                "name": self.service,
                "method": self.method,
                "conf": "10" if self.method == "probed" else "3",
            }
            if self.product:
                attrs["product"] = self.product
            if self.version:
                attrs["version"] = self.version
            service = "<service " + " ".join(f"{k}={quoteattr(v)}" for k, v in attrs.items()) + "/>"
        reason = "conn-refused" if self.state == "closed" else self.reason
        return (
            f'<port protocol="tcp" portid="{self.port}"><state state="{self.state}" '
            f'reason="{reason}" reason_ttl="0"/>{service}</port>'
        )


@dataclass
class Host:
    address: str
    ports: list[Port] = field(default_factory=list)
    # (state, count, ports spec or None) for <extraports>
    extraports: list[tuple[str, int, str | None]] = field(default_factory=list)
    reason: str = "conn-refused"  # "user-set" for -Pn
    state: str = "up"
    timed_out: bool = False
    endtime: int | None = None

    def xml(self, offset: int) -> str:
        end = self.endtime or BASE_TIME + offset
        timed = ' timedout="true"' if self.timed_out else ""
        extras = ""
        for state, count, ports in self.extraports:
            reason = "conn-refused" if state == "closed" else "no-response"
            inner = (
                f'<extrareasons reason="{reason}" count="{count}" proto="tcp" ports="{ports}"/>'
                if ports
                else ""
            )
            extras += f'<extraports state="{state}" count="{count}">{inner}</extraports>'
        kind = "ipv6" if ":" in self.address else "ipv4"
        return (
            f'<host starttime="{end - 1}" endtime="{end}"{timed}>'
            f'<status state="{self.state}" reason="{self.reason}" reason_ttl="0"/>'
            f'<address addr="{self.address}" addrtype="{kind}"/><hostnames/>'
            f"<ports>{extras}{''.join(p.xml() for p in self.ports)}</ports></host>"
        )


def nmap_xml(*hosts: Host, services: str | None = "1-1000", offset: int = 0) -> str:
    """A complete -oX document. ``services`` is the scanned port spec (<scaninfo>)."""
    scaninfo = (
        f'<scaninfo type="connect" protocol="tcp" numservices="0" services="{services}"/>'
        if services is not None
        else ""
    )
    up = sum(1 for h in hosts if h.state == "up")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        f'<nmaprun scanner="nmap" args="nmap" start="{BASE_TIME + offset}" version="7.99">'
        f"{scaninfo}{''.join(h.xml(offset + i) for i, h in enumerate(hosts))}"
        f'<runstats><finished time="{BASE_TIME + offset + 5}" exit="success"/>'
        f'<hosts up="{up}" down="{len(hosts) - up}" total="{len(hosts)}"/></runstats></nmaprun>\n'
    )
