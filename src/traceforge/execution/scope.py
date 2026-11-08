"""Authorized-target scope: parsing and enforcement.

Scope is **deny by default**. A project authorizes targets with ``include``
rules and carves out exceptions with ``exclude`` rules; exclusions always win.

Rule and target syntax:

* IPv4/IPv6 address           ``10.0.0.5``, ``2001:db8::1``
* CIDR network (strict)       ``10.0.0.0/24``
* Hostname                    ``app.example.com``
* Wildcard (rules only)       ``*.example.com`` — subdomains, not the apex

A target is authorized when:

* **address/network**: it lies entirely inside one include network and does
  not overlap any exclude network (partial overlap is a denial: split the
  range instead);
* **hostname**: it matches an include hostname rule and no exclude hostname
  rule, *and* every address it resolves to is not excluded. Addresses that are
  not publicly routable (private, loopback, link-local, …) must additionally
  be covered by an include network, so a scoped domain cannot silently point
  a tool at internal infrastructure.

The only way to obtain :class:`AuthorizedTargets` — the type every tool
adapter must accept — is :meth:`ScopePolicy.authorize`.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Sequence[IPAddress]]
RuleKind = Literal["include", "exclude"]

# Broadest networks an include rule may authorize. Prevents accidental
# "scan the internet" scopes such as 0.0.0.0/0 while still allowing 10.0.0.0/8.
MIN_INCLUDE_PREFIX = {4: 8, 6: 32}
MAX_TARGETS_PER_REQUEST = 1024

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InvalidTargetError(ValueError):
    """A target or scope value is syntactically invalid or not permitted."""


class ScopeViolationError(PermissionError):
    """One or more targets are outside the project's authorized scope."""

    def __init__(self, decisions: Sequence[ScopeDecision], message: str | None = None) -> None:
        self.decisions = list(decisions)
        denied = [d for d in self.decisions if not d.allowed]
        super().__init__(
            message
            or f"{len(denied)} target(s) outside authorized scope: "
            + ", ".join(f"{d.target} ({d.reason})" for d in denied)
        )


# --------------------------------------------------------------------------- parsing


def _canonical_ip(address: IPAddress) -> IPAddress:
    """Map IPv4-mapped IPv6 (``::ffff:10.0.0.1``) to IPv4 so v4 rules apply."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _canonical_network(network: IPNetwork) -> IPNetwork:
    """Map IPv4-mapped IPv6 networks (``::ffff:10.0.0.0/120``) to IPv4."""
    mapped = network.network_address.ipv4_mapped if network.version == 6 else None
    if mapped is not None and network.prefixlen >= 96:
        return ipaddress.IPv4Network(f"{mapped}/{network.prefixlen - 96}")
    return network


def _validate_hostname(name: str) -> str:
    name = name.lower().removesuffix(".")
    if not name or len(name) > 253:
        raise InvalidTargetError(f"invalid hostname {name!r}")
    labels = name.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise InvalidTargetError(f"invalid hostname {name!r}")
    if labels[-1].isdigit():
        raise InvalidTargetError(f"{name!r} is neither a valid IP address nor a hostname")
    return name


def _precheck(value: str) -> str:
    value = value.strip()
    if not value:
        raise InvalidTargetError("empty value")
    if value.startswith("-"):
        # Would be interpreted as an option by command-line tools.
        raise InvalidTargetError(f"{value!r} may not start with '-'")
    if any(c.isspace() or not c.isprintable() for c in value) or "%" in value:
        raise InvalidTargetError(f"{value!r} contains forbidden characters")
    if not value.isascii():
        raise InvalidTargetError(f"{value!r} must be ASCII (use punycode for IDNs)")
    return value


def _parse_network(value: str) -> IPNetwork | None:
    if "/" in value:
        try:
            return _canonical_network(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise InvalidTargetError(f"invalid network {value!r}: {exc}") from exc
    try:
        address = _canonical_ip(ipaddress.ip_address(value))
    except ValueError:
        return None
    return ipaddress.ip_network(address)


@dataclass(frozen=True)
class Target:
    """A syntactically valid target. Not yet authorized."""

    network: IPNetwork | None = None
    hostname: str | None = None

    def __str__(self) -> str:
        if self.network is not None:
            single = self.network.num_addresses == 1
            return str(self.network.network_address) if single else str(self.network)
        return str(self.hostname)


def parse_target(value: str) -> Target:
    value = _precheck(value)
    if value.startswith("*"):
        raise InvalidTargetError("wildcards are only allowed in scope rules, not targets")
    network = _parse_network(value)
    if network is not None:
        return Target(network=network)
    return Target(hostname=_validate_hostname(value))


@dataclass(frozen=True)
class HostnamePattern:
    name: str
    wildcard: bool = False

    def matches(self, hostname: str) -> bool:
        if self.wildcard:
            return hostname.endswith("." + self.name)
        return hostname == self.name

    def __str__(self) -> str:
        return f"*.{self.name}" if self.wildcard else self.name


@dataclass(frozen=True)
class ScopeRule:
    kind: RuleKind
    network: IPNetwork | None = None
    hostname: HostnamePattern | None = None

    @property
    def value(self) -> str:
        return str(self.network if self.network is not None else self.hostname)


def parse_scope_rule(kind: RuleKind, value: str) -> ScopeRule:
    """Validate and normalise a scope rule."""
    value = _precheck(value).lower()

    if value.startswith("*."):
        name = _validate_hostname(value[2:])
        if "." not in name:
            raise InvalidTargetError(
                f"wildcard {value!r} is too broad; it must cover a domain such as *.example.com"
            )
        return ScopeRule(kind=kind, hostname=HostnamePattern(name, wildcard=True))
    if "*" in value:
        raise InvalidTargetError("only a leading '*.' wildcard is supported")

    network = _parse_network(value)
    if network is None:
        return ScopeRule(kind=kind, hostname=HostnamePattern(_validate_hostname(value)))

    if kind == "include":
        minimum = MIN_INCLUDE_PREFIX[network.version]
        if network.prefixlen < minimum:
            raise InvalidTargetError(
                f"{network} is too broad to authorize; the widest allowed "
                f"IPv{network.version} include is /{minimum}"
            )
        if network.is_multicast or network.is_unspecified:
            raise InvalidTargetError(f"{network} is not a valid scan target range")
    return ScopeRule(kind=kind, network=network)


# --------------------------------------------------------------------------- policy


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str


_AUTHORIZATION_KEY = object()


@dataclass(frozen=True)
class AuthorizedTargets:
    """Targets that passed scope enforcement for a specific project.

    Tool adapters accept only this type, so a tool cannot be handed a target
    that has not been checked. Instances can only be created by
    :meth:`ScopePolicy.authorize`.
    """

    project_id: int
    targets: tuple[Target, ...]
    _key: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._key is not _AUTHORIZATION_KEY:
            raise TypeError("AuthorizedTargets can only be created by ScopePolicy.authorize()")

    def as_arguments(self) -> list[str]:
        """Targets as command-line arguments (never start with '-')."""
        return [str(target) for target in self.targets]


def system_resolver(hostname: str) -> list[IPAddress]:
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return sorted(
        {_canonical_ip(ipaddress.ip_address(info[4][0].split("%")[0])) for info in infos},
        key=lambda a: (a.version, a),
    )


class ScopePolicy:
    def __init__(self, project_id: int, rules: Iterable[ScopeRule]) -> None:
        self.project_id = project_id
        rules = list(rules)
        self._include_nets = [r.network for r in rules if r.kind == "include" and r.network]
        self._exclude_nets = [r.network for r in rules if r.kind == "exclude" and r.network]
        self._include_hosts = [r.hostname for r in rules if r.kind == "include" and r.hostname]
        self._exclude_hosts = [r.hostname for r in rules if r.kind == "exclude" and r.hostname]

    @property
    def is_empty(self) -> bool:
        return not (self._include_nets or self._include_hosts)

    def _excluded(self, network: IPNetwork) -> IPNetwork | None:
        for excluded in self._exclude_nets:
            if excluded.version == network.version and excluded.overlaps(network):
                return excluded
        return None

    def _included(self, network: IPNetwork) -> IPNetwork | None:
        for included in self._include_nets:
            if included.version == network.version and network.subnet_of(included):  # type: ignore[arg-type]
                return included
        return None

    def evaluate(self, target: Target, resolver: Resolver | None = None) -> ScopeDecision:
        name = str(target)
        if self.is_empty:
            return ScopeDecision(name, False, "project has no authorized scope")

        if target.network is not None:
            if excluded := self._excluded(target.network):
                return ScopeDecision(name, False, f"overlaps excluded range {excluded}")
            if included := self._included(target.network):
                return ScopeDecision(name, True, f"within authorized range {included}")
            return ScopeDecision(name, False, "not within any authorized range")

        hostname = str(target.hostname)
        for pattern in self._exclude_hosts:
            if pattern.matches(hostname):
                return ScopeDecision(name, False, f"matches excluded hostname {pattern}")
        include = next((p for p in self._include_hosts if p.matches(hostname)), None)
        if include is None:
            return ScopeDecision(name, False, "hostname not in authorized scope")
        if resolver is None:
            return ScopeDecision(name, True, f"matches authorized hostname {include} (unresolved)")

        try:
            addresses = list(resolver(hostname))
        except OSError as exc:
            return ScopeDecision(name, False, f"could not resolve hostname: {exc}")
        if not addresses:
            return ScopeDecision(name, False, "hostname did not resolve to any address")
        for address in addresses:
            network = ipaddress.ip_network(_canonical_ip(address))
            if excluded := self._excluded(network):
                return ScopeDecision(name, False, f"resolves to {address} in excluded {excluded}")
            if not address.is_global and not self._included(network):
                return ScopeDecision(
                    name,
                    False,
                    f"resolves to non-public address {address} that is not explicitly in scope",
                )
        return ScopeDecision(name, True, f"matches authorized hostname {include}")

    def evaluate_all(
        self, targets: Sequence[Target], resolver: Resolver | None = None
    ) -> list[ScopeDecision]:
        return [self.evaluate(target, resolver) for target in targets]

    def authorize(
        self, targets: Sequence[Target], resolver: Resolver | None = None
    ) -> AuthorizedTargets:
        """All-or-nothing: return authorized targets or raise ScopeViolationError."""
        if not targets:
            raise ScopeViolationError([], "no targets supplied")
        if len(targets) > MAX_TARGETS_PER_REQUEST:
            raise ScopeViolationError([], f"too many targets (max {MAX_TARGETS_PER_REQUEST})")
        decisions = self.evaluate_all(targets, resolver)
        if not all(d.allowed for d in decisions):
            raise ScopeViolationError(decisions)
        return AuthorizedTargets(self.project_id, tuple(targets), _AUTHORIZATION_KEY)
