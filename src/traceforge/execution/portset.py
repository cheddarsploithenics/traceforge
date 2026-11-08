"""Compact sets of port numbers, as written by Nmap (``"1-1024,8080,8443"``).

Used for scan coverage (``<scaninfo services=…>``) and for ports Nmap reports
in bulk (``<extrareasons ports=…>``). Input comes from tool output, so it is
parsed strictly: anything malformed is rejected rather than half-understood,
and callers treat a rejected spec as "coverage unknown", never as "covered".
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterable

_SPEC = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")
MAX_SPEC_CHARS = 1_000_000


class PortSet:
    """An immutable set of ports in 0-65535, stored as merged, sorted ranges."""

    __slots__ = ("_ranges", "_starts")

    def __init__(self, ranges: Iterable[tuple[int, int]] = ()) -> None:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if not 0 <= start <= end <= 65535:
                raise ValueError(f"invalid port range {start}-{end}")
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        self._ranges = tuple(merged)
        self._starts = [start for start, _ in merged]

    @classmethod
    def parse(cls, spec: str) -> PortSet:
        """Parse ``"22,80,8000-8100"``; raise ValueError if malformed."""
        if not spec:
            return cls()
        if len(spec) > MAX_SPEC_CHARS or not _SPEC.match(spec):
            raise ValueError("malformed port specification")
        ranges = []
        for part in spec.split(","):
            low, _, high = part.partition("-")
            ranges.append((int(low), int(high or low)))
        return cls(ranges)

    @classmethod
    def parse_or_none(cls, spec: str | None) -> PortSet | None:
        if spec is None:
            return None
        try:
            return cls.parse(spec)
        except ValueError:
            return None

    def __contains__(self, port: object) -> bool:
        if not isinstance(port, int):
            return False
        index = bisect_right(self._starts, port) - 1
        return index >= 0 and self._ranges[index][0] <= port <= self._ranges[index][1]

    def __len__(self) -> int:
        return sum(end - start + 1 for start, end in self._ranges)

    def __bool__(self) -> bool:
        return bool(self._ranges)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PortSet) and self._ranges == other._ranges

    def __hash__(self) -> int:
        return hash(self._ranges)

    def __str__(self) -> str:
        return ",".join(str(s) if s == e else f"{s}-{e}" for s, e in self._ranges)

    def __repr__(self) -> str:
        return f"PortSet({str(self)!r})"

    def union(self, other: PortSet) -> PortSet:
        return PortSet((*self._ranges, *other._ranges))
