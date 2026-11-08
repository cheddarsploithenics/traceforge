"""Tool adapter contract and registry.

No adapters ship in this version. A future adapter (e.g. Nmap) implements
:class:`ToolAdapter`; it receives only :class:`AuthorizedTargets`, and must
return an argv list (never a shell string). Placing targets after ``--``
is recommended where the tool supports it.
"""

from __future__ import annotations

from typing import Protocol

from traceforge.execution.scope import AuthorizedTargets


class ToolAdapter(Protocol):
    name: str

    def build_argv(self, targets: AuthorizedTargets) -> list[str]:
        """Return the command to execute, as an argument vector."""
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
