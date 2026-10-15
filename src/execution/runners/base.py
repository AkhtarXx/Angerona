"""Execution-runner abstraction for Angerona enrichment.

A runner is any object that can accept an ``EmulatorProbeRequest`` and return
a result that can be turned into a ``MemorySnapshot``.  Runners are optional
dependencies: if their underlying engine is missing, ``can_run()`` returns
False and ``run()`` returns a graceful unavailable result.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.execution.models import DynamicEvent, MemoryImage, MemorySnapshot


@dataclass
class RunnerResult:
    """Outcome of a single runner invocation."""

    status: str  # success | inconclusive | unavailable | no_backend | missing_symbol | error
    snapshot: "MemorySnapshot | None" = None
    snapshots: list["MemorySnapshot"] = field(default_factory=list)
    memory_image: "MemoryImage | None" = None
    events: list["DynamicEvent"] = field(default_factory=list)
    note: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Keep the legacy singular snapshot and the canonical list in sync."""
        if self.snapshot is not None and not self.snapshots:
            self.snapshots = [self.snapshot]
        elif self.snapshot is None and self.snapshots:
            self.snapshot = self.snapshots[0]


class AbstractRunner(ABC):
    """Base class for all enrichment runners."""

    name: str = ""

    @abstractmethod
    def can_run(self) -> bool:
        """Return True if the backend engine is available on this host."""
        ...

    @abstractmethod
    def run(self, probe: Any, binary_path: str | None = None) -> RunnerResult:
        """Execute ``probe`` and return a ``RunnerResult``."""
        ...
