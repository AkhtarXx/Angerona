"""Loader-backed Unicorn CPU-emulation runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.execution.runners.base import AbstractRunner, RunnerResult
from src.execution.unicorn_harness import UnicornHarness


class UnicornRunner(AbstractRunner):
    """Execute ELF, PE, or explicitly-described raw code under Unicorn."""

    name = "unicorn"

    def __init__(self, harness: UnicornHarness | None = None) -> None:
        self.harness = harness or UnicornHarness()

    def can_run(self) -> bool:
        return self.harness.available()

    @staticmethod
    def _parse_entry(probe: Any) -> int | None:
        explicit = getattr(probe, "entry_address", None)
        if explicit is not None:
            return int(explicit)
        value = getattr(probe, "function_name", "")
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_args(probe: Any) -> list[int]:
        values: list[int] = []
        for index, value in enumerate(getattr(probe, "args", []) or []):
            try:
                values.append(int(value, 0) if isinstance(value, str) else int(value))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"argument {index} is not an integer: {value!r}") from exc
        return values

    def run(self, probe: Any, binary_path: str | None = None) -> RunnerResult:
        if binary_path is None or not Path(binary_path).is_file():
            return RunnerResult(status="error", note="binary path missing")
        if not self.can_run():
            return RunnerResult(status="unavailable", note="unicorn engine not installed")
        try:
            args = self._parse_args(probe)
        except ValueError as exc:
            return RunnerResult(status="error", note=str(exc))
        entry = self._parse_entry(probe)
        if entry is None:
            return RunnerResult(
                status="missing_symbol",
                note=(
                    f"cannot resolve function {getattr(probe, 'function_name', '')!r}; "
                    "provide its runtime address"
                ),
            )
        return self.harness.run_path(
            binary_path,
            entry_point=entry,
            architecture=getattr(probe, "isa", None),
            args=args,
            capture_ranges=list(getattr(probe, "capture_memory_ranges", []) or []),
            max_instructions=int(getattr(probe, "max_instructions", 2_000)),
            max_events=int(getattr(probe, "max_trace_events", 16_384)),
        )
