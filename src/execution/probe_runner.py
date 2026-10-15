"""Central dispatch for execution backends."""

from __future__ import annotations

from typing import Any

from src.execution.backend_selector import BackendSelector, EmulatorProbeRequest
from src.execution.runners.base import AbstractRunner, RunnerResult


class ProbeRunner:
    """Dispatch emulator probe requests to the appropriate runner."""

    def __init__(self, selector: BackendSelector | None = None) -> None:
        self.selector = selector or BackendSelector()
        self._runners: dict[str, AbstractRunner] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        from src.execution.runners.unicorn_runner import UnicornRunner
        from src.execution.runners.native_runner import NativeAppcallRunner
        from src.execution.runners.symbolic_runner import SymbolicRunner

        self.register("unicorn", UnicornRunner())
        self.register("native", NativeAppcallRunner())
        self.register("symbolic", SymbolicRunner())

    def register(self, name: str, runner: AbstractRunner) -> None:
        self._runners[name.lower()] = runner

    def get(self, name: str) -> AbstractRunner | None:
        return self._runners.get(name.lower())

    def available(self) -> dict[str, bool]:
        """Return map of backend name -> can_run()."""
        return {name: runner.can_run() for name, runner in self._runners.items()}

    def run(
        self,
        probe: EmulatorProbeRequest,
        binary_path: str | None = None,
        backend_name: str | None = None,
    ) -> RunnerResult:
        """Execute ``probe`` using the named backend (or probe hint)."""
        backend_name = (backend_name or probe.expected_backend or "unicorn").lower()

        runner = self.get(backend_name)
        if runner is None:
            return RunnerResult(
                status="no_backend",
                note=f"unknown backend: {backend_name}",
            )

        if not runner.can_run():
            return RunnerResult(
                status="unavailable",
                note=f"backend {backend_name} is not available on this host",
            )

        return runner.run(probe, binary_path=binary_path)
