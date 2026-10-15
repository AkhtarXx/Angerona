"""Execution runners for the enrichment pipeline.

Concrete runners are imported lazily so importing the shared result model does
not pull the Unicorn adapter back into itself.
"""

from typing import TYPE_CHECKING, Any

from src.execution.runners.base import AbstractRunner, RunnerResult

if TYPE_CHECKING:
    from src.execution.runners.native_runner import NativeAppcallRunner
    from src.execution.runners.unicorn_runner import UnicornRunner

__all__ = [
    "AbstractRunner",
    "RunnerResult",
    "UnicornRunner",
    "QemuUnicornRunner",
    "NativeAppcallRunner",
]


def __getattr__(name: str) -> Any:
    if name == "UnicornRunner":
        from src.execution.runners.unicorn_runner import UnicornRunner

        return UnicornRunner
    if name == "QemuUnicornRunner":
        from src.execution.runners.unicorn_runner import UnicornRunner

        return UnicornRunner
    if name == "NativeAppcallRunner":
        from src.execution.runners.native_runner import NativeAppcallRunner

        return NativeAppcallRunner
    raise AttributeError(name)
