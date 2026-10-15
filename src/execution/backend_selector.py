"""Adaptive multi-fidelity execution backend selector.

Routes samples to the most appropriate execution engine based on file format,
operating-system context, and requested analysis mode. The selector is a
prototype: it makes static routing decisions and leaves runtime environment
detection to the caller.

The backend taxonomy mirrors the Bochs execution modes described in
*The IDA Pro Book*:

* ``bochs_idb``   – Bochs IDB mode for raw blobs / shellcode / function-level
                    isolation when no rich OS environment is required.
* ``bochs_pe``    – Bochs PE mode for Windows executables using stubbed DLLs.
* ``bochs_disk``  – Bochs disk-image mode for boot sectors, firmware, and
                    kernel images.
* ``gdb``         – GDB server/user-mode debugging for ELF binaries with
                    interpreter / symbols.
* ``qemu-user``   – Real QEMU Linux user-mode process execution for ELF targets.
* ``unicorn``     – Function-level CPU emulation without an operating system.
* ``native``      – Native execution on the host OS (highest fidelity).
* ``none``        – No execution backend selected / disabled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExecutionBackend:
    """Descriptor for a selected execution backend.

    Attributes:
        name: Backend identifier.
        fidelity: Coarse execution fidelity level.
        os_context: Expected operating-system context, if any.
        supports_appcall: Whether the backend can perform Appcall-style function
            probes.
        supports_snapshot: Whether the backend supports snapshot/replay.
        requirements: Human-readable prerequisites for using the backend.
        reason: Explanation of why the backend was selected for this sample.
    """

    name: str
    fidelity: str
    os_context: str | None
    supports_appcall: bool
    supports_snapshot: bool
    requirements: list[str] = field(default_factory=list)
    reason: str = ""

    def __post_init__(self) -> None:
        valid_names = {
            "bochs_idb",
            "bochs_pe",
            "bochs_disk",
            "gdb",
            "qemu-user",
            "unicorn",
            "qemu",  # legacy serialized descriptor
            "native",
            "symbolic",
            "none",
        }
        if self.name not in valid_names:
            raise ValueError(f"Unknown backend name: {self.name!r}")
        valid_fidelities = {"low", "medium", "high", "full_system"}
        if self.fidelity not in valid_fidelities:
            raise ValueError(f"Unknown fidelity level: {self.fidelity!r}")
        valid_os = {"none", "windows", "linux", "bare_metal"}
        if self.os_context is not None and self.os_context not in valid_os:
            raise ValueError(f"Unknown os_context: {self.os_context!r}")


class BackendSelector:
    """Select an execution backend for a binary sample.

    The selector uses lightweight static heuristics extracted from a triage
    profile. It does not attempt deep binary parsing or environment probing;
    those steps are intentionally left to specialised modules.
    """

    # Mapping of known executable extensions to likely file families.
    _PE_EXTS: frozenset[str] = frozenset({".exe", ".dll", ".sys", ".drv", ".cpl", ".scr"})
    _ELF_EXTS: frozenset[str] = frozenset({".elf", ".so", ".o", ".bin"})
    _BOOT_EXTS: frozenset[str] = frozenset({".img", ".iso", ".rom", ".fw", ".mbr", ".vfd"})

    def __init__(self) -> None:
        """Initialise the selector."""
        self._profile: dict[str, Any] | None = None

    def select(
        self,
        binary: str | Path,
        triage_profile: dict[str, Any] | None = None,
    ) -> ExecutionBackend:
        """Choose the best execution backend for ``binary``.

        Args:
            binary: Path to the sample. May be any file type.
            triage_profile: Optional triage summary. Expected keys include
                ``format`` (e.g. ``pe``, ``elf``, ``raw``, ``boot``),
                ``is_driver``, ``is_boot``, ``function_isolation``,
                ``execution_disabled``, and ``os_hint``.

        Returns:
            An ``ExecutionBackend`` describing the chosen engine.
        """
        self._profile = triage_profile or {}
        binary_path = Path(binary)
        ext = binary_path.suffix.lower()

        # If execution is explicitly disabled, return early.
        if self._profile.get("execution_disabled", False):
            return self._backend("none", reason="Execution explicitly disabled by profile.")

        fmt = self._profile.get("format", "unknown")
        function_isolation = self._profile.get("function_isolation", False)
        is_driver = self._profile.get("is_driver", False)
        is_boot = self._profile.get("is_boot", False)
        os_hint = self._profile.get("os_hint")

        # 1. Boot sector / firmware / kernel image -> Bochs disk-image mode.
        if fmt == "boot" or is_boot or ext in self._BOOT_EXTS:
            return self._backend(
                "bochs_disk",
                reason="Boot sector, firmware, or disk image detected; full system emulation required.",
            )

        # 2. Function isolation on a raw blob / shellcode -> Bochs IDB mode.
        if fmt == "raw" or function_isolation or fmt == "shellcode":
            return self._backend(
                "bochs_idb",
                reason="Raw data or shellcode with function-level isolation requested; use Bochs IDB mode.",
            )

        # 3. Windows PE executable -> Bochs PE mode. Linux qemu-user cannot run PE.
        if fmt == "pe" or ext in self._PE_EXTS:
            if is_driver or ext == ".sys":
                return self._backend(
                    "none",
                    reason=("Windows driver/PE kernel module requires a configured Windows "
                            "full-system VM; QEMU Linux user mode is not applicable."),
                )
            return self._backend(
                "bochs_pe",
                reason="Windows PE executable; Bochs PE mode with stubbed DLLs provides a malware sandbox.",
            )

        # 4. ELF with interpreter / symbols / dynamic linking -> GDB / QEMU user-mode.
        if fmt == "elf" or ext in self._ELF_EXTS:
            has_interpreter = self._profile.get("has_interpreter", True)
            has_debug_symbols = self._profile.get("has_debug_symbols", False)
            is_dynamic = self._profile.get("is_dynamic", True)
            if has_interpreter and (has_debug_symbols or is_dynamic):
                return self._backend(
                    "gdb",
                    reason="ELF with interpreter and dynamic symbols; GDB user-mode debugging is appropriate.",
                )
            return self._backend(
                "qemu-user",
                reason="ELF without full debug context; fall back to QEMU user-mode emulation.",
            )

        # 5. Linux / native execution hinted.
        if os_hint == "linux":
            return self._backend(
                "native",
                reason="Linux OS context requested; native execution provides highest fidelity.",
            )

        # 6. Unknown / unsupported -> disabled backend.
        return self._backend(
            "none",
            reason="No recognised format or OS context; execution disabled.",
        )

    def available_backends(self) -> list[ExecutionBackend]:
        """Return static capability metadata for all known backends.

        Note:
            This method does not probe the local environment. Use
            ``ProbeRunner.can_run()`` or similar tooling for runtime checks.
        """
        return [
            ExecutionBackend(
                name="bochs_idb",
                fidelity="low",
                os_context="none",
                supports_appcall=True,
                supports_snapshot=False,
                requirements=["Bochs installed", "IDB mode plugin support"],
                reason="Static metadata.",
            ),
            ExecutionBackend(
                name="bochs_pe",
                fidelity="medium",
                os_context="windows",
                supports_appcall=True,
                supports_snapshot=True,
                requirements=["Bochs installed", "Stubbed Windows DLLs"],
                reason="Static metadata.",
            ),
            ExecutionBackend(
                name="bochs_disk",
                fidelity="full_system",
                os_context="bare_metal",
                supports_appcall=False,
                supports_snapshot=True,
                requirements=["Bochs installed", "Bootable disk/firmware image"],
                reason="Static metadata.",
            ),
            ExecutionBackend(
                name="gdb",
                fidelity="high",
                os_context="linux",
                supports_appcall=True,
                supports_snapshot=True,
                requirements=["GDB", "GDB server or target binary"],
                reason="Static metadata.",
            ),
            ExecutionBackend(
                name="qemu-user",
                fidelity="medium",
                os_context="linux",
                supports_appcall=False,
                supports_snapshot=False,
                requirements=["Matching qemu-ARCH Linux user-mode emulator", "Outer sandbox for untrusted targets"],
                reason="Static metadata.",
            ),
            ExecutionBackend(
                name="unicorn",
                fidelity="medium",
                os_context="none",
                supports_appcall=True,
                supports_snapshot=True,
                requirements=["Python Unicorn package", "Supported target architecture"],
                reason="Function-level CPU emulation without OS syscalls.",
            ),
            ExecutionBackend(
                name="symbolic",
                fidelity="high",
                os_context=None,
                supports_appcall=False,
                supports_snapshot=False,
                requirements=["angr installed", "z3-solver installed"],
                reason="Symbolic execution for path exploration and constraint recovery.",
            ),
            ExecutionBackend(
                name="native",
                fidelity="high",
                os_context=None,
                supports_appcall=False,
                supports_snapshot=False,
                requirements=["Compatible host OS", "Sandbox / isolation"],
                reason="Static metadata.",
            ),
            ExecutionBackend(
                name="none",
                fidelity="low",
                os_context="none",
                supports_appcall=False,
                supports_snapshot=False,
                requirements=[],
                reason="Static metadata.",
            ),
        ]

    def explain_choice(self, backend: ExecutionBackend, profile: dict[str, Any] | None = None) -> str:
        """Return a human-readable explanation for a backend selection.

        Args:
            backend: The backend that was selected.
            profile: Optional triage profile used for the selection.

        Returns:
            A short paragraph summarising the decision.
        """
        profile = profile or self._profile or {}
        hints = []
        if profile.get("format"):
            hints.append(f"format={profile['format']}")
        if profile.get("os_hint"):
            hints.append(f"os_hint={profile['os_hint']}")
        if profile.get("function_isolation"):
            hints.append("function_isolation=true")
        if profile.get("is_boot"):
            hints.append("is_boot=true")
        if profile.get("is_driver"):
            hints.append("is_driver=true")

        hint_text = f" Profile hints: {', '.join(hints)}." if hints else ""
        return (
            f"Selected backend '{backend.name}' (fidelity={backend.fidelity}, "
            f"os_context={backend.os_context}).{hint_text} Reason: {backend.reason}"
        )

    def _backend(self, name: str, reason: str) -> ExecutionBackend:
        """Instantiate the named backend with the given reason."""
        candidates = {b.name: b for b in self.available_backends()}
        base = candidates[name]
        # Build a fresh instance so the frozen dataclass is never mutated.
        return ExecutionBackend(
            name=base.name,
            fidelity=base.fidelity,
            os_context=base.os_context,
            supports_appcall=base.supports_appcall,
            supports_snapshot=base.supports_snapshot,
            requirements=list(base.requirements),
            reason=reason,
        )


@dataclass(frozen=True)
class EmulatorProbeRequest:
    """Request for an Appcall-style function probe inside an emulator.

    Attributes:
        function_name: Target function symbol or address.
        args: Positional arguments to pass to the function.
        capture_memory_ranges: Memory ranges to snapshot after the call. Each
            tuple is ``(name, start_address, length)``.
        expected_backend: Optional hint naming the backend that should run the
            probe.
    """

    function_name: str
    args: list[Any] = field(default_factory=list)
    capture_memory_ranges: list[tuple[str, int, int]] = field(default_factory=list)
    expected_backend: str | None = None
    entry_address: int | None = None
    isa: str | None = None
    max_instructions: int = 2_000
    max_trace_events: int = 16_384

    def __post_init__(self) -> None:
        if not isinstance(self.function_name, str) or not self.function_name:
            raise ValueError("function_name must be a non-empty string")
        if not isinstance(self.args, list):
            raise ValueError("args must be a list")
        for idx, val in enumerate(self.args):
            if not isinstance(val, (int, str, float, bool, type(None))):
                raise ValueError(f"args[{idx}] is not JSON-serializable: {type(val).__name__}")
        if not isinstance(self.capture_memory_ranges, list):
            raise ValueError("capture_memory_ranges must be a list of (name, start, length) tuples")
        for idx, item in enumerate(self.capture_memory_ranges):
            if not (isinstance(item, tuple) and len(item) == 3):
                raise ValueError(f"capture_memory_ranges[{idx}] must be a 3-tuple")
            name, start, length = item
            if not isinstance(name, str):
                raise ValueError(f"capture_memory_ranges[{idx}][0] must be a string name")
            if not (isinstance(start, int) and isinstance(length, int)):
                raise ValueError(
                    f"capture_memory_ranges[{idx}] start/length must be integers"
                )
            if start < 0:
                raise ValueError(
                    f"capture_memory_ranges[{idx}] start must be non-negative"
                )
            if length < 0:
                raise ValueError(
                    f"capture_memory_ranges[{idx}] length must be non-negative"
                )
        if self.entry_address is not None and (
            not isinstance(self.entry_address, int) or self.entry_address < 0
        ):
            raise ValueError("entry_address must be a non-negative integer")
        if self.isa is not None and (not isinstance(self.isa, str) or not self.isa.strip()):
            raise ValueError("isa must be a non-empty string when provided")
        if not 1 <= self.max_instructions <= 10_000_000:
            raise ValueError("max_instructions must be between 1 and 10000000")
        if not 0 <= self.max_trace_events <= 16_384:
            raise ValueError("max_trace_events must be between 0 and 16384")
        # Cannot mutate frozen dataclass fields; validation only.


class ProbeRunner:
    """Compatibility facade for the implemented runner in ``probe_runner``."""

    def __init__(self, selector: BackendSelector | None = None) -> None:
        from .probe_runner import ProbeRunner as ImplementedProbeRunner
        self._delegate = ImplementedProbeRunner(selector)
        self.selector = self._delegate.selector

    def available(self) -> dict[str, bool]:
        return self._delegate.available()

    def can_run(self, backend_name: str | None = None) -> bool:
        available = self.available()
        return any(available.values()) if backend_name is None else available.get(backend_name, False)

    def run(
        self,
        probe: EmulatorProbeRequest,
        binary_path: str | None = None,
        backend_name: str | None = None,
    ) -> Any:
        return self._delegate.run(probe, binary_path=binary_path, backend_name=backend_name)
