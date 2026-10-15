"""Capability discovery and safe command plans for runtime trace providers."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sysconfig
import tempfile
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProviderCapabilities:
    launch: bool = False
    attach: bool = False
    record: bool = False
    replay: bool = False
    memory_capture: bool = False
    system_trace: bool = False


@dataclass(frozen=True)
class ProviderPlan:
    provider: str
    executable: str
    argv: tuple[str, ...]
    capabilities: ProviderCapabilities
    output_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class RuntimeProvider:
    """Base provider that emits argv plans without invoking a shell."""

    name = ""
    executables: tuple[str, ...] = ()
    capabilities = ProviderCapabilities()

    def executable(self) -> str | None:
        for candidate in self.executables:
            found = shutil.which(candidate)
            if found:
                return found
        scripts_dirs = (
            Path(sysconfig.get_path("scripts")),
            Path(__file__).resolve().parents[2] / ".venv" / "bin",
        )
        for scripts_dir in scripts_dirs:
            for candidate in self.executables:
                installed = scripts_dir / candidate
                if installed.is_file() and os.access(installed, os.X_OK):
                    return str(installed.resolve())
        return None

    def available(self) -> bool:
        return self.executable() is not None

    def details(self) -> dict[str, Any]:
        """Return provider-specific facts that do not imply successful execution."""
        return {}

    @staticmethod
    def _target(path: str | Path) -> str:
        target = Path(path).resolve(strict=True)
        if not target.is_file():
            raise ValueError("runtime target must be a regular file")
        return str(target)


class GdbProvider(RuntimeProvider):
    name = "gdb"
    executables = ("gdb", "gdb-multiarch")
    capabilities = ProviderCapabilities(launch=True, attach=True, memory_capture=True)

    def launch_plan(self, target: str | Path, command_file: str | Path) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("gdb is unavailable")
        script = Path(command_file).resolve(strict=True)
        return ProviderPlan(self.name, executable, (
            executable, "--nx", "--nh", "--batch", "--quiet", "-x", str(script), "--args", self._target(target),
        ), self.capabilities)


class LldbProvider(RuntimeProvider):
    name = "lldb"
    executables = ("lldb",)
    capabilities = ProviderCapabilities(launch=True, attach=True, memory_capture=True)

    def launch_plan(self, target: str | Path, command_file: str | Path) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("lldb is unavailable")
        script = Path(command_file).resolve(strict=True)
        return ProviderPlan(self.name, executable, (
            executable,
            "--no-lldbinit",
            "--batch",
            "--one-line-before-file",
            "settings set symbols.enable-external-lookup false",
            "--source",
            str(script),
            "--",
            self._target(target),
        ), self.capabilities)


class DbgEngProvider(RuntimeProvider):
    name = "dbgeng"
    executables = ("cdb.exe", "cdb")
    capabilities = ProviderCapabilities(launch=True, attach=True, memory_capture=True)

    def launch_plan(self, target: str | Path, command_file: str | Path) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("DbgEng/cdb is unavailable")
        script = Path(command_file).resolve(strict=True)
        return ProviderPlan(self.name, executable, (
            executable, "-cf", str(script), self._target(target),
        ), self.capabilities)


class FridaProvider(RuntimeProvider):
    name = "frida"
    executables = ("frida",)
    capabilities = ProviderCapabilities(launch=True, attach=True, memory_capture=True)

    def launch_plan(self, target: str | Path, agent_script: str | Path) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("frida is unavailable")
        script = Path(agent_script).resolve(strict=True)
        return ProviderPlan(self.name, executable, (
            executable, "-f", self._target(target), "-l", str(script), "-q", "-t", "inf",
        ), self.capabilities, metadata={
            "mode": "spawn",
            "spawn_paused": False,
            "quiet": True,
            "timeout": "infinite",
        })


class RrProvider(RuntimeProvider):
    name = "rr"
    executables = ("rr",)
    capabilities = ProviderCapabilities(launch=True, record=True, replay=True, memory_capture=True)

    @staticmethod
    @lru_cache(maxsize=1)
    def _recording_probe() -> tuple[bool, str]:
        """Perform a tiny real recording so status reflects host perf support."""
        executable = shutil.which("rr")
        if executable is None:
            return False, "rr executable is not installed"
        try:
            with tempfile.TemporaryDirectory(prefix="angerona-rr-probe-") as root:
                trace = Path(root) / "trace"
                completed = subprocess.run(
                    [
                        executable, "record", "--output-trace-dir", str(trace),
                        "/bin/true",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            return False, "rr recording probe timed out"
        except OSError as exc:
            return False, f"rr recording probe failed: {exc}"
        if completed.returncode == 0:
            return True, "real /bin/true recording succeeded"
        output = "\n".join(part.strip() for part in (completed.stderr, completed.stdout) if part.strip())
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        diagnostic = next(
            (
                line for line in lines
                if "FATAL" in line or "perf_event" in line or "performance counter" in line
            ),
            lines[-1] if lines else f"rr exited {completed.returncode}",
        )
        return False, diagnostic[:500]

    def available(self) -> bool:
        ready, _ = self._recording_probe()
        return ready

    def details(self) -> dict[str, Any]:
        ready, diagnostic = self._recording_probe()
        return {
            "binary_installed": self.executable() is not None,
            "recording_ready": ready,
            "recording_probe": diagnostic,
        }

    def record_plan(self, target: str | Path, trace_dir: str | Path) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("rr is unavailable")
        output = Path(trace_dir).resolve()
        return ProviderPlan(self.name, executable, (
            executable, "record", "--output-trace-dir", str(output), self._target(target),
        ), self.capabilities, output_path=str(output), metadata={"mode": "record"})

    def replay_plan(self, trace_dir: str | Path) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("rr is unavailable")
        trace = Path(trace_dir).resolve(strict=True)
        return ProviderPlan(self.name, executable, (
            executable, "replay", "-a", str(trace),
        ), self.capabilities, output_path=str(trace), metadata={"mode": "replay"})


class QemuUserProvider(RuntimeProvider):
    """Plan Linux ELF execution with the matching QEMU user-mode emulator.

    QEMU user mode translates CPU instructions but forwards guest system calls
    to the host kernel.  It is therefore an execution backend, not a sandbox.
    """

    name = "qemu-user"
    executables = (
        "qemu-x86_64", "qemu-i386", "qemu-aarch64", "qemu-arm",
        "qemu-riscv64", "qemu-riscv32", "qemu-mips", "qemu-mipsel",
        "qemu-mips64", "qemu-mips64el", "qemu-ppc", "qemu-ppc64",
        "qemu-ppc64le", "qemu-s390x",
    )
    capabilities = ProviderCapabilities(launch=True, system_trace=True)

    _ARCH_EXECUTABLES = {
        "x86_64": "qemu-x86_64",
        "amd64": "qemu-x86_64",
        "x64": "qemu-x86_64",
        "x86": "qemu-i386",
        "i386": "qemu-i386",
        "i686": "qemu-i386",
        "aarch64": "qemu-aarch64",
        "arm64": "qemu-aarch64",
        "arm": "qemu-arm",
        "armv7": "qemu-arm",
        "riscv64": "qemu-riscv64",
        "riscv": "qemu-riscv32",
        "mips": "qemu-mips",
        "mipsel": "qemu-mipsel",
        "mips64": "qemu-mips64",
        "mips64el": "qemu-mips64el",
        "ppc": "qemu-ppc",
        "ppc64": "qemu-ppc64",
        "ppc64le": "qemu-ppc64le",
        "s390x": "qemu-s390x",
    }
    _ARCH_ALIASES = {
        "amd64": "x86_64", "x64": "x86_64",
        "i386": "x86", "i686": "x86",
        "arm64": "aarch64", "armv7": "arm",
        "riscv32": "riscv",
    }

    @classmethod
    def _canonical_architecture(cls, architecture: str) -> str:
        lowered = architecture.lower()
        return cls._ARCH_ALIASES.get(lowered, lowered)

    def executable_for_architecture(self, architecture: str) -> str | None:
        candidate = self._ARCH_EXECUTABLES.get(self._canonical_architecture(architecture))
        return shutil.which(candidate) if candidate else None

    def details(self) -> dict[str, Any]:
        installed = {
            architecture: path
            for architecture in sorted(set(self._ARCH_EXECUTABLES))
            if (path := self.executable_for_architecture(architecture)) is not None
        }
        return {
            "mode": "linux-user",
            "installed_architectures": installed,
            "host_syscalls_forwarded": True,
            "sandbox": False,
            "tcg_plugin_api": False,
        }

    def launch_plan(
        self,
        target: str | Path,
        *,
        argv: tuple[str, ...] | list[str] = (),
        architecture: str | None = None,
        sysroot: str | Path | None = None,
        cpu: str | None = None,
        syscall_trace: bool = False,
    ) -> ProviderPlan:
        from src.execution.loaders import load_binary

        resolved_target = self._target(target)
        image = load_binary(resolved_target)
        if image.format != "elf":
            raise ValueError("QEMU user mode only launches Linux ELF executables")
        actual_arch = self._canonical_architecture(image.architecture)
        selected_arch = self._canonical_architecture(architecture or image.architecture)
        if architecture is not None and selected_arch != actual_arch:
            raise ValueError(
                f"requested architecture {selected_arch!r} does not match ELF architecture "
                f"{image.architecture!r}"
            )
        executable = self.executable_for_architecture(selected_arch)
        if executable is None:
            raise RuntimeError(f"QEMU user emulator is unavailable for architecture {selected_arch!r}")

        command = [executable]
        if sysroot is not None:
            root = Path(sysroot).resolve(strict=True)
            if not root.is_dir():
                raise ValueError("QEMU sysroot must be a directory")
            command.extend(("-L", str(root)))
        if cpu is not None:
            if not cpu or "\x00" in cpu:
                raise ValueError("invalid QEMU CPU model")
            command.extend(("-cpu", cpu))
        if syscall_trace:
            command.append("-strace")
        command.append(resolved_target)
        command.extend(str(value) for value in argv)
        return ProviderPlan(
            self.name,
            executable,
            tuple(command),
            self.capabilities,
            metadata={
                "architecture": selected_arch,
                "format": image.format,
                "syscall_trace": syscall_trace,
                "sandbox": False,
            },
        )


class QemuTcgPluginProvider(RuntimeProvider):
    """Plan full-system QEMU TCG runs with an out-of-tree instrumentation plugin."""

    name = "qemu-tcg-plugin"
    executables = (
        "qemu-system-x86_64", "qemu-system-i386", "qemu-system-aarch64",
        "qemu-system-arm", "qemu-system-riscv64", "qemu-system-riscv32",
        "qemu-system-mips", "qemu-system-mipsel", "qemu-system-ppc",
        "qemu-system-ppc64", "qemu-system-s390x",
    )
    capabilities = ProviderCapabilities(
        launch=True, memory_capture=True, system_trace=True,
    )
    _ARCH_EXECUTABLES = {
        "x86_64": "qemu-system-x86_64",
        "x86": "qemu-system-i386",
        "aarch64": "qemu-system-aarch64",
        "arm": "qemu-system-arm",
        "riscv64": "qemu-system-riscv64",
        "riscv32": "qemu-system-riscv32",
        "mips": "qemu-system-mips",
        "mipsel": "qemu-system-mipsel",
        "ppc": "qemu-system-ppc",
        "ppc64": "qemu-system-ppc64",
        "s390x": "qemu-system-s390x",
    }
    _ARCH_ALIASES = {
        "amd64": "x86_64", "x64": "x86_64",
        "i386": "x86", "i686": "x86",
        "arm64": "aarch64", "armv7": "arm",
        "riscv": "riscv32",
    }

    @classmethod
    def _canonical_architecture(cls, architecture: str) -> str:
        lowered = architecture.lower()
        return cls._ARCH_ALIASES.get(lowered, lowered)

    def executable_for_architecture(self, architecture: str) -> str | None:
        candidate = self._ARCH_EXECUTABLES.get(self._canonical_architecture(architecture))
        return shutil.which(candidate) if candidate else None

    @staticmethod
    @lru_cache(maxsize=16)
    def _supports_plugins(executable: str) -> bool:
        try:
            result = subprocess.run(
                [executable, "-plugin", "help"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        output = f"{result.stdout}\n{result.stderr}"
        return result.returncode == 0 and "Plugin options" in output and "file=" in output

    def available(self) -> bool:
        executable = self.executable()
        return executable is not None and self._supports_plugins(executable)

    def details(self) -> dict[str, Any]:
        installed: dict[str, dict[str, Any]] = {}
        for architecture in sorted(self._ARCH_EXECUTABLES):
            executable = self.executable_for_architecture(architecture)
            if executable is not None:
                installed[architecture] = {
                    "executable": executable,
                    "tcg_plugin_api": self._supports_plugins(executable),
                }
        return {
            "mode": "full-system-tcg",
            "installed_architectures": installed,
            "tcg_plugin_api": any(row["tcg_plugin_api"] for row in installed.values()),
            "sandbox": False,
        }

    def plugin_plan(
        self,
        plugin: str | Path,
        *,
        architecture: str | None = None,
        plugin_arguments: tuple[str, ...] | list[str] = (),
        qemu_arguments: tuple[str, ...] | list[str] = (
            "-machine", "none", "-nodefaults", "-display", "none", "-S",
        ),
    ) -> ProviderPlan:
        selected_arch = self._canonical_architecture(architecture or platform.machine())
        executable = self.executable_for_architecture(selected_arch)
        if executable is None:
            raise RuntimeError(
                f"QEMU system emulator is unavailable for architecture {selected_arch!r}"
            )
        if not self._supports_plugins(executable):
            raise RuntimeError(f"{executable} was built without the QEMU TCG plugin API")
        plugin_path = Path(plugin).resolve(strict=True)
        if not plugin_path.is_file():
            raise ValueError("QEMU plugin must be a regular file")
        plugin_parts = [f"file={plugin_path}"]
        for argument in plugin_arguments:
            value = str(argument)
            if not value or "\x00" in value or "," in value:
                raise ValueError("QEMU plugin arguments must be non-empty and comma-free")
            plugin_parts.append(value)
        extra = [str(argument) for argument in qemu_arguments]
        if any("\x00" in argument for argument in extra):
            raise ValueError("QEMU arguments cannot contain NUL bytes")
        command = [
            executable, "-accel", "tcg", "-plugin", ",".join(plugin_parts), *extra,
        ]
        return ProviderPlan(
            self.name,
            executable,
            tuple(command),
            self.capabilities,
            metadata={
                "architecture": selected_arch,
                "mode": "full-system-tcg",
                "tcg_plugin_api": True,
                "sandbox": False,
            },
        )


class BpftraceProvider(RuntimeProvider):
    """Plan bpftrace runs with machine-readable newline-delimited JSON output."""

    name = "bpftrace"
    executables = ("bpftrace",)
    capabilities = ProviderCapabilities(attach=True, system_trace=True)

    @staticmethod
    def sudo_noninteractive_available() -> bool:
        sudo = shutil.which("sudo")
        if sudo is None:
            return False
        try:
            return subprocess.run(
                [sudo, "-n", "true"], capture_output=True, timeout=2, check=False,
            ).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def details(self) -> dict[str, Any]:
        return {
            "output_format": "ndjson",
            "requires_kernel_tracing_privileges": True,
            "current_euid": os.geteuid(),
            "privileges_known_sufficient": os.geteuid() == 0,
            "sudo_noninteractive_available": self.sudo_noninteractive_available(),
        }

    def available(self) -> bool:
        return self.executable() is not None and (
            os.geteuid() == 0 or self.sudo_noninteractive_available()
        )

    def script_plan(
        self,
        script: str | Path,
        *,
        dry_run: bool = False,
        privileged: bool | None = None,
    ) -> ProviderPlan:
        executable = self.executable()
        if executable is None:
            raise RuntimeError("bpftrace is unavailable")
        script_path = Path(script).resolve(strict=True)
        if not script_path.is_file():
            raise ValueError("bpftrace script must be a regular file")
        if privileged is None:
            privileged = os.geteuid() != 0
        command = [executable, "-f", "json"]
        privilege_mode = "direct"
        if privileged and os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if sudo is None or not self.sudo_noninteractive_available():
                raise RuntimeError("non-interactive sudo is unavailable for privileged bpftrace")
            command = [sudo, "-n", *command]
            privilege_mode = "sudo-noninteractive"
        if dry_run:
            command.append("--dry-run")
        command.append(str(script_path))
        return ProviderPlan(
            self.name,
            executable,
            tuple(command),
            self.capabilities,
            metadata={
                "output_format": "ndjson",
                "dry_run": dry_run,
                "requires_privilege": True,
                "privilege_mode": privilege_mode,
            },
        )


class ProviderRegistry:
    """Expose only providers that passed their real availability gate.

    Audits use the default active-only view, so an installed-but-broken tool
    cannot enter planning or appear as a usable option. Operators may request
    the complete diagnostic inventory explicitly.
    """

    def __init__(self, *, include_unavailable: bool = False) -> None:
        candidates = (
            GdbProvider(), LldbProvider(), DbgEngProvider(), FridaProvider(), RrProvider(),
            QemuUserProvider(), QemuTcgPluginProvider(), BpftraceProvider(),
        )
        self.all_providers = {provider.name: provider for provider in candidates}
        self.providers = {
            name: provider
            for name, provider in self.all_providers.items()
            if include_unavailable or provider.available()
        }

    def status(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "available": provider.available(),
                "executable": provider.executable(),
                "capabilities": provider.capabilities.__dict__,
                "details": provider.details(),
            }
            for name, provider in self.providers.items()
        }
