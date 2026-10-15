"""Sandboxed, GDB-backed native integer-ABI Appcall runner."""

from __future__ import annotations

import platform
import re
import shutil
from pathlib import Path
from typing import Any

from src.execution.runners.base import AbstractRunner, RunnerResult
from src.subprocess_observability import observed_run


_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$@]*$")
_RESULT = re.compile(r"^ANGERONA_APPCALL_RESULT=(-?\d+)$", re.MULTILINE)


class NativeAppcallRunner(AbstractRunner):
    """Invoke a native ELF symbol through GDB inside a locked-down bubblewrap."""

    name = "native"

    def can_run(self) -> bool:
        from src.analysis.sandbox import available
        return shutil.which("gdb") is not None and available()

    def run(self, probe: Any, binary_path: str | None = None) -> RunnerResult:
        """Attempt a native Appcall-style invocation.

        ``probe.function_name`` is expected to be a symbol name.  If the binary
        is stripped or the symbol missing, returns ``missing_symbol`` without
        attempting execution.
        """
        if binary_path is None or not Path(binary_path).is_file():
            return RunnerResult(status="error", note="binary path missing")

        if not self.can_run():
            return RunnerResult(
                status="unavailable",
                note="native Appcall requires GDB and bubblewrap",
                detail={"executed": False},
            )

        function_name = getattr(probe, "function_name", "")
        if not function_name or not _SYMBOL.fullmatch(str(function_name)):
            return RunnerResult(status="error", note="invalid or missing function_name")

        try:
            from src.execution.loaders import load_binary
            image = load_binary(binary_path)
        except Exception as exc:
            return RunnerResult(status="error", note=f"native target is not a valid executable: {exc}")
        host_arch = {"amd64": "x86_64", "x86-64": "x86_64", "arm64": "aarch64"}.get(
            platform.machine().lower(), platform.machine().lower()
        )
        if image.format != "elf" or image.architecture != host_arch:
            return RunnerResult(
                status="unavailable",
                note=f"native Appcall requires a host-compatible ELF ({host_arch})",
                detail={"target_format": image.format, "target_architecture": image.architecture, "executed": False},
            )

        symbol_ok, symbol_note = self._find_symbol(binary_path, function_name)
        if not symbol_ok:
            return RunnerResult(status="missing_symbol", note=symbol_note)

        main_ok, _ = self._find_symbol(binary_path, "main")
        if not main_ok:
            return RunnerResult(
                status="unavailable",
                note="native Appcall currently requires an executable with a main symbol",
                detail={"symbol_found": True, "executed": False},
            )

        raw_args = list(getattr(probe, "args", []) or [])
        if len(raw_args) > 6:
            return RunnerResult(status="error", note="native integer ABI supports at most six arguments")
        args: list[int] = []
        for index, value in enumerate(raw_args):
            try:
                args.append(int(value, 0) if isinstance(value, str) else int(value))
            except (TypeError, ValueError):
                return RunnerResult(status="error", note=f"native argument {index} is not an integer")

        gdb = shutil.which("gdb")
        if gdb is None:  # guarded by can_run, retained for race-safe failure
            return RunnerResult(status="unavailable", note="GDB disappeared before execution")
        expression = f"(long){function_name}({', '.join(str(value) for value in args)})"
        command = [
            gdb, "--nx", "--nh", "--batch", "--quiet",
            "-ex", "set pagination off",
            "-ex", "set confirm off",
            "-ex", "set debuginfod enabled off",
            "-ex", "set auto-load off",
            "-ex", "set startup-with-shell off",
            "-ex", "set inferior-tty /dev/null",
            "-ex", "start",
            "-ex", f"set $angerona_result = {expression}",
            "-ex", 'printf "ANGERONA_APPCALL_RESULT=%lld\\n", $angerona_result',
            "-ex", "kill",
            "--args", str(Path(binary_path).resolve()),
        ]
        from src.analysis.sandbox import wrap
        sandboxed = wrap(command, [], readonly_binds=[Path(binary_path).resolve()])
        try:
            completed = observed_run(
                sandboxed, capture_output=True, text=True, timeout=30, check=False,
            )
        except Exception as exc:
            return RunnerResult(
                status="error", note=f"sandboxed native Appcall failed: {exc}",
                detail={"symbol_found": True, "executed": False},
            )
        matches = list(_RESULT.finditer(completed.stdout or ""))
        match = matches[0] if len(matches) == 1 else None
        if completed.returncode != 0 or match is None:
            return RunnerResult(
                status="error",
                note="GDB did not produce a verified native Appcall result",
                detail={
                    "symbol_found": True, "executed": False,
                    "gdb_exit_code": completed.returncode,
                    "stdout_tail": (completed.stdout or "")[-2000:],
                    "stderr_tail": (completed.stderr or "")[-2000:],
                },
            )

        return RunnerResult(
            status="success",
            note=f"{symbol_note}; sandboxed native Appcall completed",
            detail={
                "symbol_found": True,
                "executed": True,
                "sandbox": "bubblewrap",
                "network": False,
                "abi": "host integer/pointer ABI",
                "return_value": int(match.group(1)),
            },
        )

    def _find_symbol(self, binary_path: str, function_name: str) -> tuple[bool, str]:
        """Check the symbol table for ``function_name``.

        Prefers ``readelf -s``, then ``nm``.  A raw byte scan is used only as a
        last resort and requires the candidate name to be NUL-terminated to
        reduce false positives.
        """
        tools = [t for t in ("readelf", "nm") if shutil.which(t)]
        for tool in tools:
            try:
                if tool == "readelf":
                    out = observed_run(
                        [tool, "-s", binary_path],
                        capture_output=True, text=True, timeout=10, check=False,
                    ).stdout
                else:
                    out = observed_run(
                        [tool, binary_path],
                        capture_output=True, text=True, timeout=10, check=False,
                    ).stdout
                if function_name in out:
                    return True, f"symbol {function_name} found via {tool}"
            except Exception as exc:
                return False, f"{tool} failed: {exc}"

        # Last-resort byte scan: require NUL terminator to avoid substring matches.
        data = Path(binary_path).read_bytes()
        needle = function_name.encode() + b"\x00"
        if needle in data:
            return True, f"symbol {function_name} located by byte scan"
        return False, f"symbol {function_name} not present (binary may be stripped)"
