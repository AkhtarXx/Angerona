"""Fail-fast boot checklist (QM ``bootProblems()`` pattern) for Angerona.

Runs at CLI start to catch configuration problems before an analysis begins.
A misconfigured security tool that silently degrades is worse than a fast crash.

Checks are:
  - the RE engine is installed and ready (IDA or Ghidra)
  - the agent CLIs the run needs (claude/codex) are present on PATH
  - ANGERONA_HOME is usable with enough free space
  - the target binary exists, is readable, non-empty, and not a symlink
  - Bubblewrap is available when --sandbox is requested (otherwise it silently
    runs un-sandboxed, which is exactly what the user did not want)
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .config import load_config, default_engine


@dataclass(frozen=True)
class BootProblem:
    code: str           # machine code, e.g. "engine.missing"
    severity: str       # "error" (blocks) | "warning" (runs degraded)
    detail: str         # human-readable explanation


@dataclass(frozen=True)
class BootReport:
    problems: tuple[BootProblem, ...] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(p.severity == "error" for p in self.problems)

    def format(self) -> str:
        if self.ok:
            return "boot: ok"
        return "\n".join(f"boot[{p.severity}] {p.code}: {p.detail}" for p in self.problems)


def check_boot(
    *,
    engine: str | None = None,
    agent: str | None = None,
    sandbox: bool = False,
    binary: str | Path | None = None,
    min_free_bytes: int = 2 * 1024 * 1024,  # 2 MiB
    require_agent: bool = True,
) -> BootReport:
    """Run the boot checklist and return every detected problem.

    Non-fatal issues are warnings; fatal issues are errors. ``ok`` is True iff
    no error was raised.  Never raises for well-known failure classes; a broken
    environment should surface as problems, not an exception.
    """
    problems: list[BootProblem] = []

    engine_name = (engine or default_engine()).strip()
    if engine_name not in {"ida", "ghidra"}:
        problems.append(BootProblem(
            "engine.invalid", "error",
            f"engine {engine_name!r} is not one of 'ida' or 'ghidra'",
        ))
    else:
        try:
            cfg = load_config(engine_name)
            ok, msg = cfg.ghidra_ready() if engine_name == "ghidra" else cfg.ida_ready()
            if not ok:
                problems.append(BootProblem("engine.missing", "error", msg))
        except Exception as exc:  # noqa: BLE001
            problems.append(BootProblem(
                "engine.discovery_failed", "error",
                f"engine discovery failed: {exc}",
            ))

    agent_name = (agent or "").strip() or "claude"
    if require_agent and agent_name not in {"", "claude", "codex"}:
        problems.append(BootProblem(
            "agent.invalid", "error",
            f"agent {agent_name!r} is not one of 'claude' or 'codex'",
        ))
    elif require_agent:
        try:
            from .agents.runtime import ClaudeCodeAgent, CodexAgent
            available = ClaudeCodeAgent().available() if agent_name == "claude" else CodexAgent().available()
            if not available:
                problems.append(BootProblem(
                    "agent.missing", "error",
                    f"{agent_name} CLI not found on PATH; install the subscription agent CLI or pass --agent",
                ))
        except Exception as exc:  # noqa: BLE001
            problems.append(BootProblem(
                "agent.discovery_failed", "warning",
                f"agent availability probe failed: {exc}",
            ))

    if sandbox and shutil.which("bwrap") is None:
        problems.append(BootProblem(
            "sandbox.bwrap_missing", "error",
            "bubblewrap (bwrap) is required for --sandbox but is not installed; "
            "install bubblewrap or drop the flag (running un-sandboxed is a security regression)",
        ))

    if binary is not None:
        path = Path(binary)
        try:
            if path.is_symlink():
                problems.append(BootProblem(
                    "binary.symlink", "error",
                    f"target binary must not be a symlink: {path}",
                ))
            elif not path.exists():
                problems.append(BootProblem(
                    "binary.missing", "error",
                    f"target binary not found: {path}",
                ))
            elif path.stat().st_size == 0:
                problems.append(BootProblem(
                    "binary.empty", "error",
                    f"target binary is empty: {path}",
                ))
            elif not os.access(path, os.R_OK):
                problems.append(BootProblem(
                    "binary.unreadable", "error",
                    f"target binary is not readable: {path}",
                ))
        except OSError as exc:
            problems.append(BootProblem(
                "binary.stat_failed", "error",
                f"could not stat binary {path}: {exc}",
            ))

    try:
        state_dir = None
        try:
            state_dir = load_config(engine_name if engine_name in {"ida", "ghidra"} else "ida").state_dir
        except Exception:  # noqa: BLE001
            pass
        home_root = state_dir or Path(os.environ.get("ANGERONA_HOME", Path.home() / ".angerona"))
        usage = shutil.disk_usage(home_root if home_root.exists() else home_root.parent)
        if usage.free < min_free_bytes:
            problems.append(BootProblem(
                "disk.low_free", "error",
                f"only {_human_bytes(usage.free)} free under {home_root}; need at least "
                f"{_human_bytes(min_free_bytes)} to record audit state",
            ))
    except OSError as exc:
        problems.append(BootProblem(
            "disk.check_failed", "warning",
            f"free-space check failed: {exc}",
        ))

    # Report invalid user input before environment provisioning problems.
    problems.sort(key=lambda item: 0 if item.code.startswith("binary.") else 1)
    return BootReport(problems=tuple(problems))


def _human_bytes(value: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024
    return f"{value} B"


def fail_fast(report: BootReport) -> int:
    """Print the report and return 1 when it contains errors, else 0."""
    if not report.ok:
        print(report.format(), file=os.sys.stderr)
        return 1
    return 0
