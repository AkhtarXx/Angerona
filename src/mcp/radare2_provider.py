"""Safe launch planning for the official radareorg/radare2-mcp server."""

from __future__ import annotations

import os
import shutil
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Radare2McpPlan:
    executable: str
    argv: tuple[str, ...]
    metadata: dict[str, Any]


class Radare2McpProvider:
    """Discover and configure r2mcp with fail-closed analysis defaults."""

    name = "radare2-mcp"

    @staticmethod
    def r2pm_executable() -> str | None:
        return shutil.which("r2pm")

    @staticmethod
    def server_executable() -> str | None:
        candidates = [
            Path.home() / ".local/share/radare2/prefix/bin/r2mcp",
            Path(sysconfig.get_path("scripts")) / "r2mcp",
        ]
        direct = shutil.which("r2mcp")
        if direct:
            candidates.insert(0, Path(direct))
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate.resolve())
        return None

    def available(self) -> bool:
        return self.r2pm_executable() is not None and self.server_executable() is not None

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available(),
            "r2pm": self.r2pm_executable(),
            "server": self.server_executable(),
            "transport": "stdio",
            "readonly_supported": True,
            "sandbox_lock_supported": True,
        }

    def launch_plan(self, allowed_root: str | Path, *, minimal_tools: bool = True) -> Radare2McpPlan:
        r2pm = self.r2pm_executable()
        server = self.server_executable()
        if r2pm is None or server is None:
            raise RuntimeError("official radare2 MCP server is unavailable")
        root = Path(allowed_root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("radare2 MCP sandbox root must be a directory")
        command = [
            r2pm, "-r", "r2mcp",
            "-R",                 # expose only non-mutating tools
            "-s", str(root),      # reject files outside the analysis root
            "-n",                 # do not load user radare2rc or plugins
            "-N",                 # do not load prompt files
        ]
        if minimal_tools:
            command.append("-m")
        return Radare2McpPlan(
            executable=r2pm,
            argv=tuple(command),
            metadata={
                "implementation": "radareorg/radare2-mcp",
                "server_executable": server,
                "readonly": True,
                "sandbox_root": str(root),
                "load_user_config": False,
                "load_prompts": False,
                "minimal_tools": minimal_tools,
            },
        )


__all__ = ["Radare2McpPlan", "Radare2McpProvider"]
