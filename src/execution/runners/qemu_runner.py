"""Backward-compatible import for the former, inaccurately named runner."""

from src.execution.runners.unicorn_runner import UnicornRunner

# Compatibility only. This runner has always used Unicorn, never QEMU.
QemuUnicornRunner = UnicornRunner

__all__ = ["QemuUnicornRunner", "UnicornRunner"]
