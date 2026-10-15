"""Truthfully named public interface for Angerona's Unicorn execution oracle."""

from .qemu_oracle import EmuResult, arch_supported, emulate_function

__all__ = ["EmuResult", "arch_supported", "emulate_function"]
