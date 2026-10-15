"""Engine factory — pick the active reverse-engineering backend.

Both engines expose the same duck-typed interface used by the rest of the
pipeline: ``status()``, ``analyze(binary, *, decompile, max_functions, force)``,
``decompile_function(binary, name)``, ``load_meta(binary)``.
"""

from __future__ import annotations

from ..config import Config, load_config


def make_engine(config: Config | None = None):
    """Return the engine object for ``config.engine`` (default: ida)."""
    config = config or load_config()
    if config.engine == "ghidra":
        from .ghidra import GhidraEngine
        return GhidraEngine(config)
    if config.engine == "ida":
        from .ida import IdaEngine
        return IdaEngine(config)
    raise ValueError(f"unsupported engine: {config.engine!r}")
