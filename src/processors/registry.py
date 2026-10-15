"""Processor registry for hot-plugging custom ISAs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from src.processors.base import ProcessorModule


class ProcessorRegistry:
    """Global registry of named processor modules."""

    _processors: dict[str, Type["ProcessorModule"]] = {}

    @classmethod
    def register(cls, name: str, processor_class: Type["ProcessorModule"]) -> None:
        """Register ``processor_class`` under ``name``."""
        if not name:
            raise ValueError("processor name must be non-empty")
        cls._processors[name.lower()] = processor_class

    @classmethod
    def get(cls, name: str) -> Type["ProcessorModule"]:
        """Look up a processor class by name."""
        key = name.lower()
        if key not in cls._processors:
            raise KeyError(f"unknown processor: {name}")
        return cls._processors[key]

    @classmethod
    def has(cls, name: str) -> bool:
        return name.lower() in cls._processors

    @classmethod
    def list(cls) -> list[str]:
        return sorted(cls._processors.keys())

    @classmethod
    def clear(cls) -> None:
        cls._processors.clear()


# Convenience alias used by analyzer/CLI.
register_processor = ProcessorRegistry.register
