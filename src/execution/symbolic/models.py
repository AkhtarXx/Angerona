"""Data models for the symbolic / concolic execution probe layer."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SymbolicProbeRequest:
    """Parameters for a symbolic/concolic function probe.

    Mirrors ``EmulatorProbeRequest`` in spirit but adds angr-specific controls.
    """

    function_name: str
    function_address: int | None = None
    args: list[Any] = field(default_factory=list)
    symbolic_args: list[int] = field(default_factory=list)
    max_paths: int = 16
    max_steps: int = 2000
    target_addresses: list[int] = field(default_factory=list)
    capture_memory_ranges: list[tuple[str, int, int]] = field(default_factory=list)
    expected_backend: str = "symbolic"

    def __post_init__(self) -> None:
        if not self.function_name and self.function_address is None:
            raise ValueError("function_name or function_address is required")
        if self.max_paths < 1:
            raise ValueError("max_paths must be >= 1")
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        bad = [i for i in self.symbolic_args if i < 0]
        if bad:
            raise ValueError(f"symbolic arg indices must be non-negative: {bad}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_address": self.function_address,
            "args": list(self.args),
            "symbolic_args": list(self.symbolic_args),
            "max_paths": self.max_paths,
            "max_steps": self.max_steps,
            "target_addresses": [a for a in self.target_addresses],
            "capture_memory_ranges": [list(r) for r in self.capture_memory_ranges],
            "expected_backend": self.expected_backend,
        }


@dataclass
class InputSeed:
    """Concrete input value for a symbolic argument on one path."""

    arg_index: int
    concrete_value: int | None = None
    width_bits: int = 64
    pointed_buffer: bytes | None = None

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "arg_index": self.arg_index,
            "concrete_value": self.concrete_value,
            "width_bits": self.width_bits,
        }
        if self.pointed_buffer is not None:
            d["pointed_buffer_b64"] = base64.b64encode(self.pointed_buffer).decode("ascii")
        return d


@dataclass
class PathConstraint:
    """One explored path through the function."""

    path_id: int
    reachable: bool = True
    input_seeds: dict[int, InputSeed] = field(default_factory=dict)
    predicate_smt: list[str] = field(default_factory=list)
    predicate_text: list[str] = field(default_factory=list)
    block_trace: list[int] = field(default_factory=list)
    hit_target: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "reachable": self.reachable,
            "input_seeds": {k: v.as_dict() for k, v in self.input_seeds.items()},
            "predicate_smt": list(self.predicate_smt),
            "predicate_text": list(self.predicate_text),
            "block_trace": [a for a in self.block_trace],
            "hit_target": self.hit_target,
        }


@dataclass
class MemoryWriteObservation:
    """One memory write observed by the symbolic or static fallback probe."""

    address_expr: str | None = None
    concrete_address: int | None = None
    value_expr: str | None = None
    concrete_value: int | None = None
    width_bits: int = 8

    def as_dict(self) -> dict[str, Any]:
        return {
            "address_expr": self.address_expr,
            "concrete_address": self.concrete_address,
            "value_expr": self.value_expr,
            "concrete_value": self.concrete_value,
            "width_bits": self.width_bits,
        }


@dataclass
class SymbolicProbeResult:
    """Result of a symbolic probe, serializable and engine-agnostic."""

    backend: str = "symbolic"
    status: str = ""  # success | unavailable | timeout | error | missing_symbol
    paths: list[PathConstraint] = field(default_factory=list)
    memory_writes: list[MemoryWriteObservation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "status": self.status,
            "paths": [p.as_dict() for p in self.paths],
            "memory_writes": [w.as_dict() for w in self.memory_writes],
            "notes": list(self.notes),
            "detail": dict(self.detail),
        }
