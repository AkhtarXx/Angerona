"""Data models for structured decompiler pseudocode and function summaries."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PseudocodeLine:
    """One line of structured pseudocode output."""

    depth: int = 0
    label: str | None = None
    text: str = ""
    kind: str = "statement"  # statement | branch | call | return | loop_header | comment

    def as_dict(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "label": self.label,
            "text": self.text,
            "kind": self.kind,
        }


@dataclass
class PseudocodeFunction:
    """Pseudocode for a single function."""

    function_id: str
    address: str | None = None
    name: str | None = None
    signature: str | None = None
    pseudocode: list[PseudocodeLine] = field(default_factory=list)
    locals_: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "address": self.address,
            "name": self.name,
            "signature": self.signature,
            "pseudocode": [p.as_dict() for p in self.pseudocode],
            "locals": list(self.locals_),
            "calls": list(self.calls),
            "strings": list(self.strings),
        }


@dataclass
class FunctionSummary:
    """Natural-language summary for one function."""

    function_id: str
    address: str | None = None
    name: str | None = None
    purpose: str = ""
    io_summary: str = ""
    risk_flags: list[str] = field(default_factory=list)
    confidence: str = "low"  # high | medium | low

    def as_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "address": self.address,
            "name": self.name,
            "purpose": self.purpose,
            "io_summary": self.io_summary,
            "risk_flags": list(self.risk_flags),
            "confidence": self.confidence,
        }


@dataclass
class SummaryReport:
    """Combined pseudocode + summary report for a workspace."""

    workspace: str | None = None
    functions: list[PseudocodeFunction] = field(default_factory=list)
    summaries: list[FunctionSummary] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "workspace": self.workspace,
            "functions": [f.as_dict() for f in self.functions],
            "summaries": [s.as_dict() for s in self.summaries],
        }

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.as_dict(), indent=2, default=str), encoding="utf-8")
