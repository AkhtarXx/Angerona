"""Reproducible multi-format/corpus benchmark matrix and regression gates."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable


BENCHMARK_SCHEMA_VERSION = "angerona.benchmark-matrix/v1"


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    source: str
    language: str
    compiler: str
    flags: tuple[str, ...]
    expected_format: str
    expected_architecture: str
    oracle: str
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, row: dict[str, Any], base: Path) -> "BenchmarkCase":
        return cls(
            str(row["case_id"]), str((base / row["source"]).resolve()),
            str(row["language"]), str(row["compiler"]), tuple(row.get("flags") or ()),
            str(row["expected_format"]), str(row["expected_architecture"]),
            str((base / row["oracle"]).resolve()), tuple(row.get("tags") or ()),
        )


@dataclass(frozen=True)
class BuiltCase:
    case: BenchmarkCase
    binary: str
    sha256: str
    compiler_path: str
    compiler_version: str
    command: tuple[str, ...]


class CorpusMatrix:
    def __init__(self, cases: list[BenchmarkCase], thresholds: dict[str, float] | None = None) -> None:
        identities = [case.case_id for case in cases]
        if len(identities) != len(set(identities)):
            raise ValueError("benchmark case IDs must be unique")
        self.cases = cases
        self.thresholds = dict(thresholds or {})

    @classmethod
    def load(cls, path: str | Path) -> "CorpusMatrix":
        manifest = Path(path).resolve(strict=True)
        row = json.loads(manifest.read_text())
        if row.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
            raise ValueError("unsupported benchmark manifest schema")
        return cls(
            [BenchmarkCase.from_dict(item, manifest.parent) for item in row.get("cases") or []],
            row.get("thresholds"),
        )

    def dimensions(self) -> dict[str, list[str]]:
        return {
            "formats": sorted({case.expected_format for case in self.cases}),
            "architectures": sorted({case.expected_architecture for case in self.cases}),
            "languages": sorted({case.language for case in self.cases}),
            "compilers": sorted({case.compiler for case in self.cases}),
            "tags": sorted({tag for case in self.cases for tag in case.tags}),
        }


class CorpusBuilder:
    def build(self, case: BenchmarkCase, output_dir: str | Path) -> BuiltCase:
        compiler = shutil.which(case.compiler)
        if compiler is None:
            raise RuntimeError(f"benchmark compiler is unavailable: {case.compiler}")
        source = Path(case.source).resolve(strict=True)
        destination = Path(output_dir).resolve() / case.case_id / "sample"
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = (compiler, *case.flags, str(source), "-o", str(destination))
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"benchmark build failed: {result.stderr[-4000:]}")
        version = subprocess.run(
            (compiler, "--version"), capture_output=True, text=True, timeout=10, check=False
        ).stdout.splitlines()[0]
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        return BuiltCase(case, str(destination), digest, compiler, version, command)


@dataclass(frozen=True)
class CaseMetrics:
    case_id: str
    function_precision: float
    function_recall: float
    symbol_precision: float
    symbol_recall: float
    cfg_edge_recall: float
    analysis_seconds: float
    crashes: int = 0
    properties: dict[str, Any] = field(default_factory=dict, compare=False)


class MatrixEvaluator:
    @staticmethod
    def set_metrics(expected: Iterable[str], actual: Iterable[str]) -> tuple[float, float]:
        wanted, found = set(expected), set(actual)
        true_positive = len(wanted & found)
        precision = true_positive / len(found) if found else (1.0 if not wanted else 0.0)
        recall = true_positive / len(wanted) if wanted else 1.0
        return precision, recall

    def evaluate_case(
        self,
        case: BenchmarkCase,
        result: dict[str, Any],
        elapsed: float,
    ) -> CaseMetrics:
        oracle = json.loads(Path(case.oracle).read_text())
        function_precision, function_recall = self.set_metrics(
            oracle.get("functions") or [], result.get("functions") or []
        )
        symbol_precision, symbol_recall = self.set_metrics(
            oracle.get("symbols") or [], result.get("symbols") or []
        )
        _edge_precision, edge_recall = self.set_metrics(
            [tuple(row) for row in oracle.get("cfg_edges") or []],
            [tuple(row) for row in result.get("cfg_edges") or []],
        )
        return CaseMetrics(
            case.case_id, function_precision, function_recall,
            symbol_precision, symbol_recall, edge_recall, elapsed,
            int(result.get("crashes") or 0),
        )

    @staticmethod
    def aggregate(rows: Iterable[CaseMetrics]) -> dict[str, float]:
        metrics = list(rows)
        if not metrics:
            raise ValueError("cannot aggregate an empty benchmark matrix")
        names = (
            "function_precision", "function_recall", "symbol_precision",
            "symbol_recall", "cfg_edge_recall", "analysis_seconds",
        )
        return {name: sum(getattr(row, name) for row in metrics) / len(metrics) for name in names} | {
            "crashes": float(sum(row.crashes for row in metrics)),
            "cases": float(len(metrics)),
        }

    @staticmethod
    def enforce(aggregate: dict[str, float], thresholds: dict[str, float]) -> list[str]:
        failures: list[str] = []
        for metric, threshold in thresholds.items():
            value = aggregate.get(metric)
            if value is None:
                failures.append(f"missing metric: {metric}")
            elif metric in {"analysis_seconds", "crashes"}:
                if value > threshold:
                    failures.append(f"{metric}={value:.4f} exceeds {threshold:.4f}")
            elif value < threshold:
                failures.append(f"{metric}={value:.4f} below {threshold:.4f}")
        return failures
