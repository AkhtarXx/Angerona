"""Headless deterministic automation backbone for the Angerona RE platform.

This module runs the full state-of-the-art pipeline end-to-end from a batch job
spec: structural triage, engine-driven disassembly/decompilation, analysis-graph
build, library-signature matching, type recovery, xref-graph construction,
vulnerability-sink hunting, C++ / vtable / RTTI recovery, and reversible
checkpointing.  It is designed for non-interactive operation: no TTY is required,
environment variables are reconciled so IDA Pro's TVHEADLESS / headless mode wins,
and every stage produces structured, traceable log output.

Design based on *The IDA Pro Book* batch-mode guidance (``TVHEADLESS=1``,
``no interactive dialogs``, headless script execution) generalized so the same
entry point works for both the IDA and Ghidra backends.
"""

from __future__ import annotations

import json
import logging
import os
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..analysis.export import export_analysis
from ..analysis.library_signatures import SignatureDB, quick_library_mark
from ..analysis.security_slices import write_security_slices
from ..analysis.sink_hunter import SinkHunter
from ..analysis.xref_graph import XrefGraph
from ..config import load_config
from ..engines import make_engine
from ..models.analysis_graph import AnalysisGraph
from ..models.checkpoint_db import CheckpointDB
from ..models.cpp_recovery import CppRecoveryAgent
from ..models.triage_profile import MultiSourceTriager
from ..models.type_recovery import TypeRecoveryAgent
from ..workspace import RunWorkspace


DEFAULT_STAGES = [
    "triage",
    "analyze",
    "graph",
    "signatures",
    "types",
    "xref",
    "sinks",
    "cpp",
]


@dataclass
class BatchJobSpec:
    """Specification for a single headless reverse-engineering batch job.

    Attributes
    ----------
    binary:
        Path to the target executable/library/firmware image.
    engine:
        Reverse-engineering backend to use: ``"ida"`` or ``"ghidra"``.
    max_functions:
        Cap on the number of functions to decompile (``0`` = all).  The meta
        analysis pass is always unbounded.
    force:
        Ignore on-disk engine caches and re-run from scratch.
    signature_db:
        Optional path to a JSON library-signature database to load.
    type_library:
        Optional path to a serialized type-library / IDA til file to apply.
    sandbox:
        Whether to request sandboxed subprocess execution when available.
    output_dir:
        Optional parent directory for the run workspace.  Defaults to the
        configured Angerona state home.
    stages:
        Ordered list of pipeline stages to execute.  Any stage not in this list
        is skipped.
    tags:
        Free-form key/value annotations propagated into checkpoint and report
        metadata.
    """

    binary: str
    engine: str
    max_functions: int = 0
    force: bool = False
    signature_db: str | None = None
    type_library: str | None = None
    sandbox: bool = False
    output_dir: str | None = None
    stages: list[str] = field(default_factory=lambda: list(DEFAULT_STAGES))
    tags: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.engine not in {"ida", "ghidra"}:
            raise ValueError(f"unsupported engine: {self.engine!r}")
        if self.max_functions < 0:
            raise ValueError("max_functions must be >= 0")
        unknown = sorted(set(self.stages) - set(DEFAULT_STAGES))
        if unknown:
            raise ValueError(f"unknown pipeline stage(s): {', '.join(unknown)}")
        if not self.stages:
            raise ValueError("at least one pipeline stage is required")


@dataclass
class BatchJobResult:
    """Structured result of a completed (or failed) batch job.

    Attributes
    ----------
    workspace:
        Absolute path of the per-run workspace directory.
    return_code:
        ``0`` on success, non-zero on failure.  Partial successes still carry
        a non-zero code when at least one required stage failed.
    duration_seconds:
        Wall-clock runtime of the whole pipeline.
    stage_logs:
        Per-stage records produced by :class:`BatchSpine`.
    summary:
        Aggregate metrics (node/edge counts, sink counts, etc.).
    artifacts:
        Mapping from logical artifact name to absolute file path.
    """

    workspace: str
    return_code: int
    duration_seconds: float
    stage_logs: list[dict[str, Any]]
    summary: dict[str, Any]
    artifacts: dict[str, str]


class BatchSpine:
    """Headless deterministic pipeline runner.

    Parameters
    ----------
    state_dir:
        Directory under which per-run workspaces are created.  Each run gets a
        timestamped sub-directory.
    log_level:
        Logging level for the Python root logger in this module.
    """

    def __init__(self, state_dir: str | Path, *, log_level: str = "INFO") -> None:
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("angerona.batch_spine")
        self._logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            self._logger.addHandler(handler)

        # Shared pipeline state populated across stages.
        self._workspace: RunWorkspace | None = None
        self._checkpoint_db: CheckpointDB | None = None
        self._engine: Any = None
        self._engine_analysis: dict[str, Any] = {}
        self._analysis_graph: AnalysisGraph | None = None
        self._xref_graph: XrefGraph | None = None
        self._signature_db: SignatureDB | None = None
        self._signature_matches: dict[str, dict] | None = None
        self._signature_match_source: str | None = None
        self._type_recovery: TypeRecoveryAgent | None = None

    # ------------------------------------------------------------------ helpers

    def _env_for_headless(self, spec: BatchJobSpec) -> dict[str, str]:
        """Return environment variables that silence interactive engine dialogs.

        IDA Pro honors ``TVHEADLESS`` and ``IDA_IS_INTERACTIVE``; Ghidra is
        already headless but we still suppress any X11 plugins when present.
        """
        env = dict(os.environ)
        env["TVHEADLESS"] = "1"
        env["IDA_IS_INTERACTIVE"] = "0"
        env["TERM"] = env.get("TERM", "dumb")
        env["DISPLAY"] = ""  # headless: never open X
        if spec.sandbox:
            env["ANGERONA_SANDBOX"] = "1"
        return env

    def _run_stage(self, name: str, func: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        """Execute a pipeline stage, capturing timing, status and errors.

        Every stage emits ``stage.<name>.start`` and ``stage.<name>.complete`` or
        ``stage.<name>.error`` traces via the workspace.  Exceptions are caught
        and converted to a failed stage log so that subsequent stages can still
        run when it makes sense.
        """
        assert self._workspace is not None
        log_entry: dict[str, Any] = {"stage": name, "status": "running"}
        self._workspace.trace(f"stage.{name}.start")
        start = time.monotonic()
        try:
            result = func()
            log_entry.update(
                {
                    "status": "ok",
                    "duration_seconds": round(time.monotonic() - start, 3),
                    "result": result if isinstance(result, dict) else {"value": result},
                }
            )
            self._workspace.trace(f"stage.{name}.complete", duration=log_entry["duration_seconds"])
        except Exception as exc:  # noqa: BLE001
            duration = time.monotonic() - start
            log_entry.update(
                {
                    "status": "error",
                    "duration_seconds": round(duration, 3),
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }
            )
            self._workspace.trace(
                f"stage.{name}.error", error=str(exc), duration=round(duration, 3)
            )
            self._logger.exception("Stage %s failed", name)
        return log_entry

    def _should_run(self, spec: BatchJobSpec, name: str) -> bool:
        """Return True when a stage is present in ``spec.stages``."""
        return name in spec.stages

    def _stage_failed(self, name: str, logs: list[dict[str, Any]]) -> bool:
        """Check whether a specific stage has already failed."""
        for log in logs:
            if log.get("stage") == name and log.get("status") != "ok":
                return True
        return False

    def _artifact(self, name: str) -> Path:
        """Return an absolute raw-path target for an artifact."""
        assert self._workspace is not None
        return self._workspace.raw_dir / name

    def _save_json(self, path: Path, data: Any) -> None:
        """Serialize ``data`` to JSON, creating the parent directory if needed."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    # ---------------------------------------------------------------- pipeline

    def run(self, spec: BatchJobSpec) -> BatchJobResult:
        """Execute the full deterministic pipeline described by ``spec``.

        The method is intentionally linear and explicit.  Engine-specific
        environment variables are set, a workspace is created, each requested
        stage is run in order, and a ``batch_report.json`` is persisted in the
        workspace ``raw/`` folder.  A checkpoint is recorded before each mutating
        stage so the run can be audited or partially rolled back later.
        """
        return self._run_pipeline(spec, self._env_for_headless(spec))

    def _run_pipeline(self, spec: BatchJobSpec, env: dict[str, str]) -> BatchJobResult:
        """Internal pipeline implementation."""
        overall_start = time.monotonic()
        stage_logs: list[dict[str, Any]] = []
        artifacts: dict[str, str] = {}
        summary: dict[str, Any] = {"binary": str(spec.binary), "engine": spec.engine}

        # Ensure the binary exists early so the workspace isn't created for nothing.
        binary_path = Path(spec.binary).expanduser().resolve()
        if not binary_path.is_file():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Workspace setup.
        runs_dir = (
            Path(spec.output_dir).expanduser().resolve()
            if spec.output_dir else self.state_dir
        )
        runs_dir.mkdir(parents=True, exist_ok=True)
        self._workspace = RunWorkspace.create(runs_dir, str(binary_path))
        self._workspace.meta.update(
            {
                "engine": spec.engine,
                "stages": list(spec.stages or DEFAULT_STAGES),
                "tags": dict(spec.tags),
                "max_functions": spec.max_functions,
                "force": spec.force,
                "signature_db": spec.signature_db,
                "type_library": spec.type_library,
            }
        )
        self._workspace._save_meta()
        self._workspace.trace(
            "batch.start",
            binary=str(binary_path),
            engine=spec.engine,
            workspace=str(self._workspace.root),
        )
        self._logger.info("Starting batch run for %s (engine=%s)", binary_path, spec.engine)

        # Checkpoint database is initialized empty; each stage can create its own
        # checkpoint later if it performs mutations.
        self._checkpoint_db = CheckpointDB(self._workspace.checkpoint_db_path)
        self._workspace.trace("checkpoint.init", path=str(self._workspace.checkpoint_db_path))

        # --- stage: triage --------------------------------------------------
        if self._should_run(spec, "triage"):
            log = self._run_stage("triage", lambda: self._stage_triage(spec, artifacts))
            stage_logs.append(log)

        # --- stage: analyze -------------------------------------------------
        if self._should_run(spec, "analyze"):
            log = self._run_stage("analyze", lambda: self._stage_analyze(spec, artifacts))
            stage_logs.append(log)

        # Stages below require the analysis graph; abort early graph report if
        # analyze failed or was skipped and no cached graph is available.
        if self._should_run(spec, "graph"):
            if self._analysis_graph is None and self._stage_failed("analyze", stage_logs):
                stage_logs.append(
                    {
                        "stage": "graph",
                        "status": "skipped",
                        "reason": "analyze stage failed or produced no graph",
                    }
                )
                self._workspace.trace("stage.graph.skipped", reason="analyze failed")
            else:
                log = self._run_stage("graph", lambda: self._stage_graph(spec, artifacts))
                stage_logs.append(log)

        if self._should_run(spec, "signatures"):
            if self._analysis_graph is None:
                stage_logs.append({"stage": "signatures", "status": "skipped", "reason": "analysis graph unavailable"})
                self._workspace.trace("stage.signatures.skipped", reason="analysis graph unavailable")
            else:
                log = self._run_stage("signatures", lambda: self._stage_signatures(spec, artifacts))
                stage_logs.append(log)

        if self._should_run(spec, "types"):
            if self._analysis_graph is None:
                stage_logs.append({"stage": "types", "status": "skipped", "reason": "analysis graph unavailable"})
                self._workspace.trace("stage.types.skipped", reason="analysis graph unavailable")
            else:
                log = self._run_stage("types", lambda: self._stage_types(spec, artifacts))
                stage_logs.append(log)

        if self._should_run(spec, "xref"):
            if self._analysis_graph is None:
                stage_logs.append({"stage": "xref", "status": "skipped", "reason": "analysis graph unavailable"})
                self._workspace.trace("stage.xref.skipped", reason="analysis graph unavailable")
            else:
                log = self._run_stage("xref", lambda: self._stage_xref(spec, artifacts))
                stage_logs.append(log)

        if self._should_run(spec, "sinks"):
            if self._xref_graph is None:
                stage_logs.append(
                    {"stage": "sinks", "status": "skipped", "reason": "xref graph unavailable"}
                )
                self._workspace.trace("stage.sinks.skipped", reason="xref graph unavailable")
            else:
                log = self._run_stage("sinks", lambda: self._stage_sinks(spec, artifacts))
                stage_logs.append(log)

        if self._should_run(spec, "cpp"):
            if self._analysis_graph is None:
                stage_logs.append(
                    {"stage": "cpp", "status": "skipped", "reason": "analysis graph unavailable"}
                )
                self._workspace.trace("stage.cpp.skipped", reason="analysis graph unavailable")
            else:
                log = self._run_stage("cpp", lambda: self._stage_cpp(spec, artifacts))
                stage_logs.append(log)

        # --- checkpoint: final run checkpoint --------------------------------
        if self._checkpoint_db is not None:
            try:
                ckpt = self._checkpoint_db.create_checkpoint(
                    agent="BatchSpine",
                    rationale="pipeline completion",
                    tags=dict(spec.tags),
                )
                self._workspace.trace("checkpoint.final", checkpoint_id=ckpt.id)
                artifacts["final_checkpoint"] = str(self._workspace.checkpoint_db_path)
            except Exception as exc:  # noqa: BLE001
                self._workspace.trace("checkpoint.final.error", error=str(exc))
                self._logger.exception("Failed to create final checkpoint")

        # Return code: success only when all requested stages completed ok.
        requested_logs = [log for log in stage_logs if log.get("stage") in set(spec.stages)]
        failed = [log for log in requested_logs if log.get("status") != "ok"]
        return_code = 0 if not failed else 1

        duration = round(time.monotonic() - overall_start, 3)
        summary.update(
            {
                "duration_seconds": duration,
                "requested_stages": list(spec.stages),
                "completed_stages": len([log for log in requested_logs if log.get("status") == "ok"]),
                "failed_stages": len(failed),
            }
        )

        report = {
            "spec": asdict(spec),
            "stage_logs": stage_logs,
            "summary": summary,
            "artifacts": artifacts,
        }
        report_path = self._workspace.raw_dir / "batch_report.json"
        self._save_json(report_path, report)
        artifacts["batch_report"] = str(report_path)

        self._workspace.finish(
            converged=(return_code == 0),
            rounds=len(stage_logs),
            note=f"return_code={return_code}, duration={duration}s",
        )
        self._workspace.trace("batch.finish", return_code=return_code, duration=duration)

        return BatchJobResult(
            workspace=str(self._workspace.root),
            return_code=return_code,
            duration_seconds=duration,
            stage_logs=stage_logs,
            summary=summary,
            artifacts=artifacts,
        )

    # ----------------------------------------------------------------- stages

    def _stage_triage(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Run structural triage on the binary."""
        triager = MultiSourceTriager()
        profile = triager.triage(spec.binary)
        result = {
            "format": profile.format,
            "arch": profile.arch,
            "bitness": profile.bitness,
            "endian": profile.endian,
            "linker": profile.linker,
            "stripped": profile.stripped,
            "packed_entropy": profile.packed_entropy,
            "compiler": profile.compiler,
            "confidence": profile.confidence,
            "indicators": profile.indicators,
        }
        path = self._artifact("triage.json")
        self._save_json(path, result)
        artifacts["triage"] = str(path)
        self._workspace.trace("artifact.triage", path=str(path))
        return result

    def _stage_analyze(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Drive the configured RE engine over the binary."""
        config = load_config(engine=spec.engine)
        if spec.sandbox:
            config.sandbox = True
        self._engine = make_engine(config)
        status = self._engine.status()
        if not status.get("ready"):
            raise RuntimeError(f"Engine not ready: {status.get('message')}")

        self._workspace.trace(
            "engine.status", ready=status.get("ready"), message=status.get("message")
        )
        solana_fusion = None
        try:
            from ..solana.adapters import is_solana_elf

            solana_target = is_solana_elf(spec.binary)
        except Exception:  # noqa: BLE001
            solana_target = False

        if solana_target:
            try:
                from ..solana.fusion import (
                    analyze_solana_with_engines,
                    build_solana_engine_map,
                )

                solana_fusion = analyze_solana_with_engines(
                    spec.binary,
                    engines=build_solana_engine_map(
                        config,
                        primary_name=spec.engine,
                        primary_engine=self._engine,
                    ),
                    primary=spec.engine,
                    max_functions=spec.max_functions,
                    force=spec.force,
                )
                self._engine_analysis = solana_fusion.fused
                for source_name, source_analysis in solana_fusion.analyses.items():
                    source_path = self._workspace.raw_dir / f"solana_{source_name}_analysis.json"
                    self._save_json(source_path, source_analysis)
                    artifacts[f"solana_{source_name}_analysis"] = str(source_path)
                    source_cache = source_analysis.get("_cache")
                    if source_cache:
                        artifacts[f"solana_{source_name}_cache"] = str(source_cache)
                summary_path = self._workspace.raw_dir / "solana_fusion.json"
                self._save_json(summary_path, solana_fusion.summary())
                artifacts["solana_fusion"] = str(summary_path)
                self._workspace.trace(
                    "engine.solana_fusion",
                    primary=solana_fusion.primary,
                    sources=list(solana_fusion.analyses),
                    errors=solana_fusion.errors,
                )
            except Exception as exc:  # noqa: BLE001
                solana_fusion = None
                self._workspace.trace(
                    "engine.solana_fusion_fallback",
                    error=f"{type(exc).__name__}: {exc}",
                )
                self._engine_analysis = self._engine.analyze(
                    spec.binary,
                    decompile=True,
                    max_functions=spec.max_functions,
                    force=spec.force,
                )
        else:
            self._engine_analysis = self._engine.analyze(
                spec.binary,
                decompile=True,
                max_functions=spec.max_functions,
                force=spec.force,
            )
        if solana_target:
            try:
                from ..solana.utilities import collect_solana_utility_evidence

                utility_dir = self._workspace.raw_dir / "solana_utilities"
                utility_manifest = collect_solana_utility_evidence(
                    spec.binary,
                    utility_dir,
                    timeout=30,
                )
                utility_path = self._workspace.raw_dir / "solana_utilities.json"
                self._save_json(utility_path, utility_manifest)
                artifacts["solana_utilities"] = str(utility_path)
                self._engine_analysis.setdefault("metadata", {}).setdefault(
                    "solana_utilities",
                    {
                        "manifest": str(utility_path),
                        "policy": utility_manifest.get("policy"),
                        "available": [
                            name
                            for name, item in utility_manifest.get("utilities", {}).items()
                            if item.get("available")
                        ],
                    },
                )
                self._workspace.trace(
                    "engine.solana_utilities",
                    path=str(utility_path),
                    available=[
                        name
                        for name, item in utility_manifest.get("utilities", {}).items()
                        if item.get("available")
                    ],
                )
            except Exception as exc:  # noqa: BLE001
                self._workspace.trace(
                    "engine.solana_utilities_error",
                    error=f"{type(exc).__name__}: {exc}",
                )
        if solana_fusion is not None:
            source_results = list(solana_fusion.analyses.values())
            cached = bool(source_results) and all(
                bool(source.get("_cached")) for source in source_results
            )
            source_seconds = [
                source["_seconds"]
                for source in source_results
                if isinstance(source.get("_seconds"), (int, float))
            ]
            seconds = round(sum(source_seconds), 3) if source_seconds else None
        else:
            cached = bool(self._engine_analysis.get("_cached"))
            seconds = self._engine_analysis.get("_seconds")

        result = {
            "engine": "solana-fused" if solana_fusion is not None else spec.engine,
            "source_engines": (
                list(solana_fusion.analyses) if solana_fusion is not None else [spec.engine]
            ),
            "engine_errors": (
                solana_fusion.errors if solana_fusion is not None else {}
            ),
            "cached": cached,
            "seconds": seconds,
            "function_count": len(self._engine_analysis.get("functions", [])),
            "import_count": len(self._engine_analysis.get("imports", [])),
            "export_count": len(self._engine_analysis.get("exports", [])),
            "string_count": len(self._engine_analysis.get("strings", [])),
        }
        cache_path = self._engine_analysis.get("_cache")
        if cache_path:
            artifacts["engine_cache"] = str(cache_path)
            self._workspace.trace("artifact.engine_cache", path=str(cache_path))
        manifest = export_analysis(
            self._engine,
            str(Path(spec.binary).expanduser().resolve()),
            self._workspace.code_dir,
            decompile=True,
            max_functions=spec.max_functions,
            analysis_data=self._engine_analysis,
            producer=(
                "solana_fusion"
                if solana_fusion is not None
                else f"{spec.engine}_batch_analyze"
            ),
        )
        artifacts["code_export"] = str(self._workspace.code_dir)
        artifacts["export_manifest"] = str(self._workspace.code_dir / "EXPORT_MANIFEST.json")
        artifacts["evidence_ledger"] = str(self._workspace.code_dir / "EVIDENCE_LEDGER.json")
        self._workspace.trace(
            "artifact.code_export",
            path=str(self._workspace.code_dir),
            status=manifest.get("status"),
            functions=manifest.get("counts", {}).get("functions"),
            decompiled=manifest.get("counts", {}).get("decompiled_functions"),
        )
        path = self._artifact("engine_analysis_meta.json")
        self._save_json(path, result)
        artifacts["engine_analysis_meta"] = str(path)
        self._workspace.trace("artifact.engine_analysis", path=str(path))
        return result

    def _stage_graph(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Build the engine-agnostic analysis graph."""
        if self._engine_analysis is None:
            raise RuntimeError("No engine analysis available for graph build")
        self._analysis_graph = AnalysisGraph()
        self._analysis_graph.from_engine_json(self._engine_analysis)

        path = self._artifact("analysis_graph.json")
        self._analysis_graph.save_json(path)
        artifacts["analysis_graph"] = str(path)
        self._workspace.trace("artifact.analysis_graph", path=str(path))
        return {
            "node_count": self._analysis_graph.node_count,
            "edge_count": self._analysis_graph.edge_count,
        }

    def _stage_signatures(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Match functions against a supplied signature DB or build one from scratch."""
        functions = self._engine_analysis.get("functions", []) or []
        if spec.signature_db:
            db_path = Path(spec.signature_db).expanduser().resolve()
            self._signature_db = SignatureDB.load_json(db_path)
            matches = self._signature_db.match_many(functions)
            self._signature_matches = matches
            self._signature_match_source = "external_db"
            matched = sum(1 for m in matches.values() if m.get("matched"))
            result = {"signature_db_loaded": str(db_path), "functions_matched": matched, "total": len(matches)}
        else:
            self._signature_db = SignatureDB()
            self._signature_db.build_from_export("target", self._engine_analysis)
            self._signature_matches = None
            self._signature_match_source = "target_self"
            result = {
                "signatures_built": len(self._signature_db.signatures),
                "source": "target_self",
                "artifact_mode": "compact",
            }
        path = self._artifact("signatures.json")
        save_data = (
            {"matches": matches}
            if spec.signature_db else
            {
                "signatures": [
                    {
                        "library": s.library,
                        "name": s.name,
                        "num_instructions": s.num_instructions,
                        "shingle_hash": s.shingle_hash,
                        "minhash": s.minhash,
                    }
                    for s in self._signature_db.signatures
                ],
                "omitted_fields": ["normalized_text", "shingles", "metadata"],
            }
        )
        self._save_json(path, save_data)
        artifacts["signatures"] = str(path)
        self._workspace.trace("artifact.signatures", path=str(path))
        return result

    def _stage_types(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Recover function signatures and aggregate structures."""
        if self._analysis_graph is None:
            raise RuntimeError("Analysis graph required for type recovery")
        self._type_recovery = TypeRecoveryAgent(self._analysis_graph)

        signatures = self._type_recovery.recover_signatures()
        structures = self._type_recovery.recover_structures()

        result = {
            "function_signatures": len(signatures),
            "structures": len(structures),
        }

        # Apply external type library if provided (best-effort enrichment of names).
        if spec.type_library:
            lib_path = Path(spec.type_library).expanduser().resolve()
            self._workspace.trace("type_library.load", path=str(lib_path))
            applied = self._apply_type_library(lib_path, signatures)
            result["type_library_applied"] = str(lib_path)
            result["type_library_renames"] = applied

        typed = {
            "signatures": {k: v.as_dict() for k, v in signatures.items()},
            "structures": [s.as_dict() for s in structures],
        }
        path = self._artifact("types.json")
        self._save_json(path, typed)
        artifacts["types"] = str(path)
        self._workspace.trace("artifact.types", path=str(path))
        return result

    def _apply_type_library(self, lib_path: Path, signatures: dict) -> int:
        """Apply an external type library to the recovered signatures.

        If the path is a JSON file with ``{"name": "signature", ...}`` entries,
        we use the keys as a hint map.  For raw IDA ``.til`` files we currently
        only record their presence because parsing them requires IDA itself.
        """
        if not lib_path.is_file():
            return 0
        applied = 0
        if lib_path.suffix.lower() == ".til":
            # Best-effort: record, but do not attempt to parse binary TIL here.
            self._workspace.trace("type_library.til", path=str(lib_path), note="not parsed")
            return 0
        try:
            data = json.loads(lib_path.read_text(encoding="utf-8"))
            hints = data if isinstance(data, dict) else {}
            for sig in signatures.values():
                if sig.name in hints:
                    sig.return_type = hints[sig.name]
                    applied += 1
        except Exception as exc:  # noqa: BLE001
            self._workspace.trace("type_library.error", error=str(exc))
            self._logger.warning("Could not apply type library %s: %s", lib_path, exc)
        return applied

    def _stage_xref(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Build the cross-reference reasoning graph."""
        if self._analysis_graph is None:
            raise RuntimeError("Analysis graph required for xref graph")
        library_marks = quick_library_mark(self._engine_analysis.get("functions", []) or [])
        if spec.signature_db and self._signature_matches is None:
            db_path = Path(spec.signature_db).expanduser().resolve()
            self._signature_db = SignatureDB.load_json(db_path)
            self._signature_matches = self._signature_db.match_many(
                self._engine_analysis.get("functions", []) or []
            )
            self._signature_match_source = "external_db"
        if self._signature_match_source == "external_db" and self._signature_matches:
            sig_matches = self._signature_matches
            for name, match in sig_matches.items():
                if match.get("matched"):
                    library_marks[name] = True
        self._xref_graph = XrefGraph(self._analysis_graph, library_marks=library_marks)
        path = self._artifact("xref_graph.json")
        self._xref_graph.save_json(path)
        artifacts["xref_graph"] = str(path)
        self._workspace.trace("artifact.xref_graph", path=str(path))
        return {"node_count": self._xref_graph.node_count, "edge_count": self._xref_graph.edge_count}

    def _stage_sinks(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Run the vulnerability sink hunter over the xref graph."""
        assert self._xref_graph is not None
        hunter = SinkHunter(self._xref_graph)
        result = hunter.run(max_depth=16)
        path = self._artifact("sinks.json")
        self._save_json(path, result)
        artifacts["sinks"] = str(path)
        self._workspace.trace("artifact.sinks", path=str(path))
        slice_path = self._artifact("security_slices.json")
        slice_report = write_security_slices(
            path=slice_path,
            xref_graph=self._xref_graph,
            sink_report=result,
            evidence_ledger=self._workspace.code_dir / "EVIDENCE_LEDGER.json",
            max_slices=100,
        )
        artifacts["security_slices"] = str(slice_path)
        self._workspace.trace(
            "artifact.security_slices",
            path=str(slice_path),
            candidate_slices=slice_report.get("summary", {}).get("candidate_slices"),
        )
        return {
            "total_sinks": result.get("total_sinks"),
            "reachable_sinks": result.get("reachable_sinks"),
            "high_risk_reachable": len(result.get("high_risk_reachable", [])),
            "security_slices": slice_report.get("summary", {}).get("candidate_slices"),
        }

    def _stage_cpp(self, spec: BatchJobSpec, artifacts: dict[str, str]) -> dict[str, Any]:
        """Recover C++ classes, vtables, constructors and destructors."""
        assert self._analysis_graph is not None
        agent = CppRecoveryAgent(self._analysis_graph)
        classes = agent.build_hierarchy()
        user_classes = [
            cls for cls in classes.values()
            if cls.role == "user_candidate"
        ]
        runtime_classes = [
            cls for cls in classes.values()
            if cls.role == "runtime_support"
        ]
        library_classes = [
            cls for cls in classes.values()
            if cls.role == "library_support"
        ]
        user_vtables = {
            address
            for cls in user_classes
            for address in cls.vtables
        }
        result = {
            "classes": len(classes),
            "user_classes": len(user_classes),
            "runtime_support_classes": len(runtime_classes),
            "library_support_classes": len(library_classes),
            "user_vtable_count": len(user_vtables),
            "vtable_count": len(agent.vtables),
        }
        path = self._artifact("cpp_recovery.json")
        self._save_json(path, {name: cls.as_dict() for name, cls in classes.items()})
        artifacts["cpp_recovery"] = str(path)
        self._workspace.trace("artifact.cpp_recovery", path=str(path))
        return result


# ---------------------------------------------------------------- convenience

def run_batch(
    binary: str,
    *,
    engine: str = "ghidra",
    state_dir: str | None = None,
    **kwargs: Any,
) -> BatchJobResult:
    """Fire-and-forget one batch job.

    Parameters
    ----------
    binary:
        Path to the target binary.
    engine:
        ``"ida"`` or ``"ghidra"`` (default ``"ghidra"``).
    state_dir:
        Root directory for workspaces.  Defaults to the configured Angerona state
        home.
    kwargs:
        Any other :class:`BatchJobSpec` field by name.

    Returns
    -------
    BatchJobResult:
        Structured result including workspace path and artifact layout.
    """
    if state_dir is None:
        state_dir = load_config().state_dir
    spec = BatchJobSpec(binary=binary, engine=engine, **kwargs)
    spine = BatchSpine(state_dir)
    return spine.run(spec)
