"""Static + dynamic enrichment loop.

Interleaves static analysis with controlled execution: select an emulation backend,
request a function-level probe (Appcall-like), capture a memory snapshot, feed the
discovered bytes and types back into the static model, and rerun analysis.

Based on the runtime-to-static enrichment loop described in *The IDA Pro Book*
(Appcall + TakeMemorySnapshot).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.execution.backend_selector import BackendSelector, EmulatorProbeRequest
from src.execution.models import EnrichmentResult, MemorySnapshot
from src.execution.probe_runner import ProbeRunner
from src.execution.snapshot_applier import SnapshotApplier
from src.models.analysis_graph import AnalysisGraph, Node

# Convenience re-exports so older imports keep working.
__all__ = ["EnrichmentLoop", "MemorySnapshot"]


@dataclass
class _LoopState:
    status: str = "success"
    last_snapshot: MemorySnapshot | None = None
    last_note: str = ""


class EnrichmentLoop:
    """Orchestrator for runtime-to-static enrichment."""

    VALID_STATUSES = {"success", "inconclusive", "no_backend", "probe_not_implemented", "error"}

    def __init__(
        self,
        selector_or_none: Any | None = None,
        runner_or_none: Any | None = None,
    ) -> None:
        self.selector = selector_or_none
        self.runner = runner_or_none
        self._iterations: int = 0
        self._last_target_id: str | None = None

    def enrich(
        self,
        graph: AnalysisGraph,
        target_fn_id: str,
        *,
        probe_input: dict[str, Any] | None = None,
        max_iterations: int = 1,
    ) -> EnrichmentResult:
        """Run at most ``max_iterations`` static/dynamic enrichment cycles."""
        probe_input = dict(probe_input or {})
        max_iterations = max(1, int(max_iterations))

        self._last_target_id = target_fn_id
        fn_node = self._find_function(graph, target_fn_id)
        if fn_node is None:
            return EnrichmentResult(
                status="error", snapshot=None,
                note=f"target function not found: {target_fn_id}",
            )

        probe_input.setdefault("entry_address", fn_node.address)

        binary_path = self._binary_path(graph, fn_node)
        if not binary_path or binary_path == "unknown":
            return EnrichmentResult(
                status="error", snapshot=None,
                note="binary path not found in graph metadata or function properties",
            )

        function_name = fn_node.name or fn_node.address or target_fn_id
        aggregated_changes: list[dict[str, Any]] = []
        aggregated_discovered_types: list[dict[str, Any]] = []
        last_snapshot: MemorySnapshot | None = None
        last_status = "success"
        last_note = ""
        last_detail: dict[str, Any] = {}

        for iteration in range(1, max_iterations + 1):
            self._iterations += 1
            result = self._enrich_one(graph, function_name, binary_path, probe_input, iteration)
            if result.snapshot:
                last_snapshot = result.snapshot
            aggregated_changes.extend(result.changes)
            aggregated_discovered_types.extend(result.discovered_types)
            last_status = result.status
            last_note = result.note or ""
            if result.detail:
                last_detail = dict(result.detail)
            if result.status != "success":
                break

        return EnrichmentResult(
            status=last_status,
            snapshot=last_snapshot,
            discovered_types=aggregated_discovered_types,
            changes=aggregated_changes,
            note=last_note,
            detail=last_detail,
        )

    def _enrich_one(
        self,
        graph: AnalysisGraph,
        function_name: str,
        binary_path: str,
        probe_input: dict[str, Any],
        iteration: int,
    ) -> EnrichmentResult:
        """Run a single enrichment cycle."""
        requested_backend = probe_input.get("backend")
        selector = self._resolve_selector()
        if selector is None and not requested_backend:
            return EnrichmentResult(
                status="no_backend", snapshot=None,
                note="no backend selector provided and no explicit backend requested",
            )

        if not requested_backend:
            try:
                selected = selector.select(binary_path)
            except Exception as exc:
                return EnrichmentResult(
                    status="error", snapshot=None,
                    note=f"backend selection failed: {exc}",
                )

            if selected is None or getattr(selected, "name", "none") == "none":
                return EnrichmentResult(
                    status="no_backend", snapshot=None,
                    note=f"no backend available for {binary_path}",
                )
            expected_backend = selected.name
        else:
            expected_backend = requested_backend

        ranges = list(probe_input.get("capture_memory_ranges", []))
        probe = EmulatorProbeRequest(
            function_name=function_name,
            args=list(probe_input.get("args", [])),
            capture_memory_ranges=ranges,
            expected_backend=expected_backend,
            entry_address=self._parse_address(probe_input.get("entry_address")),
            isa=probe_input.get("isa"),
            max_instructions=int(probe_input.get("max_instructions", 2_000)),
            max_trace_events=int(probe_input.get("max_trace_events", 16_384)),
        )

        # Legacy support: a selector may expose its own run() method.
        legacy_runner = getattr(selector, "run", None)
        if legacy_runner is not None and callable(legacy_runner):
            try:
                legacy_result = legacy_runner(probe)
                if isinstance(legacy_result, MemorySnapshot):
                    applier = SnapshotApplier(graph)
                    changes = applier.apply(legacy_result, target_fn_id=self._last_target_id)
                    return EnrichmentResult(
                        status="success",
                        snapshot=legacy_result,
                        changes=changes,
                        note=f"iteration {iteration} completed via legacy selector.run()",
                    )
            except Exception as exc:
                return EnrichmentResult(
                    status="error", snapshot=None,
                    note=f"legacy selector.run() failed: {exc}",
                )

        runner = self.runner if self.runner is not None else ProbeRunner(self._ensure_selector())
        # If the user explicitly requested a backend, honor it; otherwise try a
        # fallback chain.
        if requested_backend:
            backend_chain = [requested_backend]
        else:
            backend_chain = [probe.expected_backend, "native", "unicorn", "symbolic"]
        seen: set[str] = set()
        runner_result = None
        for backend_name in backend_chain:
            if not backend_name or backend_name in seen:
                continue
            seen.add(backend_name)
            runner_result = runner.run(probe, binary_path=binary_path, backend_name=backend_name)
            if runner_result.status == "success":
                break
            if runner_result.status == "missing_symbol" and not requested_backend:
                # A missing symbol is a strong signal; don't keep trying other
                # auto-selected backends unless the user explicitly asked for one.
                break

        if runner_result is None:
            return EnrichmentResult(
                status="error", snapshot=None,
                note="no backend returned a result",
            )
        if runner_result.status == "unavailable":
            return EnrichmentResult(
                status="probe_not_implemented", snapshot=None,
                note=f"backend {probe.expected_backend} unavailable: {runner_result.note}",
            )
        if runner_result.status not in {"success", "inconclusive"}:
            return EnrichmentResult(
                status="error", snapshot=None,
                note=f"probe execution failed: {runner_result.note}",
            )
        if not runner_result.snapshots and runner_result.memory_image is None:
            return EnrichmentResult(
                status="success", snapshot=None,
                changes=[],
                note=runner_result.note or "execution completed without a memory snapshot",
                detail=runner_result.detail,
            )

        applier = SnapshotApplier(graph)
        changes: list[dict[str, Any]] = []
        for snapshot in runner_result.snapshots:
            changes.extend(applier.apply(snapshot, target_fn_id=self._last_target_id))
        if runner_result.memory_image is not None:
            changes.extend(applier.apply_image(
                runner_result.memory_image,
                target_fn_id=self._last_target_id,
            ))
        discovered_types: list[dict[str, Any]] = []

        note = runner_result.note or (
            f"iteration {iteration} completed with {len(changes)} change(s) "
            f"using backend {probe.expected_backend}"
        )
        return EnrichmentResult(
            status=runner_result.status,
            snapshot=runner_result.snapshot,
            discovered_types=discovered_types,
            changes=changes,
            note=note,
            detail=runner_result.detail,
        )

    @staticmethod
    def _parse_address(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return None

    def _resolve_selector(self) -> BackendSelector | None:
        if self.selector is None or self.selector is False:
            return None
        if not callable(getattr(self.selector, "select", None)):
            return None
        return self.selector

    def _ensure_selector(self) -> BackendSelector:
        if self.selector is None:
            return BackendSelector()
        return self.selector

    @staticmethod
    def _find_function(graph: AnalysisGraph, target_fn_id: str) -> Node | None:
        node = graph.get_node(target_fn_id)
        if node is not None and node.kind == "function":
            return node
        for n in graph.nodes:
            if n.kind != "function":
                continue
            if n.id == target_fn_id or n.name == target_fn_id or n.address == target_fn_id:
                return n
        return None

    @staticmethod
    def _binary_path(graph: AnalysisGraph, fn_node: Node) -> str | None:
        return (
            fn_node.properties.get("binary")
            or graph.metadata.get("executable_path")
            or graph.metadata.get("binary_path")
            or graph.metadata.get("filename")
        )

    def summarize(self) -> str:
        return f"EnrichmentLoop(selector={self.selector is not None}, iterations={self._iterations})"
