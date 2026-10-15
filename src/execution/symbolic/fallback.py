"""Static-only fallback for symbolic probing when angr/z3 is absent.

The fallback is deterministic and never requires angr. It uses the
``AnalysisGraph`` to produce a conservative, evidence-poor result so the
rest of the pipeline can still test appliers, CLI output, and summary
integration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.execution.symbolic.models import (
    MemoryWriteObservation,
    PathConstraint,
    SymbolicProbeRequest,
    SymbolicProbeResult,
)

if TYPE_CHECKING:
    from src.models.analysis_graph import AnalysisGraph


def static_probe_fallback(
    graph: AnalysisGraph,
    request: SymbolicProbeRequest,
) -> SymbolicProbeResult:
    """Return a deterministic no-engine result based on static CFG shape.

    For each block that appears to belong to the target function, emit one
    fall-through path with an empty predicate set.  The result is intentionally
    conservative: ``reachable`` is True but ``predicate_text`` is empty so
    downstream consumers know no real constraints were recovered.
    """

    fn_address = request.function_address
    fn_name = request.function_name
    block_traces: list[list[int]] = []

    for node in graph.nodes:
        if node.kind != "function":
            continue
        if fn_address is not None and node.address:
            try:
                if int(node.address, 0) == fn_address:
                    block_traces = _blocks_for_function(graph, node.id)
                    break
            except Exception:
                pass
        if node.name and fn_name and node.name == fn_name:
            block_traces = _blocks_for_function(graph, node.id)
            break

    paths = [
        PathConstraint(
            path_id=idx,
            reachable=True,
            predicate_text=["static fall-through (no angr/z3 installed)"],
            block_trace=trace,
            hit_target=bool(request.target_addresses and any(a in request.target_addresses for a in trace)),
        )
        for idx, trace in enumerate(block_traces or [[0x0]])
    ]

    return SymbolicProbeResult(
        backend="symbolic",
        status="success",
        paths=paths,
        notes=["angr/z3 not installed; using static CFG fallback"],
        detail={"fallback": True, "function_name": fn_name},
    )


def _blocks_for_function(graph: AnalysisGraph, fn_id: str) -> list[list[int]]:
    """Collect direct child block addresses for a function node."""
    blocks: list[int] = []
    for edge in graph.edges:
        if edge.kind == "contains" and edge.src == fn_id:
            block = graph.get_node(edge.dst)
            if block is not None and block.address:
                try:
                    blocks.append(int(block.address, 0))
                except Exception:
                    pass
    if blocks:
        # Each block is its own single-block "path" in the fallback.
        return [[addr] for addr in sorted(blocks)]
    return [[0x0]]
