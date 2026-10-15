"""Tests for CFG build caching and parallel xref traversals.

Covers:
* cache hit produces identical CFG to a cold build,
* graph mutation invalidates the cached entry,
* ``ANGERONA_CFG_CACHE=0`` cleanly falls back to uncached builds,
* ``parallel_all_callers``/``parallel_all_reachable`` match sequential results
  on 50+ nodes,
* ``max_workers=1`` degrades to sequential (no thread pool).
"""

from __future__ import annotations

import concurrent.futures

import pytest

from src.analysis.cfg_cache import CFGCache, CachedCFGSpine
from src.analysis.cfg_spine import CFGSpine, FunctionCFG
from src.analysis.xref_graph import XrefGraph
from src.models.analysis_graph import AnalysisGraph, Edge, Node


# --------------------------------------------------------------------------- helpers


def _function_node(addr: int, name: str, size: int = 0x40) -> Node:
    return Node(
        id=f"function:0x{addr:x}",
        kind="function",
        address=f"0x{addr:x}",
        name=name,
        properties={"size": size},
    )


def _instruction_node(addr: int, mnemonic: str, operands: str = "") -> Node:
    return Node(
        id=f"instruction:0x{addr:x}",
        kind="instruction",
        address=f"0x{addr:x}",
        properties={
            "mnemonic": mnemonic,
            "operands": operands,
            "address": f"0x{addr:x}",
            "bytes": b"\x90".hex(),
            "size": 1,
        },
    )


def _graph_with_function(instrs: list[tuple[int, str, str]] | None = None) -> tuple[AnalysisGraph, Node]:
    """Build a graph with one function owning a small instruction sequence."""
    graph = AnalysisGraph()
    fn = _function_node(0x401000, "target_fn")
    graph.add_node(fn)
    for addr, mnemonic, operands in (
        instrs
        if instrs is not None
        else [
            (0x401000, "push", "rbp"),
            (0x401001, "mov", "rbp, rsp"),
            (0x401004, "cmp", "eax, 0x10"),
            (0x401008, "je", "0x401010"),
            (0x40100A, "xor", "eax, eax"),
            (0x40100C, "jmp", "0x401012"),
            (0x401010, "mov", "eax, 1"),
            (0x401012, "pop", "rbp"),
            (0x401013, "ret", ""),
        ]
    ):
        node = _instruction_node(addr, mnemonic, operands)
        graph.add_node(node)
        graph.add_edge(Edge(src=fn.id, dst=node.id, kind="contains"))
    return graph, fn


def _cfg_fingerprint(cfg: FunctionCFG) -> dict:
    """Structural fingerprint of a CFG for behavioural comparison."""
    return cfg.as_dict()


def _chain_xref_graph(count: int) -> XrefGraph:
    """Build a chain of ``count`` functions f0 -> f1 -> ... via calls edges."""
    ag = AnalysisGraph()
    ids = []
    for i in range(count):
        node = _function_node(0x500000 + i * 0x10, f"f{i}")
        ag.add_node(node)
        ids.append(node.id)
    for i in range(count - 1):
        ag.add_edge(Edge(src=ids[i], dst=ids[i + 1], kind="calls"))
    return XrefGraph(ag), ids


# --------------------------------------------------------------------------- TASK A: cache


@pytest.fixture(autouse=True)
def _reset_class_cache():
    """Isolate the class-level default cache between tests."""
    CFGSpine._default_cache = None
    yield
    CFGSpine._default_cache = None


def test_cache_hit_identical_to_cold_build():
    graph, fn = _graph_with_function()

    cold = CFGSpine(graph).build_function_cfg(fn)

    spine = CachedCFGSpine(graph, cache=CFGCache())
    first = spine.build_function_cfg(fn)   # miss -> populates cache
    second = spine.build_function_cfg(fn)  # hit

    assert spine.cache.hits == 1
    assert spine.cache.misses == 1
    assert first is second
    assert _cfg_fingerprint(second) == _cfg_fingerprint(cold)


def test_graph_mutation_invalidates_cached_entry():
    graph, fn = _graph_with_function()
    spine = CachedCFGSpine(graph, cache=CFGCache())
    first = spine.build_function_cfg(fn)
    assert first.exits

    # Mutate: append an extra instruction node -> digest changes.
    extra = _instruction_node(0x401020, "ret", "")
    graph.add_node(extra)
    graph.add_edge(Edge(src=fn.id, dst=extra.id, kind="contains"))

    second = spine.build_function_cfg(fn)
    assert spine.cache.hits == 0
    assert spine.cache.misses == 2
    assert _cfg_fingerprint(second) != _cfg_fingerprint(first)


def test_property_mutation_invalidates_cached_entry():
    graph, fn = _graph_with_function()
    spine = CachedCFGSpine(graph, cache=CFGCache())
    first = spine.build_function_cfg(fn)

    # Mutate an instruction's properties without touching the edge set.
    instr = next(n for n in graph.nodes if n.kind == "instruction")
    instr.properties["mnemonic"] = "jmp"
    instr.properties["operands"] = "0x401013"

    second = spine.build_function_cfg(fn)
    assert spine.cache.misses == 2
    assert spine.cache.hits == 0
    assert _cfg_fingerprint(second) != _cfg_fingerprint(first)


def test_build_all_uses_cache_by_default():
    graph, _fn = _graph_with_function()
    spine = CFGSpine(graph)

    first = spine.build_all()
    cache = CFGSpine.default_cache()
    assert cache is not None
    assert len(cache) == 1

    second = spine.build_all()
    assert set(second) == set(first)
    assert {a: _cfg_fingerprint(c) for a, c in second.items()} == {
        a: _cfg_fingerprint(c) for a, c in first.items()
    }
    assert cache.hits >= 1


def test_env_var_disables_cache(monkeypatch):
    monkeypatch.setenv("ANGERONA_CFG_CACHE", "0")
    CFGSpine._default_cache = None

    graph, _fn = _graph_with_function()
    spine = CFGSpine(graph)
    result = spine.build_all()

    assert CFGSpine.default_cache() is None
    assert CFGSpine._default_cache is None
    assert result  # clean fallback: normal build still returned


def test_env_var_enabled_builds_identical_result(monkeypatch):
    graph, fn = _graph_with_function()
    reference = {a: _cfg_fingerprint(c) for a, c in CFGSpine(graph).build_all().items()}

    monkeypatch.setenv("ANGERONA_CFG_CACHE", "1")
    CFGSpine._default_cache = None
    cached_first = {a: _cfg_fingerprint(c) for a, c in CFGSpine(graph).build_all().items()}
    cached_second = {a: _cfg_fingerprint(c) for a, c in CFGSpine(graph).build_all().items()}
    assert cached_first == reference
    assert cached_second == reference


def test_cache_lru_eviction_bounds_size():
    cache = CFGCache(maxsize=4)
    graph = AnalysisGraph()
    spine = CachedCFGSpine(graph, cache=cache)
    for i in range(10):
        fn = _function_node(0x600000 + i * 0x20, f"fn{i}")
        graph.add_node(fn)
        spine.build_function_cfg(fn)
    assert len(cache) == 4


# --------------------------------------------------------------------------- TASK B: parallel BFS


def test_parallel_all_callers_matches_sequential():
    graph, ids = _chain_xref_graph(60)
    expected = {n: set(graph.all_callers(n)) for n in ids}
    result = graph.parallel_all_callers(ids)
    assert result == expected
    # Spot-check: all_callers defaults to max_depth=10, so node f10 is
    # transitively called by exactly f0..f9 (f0 lies at depth 10).
    tail = ids[10]
    assert result[tail] == set(ids[0:10])


def test_parallel_all_reachable_matches_sequential():
    graph, ids = _chain_xref_graph(60)
    expected = {n: set(graph.all_reachable(n)) for n in ids}
    result = graph.parallel_all_reachable(ids)
    assert result == expected
    # all_reachable defaults to max_depth=10; from f0 that is f1..f10.
    assert result[ids[0]] == set(ids[1:11])


def test_parallel_workers_explicit_and_empty_input():
    graph, ids = _chain_xref_graph(5)
    assert graph.parallel_all_callers([], max_workers=4) == {}
    assert graph.parallel_all_reachable([], max_workers=4) == {}
    explicit = graph.parallel_all_callers(ids, max_workers=3)
    expected = {n: set(graph.all_callers(n)) for n in ids}
    assert explicit == expected


def test_max_workers_one_degrades_to_sequential(monkeypatch):
    graph, ids = _chain_xref_graph(6)

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("ThreadPoolExecutor must not be created for workers=1")

    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", _boom)
    import src.analysis.xref_graph as xref_mod

    monkeypatch.setattr(xref_mod, "ThreadPoolExecutor", _boom)
    result = graph.parallel_all_callers(ids, max_workers=1)
    expected = {n: set(graph.all_callers(n)) for n in ids}
    assert result == expected
    result_r = graph.parallel_all_reachable(ids, max_workers=1)
    expected_r = {n: set(graph.all_reachable(n)) for n in ids}
    assert result_r == expected_r


def test_parallel_traversals_thread_safe_under_contention():
    """Hammer the graph from many threads; results must stay deterministic."""
    graph, ids = _chain_xref_graph(64)
    baseline = {n: set(graph.all_callers(n)) for n in ids}
    for _ in range(3):
        assert graph.parallel_all_callers(ids) == baseline
        assert graph.parallel_all_reachable(ids) == {
            n: set(graph.all_reachable(n)) for n in ids
        }
