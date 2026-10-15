"""Cross-reference reasoning graph built on top of AnalysisGraph.

The IDA Pro Book positions xrefs as the connective tissue of a disassembly:
code xrefs (call/jump/ordinary flow) and data xrefs (read/write/offset) are the
edges over which an analyst — or an AI agent — walks. This module wraps the
canonical AnalysisGraph in NetworkX and adds the security-relevant query
operations that agents need:

  - call-chain reachability
  - path enumeration to sinks
  - function influence sets
  - forward/backward slicing via graph traversal
  - library-function filtering

It is designed to be serialized to disk as JSONL so it can be reloaded without
the original engine.
"""

from __future__ import annotations

import heapq
import json
import os
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable


def _default_parallel_workers(count: int) -> int:
    """Pick a bounded thread count for parallel traversal fan-out.

    Defaults to ``min(32, os.cpu_count() - 2, count)`` with a floor of 1, so a
    tiny workload never pays for an oversized pool.
    """
    cpus = os.cpu_count() or 4
    return max(1, min(32, cpus - 2, count))

from ..models.analysis_graph import AnalysisGraph

try:
    import networkx as nx  # type: ignore
except Exception as exc:  # noqa: BLE001
    nx = None  # type: ignore


class XrefGraph:
    """NetworkX-backed reasoning graph derived from an AnalysisGraph."""

    def __init__(self, analysis_graph: AnalysisGraph | None = None,
                 library_marks: dict[str, bool] | None = None) -> None:
        if nx is None:
            raise RuntimeError("networkx is required; install with 'pip install networkx'")
        self.g = nx.DiGraph()
        self.metadata: dict[str, Any] = dict(analysis_graph.metadata) if analysis_graph else {}
        self._library_marks: dict[str, bool] = library_marks or {}
        self._function_nodes_cache: list[str] | None = None
        self._import_nodes_cache: list[str] | None = None
        self._function_by_name_cache: dict[str, str] | None = None
        self._function_by_address_cache: dict[str, str] | None = None
        if analysis_graph:
            self._build_from_analysis_graph(analysis_graph)

    # ------------------------------------------------------- construction

    def _build_from_analysis_graph(self, ag: AnalysisGraph) -> None:
        for node in ag.nodes:
            self.g.add_node(node.id, **node.as_dict())
        for edge in ag.edges:
            self.g.add_edge(edge.src, edge.dst, kind=edge.kind, address=edge.address,
                            **edge.properties)
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        self._function_nodes_cache = []
        self._import_nodes_cache = []
        self._function_by_name_cache = {}
        self._function_by_address_cache = {}
        for node_id, data in self.g.nodes(data=True):
            kind = data.get("kind")
            if kind == "import":
                self._import_nodes_cache.append(node_id)
                continue
            if kind != "function":
                continue
            self._function_nodes_cache.append(node_id)
            name = data.get("name")
            if name:
                self._function_by_name_cache.setdefault(str(name), node_id)
            address = data.get("address")
            if address:
                self._function_by_address_cache.setdefault(
                    self._normalize_address(address),
                    node_id,
                )

    @property
    def node_count(self) -> int:
        return self.g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.g.number_of_edges()

    # ------------------------------------------------------- filter helpers

    def is_library(self, node_id: str) -> bool:
        if not node_id or node_id not in self.g:
            return False
        if node_id in self._library_marks:
            return bool(self._library_marks[node_id])
        name = self.g.nodes[node_id].get("name", "")
        if name in self._library_marks:
            return bool(self._library_marks[name])
        from .library_signatures import _is_likely_library_name
        return _is_likely_library_name(name)

    def function_nodes(self) -> list[str]:
        if self._function_nodes_cache is None:
            self._rebuild_indexes()
        return list(self._function_nodes_cache or [])

    def import_nodes(self) -> list[str]:
        if self._import_nodes_cache is None:
            self._rebuild_indexes()
        return list(self._import_nodes_cache or [])

    def node_name(self, node_id: str) -> str | None:
        if not node_id or node_id not in self.g:
            return None
        return self.g.nodes[node_id].get("name") or node_id

    def function_by_name(self, name: str) -> str | None:
        if self._function_by_name_cache is None:
            self._rebuild_indexes()
        return (self._function_by_name_cache or {}).get(name)

    def function_by_address(self, addr: str) -> str | None:
        if self._function_by_address_cache is None:
            self._rebuild_indexes()
        return (self._function_by_address_cache or {}).get(
            self._normalize_address(addr)
        )

    @staticmethod
    def _normalize_address(addr: Any) -> str:
        text = str(addr or "").strip().lower()
        if ":" in text:
            text = text.rsplit(":", 1)[1]
        try:
            return f"{int(text, 0):x}"
        except ValueError:
            return text.replace("0x", "")

    # ------------------------------------------------------- traversal primitives

    def callers(self, node_id: str) -> list[str]:
        """Return function nodes that call this node."""
        if not node_id or node_id not in self.g:
            return []
        preds = []
        for pred in self.g.predecessors(node_id):
            if (pred, node_id) in self.g.edges and self.g.edges[pred, node_id].get("kind") == "calls":
                preds.append(pred)
        return preds

    def callees(self, node_id: str) -> list[str]:
        """Return function nodes called by this node."""
        if not node_id or node_id not in self.g:
            return []
        succs = []
        for succ in self.g.successors(node_id):
            if (node_id, succ) in self.g.edges and self.g.edges[node_id, succ].get("kind") == "calls":
                succs.append(succ)
        return succs

    def all_callers(self, node_id: str, max_depth: int = 10,
                    ignore_library: bool = True) -> dict[str, int]:
        """Return every function that can reach node_id via call edges, with shortest depth."""
        result: dict[str, int] = {}
        queue = deque([(node_id, 0)])
        seen = {node_id: 0}
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for pred in self.g.predecessors(current):
                edge = self.g.edges[pred, current]
                if edge.get("kind") != "calls":
                    continue
                if ignore_library and self.is_library(pred):
                    continue
                if pred in seen and seen[pred] <= depth + 1:
                    continue
                seen[pred] = depth + 1
                result[pred] = depth + 1
                queue.append((pred, depth + 1))
        return result

    def all_reachable(self, node_id: str, max_depth: int = 10,
                      edge_kinds: tuple[str, ...] = ("calls",)) -> dict[str, int]:
        """Return every node reachable from node_id via selected edge kinds."""
        result: dict[str, int] = {}
        stack = [(node_id, 0)]
        seen = {node_id}
        while stack:
            current, depth = stack.pop()
            if depth >= max_depth:
                continue
            for succ in self.g.successors(current):
                edge = self.g.edges[current, succ]
                if edge.get("kind") not in edge_kinds:
                    continue
                if succ in seen:
                    continue
                seen.add(succ)
                result[succ] = depth + 1
                stack.append((succ, depth + 1))
        return result

    def parallel_all_callers(self, node_ids: list[str], *,
                             max_workers: int = 0) -> dict[str, set[str]]:
        """Fans out :meth:`all_callers` over ``node_ids`` in a thread pool.

        Each submission performs the standard transitive backward BFS; NetworkX
        reads are safe under the GIL and the graph is not mutated during
        traversal.  Returns a mapping ``node_id -> set of transitive callers``.
        With ``max_workers=1`` the work degrades to a plain sequential loop
        (no thread pool is created), which keeps single-item callers cheap.
        """
        ids = [n for n in node_ids if n]
        if not ids:
            return {}
        workers = max_workers if max_workers > 0 else _default_parallel_workers(len(ids))
        if workers <= 1 or len(ids) == 1:
            return {n: set(self.all_callers(n)) for n in ids}
        result: dict[str, set[str]] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {n: pool.submit(self.all_callers, n) for n in ids}
            for n, fut in futures.items():
                result[n] = set(fut.result())
        return result

    def parallel_all_reachable(self, node_ids: list[str], *,
                               max_workers: int = 0) -> dict[str, set[str]]:
        """Fans out :meth:`all_reachable` over ``node_ids`` in a thread pool.

        Mirrors :meth:`parallel_all_callers` for the forward reachability BFS.
        Returns ``node_id -> set of reachable nodes``.
        """
        ids = [n for n in node_ids if n]
        if not ids:
            return {}
        workers = max_workers if max_workers > 0 else _default_parallel_workers(len(ids))
        if workers <= 1 or len(ids) == 1:
            return {n: set(self.all_reachable(n)) for n in ids}
        result: dict[str, set[str]] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {n: pool.submit(self.all_reachable, n) for n in ids}
            for n, fut in futures.items():
                result[n] = set(fut.result())
        return result

    def paths_to(self, source: str, target: str, max_depth: int = 12,
                 edge_kinds: tuple[str, ...] = ("calls",),
                 max_paths: int = 100) -> list[list[str]]:
        """Enumerate simple paths from source to target limited by depth and count.

        ``max_paths`` bounds the accumulated result so a dense call graph cannot
        exhaust memory enumerating combinatorially many simple paths.
        """
        paths: list[list[str]] = []

        def dfs(current: str, goal: str, depth: int, path: list[str]) -> None:
            if len(paths) >= max_paths:
                return
            if current == goal:
                paths.append(path[:])
                return
            if depth >= max_depth:
                return
            for succ in self.g.successors(current):
                edge = self.g.edges[current, succ]
                if edge.get("kind") not in edge_kinds:
                    continue
                if succ in path:
                    continue
                path.append(succ)
                dfs(succ, goal, depth + 1, path)
                path.pop()
                if len(paths) >= max_paths:
                    return

        dfs(source, target, 0, [source])
        return paths

    def shortest_path(self, source: str, target: str, *, max_depth: int = 12,
                      edge_kinds: tuple[str, ...] = ("calls",)) -> list[str] | None:
        """BFS shortest path using only selected edge kinds, bounded by max_depth."""
        if source not in self.g or target not in self.g:
            return None

        pred: dict[str, str | None] = {source: None}
        depth: dict[str, int] = {source: 0}
        queue = deque([source])
        while queue:
            u = queue.popleft()
            if u == target:
                break
            if depth[u] >= max_depth:
                continue
            for v in self.g.successors(u):
                if self.g.edges[u, v].get("kind") not in edge_kinds:
                    continue
                if v in pred:
                    continue
                pred[v] = u
                depth[v] = depth[u] + 1
                queue.append(v)
        if target not in pred:
            return None
        path = [target]
        while path[-1] != source:
            path.append(pred[path[-1]])  # type: ignore[arg-type]
        return list(reversed(path))

    def shortest_paths_from(
        self,
        source: str,
        targets: set[str],
        *,
        max_depth: int = 12,
        edge_kinds: tuple[str, ...] = ("calls",),
    ) -> dict[str, list[str]]:
        """Return shortest paths from one source to any target in one BFS."""
        if source not in self.g or not targets:
            return {}
        remaining = set(targets)
        found: dict[str, list[str]] = {}
        pred: dict[str, str | None] = {source: None}
        depth: dict[str, int] = {source: 0}
        queue = deque([source])
        while queue and remaining:
            u = queue.popleft()
            if u in remaining:
                path = [u]
                while path[-1] != source:
                    path.append(pred[path[-1]])  # type: ignore[arg-type]
                found[u] = list(reversed(path))
                remaining.remove(u)
                # Keep expanding: a target may sit on the only path to another
                # target, so recording it must not cut off its successors.
            if depth[u] >= max_depth:
                continue
            for v in self.g.successors(u):
                if self.g.edges[u, v].get("kind") not in edge_kinds:
                    continue
                if v in pred:
                    continue
                pred[v] = u
                depth[v] = depth[u] + 1
                queue.append(v)
        return found

    def _semantic_transparency(self, node_id: str) -> tuple[bool, str | None]:
        """Return whether an intermediate node is a proven boundary artifact."""
        if node_id not in self.g:
            return False, None
        node = self.g.nodes[node_id]
        if node.get("kind") != "function":
            return False, None
        properties = dict(node.get("properties") or {})
        if properties.get("is_thunk"):
            return True, "engine_thunk"
        if properties.get("is_exception_handler"):
            return True, "exception_handler_fragment"
        if (
            properties.get("synthetic")
            and properties.get("inferred_from") == "orphan_code_xref"
        ):
            return True, "orphan_callsite_boundary"

        from .library_signatures import classify_user_fragment

        function_record = {
            **properties,
            "name": node.get("name"),
            "entry": node.get("address"),
        }
        is_fragment, reason = classify_user_fragment(function_record)
        return (True, reason) if is_fragment else (False, None)

    def semantic_shortest_path(
        self,
        source: str,
        target: str,
        *,
        max_depth: int = 12,
        edge_kinds: tuple[str, ...] = ("calls",),
    ) -> dict[str, Any] | None:
        """Find the shortest logical path while retaining its raw node chain.

        Proven engine thunks, synthetic callsite boundaries, and compiler-split
        user fragments cost zero as intermediate nodes. Endpoints always remain
        visible and cost one hop, so a sink boundary cannot become zero-hop.
        """
        if source not in self.g or target not in self.g:
            return None
        queue: list[tuple[int, int, str, tuple[str, ...]]] = [
            (0, 0, source, (source,))
        ]
        best: dict[tuple[str, int], int] = {(source, 0): 0}
        while queue:
            semantic_distance, raw_depth, current, path = heapq.heappop(queue)
            if semantic_distance != best.get((current, raw_depth)):
                continue
            if current == target:
                collapsed = []
                semantic_path = [path[0]]
                for node_id in path[1:-1]:
                    transparent, reason = self._semantic_transparency(node_id)
                    if transparent:
                        collapsed.append({
                            "node_id": node_id,
                            "name": self.node_name(node_id),
                            "reason": reason,
                        })
                    else:
                        semantic_path.append(node_id)
                if len(path) > 1:
                    semantic_path.append(path[-1])
                return {
                    "distance": semantic_distance,
                    "path": semantic_path,
                    "raw_path": list(path),
                    "collapsed_nodes": collapsed,
                }
            if raw_depth >= max_depth:
                continue
            for successor in self.g.successors(current):
                if self.g.edges[current, successor].get("kind") not in edge_kinds:
                    continue
                if successor in path:
                    continue
                transparent, _ = self._semantic_transparency(successor)
                step_cost = 0 if successor != target and transparent else 1
                next_distance = semantic_distance + step_cost
                next_depth = raw_depth + 1
                state = (successor, next_depth)
                if next_distance >= best.get(state, next_distance + 1):
                    continue
                best[state] = next_distance
                heapq.heappush(
                    queue,
                    (
                        next_distance,
                        next_depth,
                        successor,
                        (*path, successor),
                    ),
                )
        return None

    # ------------------------------------------------------- security queries

    def find_reachable_sinks(self, sources: list[str], sinks: list[str],
                             max_depth: int = 12) -> list[dict]:
        """Compute reachability from any source to any sink via calls."""
        results = []
        sink_set = set(sinks)
        for src in sources:
            if src not in self.g:
                continue
            visited: dict[str, int] = {src: 0}
            queue = deque([src])
            while queue:
                u = queue.popleft()
                if visited[u] >= max_depth:
                    continue
                for v in self.g.successors(u):
                    edge = self.g.edges[u, v]
                    if edge.get("kind") != "calls":
                        continue
                    if v in visited:
                        continue
                    visited[v] = visited[u] + 1
                    queue.append(v)
            for s in sink_set & set(visited.keys()):
                path = self.shortest_path(src, s, max_depth=max_depth)
                results.append({
                    "source": src,
                    "source_name": self.node_name(src),
                    "sink": s,
                    "sink_name": self.node_name(s),
                    "depth": visited[s],
                    "shortest_path": path,
                })
        return results

    def exports_reachable_from(self, node_id: str, max_depth: int = 10) -> list[str]:
        """Return exports reachable from this node (helps assess outward API surface)."""
        reachable = self.all_reachable(node_id, max_depth=max_depth, edge_kinds=("calls", "jump"))
        return [n for n in reachable if self.g.nodes[n].get("kind") == "export"]

    # ------------------------------------------------------- data-flow stubs

    def reads_of(self, node_id: str) -> list[str]:
        """Return nodes with data_read edges *to* this node (reads of this data)."""
        return [p for p in self.g.predecessors(node_id)
                if self.g.edges[p, node_id].get("kind") == "data_read"]

    def writes_to(self, node_id: str) -> list[str]:
        """Predecessors with data_write edges — writers of this data."""
        return [p for p in self.g.predecessors(node_id)
                if self.g.edges[p, node_id].get("kind") == "data_write"]

    # ------------------------------------------------------- filtering

    def remove_library_nodes(self, preserve_names: list[str] | None = None) -> "XrefGraph":
        """Return a new XrefGraph with library-marked functions removed."""
        preserve = set(preserve_names or [])
        keep = [n for n in self.g.nodes()
                if not (self.is_library(n) and n not in preserve)]
        new = XrefGraph()
        new.g = self.g.subgraph(keep).copy()
        new.metadata = dict(self.metadata)
        new._library_marks = dict(self._library_marks)
        new._rebuild_indexes()
        return new

    # ------------------------------------------------------- persistence

    def save_json(self, path: str | Path) -> None:
        """Serialize nodes and edges as JSON."""
        data = {
            "metadata": self.metadata,
            "nodes": [dict(d, id=n) for n, d in self.g.nodes(data=True)],
            "edges": [dict(d, src=u, dst=v) for u, v, d in self.g.edges(data=True)],
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    @classmethod
    def load_json(cls, path: str | Path) -> "XrefGraph":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        g = nx.DiGraph()
        for n in data.get("nodes", []):
            nid = n.pop("id")
            g.add_node(nid, **n)
        for e in data.get("edges", []):
            src = e.pop("src")
            dst = e.pop("dst")
            g.add_edge(src, dst, **e)
        obj = cls()
        obj.g = g
        obj.metadata = data.get("metadata", {})
        obj._rebuild_indexes()
        return obj

    def summary(self) -> dict[str, Any]:
        fn_count = len(self.function_nodes())
        imp_count = len(self.import_nodes())
        lib_count = sum(1 for f in self.function_nodes() if self.is_library(f))
        return {
            "nodes": self.node_count,
            "edges": self.edge_count,
            "functions": fn_count,
            "imports": imp_count,
            "library_functions": lib_count,
            "metadata": self.metadata,
        }
