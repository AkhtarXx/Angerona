"""Differential / patch analysis for two AnalysisGraph instances.

This module compares two engine-agnostic analysis graphs (e.g. patched vs
unpatched binary) and produces a function-level ``DiffFunction`` report
inspired by the patch-diffing workflow described in The IDA Pro Book.

Status taxonomy:
  * identical  - hash-identical text (matched, no changes).
  * similar    - name/address match with high textual similarity
                 (above simhash_threshold) but not byte-identical.
  * modified   - matched by name/address/hash but similarity below threshold.
  * unique_a   - present only in graph_a.
  * unique_b   - present only in graph_b.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Callable

from ..models.analysis_graph import AnalysisGraph, Node


def _addr_val(address: str | None) -> int:
    """Parse a (hex) address string to an int, returning 0 when unparsable.

    Function addresses are normally hex, but ``_norm_addr`` returns non-hex
    labels (e.g. ``"main"``) verbatim; guarding here keeps those nodes from
    aborting an entire diff sort.
    """
    try:
        return int(address or "0", 16)
    except Exception:
        return 0


@dataclass
class DiffFunction:
    """A single function comparison result."""

    name: str
    address_a: str | None
    address_b: str | None
    status: str  # identical / similar / modified / unique_a / unique_b
    similarity_score: float
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address_a": self.address_a,
            "address_b": self.address_b,
            "status": self.status,
            "similarity_score": self.similarity_score,
            "notes": list(self.notes),
        }

class GraphDiffer:
    """Compare two :class:`AnalysisGraph` instances."""

    # Textual fields extracted from a function node, in preference order.
    _TEXT_FIELDS = ("decompiled", "pseudocode", "disassembly", "assembly", "bytes")

    def __init__(self, graph_a: AnalysisGraph, graph_b: AnalysisGraph) -> None:
        self.graph_a = graph_a
        self.graph_b = graph_b
        self._fns_a = self._function_nodes(graph_a)
        self._fns_b = self._function_nodes(graph_b)

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _function_nodes(graph: AnalysisGraph) -> list[Node]:
        """Return all nodes of kind ``function`` sorted by address."""
        fns = [n for n in graph.nodes if n.kind == "function"]
        fns.sort(key=lambda n: _addr_val(n.address))
        return fns

    @staticmethod
    def _node_addr(node: Node | None) -> str | None:
        """Return a normalized hex address string for a node, if available."""
        if node is None or not node.address:
            return None
        try:
            return f"0x{int(node.address, 16):x}"
        except Exception:
            return node.address

    def _function_text(self, fn_node: Node) -> str:
        """Extract comparable textual representation from a function node."""
        props = fn_node.properties or {}
        for key in self._TEXT_FIELDS:
            val = props.get(key)
            if val:
                return str(val)
        # Fallback: name + address + callees signature.
        parts = [fn_node.name or "", fn_node.address or ""]
        callees = props.get("callees") or props.get("calls") or []
        if isinstance(callees, (list, tuple, set)):
            parts.extend(sorted(str(c) for c in callees))
        return "\n".join(parts)

    def _function_hash(self, fn_node: Node) -> str:
        """Simple hash of decompiled/disassembly text, falling back to properties."""
        text = self._function_text(fn_node).strip()
        if text:
            return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        # Empty text fall-back: hash a stable description of the node.
        payload = f"{fn_node.id}|{fn_node.name or ''}|{fn_node.address or ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _similarity(fa: Node, fb: Node, text_extractor: Callable[[Node], str]) -> float:
        """Return SequenceMatcher-based string similarity for two function nodes."""
        ta = text_extractor(fa).strip()
        tb = text_extractor(fb).strip()
        if not ta and not tb:
            return 1.0
        if not ta or not tb:
            return 0.0
        return SequenceMatcher(None, ta, tb).ratio()

    # --------------------------------------------------------------- matching

    def _match_functions(self) -> tuple[dict[str, Node], dict[str, Node], dict[str, Node], dict[str, Node]]:
        """Match functions by name, then nearest address, then hash.

        Returns four dicts mapping internal key -> node:
          matched_a, matched_b, unique_a, unique_b
        """
        matched_a: dict[str, Node] = {}
        matched_b: dict[str, Node] = {}
        used_b: set[str] = set()

        # 1. Match by name.
        by_name_b = {n.name: n for n in self._fns_b if n.name}
        for a_node in self._fns_a:
            if a_node.name and a_node.name in by_name_b:
                b_node = by_name_b[a_node.name]
                key = a_node.name
                matched_a[key] = a_node
                matched_b[key] = b_node
                used_b.add(b_node.id)

        # 2. Match remaining by nearest address.
        matched_a_ids = {x.id for x in matched_a.values()}
        unmatched_a = [n for n in self._fns_a if n.id not in matched_a_ids]
        unmatched_b = [n for n in self._fns_b if n.id not in used_b]

        for a_node in sorted(unmatched_a, key=lambda n: _addr_val(n.address)):
            a_addr = _addr_val(a_node.address)
            best: Node | None = None
            best_dist: int | None = None
            key: str | None = None
            for b_node in sorted(unmatched_b, key=lambda n: _addr_val(n.address)):
                b_addr = _addr_val(b_node.address)
                dist = abs(a_addr - b_addr)
                if best_dist is None or dist < best_dist:
                    best_dist = dist
                    best = b_node
                    if b_node.name:
                        key = b_node.name
                    else:
                        key = f"addr_{b_node.address or 'unknown'}"
            if best is not None and best_dist is not None:
                key = key or f"addr_{a_node.address or 'unknown'}"
                # Avoid colliding with an existing name-based key.
                base_key = key
                i = 1
                while key in matched_a or key in matched_b:
                    key = f"{base_key}_{i}"
                    i += 1
                matched_a[key] = a_node
                matched_b[key] = best
                unmatched_b.remove(best)

        # 3. Match remaining by hash (catches renamed/moved identical code).
        remaining_a = [n for n in unmatched_a if n.id not in {x.id for x in matched_a.values()}]
        remaining_b = [n for n in unmatched_b]
        hashes_b = {self._function_hash(n): n for n in remaining_b}
        for a_node in remaining_a:
            h = self._function_hash(a_node)
            if h in hashes_b:
                b_node = hashes_b.pop(h)
                if b_node.name:
                    key = b_node.name
                else:
                    key = f"hash_match_{a_node.address or 'unknown'}"
                base_key = key
                i = 1
                while key in matched_a or key in matched_b:
                    key = f"{base_key}_{i}"
                    i += 1
                matched_a[key] = a_node
                matched_b[key] = b_node

        unique_a = {n.id: n for n in self._fns_a if n.id not in {x.id for x in matched_a.values()}}
        unique_b = {n.id: n for n in self._fns_b if n.id not in {x.id for x in matched_b.values()}}
        return matched_a, matched_b, unique_a, unique_b

    # ---------------------------------------------------------------- public API

    def diff_functions(self, simhash_threshold: float = 0.85) -> list[DiffFunction]:
        """Compare functions across the two graphs.

        Args:
            simhash_threshold: similarity above which a matched function is
                considered ``similar`` instead of ``modified``.

        Returns:
            List of :class:`DiffFunction` records sorted by status then name.
        """
        matched_a, matched_b, unique_a, unique_b = self._match_functions()
        results: list[DiffFunction] = []

        for key in sorted(matched_a.keys() & matched_b.keys()):
            a_node = matched_a[key]
            b_node = matched_b[key]
            addr_a = self._node_addr(a_node)
            addr_b = self._node_addr(b_node)
            name = a_node.name or b_node.name or key
            hash_a = self._function_hash(a_node)
            hash_b = self._function_hash(b_node)
            sim = self._similarity(a_node, b_node, self._function_text)
            notes: list[str] = []

            if hash_a == hash_b and sim == 1.0:
                status = "identical"
                notes.append("function text hash identical")
            elif sim >= simhash_threshold:
                status = "similar"
                if hash_a != hash_b:
                    notes.append(f"hash differs ({hash_a[:8]}... vs {hash_b[:8]}...)")
                notes.append(f"sequence similarity {sim:.3f} >= threshold {simhash_threshold:.3f}")
            else:
                status = "modified"
                notes.append(f"sequence similarity {sim:.3f} < threshold {simhash_threshold:.3f}")

            if a_node.name != b_node.name:
                notes.append(f"renamed: {a_node.name or '<none>'} -> {b_node.name or '<none>'}")
            if addr_a != addr_b and (addr_a and addr_b):
                notes.append(f"address shifted: {addr_a} -> {addr_b}")

            results.append(DiffFunction(
                name=name,
                address_a=addr_a,
                address_b=addr_b,
                status=status,
                similarity_score=round(sim, 6),
                notes=notes,
            ))

        for node in sorted(unique_a.values(), key=lambda n: _addr_val(n.address)):
            results.append(DiffFunction(
                name=node.name or node.id,
                address_a=self._node_addr(node),
                address_b=None,
                status="unique_a",
                similarity_score=0.0,
                notes=["present only in graph_a"],
            ))

        for node in sorted(unique_b.values(), key=lambda n: _addr_val(n.address)):
            results.append(DiffFunction(
                name=node.name or node.id,
                address_a=None,
                address_b=self._node_addr(node),
                status="unique_b",
                similarity_score=0.0,
                notes=["present only in graph_b"],
            ))

        # Sort by status priority then name. Use address as stable tie-breaker.
        order = {"unique_a": 0, "unique_b": 1, "modified": 2, "similar": 3, "identical": 4}
        results.sort(
            key=lambda r: (
                order.get(r.status, 99),
                r.name or "",
                _addr_val(r.address_a),
                _addr_val(r.address_b),
            )
        )
        return results

    def diff_call_graph(self) -> dict[str, Any]:
        """Compare call graph topology.

        Returns a dictionary with:
          * common_nodes: function names/ids present in both graphs.
          * unique_a_nodes, unique_b_nodes: function names only in one graph.
          * matched_edges: call edges that exist in both graphs (by callee name).
          * unique_a_edges, unique_b_edges: call edges only in one graph.
          * call_graph_similarity: Jaccard-like edge overlap score.
        """
        matched_a, matched_b, unique_a, unique_b = self._match_functions()

        def _call_edges(graph: AnalysisGraph, node_id_to_name: dict[str, str]) -> set[tuple[str, str]]:
            edges: set[tuple[str, str]] = set()
            for e in graph.edges:
                if e.kind != "calls":
                    continue
                src = node_id_to_name.get(e.src, e.src)
                dst = node_id_to_name.get(e.dst, e.dst)
                edges.add((src, dst))
            return edges

        names_a = {n.id: n.name or n.id for n in self._fns_a}
        names_b = {n.id: n.name or n.id for n in self._fns_b}

        a_nodes = {names_a[n.id] for n in self._fns_a}
        b_nodes = {names_b[n.id] for n in self._fns_b}
        common_nodes = sorted(a_nodes & b_nodes)
        unique_a_nodes = sorted(a_nodes - b_nodes)
        unique_b_nodes = sorted(b_nodes - a_nodes)

        edges_a = _call_edges(self.graph_a, names_a)
        edges_b = _call_edges(self.graph_b, names_b)
        matched_edges = sorted(edges_a & edges_b)
        unique_a_edges = sorted(edges_a - edges_b)
        unique_b_edges = sorted(edges_b - edges_a)

        union = len(edges_a | edges_b)
        overlap = len(matched_edges) / union if union else 1.0

        return {
            "common_nodes": common_nodes,
            "unique_a_nodes": unique_a_nodes,
            "unique_b_nodes": unique_b_nodes,
            "matched_edges": matched_edges,
            "unique_a_edges": unique_a_edges,
            "unique_b_edges": unique_b_edges,
            "call_graph_similarity": round(overlap, 6),
        }

    def diff_sinks(self, sink_hunter_a: Any, sink_hunter_b: Any) -> dict[str, Any]:
        """Compare dangerous sink call counts across two sink-hunter reports.

        Args:
            sink_hunter_a, sink_hunter_b: objects exposing a ``run()`` method that
                returns a dictionary with ``categories`` (mapping category -> list
                of sink matches) such as the one produced by
                :class:`src.analysis.sink_hunter.SinkHunter`.

        Returns:
            Aggregated per-category sink counts with deltas.
        """
        report_a = sink_hunter_a.run() if hasattr(sink_hunter_a, "run") else dict(sink_hunter_a)
        report_b = sink_hunter_b.run() if hasattr(sink_hunter_b, "run") else dict(sink_hunter_b)

        cats_a = report_a.get("categories", {})
        cats_b = report_b.get("categories", {})

        counts_a = {cat: len(items) for cat, items in cats_a.items()}
        counts_b = {cat: len(items) for cat, items in cats_b.items()}

        all_categories = sorted(set(counts_a) | set(counts_b))
        per_category: dict[str, dict[str, int]] = {}
        for cat in all_categories:
            per_category[cat] = {
                "count_a": counts_a.get(cat, 0),
                "count_b": counts_b.get(cat, 0),
                "delta": counts_b.get(cat, 0) - counts_a.get(cat, 0),
            }

        total_a = sum(counts_a.values())
        total_b = sum(counts_b.values())

        return {
            "total_a": total_a,
            "total_b": total_b,
            "delta": total_b - total_a,
            "per_category": per_category,
            "unique_to_a": sorted(set(counts_a) - set(counts_b)),
            "unique_to_b": sorted(set(counts_b) - set(counts_a)),
        }
