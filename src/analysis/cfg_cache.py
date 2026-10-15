"""Bounded LRU cache for function-level CFG builds.

Rebuilding :class:`~src.analysis.cfg_spine.FunctionCFG` objects for an entire
``AnalysisGraph`` is one of the hot loops of the analysis spine: recursive-
descent disassembly (as described in *The IDA Pro Book*) is re-executed for
every function even though the underlying instruction set rarely changes
between analysis passes.  Following the classic memoisation argument used by
incremental binary-analysis engines (e.g. IDA's cached function flows), a
repeated build over an *unmodified* byte stream must return an identical
result, so caching is behaviour-preserving.

Cache keys pair the stable function node id with a SHA-256 digest of the
instruction payload owned by that function.  Any graph mutation that changes
the function's instruction nodes (added/removed nodes, edited mnemonics or
operands) changes the digest and therefore invalidates the entry, while
unrelated mutations elsewhere in the graph keep the cached CFG valid.

The cache is deliberately lightweight:

* in-memory only (no pickling — a miss recomputes),
* :class:`collections.OrderedDict` LRU eviction with a configurable bound
  (default 2048 entries, overridable via ``CFGCache(maxsize=...)``).

The module is stdlib-only, matching the design constraints of
:mod:`src.analysis.cfg_spine`.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from .cfg_spine import CFGSpine, FunctionCFG, _norm_hex

if TYPE_CHECKING:  # pragma: no cover - typing only
    from src.models.analysis_graph import Node


def _jsonable(value: Any) -> Any:
    """Reduce an arbitrary property value to a JSON-ish, hashable payload.

    The digest only needs determinism, not fidelity, so unknown containers are
    flattened recursively and opaque objects fall back to ``repr``.
    """
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(v) for v in value), key=repr)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


class CFGCache:
    """LRU cache of :class:`FunctionCFG` objects.

    Keys are ``(function_node_id, digest)`` tuples where ``digest`` is the
    SHA-256 of the function's instruction-node data extracted from the graph.
    Lookups are O(1); eviction removes the least-recently-used entry once the
    cache exceeds ``maxsize``.
    """

    def __init__(self, maxsize: int = 2048) -> None:
        if maxsize < 1:
            raise ValueError("CFGCache maxsize must be >= 1")
        self.maxsize = int(maxsize)
        self._store: "OrderedDict[tuple[str, str], FunctionCFG]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    # ------------------------------------------------------------------ key building

    @staticmethod
    def key_for(graph: Any, fn_node: "Node") -> tuple[str, str] | None:
        """Return the cache key for ``fn_node`` against ``graph``.

        The first element is the stable function node id; the second is a
        SHA-256 hex digest over the function's identity, its own mutable
        properties, and the instruction nodes directly contained by it.
        ``None`` is returned when the node is not cache-addressable.
        """
        if fn_node is None:
            return None
        try:
            fn_id = str(fn_node.id)
            props = fn_node.properties or {}
            addr = _norm_hex(getattr(fn_node, "address", None))

            hasher = hashlib.sha256()
            hasher.update(fn_id.encode("utf-8", "surrogateescape"))
            hasher.update(b"\x00")
            hasher.update(addr.encode("ascii", "replace"))
            hasher.update(b"\x00")
            hasher.update(repr(_jsonable(props)).encode("utf-8", "surrogateescape"))
            hasher.update(b"\x00")

            # Hash the local containment structure: instruction/block children
            # in deterministic order.  A mutation anywhere in this payload
            # changes the digest and therefore invalidates the cached CFG.
            contain_edges = sorted(
                (getattr(e, "dst", None), getattr(e, "kind", None))
                for e in graph.edge_list(fn_node.id, edge_kind="contains", direction="out")
            )
            child_ids = [dst for dst, _kind in contain_edges]
            child_instructions: list[str] = []
            for dst, _kind in contain_edges:
                node = graph.get_node(dst) if dst else None
                if node is None:
                    continue
                if node.kind == "block":
                    instr_children = sorted(
                        getattr(e, "dst", "")
                        for e in graph.edge_list(dst, edge_kind="contains", direction="out")
                    )
                    child_instructions.extend(instr_children)
                    hasher.update(repr((dst, instr_children)).encode("utf-8", "surrogateescape"))
            for dst in child_instructions:
                child_ids.append(dst)

            for child_id in sorted(str(c) for c in child_ids):
                node = graph.get_node(child_id)
                if node is None:
                    continue
                child_props = node.properties or {}
                payload = repr((
                    node.id,
                    node.kind,
                    _norm_hex(getattr(node, "address", None)),
                    _jsonable(child_props),
                ))
                hasher.update(payload.encode("utf-8", "surrogateescape"))
                hasher.update(b"\x00")

            return fn_id, hasher.hexdigest()
        except Exception:  # noqa: BLE001 - never let key building break a build
            return None

    # ------------------------------------------------------------------ LRU ops

    def get(self, key: tuple[str, str] | None) -> FunctionCFG | None:
        """Return the cached CFG for ``key`` (and mark it most-recently used)."""
        if key is None:
            return None
        with self._lock:
            cfg = self._store.get(key)
            if cfg is None:
                self.misses += 1
                return None
            self._store.move_to_end(key)
            self.hits += 1
            return cfg

    def put(self, key: tuple[str, str] | None, cfg: FunctionCFG) -> None:
        """Insert ``cfg`` under ``key``, evicting the LRU entry when full."""
        if key is None or cfg is None:
            return
        with self._lock:
            self._store[key] = cfg
            self._store.move_to_end(key)
            while len(self._store) > self.maxsize:
                self._store.popitem(last=False)

    def clear(self) -> None:
        """Drop every cached entry and reset statistics."""
        with self._lock:
            self._store.clear()
            self.hits = 0
            self.misses = 0

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._store)


class CachedCFGSpine(CFGSpine):
    """:class:`CFGSpine` variant whose builds consult a :class:`CFGCache`.

    ``build_function_cfg`` first derives the (function id, digest) key; on a
    hit the cached CFG is returned, on a miss the regular recursive-descent
    build runs and the result is memoised.  The public interface is identical
    to the parent class, so existing call sites may swap implementations
    freely.
    """

    def __init__(self, graph: "Any", cache: CFGCache | None = None) -> None:
        super().__init__(graph)
        self.cache = cache if cache is not None else CFGCache()
        self.owns_cache = cache is None

    def build_function_cfg(self, fn_node: "Node") -> FunctionCFG:
        """Build (or fetch) the CFG for ``fn_node`` through the cache."""
        key = self.cache.key_for(self.graph, fn_node)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        cfg = super().build_function_cfg(fn_node)
        self.cache.put(key, cfg)
        return cfg
