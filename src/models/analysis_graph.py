"""Engine-agnostic analysis graph model.

This module defines the canonical IR that both the IDA and Ghidra engines feed
into. It models:

* nodes: program, function, block, instruction, string, import, export, symbol
* edges: contains, calls, jumps, falls_through, data_read, data_write, offset,
  imports, exports, references

The graph is intentionally serializable as JSONL/JSON so later stages (NetworkX,
SQLite, Neo4j) can consume it without engine-specific knowledge.

Every node has:
  id        - stable URI-style id, e.g. "func:0x401000"
  kind      - node type
  address   - hex string where applicable
  name      - human label when available
  properties - engine-specific extras (decompiled text, signature, ...)

Every edge has:
  src, dst - node ids
  kind      - edge type from the controlled vocabulary below
  properties - address, reference type, confidence, etc.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


NODE_KINDS = {
    "program",
    "function",
    "block",
    "instruction",
    "string",
    "import",
    "export",
    "symbol",
    "segment",
    "constraint",   # symbolic execution path predicate / condition node
}

EDGE_KINDS = {
    "contains",          # parent -> child (program -> function, function -> block, ...)
    "calls",             # instruction/function -> function
    "jump",              # unconditional jump edge
    "conditional_jump",  # conditional jump edge
    "fall_through",      # sequential flow
    "data_read",         # instruction reads data at address
    "data_write",        # instruction writes data at address
    "offset",            # address taken / lea / pointer
    "imports",           # import node -> function node (IAT slot)
    "exports",           # program -> export node
    "references",        # generic xref used when a finer edge is unavailable
    "symbolic_constraint", # function -> constraint node (from symbolic probe)
    "proves_reachable",  # constraint -> block/instruction node it proves reachable
    "writes_to",         # instruction -> memory region written
}


@dataclass
class Node:
    id: str
    kind: str
    address: str | None = None
    name: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = {"id": self.id, "kind": self.kind}
        if self.address is not None:
            d["address"] = self.address
        if self.name is not None:
            d["name"] = self.name
        d["properties"] = self.properties
        return d


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    address: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = {"src": self.src, "dst": self.dst, "kind": self.kind}
        if self.address is not None:
            d["address"] = self.address
        d["properties"] = self.properties
        return d


def _norm_addr(a: Any) -> str:
    """Normalize an address to a hex string."""
    if a is None or a == "":
        return "0x0"
    try:
        if isinstance(a, int):
            return f"0x{a & 0xFFFFFFFFFFFFFFFF:x}"
        if isinstance(a, str):
            if a.startswith("0x"):
                return f"0x{int(a, 16) & 0xFFFFFFFFFFFFFFFF:x}"
            if a.strip().lower().startswith("addr("):
                # Ghidra's toString for Address may produce "addr(...)"
                a = a.strip().lower().replace("addr(", "").replace(")", "")
            return f"0x{int(a, 16) & 0xFFFFFFFFFFFFFFFF:x}"
    except Exception:
        pass
    return str(a)


def _node_id(kind: str, addr: Any, name: str | None = None) -> str:
    """Create a stable node identifier."""
    if kind in ("program", "import", "export") and name:
        slug = name.replace(" ", "_")
        return f"{kind}:{slug}"
    if kind == "string" and name:
        # Distinct string literals at different addresses can share a value
        # (or share their first 80 chars); include the address so they do not
        # collapse into one node and silently overwrite each other.
        slug = name.replace(" ", "_").replace("\n", "\\n").replace("\r", "\\r")
        return f"{kind}:{_norm_addr(addr)}:{slug}"
    if kind == "symbol" and name:
        # Multiple labels at one address are normal (for example Ghidra emits
        # both `_ZTV...` and the primary generic label `vtable`).  Address-only
        # ids silently overwrote the precise ABI symbol with the generic alias.
        slug = name.replace(" ", "_").replace("\n", "\\n").replace("\r", "\\r")
        return f"{kind}:{_norm_addr(addr)}:{slug}"
    return f"{kind}:{_norm_addr(addr)}"


_DWARF_BODY_RANGE_RE = re.compile(
    r"DWARF\s+func\s+body\s+range\[\d+\]:\s*"
    r"\{@address\s+(?:\S+\s+)?(?P<start>(?:0x)?[0-9a-fA-F]+)\}"
    r"\s*\((?P<size>\d+)\s+bytes\)",
    re.IGNORECASE,
)


class AnalysisGraph:
    """In-memory analysis graph builder and query facade."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []
        self._outgoing: dict[str, list[Edge]] = {}
        self._incoming: dict[str, list[Edge]] = {}
        self.metadata: dict[str, Any] = {}
        self._function_indexes_valid = False
        self._function_by_name: dict[str, str] = {}
        self._function_by_address: dict[str, str] = {}
        self._function_range_pages: dict[int, list[tuple[int, int, str]]] = {}

    # --------------------------------------------------------------- node/edge add

    def add_node(self, node: Node) -> Node:
        replacing = node.id in self._nodes
        self._nodes[node.id] = node
        self._outgoing.setdefault(node.id, [])
        self._incoming.setdefault(node.id, [])
        if node.kind == "function":
            if self._function_indexes_valid and not replacing:
                self._index_function_node(node)
            else:
                self._function_indexes_valid = False
        return node

    def add_edge(self, edge: Edge) -> Edge:
        if edge.src not in self._nodes or edge.dst not in self._nodes:
            raise KeyError(f"edge references unknown nodes: {edge.src} -> {edge.dst}")
        self._edges.append(edge)
        self._outgoing.setdefault(edge.src, []).append(edge)
        self._incoming.setdefault(edge.dst, []).append(edge)
        return edge

    # ----------------------------------------------------------------- accessors

    @property
    def nodes(self) -> Iterable[Node]:
        return iter(self._nodes.values())

    @property
    def edges(self) -> Iterable[Edge]:
        return iter(self._edges)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def neighbors(self, node_id: str, *, edge_kind: str | None = None, direction: str = "out") -> list[Node]:
        """Return neighbor nodes filtered by edge kind and direction ('out','in','both')."""
        result: list[Node] = []
        if direction in ("out", "both"):
            for e in self._outgoing.get(node_id, []):
                if edge_kind is None or e.kind == edge_kind:
                    n = self._nodes.get(e.dst)
                    if n is not None:
                        result.append(n)
        if direction in ("in", "both"):
            for e in self._incoming.get(node_id, []):
                if edge_kind is None or e.kind == edge_kind:
                    n = self._nodes.get(e.src)
                    if n is not None:
                        result.append(n)
        return result

    def edge_list(self, node_id: str, *, edge_kind: str | None = None, direction: str = "out") -> list[Edge]:
        """Return matching edge objects."""
        result: list[Edge] = []
        if direction in ("out", "both"):
            for e in self._outgoing.get(node_id, []):
                if edge_kind is None or e.kind == edge_kind:
                    result.append(e)
        if direction in ("in", "both"):
            for e in self._incoming.get(node_id, []):
                if edge_kind is None or e.kind == edge_kind:
                    result.append(e)
        return result

    # ----------------------------------------------------------------- import

    def from_engine_json(self, data: dict[str, Any]) -> None:
        """Populate the graph from an IDA or Ghidra analysis JSON dump."""
        md = data.get("metadata", {})
        program_id = _node_id("program", md.get("image_base") or md.get("entry_point") or "0x0", md.get("name"))
        self.metadata = {k: v for k, v in md.items()}
        self.metadata["program_id"] = program_id

        prog_node = Node(
            id=program_id,
            kind="program",
            address=_norm_addr(md.get("image_base") or md.get("entry_point") or "0x0"),
            name=md.get("name") or md.get("filename"),
            properties={
                "executable_format": md.get("executable_format"),
                "language_id": md.get("language_id"),
                "processor": md.get("processor"),
                "sha256": md.get("sha256"),
                "md5": md.get("md5"),
                "endian": md.get("endian"),
                "pointer_size": md.get("pointer_size"),
            },
        )
        self.add_node(prog_node)

        # Memory/segments if present
        for seg in data.get("memory", []):
            seg_id = _node_id("segment", seg.get("start"), seg.get("name"))
            props = {k: v for k, v in seg.items() if k not in ("name", "start")}
            self.add_node(Node(
                id=seg_id, kind="segment", address=_norm_addr(seg.get("start")), name=seg.get("name"), properties=props
            ))
            self.add_edge(Edge(src=program_id, dst=seg_id, kind="contains"))

        # Functions are the main body
        fn_index: dict[str, str] = {}
        for fn in data.get("functions", []):
            addr = _norm_addr(fn.get("entry"))
            fn_id = _node_id("function", addr, fn.get("name"))
            fn_index[addr] = fn_id
            props = {k: v for k, v in fn.items() if k not in ("name", "entry")}
            self.add_node(Node(id=fn_id, kind="function", address=addr, name=fn.get("name"), properties=props))
            self.add_edge(Edge(src=program_id, dst=fn_id, kind="contains"))
        self._rebuild_function_indexes()

        # Identify all function-address arguments originating in a startup
        # routine that calls __libc_start_main.  A unique target is strong
        # program-main evidence; multiple targets remain callback edges but are
        # deliberately not assigned a main role.
        startup_callback_candidates: dict[str, set[str]] = {}
        for candidate_fn in data.get("functions", []):
            candidate_addr = _norm_addr(candidate_fn.get("entry"))
            candidate_id = _node_id(
                "function", candidate_addr, candidate_fn.get("name")
            )
            for ref in candidate_fn.get("xrefs_to", []) or []:
                if not isinstance(ref, dict):
                    continue
                ref_kind = _xref_kind_from_type(
                    str(ref.get("type") or "").lower()
                )
                if ref_kind not in {"offset", "references", "data_read"}:
                    continue
                ref_addr = ref.get("from")
                source_id = (
                    self._find_containing_function(ref_addr)
                    or self._find_function_by_name_or_addr(
                        ref.get("from_function") or ref_addr
                    )
                )
                source = self.get_node(source_id) if source_id else None
                if source is None:
                    continue
                if any(
                    str(callee).lstrip(".").split("@", 1)[0].lower().endswith(
                        "libc_start_main"
                    )
                    for callee in (source.properties.get("callees") or [])
                ):
                    startup_callback_candidates.setdefault(source.id, set()).add(
                        candidate_id
                    )

        # Second pass: caller/callee and xrefs_to edges
        for fn in data.get("functions", []):
            addr = _norm_addr(fn.get("entry"))
            fn_id = _node_id("function", addr, fn.get("name"))

            # callees
            for callee in fn.get("callees", []) or []:
                callee_id = self._find_function_by_name_or_addr(callee)
                if callee_id and callee_id != fn_id:
                    self.add_edge(Edge(src=fn_id, dst=callee_id, kind="calls", properties={"callee_name": callee}))

            # callers
            for caller in fn.get("callers", []) or []:
                caller_id = self._find_function_by_name_or_addr(caller)
                if caller_id and caller_id != fn_id:
                    self.add_edge(Edge(src=caller_id, dst=fn_id, kind="calls", properties={"caller_name": caller}))

            # xrefs_to this function
            for ref in fn.get("xrefs_to", []) or []:
                if isinstance(ref, dict):
                    ref_addr = ref.get("from")
                    ref_type = (ref.get("type") or "").lower()
                    from_fn = ref.get("from_function") or ref_addr
                else:
                    # Backward-compatible handling for older IDA caches that
                    # exported xref source addresses as plain strings.
                    ref_addr = ref
                    ref_type = ""
                    from_fn = ref_addr
                edge_kind = _xref_kind_from_type(ref_type)
                src_id = (
                    # The reference address is authoritative.  Stripped tools
                    # can assign the same import-like name to both a wrapper
                    # and its PLT target, making name-first lookup ambiguous.
                    self._find_containing_function(ref_addr)
                    or self._find_function_by_name_or_addr(from_fn)
                )
                if src_id is None and edge_kind in ("calls", "jump"):
                    src_id = self._add_inferred_callsite(ref_addr, program_id)
                if src_id:
                    src_node = self.get_node(src_id)
                    startup_callback = (
                        fn_id in startup_callback_candidates.get(src_id, set())
                    )
                    if (
                        startup_callback
                        and len(startup_callback_candidates.get(src_id, set())) == 1
                        and src_node is not None
                    ):
                        role_evidence = {
                            "kind": "libc_start_main_argument",
                            "xref_address": _norm_addr(ref_addr),
                            "confidence": 1.0,
                        }
                        target_node = self.get_node(fn_id)
                        src_node.properties["semantic_role"] = "process_entry"
                        src_node.properties["semantic_role_evidence"] = role_evidence
                        if target_node is not None:
                            target_node.properties["semantic_role"] = "program_main"
                            target_node.properties["semantic_role_evidence"] = (
                                role_evidence
                            )
                        self.metadata["program_roles"] = {
                            "process_entry": {
                                "node_id": src_id,
                                "address": src_node.address,
                                "evidence": role_evidence,
                            },
                            "program_main": {
                                "node_id": fn_id,
                                "address": (
                                    target_node.address if target_node is not None else addr
                                ),
                                "evidence": role_evidence,
                            },
                        }
                    # An unconditional inter-function jump is a tail call.
                    # Keeping it as a CFG jump would hide the callee from
                    # call-graph reachability (notably stripped IDA thunks).
                    is_tail_call = edge_kind == "jump" and src_id != fn_id
                    self.add_edge(Edge(
                        src=src_id,
                        dst=fn_id,
                        kind=(
                            "calls"
                            if is_tail_call or startup_callback
                            else edge_kind
                        ),
                        address=_norm_addr(ref_addr),
                        properties={
                            "raw_type": ref_type,
                            **({"tail_call": True} if is_tail_call else {}),
                            **(
                                {"inferred_callback": "libc_start_main_argument"}
                                if startup_callback else {}
                            ),
                        },
                    ))

        # Exception metadata is control-flow evidence, not a new entry source.
        # IDA exposes native try/catch records; Ghidra exposes the cold handler
        # and landing-pad jump.  Normalize both into owner -> handler call edges
        # so ranked-entry reachability can cross real exception paths.
        self._add_native_exception_edges(data)
        self._recover_cold_exception_edges()

        # Imports
        for imp in data.get("imports", []) or []:
            name = imp.get("name") or imp.get("symbol") or "unknown"
            imp_id = _node_id("import", None, name)
            props = {k: v for k, v in imp.items() if k != "name"}
            self.add_node(Node(id=imp_id, kind="import", address=None, name=name, properties=props))
            self.add_edge(Edge(src=program_id, dst=imp_id, kind="imports"))
            # Link to local function/PLT stub if name matches a local function
            target_id = self._find_function_by_name_or_addr(name)
            if target_id:
                self.add_edge(Edge(src=imp_id, dst=target_id, kind="references", properties={"resolved": True}))

        # Exports
        for exp in data.get("exports", []) or []:
            name = exp.get("name") or "unknown"
            exp_id = _node_id("export", None, name)
            props = {k: v for k, v in exp.items() if k != "name"}
            self.add_node(Node(id=exp_id, kind="export", address=_norm_addr(exp.get("address")), name=name,
                              properties=props))
            self.add_edge(Edge(src=program_id, dst=exp_id, kind="exports"))
            # Export records are boundary metadata; security reachability needs
            # the corresponding callable function node as its source.
            target_id = (
                self._find_function_by_name_or_addr(exp.get("address"))
                or self._find_function_by_name_or_addr(name)
            )
            if target_id:
                self.add_edge(Edge(
                    src=exp_id,
                    dst=target_id,
                    kind="resolves",
                    properties={"resolved": True},
                ))

        # Strings
        for s in data.get("strings", []) or []:
            val = s.get("value") or ""
            key = val[:80].replace("\n", "\\n").replace("\r", "\\r")
            str_id = _node_id("string", s.get("address"), key)
            props = {
                k: v
                for k, v in s.items()
                if k not in ("address", "value", "string", "name", "xrefs_to")
            }
            props.setdefault("length", len(val))
            string_node = self.add_node(Node(
                id=str_id,
                kind="string",
                address=_norm_addr(s.get("address")),
                name=val,
                properties=props,
            ))
            self.add_edge(Edge(src=program_id, dst=str_id, kind="contains"))

            # Preserve concrete code -> string evidence.  Raw string recovery
            # remains lossless, while downstream agents can now distinguish
            # literals actually used by code from linker/debug string tables.
            source_ids: set[str] = set()
            seen_refs: set[tuple[str, str, str]] = set()
            for ref in s.get("xrefs_to", []) or []:
                if not isinstance(ref, dict):
                    continue
                ref_addr = ref.get("from")
                ref_type = str(ref.get("type") or "").lower()
                source_id = (
                    self._find_containing_function(ref_addr)
                    or self._find_function_by_name_or_addr(
                        ref.get("from_function") or ref_addr
                    )
                )
                if source_id is None:
                    continue
                ref_key = (source_id, _norm_addr(ref_addr), ref_type)
                if ref_key in seen_refs:
                    continue
                seen_refs.add(ref_key)
                source_ids.add(source_id)
                self.add_edge(Edge(
                    src=source_id,
                    dst=str_id,
                    kind="references",
                    address=_norm_addr(ref_addr),
                    properties={
                        "string_reference": True,
                        "raw_type": ref_type,
                        "xref_kind": _xref_kind_from_type(ref_type),
                        "engine_reference_type": ref.get(
                            "engine_reference_type"
                        ),
                        "from_memory_block": ref.get("from_memory_block"),
                    },
                ))

            string_node.properties["xref_count"] = len(seen_refs)
            string_node.properties["referenced_by_function_count"] = len(source_ids)
            string_node.properties["string_role"] = (
                "code_referenced" if source_ids else "unreferenced"
            )
            string_node.properties["string_role_evidence"] = (
                "code_xref" if source_ids else "no_function_xref_exported"
            )

        # Symbols (non-external, non-function)
        canonical_symbol_by_address: dict[str, str] = {}
        for sym in data.get("symbols", []) or []:
            sym_name = sym.get("name")
            if not sym_name:
                continue
            sym_kind = (sym.get("type") or "").lower()
            if sym_kind == "function":
                continue
            sym_id = _node_id("symbol", sym.get("address"), sym_name)
            normalized_address = _norm_addr(sym.get("address"))
            if sym_id in self._nodes:
                continue
            self.add_node(Node(
                id=sym_id,
                kind="symbol",
                address=normalized_address,
                name=sym_name,
                properties={
                    "symbol_type": sym.get("type"),
                    "primary": sym.get("primary"),
                    "address_alias_group": normalized_address,
                },
            ))
            self.add_edge(Edge(src=program_id, dst=sym_id, kind="contains"))
            canonical_id = canonical_symbol_by_address.setdefault(
                normalized_address, sym_id
            )
            if canonical_id != sym_id:
                self.add_edge(Edge(
                    src=sym_id,
                    dst=canonical_id,
                    kind="aliases",
                    properties={
                        "same_address": True,
                        "alias_address": normalized_address,
                    },
                ))

    def _upsert_call_edge(
        self,
        src: str,
        dst: str,
        *,
        address: Any = None,
        properties: dict[str, Any] | None = None,
    ) -> Edge:
        """Add a call edge or enrich the matching engine-provided edge."""
        props = dict(properties or {})
        for edge in self._outgoing.get(src, []):
            if edge.kind == "calls" and edge.dst == dst:
                edge.properties.update(props)
                if edge.address is None and address is not None:
                    edge.address = _norm_addr(address)
                return edge
        return self.add_edge(Edge(
            src=src,
            dst=dst,
            kind="calls",
            address=_norm_addr(address) if address is not None else None,
            properties=props,
        ))

    def _add_native_exception_edges(self, data: dict[str, Any]) -> None:
        """Turn native protected-region metadata into owner -> handler flow."""
        regions = data.get("exception_regions") or []
        if not isinstance(regions, list):
            return
        self.metadata["exception_region_count"] = len(regions)
        for region in regions:
            if not isinstance(region, dict):
                continue
            owner_record = region.get("owner") or {}
            owner_id = self._find_function_by_name_or_addr(owner_record.get("entry"))
            protected = region.get("protected_ranges") or []
            if owner_id is None and protected and isinstance(protected[0], dict):
                owner_id = self._find_containing_function(protected[0].get("start"))
            if owner_id is None:
                continue
            for handler in region.get("handlers") or []:
                if not isinstance(handler, dict):
                    continue
                targets = [
                    target for target in (handler.get("control_targets") or [])
                    if isinstance(target, dict)
                ]
                candidates = [target.get("address") for target in targets]
                candidates.append(handler.get("entry"))
                handler_id = None
                for candidate in candidates:
                    if not candidate:
                        continue
                    handler_id = (
                        self._find_containing_function(candidate)
                        or self._find_function_by_name_or_addr(candidate)
                    )
                    if handler_id is not None and handler_id != owner_id:
                        break
                if handler_id is None or handler_id == owner_id:
                    continue
                target = targets[0] if targets else {}
                self._upsert_call_edge(
                    owner_id,
                    handler_id,
                    address=target.get("from") or handler.get("entry"),
                    properties={
                        "inferred_exception_handler": True,
                        "exception_evidence": region.get("source") or "native_exception_metadata",
                        "exception_kind": region.get("kind"),
                        "protected_ranges": protected,
                        "landing_pad": handler.get("entry"),
                        "confidence": float(region.get("confidence") or 1.0),
                    },
                )

    @staticmethod
    def _function_range_end(node: Node) -> int | None:
        """Return the maximum exclusive end from authoritative body ranges."""
        ends = []
        for body_range in node.properties.get("body_ranges") or []:
            if not isinstance(body_range, dict):
                continue
            try:
                start = int(_norm_addr(body_range.get("start")), 16)
                size = int(body_range.get("size") or 0)
                if size <= 0 and body_range.get("end") is not None:
                    end = int(_norm_addr(body_range.get("end")), 16)
                    size = end - start + (
                        1 if body_range.get("end_inclusive", True) else 0
                    )
            except (TypeError, ValueError):
                continue
            if size > 0:
                ends.append(start + size)
        if ends:
            return max(ends)
        try:
            return int(_norm_addr(node.address), 16) + max(
                1, int(node.properties.get("size") or 0)
            )
        except (TypeError, ValueError):
            return None

    def _recover_cold_exception_edges(self) -> None:
        """Recover a missed Ghidra owner edge from a strong EH conjunction.

        The recovery requires all of: a cold function that calls the C++ catch
        runtime, a concrete inter-function landing-pad jump to it, and a real
        function ending within 16 bytes of that jump.  Generic nearby orphan
        callsites remain disconnected and therefore cannot become sources.
        """
        runtime_begin = "__cxa_begin_catch"
        runtime_resume = {"_unwind_resume", "__cxa_end_catch"}
        function_nodes = [node for node in self._nodes.values() if node.kind == "function"]
        for handler in function_nodes:
            callees = {
                str(name).lstrip(".").split("@", 1)[0].lower()
                for name in (handler.properties.get("callees") or [])
            }
            if runtime_begin not in callees or not callees.intersection(runtime_resume):
                continue
            for incoming in list(self._incoming.get(handler.id, [])):
                source = self._nodes.get(incoming.src)
                if (
                    incoming.kind != "calls"
                    or source is None
                    or source.properties.get("inferred_from") != "orphan_code_xref"
                    or not incoming.properties.get("tail_call")
                ):
                    continue
                try:
                    callsite = int(_norm_addr(source.address), 16)
                except (TypeError, ValueError):
                    continue
                owners = []
                for owner in function_nodes:
                    if owner.id in {handler.id, source.id} or owner.properties.get("synthetic"):
                        continue
                    end = self._function_range_end(owner)
                    if end is not None and 0 <= callsite - end <= 16:
                        owners.append((callsite - end, owner))
                if not owners:
                    continue
                _, owner = min(owners, key=lambda item: item[0])
                self._upsert_call_edge(
                    owner.id,
                    handler.id,
                    address=source.address,
                    properties={
                        "inferred_exception_handler": True,
                        "exception_evidence": "landing_pad_tail_jump_and_eh_runtime_calls",
                        "landing_pad_callsite": source.address,
                        "confidence": 0.95,
                    },
                )

    def _find_function_by_name_or_addr(self, label: Any) -> str | None:
        if not label:
            return None
        self._ensure_function_indexes()
        label = str(label)
        normalized = _norm_addr(label)
        if normalized in self._function_by_address:
            return self._function_by_address[normalized]
        candidate = _node_id("function", label, label)
        if candidate in self._nodes:
            return candidate
        if label in self._function_by_name:
            return self._function_by_name[label]
        return None

    def _find_containing_function(self, address: Any) -> str | None:
        self._ensure_function_indexes()
        try:
            target = int(_norm_addr(address), 16)
        except (TypeError, ValueError):
            return None
        for start, end, node_id in self._function_range_pages.get(target >> 12, []):
            if start <= target < end:
                return node_id
        return None

    def _ensure_function_indexes(self) -> None:
        if not self._function_indexes_valid:
            self._rebuild_function_indexes()

    def _rebuild_function_indexes(self) -> None:
        self._function_by_name = {}
        self._function_by_address = {}
        self._function_range_pages = {}
        for node in self._nodes.values():
            if node.kind != "function":
                continue
            self._index_function_node(node)
        for ranges in self._function_range_pages.values():
            ranges.sort(key=lambda item: (item[1] - item[0], item[0]))
        self._function_indexes_valid = True

    def _index_function_node(self, node: Node) -> None:
        if node.name and node.name not in self._function_by_name:
            self._function_by_name[node.name] = node.id
        if node.address:
            self._function_by_address.setdefault(_norm_addr(node.address), node.id)
        for start, end in self._function_ranges(node):
            first_page = start >> 12
            last_page = max(first_page, (end - 1) >> 12)
            for page in range(first_page, last_page + 1):
                self._function_range_pages.setdefault(page, []).append((start, end, node.id))

    @staticmethod
    def _function_ranges(node: Node) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for body_range in node.properties.get("body_ranges") or []:
            if not isinstance(body_range, dict):
                continue
            try:
                start = int(_norm_addr(body_range.get("start")), 16)
                size = int(body_range.get("size") or 0)
                if size <= 0 and body_range.get("end") is not None:
                    end = int(_norm_addr(body_range.get("end")), 16)
                    size = end - start + (
                        1 if body_range.get("end_inclusive", True) else 0
                    )
            except (TypeError, ValueError):
                continue
            if size > 0:
                ranges.append((start, start + size))

        # Older Ghidra caches predate body_ranges, but decompiler output can
        # carry authoritative DWARF disjoint-range metadata.
        for match in _DWARF_BODY_RANGE_RE.finditer(
            str(node.properties.get("decompiled") or "")
        ):
            try:
                start = int(_norm_addr(match.group("start")), 16)
                size = int(match.group("size"))
            except (TypeError, ValueError):
                continue
            if size > 0:
                ranges.append((start, start + size))

        if ranges:
            return ranges
        try:
            start = int(_norm_addr(node.address), 16)
            size = max(1, int(node.properties.get("size") or 0))
        except (TypeError, ValueError):
            return []
        return [(start, start + size)]

    def _add_inferred_callsite(self, address: Any, program_id: str) -> str | None:
        """Represent an executable code xref whose owning function was missed.

        Stripped binaries can contain tiny tail-call wrappers that an engine
        does not promote to functions.  We retain the exact call instruction
        as a low-confidence synthetic function boundary so downstream
        reachability stays evidence-backed without inventing a wider range.
        """
        normalized = _norm_addr(address)
        try:
            value = int(normalized, 16)
        except (TypeError, ValueError):
            return None
        if value <= 0:
            return None
        node_id = _node_id("function", normalized)
        if node_id not in self._nodes:
            self.add_node(Node(
                id=node_id,
                kind="function",
                address=normalized,
                name=f"inferred_callsite_{normalized}",
                properties={
                    "size": 1,
                    "is_external": False,
                    "synthetic": True,
                    "inferred_from": "orphan_code_xref",
                    "confidence": 0.5,
                },
            ))
            self.add_edge(Edge(
                src=program_id,
                dst=node_id,
                kind="contains",
                properties={"inferred": True},
            ))
        return node_id

    # ---------------------------------------------------------------- persistence

    def to_json(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "nodes": [n.as_dict() for n in self._nodes.values()],
            "edges": [e.as_dict() for e in self._edges],
        }

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), indent=2, default=str), encoding="utf-8")

    @classmethod
    def load_json(cls, path: str | Path) -> "AnalysisGraph":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        g = cls()
        g.metadata = data.get("metadata", {})
        for n in data.get("nodes", []):
            g.add_node(Node(id=n["id"], kind=n["kind"], address=n.get("address"),
                            name=n.get("name"), properties=n.get("properties", {})))
        for e in data.get("edges", []):
            g.add_edge(Edge(src=e["src"], dst=e["dst"], kind=e["kind"],
                            address=e.get("address"), properties=e.get("properties", {})))
        g._rebuild_function_indexes()
        return g

    def save_jsonl(self, nodes_path: str | Path, edges_path: str | Path) -> None:
        with open(nodes_path, "w", encoding="utf-8") as fh:
            for n in self._nodes.values():
                fh.write(json.dumps(n.as_dict(), default=str) + "\n")
        with open(edges_path, "w", encoding="utf-8") as fh:
            for e in self._edges:
                fh.write(json.dumps(e.as_dict(), default=str) + "\n")

    @classmethod
    def load_jsonl(cls, nodes_path: str | Path, edges_path: str | Path) -> "AnalysisGraph":
        g = cls()
        for line in Path(nodes_path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                n = json.loads(line)
                g.add_node(Node(id=n["id"], kind=n["kind"], address=n.get("address"),
                                name=n.get("name"), properties=n.get("properties", {})))
        for line in Path(edges_path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                e = json.loads(line)
                g.add_edge(Edge(src=e["src"], dst=e["dst"], kind=e["kind"],
                                address=e.get("address"), properties=e.get("properties", {})))
        return g


def _xref_kind_from_type(ref_type: str) -> str:
    rt = ref_type.lower()
    if "call" in rt:
        return "calls"
    if "jump" in rt:
        # "unconditional" contains the substring "conditional"; test it first.
        if "unconditional" in rt:
            return "jump"
        return "conditional_jump" if "conditional" in rt else "jump"
    if "read" in rt:
        return "data_read"
    if "write" in rt or "mut" in rt:
        return "data_write"
    if "data" in rt or "offset" in rt or "lea" in rt:
        return "offset"
    return "references"
