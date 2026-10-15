"""Heuristic indirect control-flow recovery for switch tables and function pointer arrays.

This pass implements the "augmented recursive descent" view described in
*The IDA Pro Book*: pure heuristics over the engine-agnostic :class:`AnalysisGraph`
instead of real emulation.  It looks for indirect jumps that smell like switch
dispatchers, scans nearby data/string xrefs to infer jump table entries, and
collates offset edges around symbol/export nodes to propose function-pointer tables.

All outputs are *hypotheses* with explicit confidence scores; a downstream stage
with a real emulator must confirm them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models.analysis_graph import AnalysisGraph, Edge, Node


_SWITCH_HINTS = frozenset(
    [
        "switch",
        "case",
        "jump table",
        "jumptable",
        "lookup",
        "dispatch",
    ]
)
_GENERIC_TABLE_NAMES = frozenset(
    [
        "vtable",
        "_vtable",
        "vtbl",
        "__vmi_class_type_info",
        "__si_class_type_info",
    ]
)

try:
    import networkx as nx  # type: ignore[import-untyped]

    _HAS_NX = True
except Exception:  # noqa: BLE001
    _HAS_NX = False


@dataclass
class SwitchTable:
    """A recovered switch / jump table."""

    jump_site: str
    base: str | None
    cases: list[dict[str, Any]] = field(default_factory=list)
    entry_size: int = 4
    confidence: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "jump_site": self.jump_site,
            "base": self.base,
            "cases": self.cases,
            "entry_size": self.entry_size,
            "confidence": self.confidence,
        }


@dataclass
class FunctionPointerTable:
    """A recovered function-pointer table (vtable, handler array, etc.)."""

    address: str
    entries: list[dict[str, Any]] = field(default_factory=list)
    entry_size: int = 8
    referenced_by: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "entries": self.entries,
            "entry_size": self.entry_size,
            "referenced_by": self.referenced_by,
        }


class IndirectFlowRecovery:
    """Heuristic indirect control-flow recovery.

    Parameters
    ----------
    graph:
        The ``AnalysisGraph`` to analyse.
    cfg_spine:
        Optional caller-provided spine (e.g. a list of ``(src, dst)`` tuples or a
        NetworkX DiGraph).  If a NetworkX graph is given, shortest-path distances
        are used to boost confidence for tables that sit near an indirect jump.
    """

    def __init__(self, graph: AnalysisGraph, cfg_spine: Any | None = None) -> None:
        self.graph = graph
        self.cfg_spine = cfg_spine
        self._addr_to_node: dict[str, list[Node]] = {}
        self._name_to_node: dict[str, Node] = {}
        self._build_indices()

    # ---------------------------------------------------------------- indexing

    def _build_indices(self) -> None:
        """Populate address and name lookup maps."""
        self._addr_to_node.clear()
        self._name_to_node.clear()
        for node in self.graph.nodes:
            if node.address:
                self._addr_to_node.setdefault(node.address, []).append(node)
            if node.name:
                self._name_to_node[node.name] = node

    def _addr_int(self, addr: str | None) -> int:
        """Convert a hex (or decimal) address string to an integer."""
        if addr is None:
            return 0
        try:
            s = str(addr).strip()
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            return int(s, 0)
        except ValueError:
            return 0

    def _fmt_addr(self, value: int) -> str:
        return f"0x{value & 0xFFFFFFFFFFFFFFFF:x}"

    # ------------------------------------------------------------- switch tables

    def _looks_like_switch_dispatcher(self, func: Node) -> float:
        """Return a confidence score that ``func`` implements a switch/case dispatcher."""
        score = 0.0
        name = (func.name or "").lower()
        decomp = str(func.properties.get("decompiled", "")).lower()
        asm = str(func.properties.get("assembly", "")).lower()
        text = f"{name} {decomp} {asm}"

        hits = sum(1 for hint in _SWITCH_HINTS if hint in text)
        score += min(hits * 0.25, 0.6)

        # JMP/CALL using a register plus bracketed memory is a strong clue.
        if re.search(r"\bjmp\s+.*\[.*\]", asm, re.IGNORECASE):
            score += 0.2
        if re.search(r"\bjmp\s+[er]?[a-ds][ix]", asm, re.IGNORECASE):
            score += 0.15
        if re.search(r"\b(case\s+|swi?tc?h)", text, re.IGNORECASE):
            score += 0.15

        return min(max(score, 0.0), 0.95)

    def _node_for_address(self, address: str) -> Node | None:
        for node in self._addr_to_node.get(address, []):
            # Prefer a function node, fall back to any node.
            if node.kind == "function":
                return node
        return (self._addr_to_node.get(address) or [None])[0]

    def _find_indirect_jump_sites(self, func: Node) -> list[Node]:
        """Collect instruction nodes that are indirect jumps inside ``func``."""
        sites: list[Node] = []
        seen: set[str] = set()
        # Direct children via contains edges, plus any instruction node whose
        # address falls inside the function if blocks are not materialised.
        children = self.graph.neighbors(func.id, edge_kind="contains", direction="out")
        work = list(children)
        while work:
            child = work.pop()
            if child.id in seen:
                continue
            seen.add(child.id)
            if child.kind == "instruction":
                mnem = str(child.properties.get("mnemonic", "")).lower()
                if mnem in ("jmp", "br", "bx"):
                    ops = str(child.properties.get("operands", "")).lower()
                    # Register indirect or memory indexed operand.
                    if re.search(r"\[|\b[rvex][0-9]+\b|\b[er]?[a-ds][ix]\b|\bppc\b", ops):
                        sites.append(child)
            else:
                work.extend(
                    self.graph.neighbors(child.id, edge_kind="contains", direction="out")
                )

        # Fallback: find instructions by address contained within function bounds.
        if not sites and func.address:
            fa = self._addr_int(func.address)
            size = int(func.properties.get("size", 0) or 0)
            for node in self.graph.nodes:
                if node.kind != "instruction" or not node.address:
                    continue
                ia = self._addr_int(node.address)
                if fa <= ia < fa + max(size, 1):
                    mnem = str(node.properties.get("mnemonic", "")).lower()
                    if mnem in ("jmp", "br", "bx"):
                        sites.append(node)

        return sites

    def _infer_table_base(self, jump_site: Node) -> tuple[str | None, float]:
        """Use data references/offset edges near the jump to guess the table base."""
        best_base: str | None = None
        best_conf = 0.0
        edges = self.graph.edge_list(jump_site.id, direction="out")
        for edge in edges:
            if edge.kind in ("data_read", "offset", "references"):
                if edge.address:
                    conf = 0.7 if edge.kind == "data_read" else 0.55
                    if conf > best_conf:
                        best_base = edge.address
                        best_conf = conf
                target = self.graph.get_node(edge.dst)
                if target and target.address:
                    conf = 0.5 if edge.kind == "references" else 0.65
                    if conf > best_conf:
                        best_base = target.address
                        best_conf = conf

        # Also inspect nearest string/data symbols if they are referenced by offset.
        if best_base is None:
            near = self._guess_nearby_data(jump_site.address)
            if near:
                best_base = near
                best_conf = 0.35

        return best_base, best_conf

    def _guess_nearby_data(self, addr: str | None) -> str | None:
        """Pick the closest preceding data/symbol/string node address."""
        if addr is None:
            return None
        base_a = self._addr_int(addr)
        best: tuple[int, str] | None = None
        for node in self.graph.nodes:
            if node.kind not in ("string", "symbol", "segment") or not node.address:
                continue
            a = self._addr_int(node.address)
            if 0 < (base_a - a) <= 4096:
                if best is None or a > best[0]:
                    best = (a, node.address)
        return best[1] if best else None

    def _collect_candidate_targets(
        self, jump_site: Node, base_addr: str | None
    ) -> list[tuple[str, dict[str, Any]]]:
        """Collect target addresses that could be switch-case destinations.

        Returns a list of ``(target_addr, evidence)`` tuples.
        """
        candidates: list[tuple[str, dict[str, Any]]] = []
        base = self._addr_int(base_addr) if base_addr else 0

        # Follow jump/fall-through edges from the jump site and nearby function blocks.
        if jump_site.address:
            for edge in self.graph.edge_list(jump_site.id, direction="out"):
                if edge.kind in ("jump", "conditional_jump", "fall_through"):
                    target = self.graph.get_node(edge.dst)
                    if not target:
                        continue
                    if target.kind == "function":
                        candidates.append(
                            (target.address or edge.address or "0x0", {"kind": edge.kind})
                        )
                    elif target.kind == "block" and target.address:
                        candidates.append((target.address, {"kind": edge.kind}))

        # Use data references from the function as case targets.
        func = self._containing_function(jump_site)
        if func is not None:
            for edge in self.graph.edge_list(func.id, direction="out"):
                if edge.kind in ("offset", "data_read", "references") and edge.address:
                    addr = edge.address
                    a = self._addr_int(addr)
                    # Table entries conventionally sit above the code or in .rodata.
                    if base and abs(a - base) < 8192:
                        candidates.append((addr, {"kind": edge.kind, "via": "func_xref"}))

        # Scan symbol/string and segment nodes around the table base.
        if base:
            for node in self.graph.nodes:
                if node.kind not in ("symbol", "string", "segment") or not node.address:
                    continue
                a = self._addr_int(node.address)
                if 0 <= a - base <= 8192:
                    candidates.append(
                        (node.address, {"kind": "near_data", "node_kind": node.kind})
                    )

        return candidates

    def _containing_function(self, node: Node) -> Node | None:
        """Find the function that contains ``node`` by walking contains edges up."""
        seen: set[str] = set()
        work = [node.id]
        while work:
            cur = work.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for parent in self.graph.neighbors(cur, edge_kind="contains", direction="in"):
                if parent.kind == "function":
                    return parent
                work.append(parent.id)
        # Fallback: search by address range.
        if node.address:
            for maybe in self.graph.nodes:
                if maybe.kind != "function" or not maybe.address:
                    continue
                fa = self._addr_int(maybe.address)
                size = int(maybe.properties.get("size", 0) or 0)
                ia = self._addr_int(node.address)
                if fa <= ia < fa + max(size, 1):
                    return maybe
        return None

    def _resolve_case_targets(self, candidates: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        """Resolve candidate addresses to function nodes where possible."""
        cases: list[dict[str, Any]] = []
        seen: set[str] = set()
        for idx, (addr, evidence) in enumerate(candidates[:256]):
            if addr in seen:
                continue
            seen.add(addr)
            node = self._node_for_address(addr)
            target_id: str | None = None
            confidence = 0.5
            if node is not None:
                if node.kind == "function":
                    target_id = node.id
                    confidence = 0.8
                elif node.kind in ("block", "instruction"):
                    target_id = node.id
                    confidence = 0.6
                elif node.kind == "symbol":
                    confidence = 0.45
            else:
                confidence = 0.3
            cases.append(
                {
                    "index": idx,
                    "target_addr": addr,
                    "target_id": target_id,
                    "confidence": round(confidence, 3),
                    "evidence": evidence,
                }
            )
        return cases

    def find_switch_tables(self, max_tables: int = 50) -> list[SwitchTable]:
        """Heuristically recover switch jump tables.

        The algorithm:

        1. Score every function for switch/case flavour (name, decompilation, asm).
        2. Inside promising functions, look for indirect jump instructions.
        3. Infer a table base from data references / offset edges.
        4. Collect candidate case targets from nearby xrefs and resolved functions.
        5. Emit a :class:`SwitchTable` hypothesis with a confidence score.
        """
        results: list[SwitchTable] = []
        scored_funcs: list[tuple[Node, float]] = []

        for node in self.graph.nodes:
            if node.kind != "function":
                continue
            score = self._looks_like_switch_dispatcher(node)
            if score > 0.0:
                scored_funcs.append((node, score))

        # Also add any indirect jump instruction even if its function did not score.
        jumpers: set[str] = set()
        for node in self.graph.nodes:
            if node.kind != "instruction":
                continue
            if self._is_indirect_jump(node):
                jumpers.add(node.id)
                func = self._containing_function(node)
                if func is not None and func not in (f for f, _ in scored_funcs):
                    scored_funcs.append((func, 0.25))

        scored_funcs.sort(key=lambda x: x[1], reverse=True)

        for func, func_conf in scored_funcs:
            if len(results) >= max_tables:
                break
            sites = self._find_indirect_jump_sites(func)
            # If the function did not score but has explicit jumpers, use any site.
            if not sites and jumpers:
                for jid in jumpers:
                    jnode = self.graph.get_node(jid)
                    if jnode is None:
                        continue
                    parent = self._containing_function(jnode)
                    if parent is not None and parent.id == func.id:
                        sites.append(jnode)
            if not sites:
                continue

            for site in sites:
                if len(results) >= max_tables:
                    break
                base, base_conf = self._infer_table_base(site)
                candidates = self._collect_candidate_targets(site, base)
                cases = self._resolve_case_targets(candidates)

                # Heuristic confidence combines function flavour, base resolution,
                # case count, and case resolution rate.
                conf = self._switch_confidence(func_conf, base_conf, cases)
                entry_size = self._estimate_entry_size(func)

                st = SwitchTable(
                    jump_site=site.address or site.id,
                    base=base,
                    cases=cases,
                    entry_size=entry_size,
                    confidence=round(conf, 3),
                )
                results.append(st)

        return results

    def _is_indirect_jump(self, node: Node) -> bool:
        mnem = str(node.properties.get("mnemonic", "")).lower()
        if mnem not in ("jmp", "br", "bx", "call"):
            return False
        ops = str(node.properties.get("operands", "")).lower()
        return bool(
            re.search(r"\[|\b[rvex][0-9]+\b|\b[er]?[a-dsx][ipx]\b|\bppc\b", ops)
        )

    def _estimate_entry_size(self, func: Node) -> int:
        arch = str(self.graph.metadata.get("processor", "")).lower()
        lang = str(self.graph.metadata.get("language_id", "")).lower()
        ps = int(self.graph.metadata.get("pointer_size", 0) or 0)
        if ps == 8 or "x64" in arch or "64" in lang:
            return 8
        if ps == 4 or "x86" in arch or "arm" in arch or "32" in lang:
            return 4
        if "solana" in lang or "bpf" in arch:
            return 8
        return 4

    def _switch_confidence(
        self, func_conf: float, base_conf: float, cases: list[dict[str, Any]]
    ) -> float:
        if not cases:
            return 0.1
        resolved = sum(1 for c in cases if c.get("target_id"))
        resolution = resolved / len(cases)
        # Distance from jump to base is a strong signal when available.
        score = 0.35 * func_conf + 0.25 * base_conf + 0.25 * resolution + 0.15 * min(len(cases) / 8.0, 1.0)
        return min(max(score, 0.0), 0.99)

    # ----------------------------------------------------- function pointer tables

    def _is_function_pointer_symbol(self, node: Node) -> float:
        """Score how likely a symbol/export/string node heads a function-pointer table."""
        score = 0.0
        name = (node.name or "").lower()
        if any(hint in name for hint in _GENERIC_TABLE_NAMES):
            score += 0.5
        if "handler" in name or "callback" in name or "func_table" in name:
            score += 0.4
        if name.startswith("_ztv") or name.startswith("ztv"):
            score += 0.95  # Itanium vtable mangling (already lowercased)
        return min(score, 0.99)

    def _collect_offset_targets(self, source_id: str) -> list[tuple[str, Node | None, Edge]]:
        """Collect all addresses referenced by ``offset`` edges from ``source_id``."""
        seen: set[str] = set()
        targets: list[tuple[str, Node | None, Edge]] = []
        for edge in self.graph.edge_list(source_id, direction="out"):
            if edge.kind not in ("offset", "references"):
                continue
            dst = self.graph.get_node(edge.dst)
            # Prefer the edge address, then the destination node address.
            candidate = edge.address or (dst.address if dst else None)
            if candidate and candidate not in seen:
                seen.add(candidate)
                targets.append((candidate, dst, edge))
        return targets

    def find_function_pointer_tables(self, max_tables: int = 50) -> list[FunctionPointerTable]:
        """Heuristically recover function-pointer tables / vtables.

        The algorithm:

        1. Score symbol/export/string nodes for vtable / handler-table naming.
        2. For each promising node, follow ``offset`` edges to referenced addresses.
        3. Resolve those addresses to functions; each becomes a table entry.
        4. Record every node that references the table in ``referenced_by``.
        """
        seed_nodes: list[tuple[Node, float]] = []

        for node in self.graph.nodes:
            if node.kind not in ("symbol", "export", "string"):
                continue
            score = self._is_function_pointer_symbol(node)
            if score > 0.0:
                seed_nodes.append((node, score))

        # Function nodes that are the target of many offset edges can also be
        # interpreted as the *base* of a table if the edges come from data nodes.
        for node in self.graph.nodes:
            if node.kind != "function":
                continue
            refs = self.graph.edge_list(node.id, direction="in")
            offset_count = sum(1 for e in refs if e.kind == "offset")
            if offset_count >= 3:
                seed_nodes.append((node, 0.25 + min(offset_count, 10) * 0.05))

        seed_nodes.sort(key=lambda x: x[1], reverse=True)
        results: list[FunctionPointerTable] = []
        seen_bases: set[str] = set()

        for node, sym_conf in seed_nodes:
            if len(results) >= max_tables:
                break
            base_addr = node.address
            if not base_addr:
                continue
            base_addr = self._fmt_addr(self._addr_int(base_addr))
            if base_addr in seen_bases:
                continue
            seen_bases.add(base_addr)

            targets = self._collect_offset_targets(node.id)
            # Include offset edges whose source is the symbol's name if the graph
            # stores them separately.
            if node.name:
                for cand in self.graph.edges:
                    if (
                        cand.kind == "offset"
                        and (cand.src == node.id or cand.src.endswith(f":{node.name}"))
                    ):
                        if cand.address:
                            targets.append((cand.address, self.graph.get_node(cand.dst), cand))
                        dst = self.graph.get_node(cand.dst)
                        if dst and dst.address:
                            targets.append((dst.address, dst, cand))

            entries: list[dict[str, Any]] = []
            referenced_by: set[str] = set()
            seen_entries: set[str] = set()

            for addr, target, edge in targets:
                if addr in seen_entries:
                    continue
                seen_entries.add(addr)
                entry_conf = 0.4
                target_id: str | None = None
                if target is not None:
                    target_id = target.id
                    if target.kind == "function":
                        entry_conf = 0.85
                    else:
                        entry_conf = 0.55
                else:
                    # Maybe a function lives at this exact address but was reached
                    # by a generic edge.
                    candidate = self._node_for_address(addr)
                    if candidate is not None:
                        target_id = candidate.id
                        entry_conf = 0.75 if candidate.kind == "function" else 0.5

                entries.append(
                    {
                        "target_addr": addr,
                        "target_id": target_id,
                        "confidence": round(entry_conf, 3),
                    }
                )
                if edge.src != node.id:
                    referenced_by.add(edge.src)

            if not entries:
                continue

            table_conf = self._fptr_table_confidence(sym_conf, entries)
            fpt = FunctionPointerTable(
                address=base_addr,
                entries=entries,
                entry_size=self._estimate_entry_size(node),
                referenced_by=sorted(referenced_by),
            )
            # Annotate overall confidence into the first entry's metadata for
            # easy access; it does not otherwise exist on the dataclass.
            if fpt.entries:
                fpt.entries[0]["table_confidence"] = round(table_conf, 3)
            results.append(fpt)

        return results

    def _fptr_table_confidence(self, sym_conf: float, entries: list[dict[str, Any]]) -> float:
        if not entries:
            return 0.1
        resolved = sum(1 for e in entries if e.get("target_id"))
        funcs = sum(
            1
            for e in entries
            if e.get("target_id")
            and (nid := e["target_id"])
            and (n := self.graph.get_node(nid))
            and n.kind == "function"
        )
        resolution = resolved / len(entries)
        func_rate = funcs / len(entries)
        # Trust naming more than target resolution; many table entries may be
        # unresolved stubs, but vtable names are strong evidence on their own.
        score = 0.4 * sym_conf + 0.3 * resolution + 0.3 * func_rate
        return min(max(score, 0.0), 0.99)

    # ---------------------------------------------------------------- summary

    def summarize(self) -> dict[str, Any]:
        """Run both passes and return counts + lists of raw table dicts."""
        switches = self.find_switch_tables()
        fptrs = self.find_function_pointer_tables()
        return {
            "switch_tables": {
                "count": len(switches),
                "tables": [t.as_dict() for t in switches],
            },
            "function_pointer_tables": {
                "count": len(fptrs),
                "tables": [t.as_dict() for t in fptrs],
            },
        }
