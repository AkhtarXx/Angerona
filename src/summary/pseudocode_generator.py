"""Convert an AnalysisGraph function subgraph into structured pseudocode."""

from __future__ import annotations

from typing import Any, Iterable

from src.models.analysis_graph import AnalysisGraph, Edge, Node
from src.summary.models import PseudocodeFunction, PseudocodeLine


class PseudocodeGenerator:
    """Generate structured pseudocode from an analysis graph."""

    def __init__(self, graph: AnalysisGraph) -> None:
        self.graph = graph

    def generate_all(self, *, structured: bool = False,
                     render_asm: bool = True) -> dict[str, PseudocodeFunction]:
        """Build pseudocode for every function in the graph."""
        result: dict[str, PseudocodeFunction] = {}
        for node in self.graph.nodes:
            if node.kind == "function":
                result[node.id] = self.generate(
                    node.id, structured=structured, render_asm=render_asm)
        return result

    def generate(self, function_id: str, *, structured: bool = False,
                 render_asm: bool = True) -> PseudocodeFunction:
        """Build pseudocode for a single function.

        With ``structured=True`` the request is delegated to the Phoenix-style
        :class:`StructuredPseudocodeGenerator` (goto-free regions over the
        block CFG).  The default ``False`` keeps the original flat behavior.
        """
        if structured:
            from src.summary.structured_pseudocode import StructuredPseudocodeGenerator
            return StructuredPseudocodeGenerator(
                self.graph, render_asm=render_asm).generate(function_id)

        fn_node = self._find_function(function_id)
        if fn_node is None:
            return PseudocodeFunction(
                function_id=function_id,
                name=function_id,
                pseudocode=[PseudocodeLine(text=f"// function not found: {function_id}")],
            )

        lines: list[PseudocodeLine] = []
        lines.append(PseudocodeLine(
            text=f"// function {fn_node.name or fn_node.id} @ {fn_node.address or '?'}"
        ))
        lines.append(PseudocodeLine(
            text=f"{self._signature(fn_node)}",
            kind="statement",
        ))
        lines.append(PseudocodeLine(text="{"))

        blocks = self._blocks(fn_node.id)
        calls: set[str] = set()
        strings: set[str] = set()

        for block in blocks:
            block_label = block.address or block.id
            lines.append(PseudocodeLine(
                depth=1,
                label=block_label,
                text=f"// block {block_label}",
                kind="comment",
            ))
            for insn in self._instructions(block.id):
                rendered = self._render_instruction(insn)
                if rendered:
                    lines.append(PseudocodeLine(depth=1, label=insn.address, text=rendered))
                for c in self._calls_from_instruction(insn.id):
                    calls.add(c)
                for s in self._strings_from_instruction(insn.id):
                    strings.add(s)

            outgoing = self._outgoing_edges(block.id)
            for edge in outgoing:
                if edge.kind == "jump":
                    dst = self.graph.get_node(edge.dst)
                    lines.append(PseudocodeLine(
                        depth=1,
                        text=f"goto {dst.address if dst else edge.dst};",
                        kind="branch",
                    ))
                elif edge.kind == "conditional_jump":
                    dst = self.graph.get_node(edge.dst)
                    lines.append(PseudocodeLine(
                        depth=1,
                        text=f"if (cond) goto {dst.address if dst else edge.dst};",
                        kind="branch",
                    ))
                elif edge.kind == "fall_through" and "conditional_jump" not in {e.kind for e in outgoing}:
                    pass  # fall-through renders implicitly at the bottom

        lines.append(PseudocodeLine(text="}"))

        return PseudocodeFunction(
            function_id=fn_node.id,
            address=fn_node.address,
            name=fn_node.name,
            signature=self._signature(fn_node),
            pseudocode=lines,
            calls=sorted(calls),
            strings=sorted(strings),
        )

    def _find_function(self, function_id: str) -> Node | None:
        node = self.graph.get_node(function_id)
        if node is not None and node.kind == "function":
            return node
        for n in self.graph.nodes:
            if n.kind == "function" and (n.id == function_id or n.name == function_id or n.address == function_id):
                return n
        return None

    def _blocks(self, fn_id: str) -> list[Node]:
        blocks: list[Node] = []
        for edge in self.graph.edges:
            if edge.kind == "contains" and edge.src == fn_id:
                block = self.graph.get_node(edge.dst)
                if block and block.kind == "block":
                    blocks.append(block)
        return sorted(blocks, key=lambda b: self._addr_int(b.address) or 0)

    def _instructions(self, block_id: str) -> list[Node]:
        insns: list[Node] = []
        for edge in self.graph.edges:
            if edge.kind == "contains" and edge.src == block_id:
                insn = self.graph.get_node(edge.dst)
                if insn and insn.kind == "instruction":
                    insns.append(insn)
        return sorted(insns, key=lambda i: self._addr_int(i.address) or 0)

    def _outgoing_edges(self, block_id: str) -> list[Edge]:
        return [e for e in self.graph.edges if e.src == block_id and e.kind in {"jump", "conditional_jump", "fall_through"}]

    def _render_instruction(self, insn: Node) -> str | None:
        text = insn.properties.get("text") or insn.properties.get("mnemonic") or insn.properties.get("disasm")
        if text:
            return f"{text}"
        if insn.name:
            return f"{insn.name}"
        return f"insn @ {insn.address or '?' }"

    def _calls_from_instruction(self, insn_id: str) -> Iterable[str]:
        for edge in self.graph.edges:
            if edge.src == insn_id and edge.kind == "calls":
                callee = self.graph.get_node(edge.dst)
                if callee:
                    yield callee.name or callee.id

    def _strings_from_instruction(self, insn_id: str) -> Iterable[str]:
        for edge in self.graph.edges:
            if edge.src == insn_id and edge.kind in {"data_read", "references"}:
                ref = self.graph.get_node(edge.dst)
                if ref and ref.kind == "string":
                    yield ref.name or ref.properties.get("value") or ref.id

    def _signature(self, fn_node: Node) -> str:
        sig = fn_node.properties.get("signature")
        if sig:
            return str(sig)
        name = fn_node.name or "sub_<unknown>"
        return f"void {name}(void)"

    @staticmethod
    def _addr_int(address: str | None) -> int | None:
        if address is None:
            return None
        try:
            return int(address, 0)
        except Exception:
            return None
