"""Loader that turns raw VM / custom bytecode into an AnalysisGraph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.models.analysis_graph import AnalysisGraph, Edge, Node
from src.processors.base import ProcessorModule
from src.processors.registry import ProcessorRegistry


def _norm_hex(value: Any) -> str:
    if value is None or value == "":
        return "0x0"
    try:
        if isinstance(value, int):
            return f"0x{value & 0xFFFFFFFFFFFFFFFF:x}"
        return f"0x{int(str(value).strip(), 0) & 0xFFFFFFFFFFFFFFFF:x}"
    except Exception:
        return str(value)


class VmBytecodeLoader:
    """Load a custom-bytecode blob into the canonical AnalysisGraph IR."""

    def __init__(self, processor: ProcessorModule, base_addr: int = 0) -> None:
        self.processor = processor
        self.base_addr = base_addr

    @classmethod
    def from_registry(cls, name: str, base_addr: int = 0) -> "VmBytecodeLoader":
        """Create a loader using a registered processor."""
        proc_class = ProcessorRegistry.get(name)
        return cls(proc_class(), base_addr=base_addr)

    def load(self, data: bytes, *, program_name: str = "program") -> AnalysisGraph:
        """Disassemble the bytecode and return an AnalysisGraph."""
        graph = AnalysisGraph()
        program_id = f"program:{program_name}"
        program_node = Node(
            id=program_id,
            kind="program",
            address=_norm_hex(self.base_addr),
            name=program_name,
            properties={
                "processor": self.processor.name,
                "arch": self.processor.arch,
                "bits": self.processor.bits,
                "bytecode_size": len(data),
                "processor_maturity": self.processor.maturity,
                "coverage_notes": self.processor.coverage_notes,
                "function_model": "synthetic_single_function",
            },
        )
        graph.add_node(program_node)
        graph.metadata["processor"] = self.processor.name
        graph.metadata["arch"] = self.processor.arch
        graph.metadata["executable_path"] = program_name

        instructions = self.processor.disassemble(data, base_addr=self.base_addr)
        unknown_count = sum(insn.mnemonic == "db" for insn in instructions)
        decoded_count = len(instructions) - unknown_count
        graph.metadata.update({
            "processor_maturity": self.processor.maturity,
            "coverage_notes": self.processor.coverage_notes,
            "function_model": "synthetic_single_function",
            "instruction_count": len(instructions),
            "unknown_instruction_count": unknown_count,
            "decoded_instruction_ratio": (
                round(decoded_count / len(instructions), 6) if instructions else 0.0
            ),
        })

        # Treat the whole blob as one synthetic function unless we can detect
        # function entry patterns.  Calltargets become named functions.
        function_entries: dict[int, Node] = {}
        for idx, insn in enumerate(instructions):
            if insn.mnemonic in ("call", "CALL"):
                if self._is_helper_call(insn):
                    continue
                # For known immediate calls, create a target function stub.
                target = self._call_target(insn.address, insn.operands)
                if target is not None and target not in function_entries:
                    fn_node = Node(
                        id=f"func:0x{target:x}",
                        kind="function",
                        address=_norm_hex(target),
                        name=f"sub_{target:x}",
                        properties={"stub": True},
                    )
                    function_entries[target] = fn_node
                    graph.add_node(fn_node)

        main_fn = Node(
            id="func:main",
            kind="function",
            address=_norm_hex(self.base_addr),
            name="main",
            properties={"processor": self.processor.name},
        )
        graph.add_node(main_fn)
        function_entries[self.base_addr] = main_fn
        graph.add_edge(Edge(src=program_id, dst=main_fn.id, kind="contains"))

        # First pass: create all instruction nodes so forward jumps can resolve.
        for idx, insn in enumerate(instructions):
            addr = insn.address
            node_id = f"inst:0x{addr:x}"
            props = insn.as_dict()
            props["processor"] = self.processor.name
            node = Node(
                id=node_id,
                kind="instruction",
                address=_norm_hex(addr),
                name=insn.mnemonic,
                properties=props,
            )
            graph.add_node(node)
            graph.add_edge(Edge(src=main_fn.id, dst=node_id, kind="contains"))

        # Second pass: cross-reference edges.
        for idx, insn in enumerate(instructions):
            addr = insn.address
            node_id = f"inst:0x{addr:x}"
            for effect in insn.effects:
                kind = effect.get("kind")
                if kind == "call":
                    target = effect.get("target")
                    if effect.get("target_kind") == "helper" or self._is_helper_call(insn):
                        helper_name = str(effect.get("symbolic_target") or insn.properties.get("symbolic_target") or "")
                        if not helper_name and isinstance(target, int):
                            helper_name = f"helper_{target}"
                        if helper_name:
                            target_id = f"import:{helper_name}"
                            if graph.get_node(target_id) is None:
                                graph.add_node(Node(
                                    id=target_id,
                                    kind="import",
                                    address=_norm_hex(target) if isinstance(target, int) else "0x0",
                                    name=helper_name,
                                    properties={
                                        "processor": self.processor.name,
                                        "external": True,
                                        "helper_call": True,
                                    },
                                ))
                            graph.add_edge(Edge(
                                src=node_id,
                                dst=target_id,
                                kind="calls",
                                properties={"target_kind": "helper"},
                            ))
                        continue
                    if isinstance(target, int):
                        target_id = f"func:0x{target:x}"
                        if graph.get_node(target_id) is None:
                            graph.add_node(Node(
                                id=target_id,
                                kind="function",
                                address=_norm_hex(target),
                                name=f"sub_{target:x}",
                                properties={"stub": True, "external": True},
                            ))
                        graph.add_edge(Edge(src=node_id, dst=target_id, kind="calls"))
                elif kind in ("jump", "conditional_jump"):
                    target = effect.get("target")
                    if isinstance(target, int):
                        target_id = f"inst:0x{target:x}"
                        if graph.get_node(target_id):
                            edge_kind = "jump" if kind == "jump" else "conditional_jump"
                            graph.add_edge(Edge(src=node_id, dst=target_id, kind=edge_kind))
                elif kind == "fall_through" and idx + 1 < len(instructions):
                    next_addr = instructions[idx + 1].address
                    next_id = f"inst:0x{next_addr:x}"
                    if graph.get_node(next_id):
                        graph.add_edge(Edge(src=node_id, dst=next_id, kind="fall_through"))

        return graph

    def load_file(self, path: str | Path, *, program_name: str | None = None) -> AnalysisGraph:
        """Load bytecode from a file."""
        p = Path(path)
        data = p.read_bytes()
        name = program_name or p.name
        return self.load(data, program_name=name)

    def _call_target(self, addr: int, operands: str) -> int | None:
        """Attempt to extract an immediate call target from operands."""
        if not operands:
            return None
        # Skip symbolic target prefixes like "helper_33".
        if "_" in operands:
            return None
        try:
            return int(operands, 0)
        except Exception:
            return None

    def _is_helper_call(self, insn: Any) -> bool:
        """True for VM calls that target runtime helpers/syscalls, not functions."""
        if self.processor.name != "solana-bpf":
            return False
        props = getattr(insn, "properties", {}) or {}
        if props.get("call_target_kind") == "helper":
            return True
        symbolic = str(props.get("symbolic_target") or "")
        return symbolic.startswith("helper_")
