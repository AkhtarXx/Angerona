"""End-to-end custom ISA analyzer.

Routes a bytecode sample through the registered processor, builds an
AnalysisGraph, and runs generic passes (CFG, stack frames, indirect flow) on
the custom graph.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.analysis.cfg_spine import CFGSpine
from src.analysis.indirect_flow import IndirectFlowRecovery
from src.analysis.stack_frame_recovery import StackFrameRecovery
from src.models.analysis_graph import AnalysisGraph
from src.processors.loader import VmBytecodeLoader
from src.processors.registry import ProcessorRegistry


class CustomIsaAnalyzer:
    """Analyze a custom-bytecode binary end-to-end."""

    def __init__(self, isa_name: str) -> None:
        proc_class = ProcessorRegistry.get(isa_name)
        self.processor = proc_class()
        self.loader = VmBytecodeLoader(self.processor)
        self.isa_name = isa_name

    def analyze(self, binary: str | Path | bytes, *, base_addr: int = 0) -> dict[str, Any]:
        """Load and analyze a custom-binary sample.

        Returns a dictionary with ``graph``, ``cfgs``, ``frames``, and
        ``indirect_tables``.
        """
        if isinstance(binary, (str, Path)):
            loader = VmBytecodeLoader(self.processor, base_addr=base_addr)
            graph = loader.load_file(binary)
        else:
            loader = VmBytecodeLoader(self.processor, base_addr=base_addr)
            graph = loader.load(binary, program_name="custom_sample")

        cfg_spine = CFGSpine(graph)
        cfgs = cfg_spine.build_all()

        frames: dict[str, Any] = {}
        sf = StackFrameRecovery(graph)
        for node in graph.nodes:
            if node.kind == "function":
                frame = sf.recover(node)
                frames[node.id] = frame.as_dict() if frame else None

        indirect = IndirectFlowRecovery(graph)
        switch_tables = indirect.find_switch_tables()
        ptr_tables = indirect.find_function_pointer_tables()
        indirect_tables = switch_tables + ptr_tables  # type: ignore[operator]

        return {
            "graph": graph,
            "cfgs": {addr: cfg.as_dict() for addr, cfg in cfgs.items()},
            "frames": frames,
            "indirect_tables": [t.as_dict() for t in indirect_tables],
            "processor": self.isa_name,
        }

    @classmethod
    def supported_isas(cls) -> list[str]:
        return ProcessorRegistry.list()
