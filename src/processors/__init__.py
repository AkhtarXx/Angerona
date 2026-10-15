"""Custom / VM ISA processor framework.

Angerona treats custom bytecodes as first-class targets by registering
processor modules that decode bytes into the same :class:`AnalysisGraph` IR used
by IDA and Ghidra outputs.  This lets analysis passes (CFG, stack frames, xref
graph) run unchanged on Solana BPF,EVM,or any future VM.
"""

from src.processors.base import Instruction, ProcessorModule
from src.processors.registry import ProcessorRegistry
from src.processors.loader import VmBytecodeLoader
from src.processors.analyzer import CustomIsaAnalyzer

__all__ = [
    "Instruction",
    "ProcessorModule",
    "ProcessorRegistry",
    "VmBytecodeLoader",
    "CustomIsaAnalyzer",
]
