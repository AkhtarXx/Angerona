"""Solana/SBF reverse-engineering support."""

from .adapters import (
    SolanaAdapterStatus,
    collect_solana_adapter_status,
    ghidra_solana_language,
    is_solana_elf,
    preferred_solana_adapters,
    probe_solana_adapter_runtime,
)
from .fusion import (
    SolanaFusionResult,
    analyze_solana_with_engines,
    build_solana_engine_map,
    merge_solana_analyses,
)

__all__ = [
    "SolanaAdapterStatus",
    "collect_solana_adapter_status",
    "ghidra_solana_language",
    "is_solana_elf",
    "preferred_solana_adapters",
    "probe_solana_adapter_runtime",
    "SolanaFusionResult",
    "analyze_solana_with_engines",
    "build_solana_engine_map",
    "merge_solana_analyses",
]
