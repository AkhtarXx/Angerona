"""Register the built-in custom ISA processors.

Import this module once at application startup to make solana-bpf and evm
available through the registry.
"""

from src.processors.registry import ProcessorRegistry
from src.processors.solana_bpf import SolanaBpfProcessor
from src.processors.wasm import WasmProcessor
from src.processors.lua_bc import Lua51Processor, Lua53Processor, Lua54Processor
from src.processors.pyc import PycProcessor, Pyc38Processor, Pyc311Processor
from src.processors.jvm import JvmProcessor
from src.processors.dex import DexProcessor
from src.processors.cil import CilProcessor
from src.processors.beam import BeamProcessor
from src.processors.v8_ignition import V8IgnitionProcessor
from src.processors.evm import EvmProcessor


def register_defaults() -> None:
    if not ProcessorRegistry.has("solana-bpf"):
        ProcessorRegistry.register("solana-bpf", SolanaBpfProcessor)
    if not ProcessorRegistry.has("evm"):
        ProcessorRegistry.register("evm", EvmProcessor)


def register_managed_defaults() -> None:
    """Managed-runtime bytecode processors (wave 1+2: wasm, lua, pyc, jvm, dex, cil, beam, v8-ignition)."""
    for key, cls in (
        ("wasm", WasmProcessor),
        ("lua51", Lua51Processor),
        ("lua53", Lua53Processor),
        ("lua54", Lua54Processor),
        ("pyc", PycProcessor),
        ("pyc-38", Pyc38Processor),
        ("pyc-311", Pyc311Processor),
        ("jvm", JvmProcessor),
        ("dex", DexProcessor),
        ("cil", CilProcessor),
        ("beam", BeamProcessor),
        ("v8-ignition", V8IgnitionProcessor),
    ):
        if not ProcessorRegistry.has(key):
            ProcessorRegistry.register(key, cls)
