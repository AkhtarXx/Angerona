"""Control-flow guided disassembly spine.

This module builds a function-level Control Flow Graph (CFG) from an
engine-agnostic :class:`AnalysisGraph`.  It is inspired by the techniques
described in *The IDA Pro Book*: recursive descent disassembly, basic-block
construction, function chunks, fall-through tracking, and control-flow aware
recovery of indirect jumps (switch tables, jump tables, function-pointer
tables).

The implementation keeps heavy dependencies to a minimum.  Only the standard
library and :class:`AnalysisGraph` from ``src.models.analysis_graph`` are
required.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable


def _cfg_cache_enabled() -> bool:
    """Return whether :meth:`CFGSpine.build_all` should consult a shared cache.

    Controlled by the ``ANGERONA_CFG_CACHE`` environment variable.  Caching is
    ON by default; any value that parses as false (``0``, ``false``, ``no``,
    ``off``) disables it.
    """
    raw = os.environ.get("ANGERONA_CFG_CACHE", "").strip().lower()
    if not raw:
        return True
    return raw not in ("0", "false", "no", "off")


def _norm_hex(addr: Any) -> str:
    """Normalize an address to a lower-case ``0x...`` hex string."""
    if addr is None or addr == "":
        return "0x0"
    try:
        if isinstance(addr, int):
            return f"0x{addr & 0xFFFFFFFFFFFFFFFF:x}"
        s = str(addr).strip()
        if s.lower().startswith("addr("):
            s = s.lower().replace("addr(", "").replace(")", "")
        if s.startswith("0x"):
            return f"0x{int(s, 16) & 0xFFFFFFFFFFFFFFFF:x}"
        return f"0x{int(s, 0) & 0xFFFFFFFFFFFFFFFF:x}"
    except Exception:
        return str(addr)


@dataclass
class BasicBlock:
    """A single basic block in a function CFG."""

    address: str
    instructions: list[dict[str, Any]] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Serialize the block to a plain dictionary."""
        return {
            "address": self.address,
            "instructions": list(self.instructions),
            "successors": list(self.successors),
            "predecessors": list(self.predecessors),
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
        }


@dataclass
class FunctionCFG:
    """A function-level CFG composed of :class:`BasicBlock` instances."""

    address: str
    name: str | None
    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    entry: str | None = None
    exits: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the function CFG to a plain dictionary."""
        return {
            "address": self.address,
            "name": self.name,
            "entry": self.entry,
            "exits": list(self.exits),
            "blocks": {addr: block.as_dict() for addr, block in self.blocks.items()},
        }

    def all_paths(self, max_paths: int = 100) -> list[list[str]]:
        """Enumerate up to ``max_paths`` acyclic paths from entry to exits.

        Paths are returned as lists of block addresses.  Cycles are truncated
        to keep enumeration finite and useful for downstream summaries.
        """
        if not self.entry or self.entry not in self.blocks:
            return []

        paths: list[list[str]] = []
        stack: list[tuple[str, list[str]]] = [(self.entry, [self.entry])]

        while stack and len(paths) < max_paths:
            addr, path = stack.pop()
            block = self.blocks[addr]
            if block.is_exit or not block.successors:
                paths.append(path)
                continue
            for succ in block.successors:
                if succ in path:
                    # Terminate the path at the back-edge to avoid infinite loops.
                    paths.append(path + [succ])
                    continue
                if succ in self.blocks:
                    stack.append((succ, path + [succ]))

        return paths

    def depth(self) -> int:
        """Return the longest acyclic path length measured in block count.

        A single-block function has depth ``1``.
        """
        if not self.entry or self.entry not in self.blocks:
            return 0

        memo: dict[str, int] = {}

        def longest(addr: str, seen: set[str]) -> int:
            if addr in seen:
                return 0
            if addr in memo:
                return memo[addr]
            block = self.blocks.get(addr)
            if block is None:
                return 0
            seen.add(addr)
            best = 0
            for succ in block.successors:
                if succ in self.blocks:
                    best = max(best, longest(succ, seen))
            seen.discard(addr)
            memo[addr] = 1 + best
            return memo[addr]

        return longest(self.entry, set())


class CFGSpine:
    """Build function-level CFGs from an :class:`AnalysisGraph`.

    The spine follows the recursive-descent philosophy:  after every control-
    flow instruction it starts a new basic block at the next possible target.
    When instruction-level nodes are missing it falls back to synthesising a
    single block from the function node properties.
    """

    # Instruction classification sets.  These are intentionally conservative
    # and cover the most common architectures (x86, x86-64, ARM, AArch64).
    _TERMINAL = {
        "ret", "retn", "retf", "iret", "iretd", "iretq",
        "bx", "blx", "bxeq", "bxne", "bxlt", "bxgt",  # ARM returns via BX LR
        "eret", "mret", "sret",
        "ud2", "hlt", "udf", "brk",
    }
    _UNCONDITIONAL_JUMP = {
        "jmp", "b", "br", "bra",
        "bx", "bxx",
    }
    _CONDITIONAL_JUMP = {
        "je", "jne", "jz", "jnz", "ja", "jae", "jna", "jnae",
        "jb", "jbe", "jnb", "jnbe", "jnc", "jg", "jge", "jl", "jle",
        "jo", "jno", "js", "jns", "jp", "jnp",
        "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
        "beq", "bne", "blt", "ble", "bgt", "bge", "bcs", "bcc",
        "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "blo", "bhs",
    }
    _CALL = {
        "call", "callq", "bl", "blx", "bral",
    }
    _RETURN = {
        "ret", "retn", "retf", "iret", "iretd", "iretq",
        "eret", "mret", "sret",
        "bx", "bxeq", "bxne", "bxlt", "bxgt",
    }
    _FALL_THROUGH = {
        "nop", "nopl", "nopw", "nopd", "mov", "movabs",
        "push", "pop", "sub", "add", "and", "or", "xor", "not",
        "inc", "dec", "cmp", "test", "lea", "xchg", "cmov",
        "ldr", "str", "ldm", "stm", "mul", "div",
        "sete", "setne", "setz", "setnz", "shl", "shr", "sar", "rol", "ror",
    }

    def __init__(self, graph: "AnalysisGraph") -> None:
        """Create a new spine bound to ``graph``."""
        # Import lazily to avoid circular imports when this module is reloaded.
        from src.models.analysis_graph import AnalysisGraph

        if not isinstance(graph, AnalysisGraph):
            raise TypeError("CFGSpine requires an AnalysisGraph instance")
        self.graph = graph

    # Optional process-wide cache consulted by :meth:`build_all`.  Lazily
    # created to keep import order acyclic (``cfg_cache`` imports this module).
    _default_cache: Any = None

    @classmethod
    def default_cache(cls, enabled: bool | None = None) -> Any:
        """Return the shared :class:`CFGCache` (or ``None`` when disabled).

        ``enabled`` defaults to the ``ANGERONA_CFG_CACHE`` environment toggle.
        Subclasses (e.g. ``CachedCFGSpine``) that manage their own cache
        override this via instance state and never reach for the shared one.
        """
        if enabled is None:
            enabled = _cfg_cache_enabled()
        if not enabled:
            return None
        if cls._default_cache is None:
            from src.analysis.cfg_cache import CFGCache

            cls._default_cache = CFGCache()
        return cls._default_cache

    # --------------------------------------------------------------------- classification

    def _is_terminal(self, mnemonic: str) -> bool:
        """Return ``True`` if the instruction terminates the current block."""
        m = (mnemonic or "").lower().strip()
        if m in self._TERMINAL or m in self._UNCONDITIONAL_JUMP or m in self._CONDITIONAL_JUMP:
            return True
        return m.startswith("j")

    def _is_data_manipulation(self, mnemonic: str) -> bool:
        """Return True for mnemonics that should never be treated as terminals."""
        return (mnemonic or "").lower().strip() in {
            "bswap", "bt", "btc", "btr", "bts", "bsf", "bsr", "bound", "bnd",
            "bextr", "blsi", "blmsk", "blsr", "bzhi",
        }

    def _is_unconditional_jump(self, mnemonic: str) -> bool:
        """Return ``True`` if the instruction is an unconditional jump."""
        m = (mnemonic or "").lower().strip()
        return m in self._UNCONDITIONAL_JUMP

    def _is_conditional_jump(self, mnemonic: str) -> bool:
        """Return ``True`` if the instruction is a conditional jump/branch."""
        m = (mnemonic or "").lower().strip()
        return m in self._CONDITIONAL_JUMP

    def _is_call(self, mnemonic: str) -> bool:
        """Return ``True`` if the instruction is a call/branch-with-link."""
        m = (mnemonic or "").lower().strip()
        return m in self._CALL

    def _is_return(self, mnemonic: str) -> bool:
        """Return ``True`` if the instruction returns from the function."""
        m = (mnemonic or "").lower().strip()
        return m in self._RETURN or m in ("bx lr", "blx lr")

    def _fall_through(self, mnemonic: str) -> bool:
        """Return ``True`` if execution normally falls through to the next instruction."""
        m = (mnemonic or "").lower().strip()
        if self._is_unconditional_jump(m) or self._is_return(m):
            return False
        if self._is_call(m) or self._is_conditional_jump(m) or m in self._FALL_THROUGH:
            return True
        # Unknown instructions are assumed to fall through so that the spine
        # remains conservative and does not drop code.
        return True

    # --------------------------------------------------------------------- helpers

    def _address_to_int(self, addr: str | int | None) -> int:
        """Convert a graph address value to an integer."""
        if addr is None:
            return 0
        if isinstance(addr, int):
            return addr & 0xFFFFFFFFFFFFFFFF
        try:
            s = str(addr).strip()
            if s.lower().startswith("addr("):
                s = s.lower().replace("addr(", "").replace(")", "")
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16) & 0xFFFFFFFFFFFFFFFF
            if s:
                return int(s, 0) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            pass
        return 0

    @staticmethod
    def _jump_targets(text_or_operands: str, base_addr: int) -> list[int]:
        """Parse candidate immediate target addresses from operands.

        Supports ``ADDR``, ``0xADDR``, ``[base+offset]``-style expressions, and
        the placeholder form ``[table ... <addr>]``.  ``base_addr`` is used to
        resolve relative offsets when necessary; currently absolute targets are
        preferred.
        """
        text = (text_or_operands or "").strip()
        targets: list[int] = []

        # Placeholder for table references emitted by engine scripts.
        for m in re.finditer(r"\[table[^\]]*<([^>]+)>\]", text, re.IGNORECASE):
            try:
                targets.append(int(m.group(1).strip(), 0) & 0xFFFFFFFFFFFFFFFF)
            except Exception:
                pass

        # Bracket expressions that contain a hex number.
        for m in re.finditer(r"\[([^\]]+)\]", text):
            inner = m.group(1)
            for token in re.finditer(r"0x[0-9a-fA-F]+", inner):
                try:
                    targets.append(int(token.group(), 16) & 0xFFFFFFFFFFFFFFFF)
                except Exception:
                    pass

        # General hex numbers.  Pick the most-likely-code candidate by preferring
        # values near the base address over tiny constants or obviously huge
        # ones.  Relative short jumps are also accepted.
        for m in re.finditer(r"(?:0x[0-9a-fA-F]+|\b[0-9]+\b)", text):
            try:
                val = int(m.group(), 0)
                if val < 0x10 or val > 0xFFFFFFFFFFFFFFFF:
                    continue
                targets.append(val & 0xFFFFFFFFFFFFFFFF)
            except Exception:
                pass

        # x86-style relative jumps: ``jmp short/jmp near`` with ``+``/``-``
        # offset inside the operand literal.
        rel_match = re.search(r"([+\-]\s*(?:0x)?[0-9a-fA-F]+)", text)
        if rel_match:
            try:
                offset = int(rel_match.group(1).replace(" ", ""), 0)
                targets.append((base_addr + offset) & 0xFFFFFFFFFFFFFFFF)
            except Exception:
                pass

        return sorted(set(targets))

    def _collect_instructions(self, fn_node: "Node") -> list[dict[str, Any]]:
        """Collect instruction nodes contained by ``fn_node``.

        The returned dictionaries always contain ``address``, ``mnemonic``,
        ``operands`` and ``bytes``.  When instruction nodes are absent an
        empty list is returned so the caller can synthesise blocks.
        """
        from src.models.analysis_graph import Edge

        instrs: list[dict[str, Any]] = []
        # Prefer direct contains edges from function -> instruction.
        for edge in self.graph.edge_list(fn_node.id, edge_kind="contains", direction="out"):
            if not isinstance(edge, Edge):
                continue
            node = self.graph.get_node(edge.dst)
            if node is None or node.kind != "instruction":
                continue
            props = node.properties or {}
            instr: dict[str, Any] = {
                "address": _norm_hex(node.address or props.get("address")),
                "mnemonic": props.get("mnemonic", "nop"),
                "operands": props.get("operands", ""),
                "bytes": props.get("bytes", ""),
                "text": props.get("text", ""),
                "size": props.get("size", 0),
            }
            for key in ("comment",):
                if key in props:
                    instr[key] = props[key]
            instrs.append(instr)

        # Also accept function -> block -> instruction hierarchies.
        for edge in self.graph.edge_list(fn_node.id, edge_kind="contains", direction="out"):
            if not isinstance(edge, Edge):
                continue
            block = self.graph.get_node(edge.dst)
            if block is None or block.kind != "block":
                continue
            for bedge in self.graph.edge_list(block.id, edge_kind="contains", direction="out"):
                if not isinstance(bedge, Edge):
                    continue
                node = self.graph.get_node(bedge.dst)
                if node is None or node.kind != "instruction":
                    continue
                props = node.properties or {}
                instr = {
                    "address": _norm_hex(node.address or props.get("address")),
                    "mnemonic": props.get("mnemonic", "nop"),
                    "operands": props.get("operands", ""),
                    "bytes": props.get("bytes", ""),
                    "text": props.get("text", ""),
                    "size": props.get("size", 0),
                }
                for key in ("comment",):
                    if key in props:
                        instr[key] = props[key]
                instrs.append(instr)

        instrs.sort(key=lambda i: self._address_to_int(i.get("address")))
        # Deduplicate while preserving order.
        seen: set[int] = set()
        unique: list[dict[str, Any]] = []
        for instr in instrs:
            addr_int = self._address_to_int(instr.get("address"))
            if addr_int in seen:
                continue
            seen.add(addr_int)
            unique.append(instr)
        return unique

    # --------------------------------------------------------------------- indirect flow recovery

    def recover_indirect_targets(self, fn_node: "Node", block: BasicBlock) -> list[int]:
        """Heuristic recovery of indirect jump targets.

        Scans ``fn_node`` properties and data-reference edges for anything that
        looks like a switch/jump table or a function-pointer table.  Returns a
        list of candidate target addresses filtered by plausible function
        boundaries and string-reference availability.
        """
        candidates: set[int] = set()
        fn_props = fn_node.properties or {}
        fn_start = self._address_to_int(fn_node.address)
        fn_end = fn_start
        if isinstance(fn_props.get("size"), int):
            fn_end = fn_start + fn_props["size"]

        # Pull any tables explicitly embedded in function properties.
        for key in ("switch_table", "jump_table", "case_addresses", "table_addresses"):
            raw = fn_props.get(key)
            if raw is None:
                continue
            entries = raw if isinstance(raw, Iterable) and not isinstance(raw, str) else [raw]
            for entry in entries:
                try:
                    candidates.add(self._address_to_int(entry))
                except Exception:
                    pass

        # Treat any property whose name contains ``case``/``jump``/``table`` as
        # a potential list of addresses.
        for key, value in fn_props.items():
            low = key.lower()
            if "case" in low or "jump" in low or "table" in low or "target" in low:
                entries = value if isinstance(value, Iterable) and not isinstance(value, str) else [value]
                for entry in entries:
                    try:
                        candidates.add(self._address_to_int(entry))
                    except Exception:
                        pass

        # Data references originating from this function are strong candidates.
        # We only consider ``data_read`` and ``offset`` edges (table lookups).",
        for edge in self.graph.edge_list(fn_node.id, direction="out"):
            if edge.kind in ("data_read", "offset", "references"):
                target = self._address_to_int(getattr(edge, "address", None))
                if target == 0:
                    continue
                candidates.add(target)
                # Dereference: read consecutive words as code pointers.  This is
                # a coarse heuristic that works for many jump tables.  We try a
                # few common pointer sizes.
                target_node = self.graph.get_node(edge.dst)
                if target_node is not None:
                    tprops = target_node.properties or {}
                    for raw in (tprops.get("pointers"), tprops.get("entries"),
                                tprops.get("values"), tprops.get("case_addresses")):
                        if raw is None:
                            continue
                        entries = raw if isinstance(raw, Iterable) and not isinstance(raw, str) else [raw]
                        for entry in entries:
                            try:
                                candidates.add(self._address_to_int(entry))
                            except Exception:
                                pass

        # Filter: keep addresses that look like code.  We accept targets inside
        # the current function or any known function entry.  String addresses and
        # obviously invalid values are dropped.
        function_entries: set[int] = set()
        for node in self.graph.nodes:
            if node.kind == "function":
                function_entries.add(self._address_to_int(node.address))

        string_addresses: set[int] = set()
        for node in self.graph.nodes:
            if node.kind == "string":
                string_addresses.add(self._address_to_int(node.address))

        result: list[int] = []
        for addr in candidates:
            if addr == 0 or addr in string_addresses:
                continue
            if addr >= fn_start and (fn_end == fn_start or addr < fn_end):
                result.append(addr)
                continue
            if addr in function_entries:
                result.append(addr)
                continue
            # Targets within a reasonable distance of the current function are
            # also accepted as likely code pointers.
            if abs(addr - fn_start) < 0x10_0000:
                result.append(addr)

        return sorted(set(result))

    # --------------------------------------------------------------------- CFG construction

    def _synthetic_blocks(self, fn_node: "Node") -> dict[str, BasicBlock]:
        """Create a single block from function properties when instructions are absent."""
        addr = _norm_hex(fn_node.address)
        props = fn_node.properties or {}
        text = props.get("disassembly") or props.get("decompiled") or ""
        block = BasicBlock(
            address=addr,
            instructions=self._parse_disassembly_text(addr, text),
            is_entry=True,
            is_exit=True,
        )
        return {addr: block}

    @staticmethod
    def _parse_disassembly_text(base_addr: str, text: str) -> list[dict[str, Any]]:
        """Parse a newline-separated disassembly string into instruction dicts."""
        instructions: list[dict[str, Any]] = []
        if not text:
            instructions.append({
                "address": base_addr,
                "mnemonic": "unknown",
                "operands": "",
                "bytes": "",
                "text": "",
                "size": 0,
            })
            return instructions

        base_int = 0
        try:
            base_int = int(base_addr, 16)
        except Exception:
            pass

        # Parse instructions roughly.  Lines may be:
        #   0x401000: push rbp
        #   0x401000: 48 89 e5 mov rbp, rsp
        #   push rbp
        #   00401000 push rbp
        line_re = re.compile(
            r"^(?:(?:0x)?[0-9a-fA-F]+[:\s]+)?"  # optional address prefix
            r"(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\s+)?"  # optional hex byte column
            r"([a-zA-Z0-9_.@]+)"  # mnemonic
            r"(?:\s+(.*))?\s*$"   # optional operands
        )
        addr_re = re.compile(r"^((?:0x)?[0-9a-fA-F]+)[:\s]+")
        addr_int = base_int
        size = 0
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("//")]
        if not lines:
            instructions.append({
                "address": base_addr,
                "mnemonic": "unknown",
                "operands": "",
                "bytes": "",
                "text": "",
                "size": 0,
            })
            return instructions

        for line in lines:
            m = addr_re.match(line.strip())
            if m:
                try:
                    addr_int = int(m.group(1), 16)
                except Exception:
                    pass
            m2 = line_re.match(line.strip())
            if m2:
                mnemonic = m2.group(1).lower().strip()
                operands = (m2.group(2) or "").strip()
                instructions.append({
                    "address": _norm_hex(addr_int),
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "bytes": "",
                    "text": line.strip(),
                    "size": 0,
                })
                # Advance guessed instruction size conservatively, but not needed
                # for CFG structure over text.
                addr_int = (addr_int + 1) & 0xFFFFFFFFFFFFFFFF
            else:
                # Skip labels.
                stripped = line.strip().rstrip(":")
                if stripped:
                    instructions.append({
                        "address": _norm_hex(addr_int),
                        "mnemonic": stripped,
                        "operands": "",
                        "bytes": "",
                        "text": line.strip(),
                        "size": 0,
                    })
                    addr_int = (addr_int + 1) & 0xFFFFFFFFFFFFFFFF
        return instructions

    def build_function_cfg(self, fn_node: "Node") -> FunctionCFG:
        """Build a :class:`FunctionCFG` for ``fn_node`` using recursive descent."""
        fn_addr = _norm_hex(fn_node.address)
        instructions = self._collect_instructions(fn_node)

        if not instructions:
            blocks = self._synthetic_blocks(fn_node)
            cfg = FunctionCFG(address=fn_addr, name=fn_node.name, blocks=blocks,
                             entry=fn_addr, exits=[fn_addr])
            return cfg

        # First pass: determine block boundaries (leaders).
        leaders: set[int] = {self._address_to_int(instructions[0]["address"])}
        for idx, instr in enumerate(instructions):
            addr_int = self._address_to_int(instr["address"])
            mnemonic = str(instr.get("mnemonic", "")).lower().strip()

            if self._is_terminal(mnemonic) or self._is_unconditional_jump(mnemonic) or self._is_return(mnemonic):
                # Next instruction, if any, starts a new block.
                if idx + 1 < len(instructions):
                    leaders.add(self._address_to_int(instructions[idx + 1]["address"]))

            # Every explicit target of a control-flow instruction is a leader.
            text = str(instr.get("operands", ""))
            if not text:
                text = str(instr.get("text", ""))
            for target in self._jump_targets(text, addr_int):
                if target != 0:
                    leaders.add(target)

        # Build address -> instruction lookup.
        addr_to_instr: dict[int, dict[str, Any]] = {}
        for instr in instructions:
            addr_to_instr[self._address_to_int(instr["address"])] = instr

        # Extend leaders with recovered indirect targets so switch cases become
        # first-class blocks even without direct edges.
        for instr in instructions:
            mnemonic = str(instr.get("mnemonic", "")).lower().strip()
            if mnemonic in ("jmp", "br", "bx", "b") and "[" in str(instr.get("operands", "")):
                # Heuristic: this looks like an indirect table jump.
                placeholder_blocks = [b for b in self.blocks_for_function(fn_node)]
                if len(instructions) > 1:
                    addr_int = self._address_to_int(instr["address"])
                    # Build a lightweight temporary block containing this one
                    # instruction so recover_indirect_targets has context.
                    tmp = BasicBlock(address=_norm_hex(addr_int), instructions=[instr])
                    for cand in self.recover_indirect_targets(fn_node, tmp):
                        leaders.add(cand)

        # Second pass: populate blocks.
        blocks: dict[str, BasicBlock] = {}
        current: list[dict[str, Any]] = []
        current_start: int | None = None

        by_addr = dict(sorted(addr_to_instr.items()))
        for addr_int, instr in by_addr.items():
            addr_hex = _norm_hex(addr_int)
            if addr_int in leaders and current:
                assert current_start is not None
                blocks[_norm_hex(current_start)] = BasicBlock(
                    address=_norm_hex(current_start),
                    instructions=list(current),
                )
                current = []
            if not current:
                current_start = addr_int
            current.append(instr)

        if current:
            assert current_start is not None
            blocks[_norm_hex(current_start)] = BasicBlock(
                address=_norm_hex(current_start),
                instructions=list(current),
            )

        # Third pass: resolve successors and predecessors.
        block_starts = sorted(self._address_to_int(a) for a in blocks)
        start_set = set(block_starts)

        for start in block_starts:
            block = blocks[_norm_hex(start)]
            last = block.instructions[-1]
            mnemonic = str(last.get("mnemonic", "")).lower().strip()
            text = str(last.get("operands", ""))
            if not text:
                text = str(last.get("text", ""))
            last_addr = self._address_to_int(last.get("address"))

            if self._is_return(mnemonic):
                block.is_exit = True
                continue

            # Direct targets.
            direct_targets = self._jump_targets(text, last_addr)
            for target in direct_targets:
                if target in start_set:
                    succ_hex = _norm_hex(target)
                    if succ_hex not in block.successors:
                        block.successors.append(succ_hex)
                    succ_block = blocks[succ_hex]
                    if block.address not in succ_block.predecessors:
                        succ_block.predecessors.append(block.address)

            # Indirect jump recovery.
            if self._is_unconditional_jump(mnemonic) and "[" in text:
                for target in self.recover_indirect_targets(fn_node, block):
                    if target in start_set:
                        succ_hex = _norm_hex(target)
                        if succ_hex not in block.successors:
                            block.successors.append(succ_hex)
                        succ_block = blocks[succ_hex]
                        if block.address not in succ_block.predecessors:
                            succ_block.predecessors.append(block.address)

            # Fall-through for calls and conditional jumps.
            if self._fall_through(mnemonic):
                next_addr = last_addr + (int(last.get("size", 0)) or self._guess_size(last, text))
                if next_addr in start_set:
                    succ_hex = _norm_hex(next_addr)
                    if succ_hex not in block.successors:
                        block.successors.append(succ_hex)
                    succ_block = blocks[succ_hex]
                    if block.address not in succ_block.predecessors:
                        succ_block.predecessors.append(block.address)
                # If the next block is unknown, calls and conditional jumps simply
                # have an incomplete successor set; they are *not* exits.

            if not block.successors and not self._fall_through(mnemonic):
                block.is_exit = True

        entry_addr = _norm_hex(self._address_to_int(instructions[0]["address"]))
        if entry_addr in blocks:
            blocks[entry_addr].is_entry = True

        exits = [addr for addr, block in blocks.items() if block.is_exit]
        if not exits:
            # Defensive fallback: leaf blocks with no successors are exits.
            for addr, block in blocks.items():
                if not block.successors:
                    block.is_exit = True
                    exits.append(addr)

        cfg = FunctionCFG(
            address=fn_addr,
            name=fn_node.name,
            blocks=blocks,
            entry=entry_addr,
            exits=exits,
        )
        return cfg

    def _guess_size(self, instr: dict[str, Any], text: str) -> int:
        """Estimate instruction size when the property is missing."""
        raw_bytes = instr.get("bytes")
        if raw_bytes:
            try:
                if isinstance(raw_bytes, (list, tuple)):
                    return len(raw_bytes)
                if isinstance(raw_bytes, str):
                    cleaned = raw_bytes.replace(" ", "")
                    return max(1, len(cleaned) // 2)
            except Exception:
                pass
        # Very rough mnemonic-based heuristic when bytes are unavailable.
        lower = text.lower()
        for prefix, size in (("movabs", 10), ("call", 5), ("jmp", 5), ("j", 6), ("ret", 1)):
            if lower.startswith(prefix):
                return size
        return 1

    def blocks_for_function(self, fn_node: "Node") -> Iterable[BasicBlock]:
        """Return basic blocks when they already exist for ``fn_node``.

        This helper is used by indirect-target recovery to avoid recomputing
        the entire CFG; if no CFG has been built yet it returns an empty list.
        """
        return iter([])

    def build_all(self, max_functions: int = 0) -> dict[str, FunctionCFG]:
        """Build a :class:`FunctionCFG` for every function in the graph.

        If ``max_functions`` is greater than zero only the first ``N`` functions
        are processed (useful for smoke tests and previews).

        When the optional CFG cache is enabled (``ANGERONA_CFG_CACHE`` env var,
        ON by default) repeated builds over an unmodified graph reuse the
        previously computed CFGs.  This is behaviour-preserving memoisation:
        results are bit-identical to cold builds, only faster.
        """
        cache = self.default_cache()
        # CachedCFGSpine routes through its own instance cache in
        # build_function_cfg; skip the shared cache then to avoid double work.
        use_cache = cache is not None and getattr(self, "cache", None) is None
        cfgs: dict[str, FunctionCFG] = {}
        count = 0
        for node in self.graph.nodes:
            if node.kind != "function":
                continue
            if max_functions > 0 and count >= max_functions:
                break
            count += 1
            cfg = None
            key = None
            if use_cache:
                key = cache.key_for(self.graph, node)
                cfg = cache.get(key)
            if cfg is None:
                cfg = self.build_function_cfg(node)
                if use_cache:
                    cache.put(key, cfg)
            cfgs[cfg.address] = cfg
        return cfgs
