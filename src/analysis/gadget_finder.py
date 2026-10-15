"""Gadget finder using case-sensitive binary byte searches.

Based on The IDA Pro Book Chapter 22 gadget search notes: ROP gadget
hunting is best performed as a case-sensitive hex (byte) search rather
than a text search. This module locates tiny embedded control-transfer
sequences in a flat binary or executable file without relying on an
external disassembler.

Capstone is used opportunistically for nicer mnemonics but is not
required; when absent, the module falls back to heuristic mnemonic
sequence strings built from the gadget signatures.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Union


# Signature byte sequence (spaces stripped, case-insensitive only while
# converting to bytes — the actual search is case-sensitive on bytes).
DEFAULT_SIGNATURES: dict[str, str] = {
    "ff e4": "jmp esp",
    "ff e2": "jmp edx",
    "ff d2": "call edx",
    "50 c3": "push eax ; ret",
    "5b c3": "pop ebx ; ret",
    "58 c3": "pop eax ; ret",
    "59 c3": "pop ecx ; ret",
    "5a c3": "pop edx ; ret",
    "5e c3": "pop esi ; ret",
    "5f c3": "pop edi ; ret",
    "87 ec": "xchg ebp, esp",
    "94 c3": "xchg eax, esp ; ret",
}

# Known ret-like / control-flow termination bytes.
_RET_NEAR = b"\xc3"
_RET_FAR_IMM16 = b"\xc2"


@dataclass(frozen=True)
class Gadget:
    """A discovered code gadget.

    Attributes:
        address: Hex string of the gadget offset within the file.
        bytes_hex: Space-separated hex dump of the gadget bytes.
        mnemonic_sequence: Human-readable instruction sequence.
        category: Broad classification of the gadget behavior.
        score: Simple quality score (higher is better, ret gadgets score lower).
        method: Discovery method, either ``exact`` or ``prefix``.
    """

    address: str
    bytes_hex: str
    mnemonic_sequence: str
    category: str
    score: float
    method: str


class GadgetFinder:
    """Search a binary for useful ROP/return-oriented control-transfer gadgets.

    Example::

        finder = GadgetFinder("/path/to/binary")
        results = finder.search_all()
        print(results["exact"][:5])
    """

    def __init__(self, binary_path: Union[str, Path], *, pointer_size: int = 8) -> None:
        """Initialize the finder with a binary file.

        Args:
            binary_path: Path to the binary to scan.
            pointer_size: Target architecture pointer size in bytes (default 8).
        """
        self.binary_path = Path(binary_path)
        self.pointer_size = pointer_size
        self._bytes: bytes | None = None
        self._capstone_engine: object | None = None
        self._cs_arch: int = 0
        self._cs_mode: int = 0

        # Try to preload capstone; failure is non-fatal.
        self._init_capstone()

    def _init_capstone(self) -> None:
        """Probe capstone availability and select a reasonable arch/mode."""
        try:
            import capstone  # type: ignore
        except Exception:  # pragma: no cover - optional dependency
            return

        self._capstone_engine = None
        arch = capstone.CS_ARCH_X86
        # Prefer 64-bit, but keep the mode configurable via pointer_size.
        mode = capstone.CS_MODE_64 if self.pointer_size == 8 else capstone.CS_MODE_32
        try:
            self._capstone_engine = capstone.Cs(arch, mode)
        except Exception:  # pragma: no cover - capstone may not support mode
            return

        self._cs_arch = arch
        self._cs_mode = mode

    # ------------------------------------------------------------------
    # File I/O helpers
    # ------------------------------------------------------------------
    def _read_file_bytes(self) -> bytes:
        """Read and cache the target binary as raw bytes.

        Returns:
            Raw bytes of the binary.
        """
        if self._bytes is None:
            self._bytes = self.binary_path.read_bytes()
        return self._bytes

    def _byte_search(self, pattern: bytes) -> list[int]:
        """Find all non-overlapping occurrences of ``pattern`` in the binary.

        Args:
            pattern: Byte string to search for.

        Returns:
            List of offsets where ``pattern`` starts.
        """
        data = self._read_file_bytes()
        if not pattern:
            return []

        offsets: list[int] = []
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + len(pattern)
        return offsets

    # ------------------------------------------------------------------
    # Disassembly helpers
    # ------------------------------------------------------------------
    def _hex_dump(self, data: bytes) -> str:
        """Convert bytes to a space-separated lower-case hex string."""
        return " ".join(f"{b:02x}" for b in data)

    def _disassemble_one(self, addr: int, data: bytes) -> dict | None:
        """Disassemble a single instruction from ``data`` at offset ``addr``.

        Uses capstone if it was successfully loaded; otherwise returns a
        heuristic placeholder based on a small table of known byte patterns.

        Args:
            addr: Virtual or file offset used for display.
            data: Candidate instruction bytes.

        Returns:
            A dict with keys ``addr``, ``size``, ``mnemonic`` and
            optionally ``op_str``/``bytes``, or ``None`` when nothing can
            be decoded.
        """
        if not data:
            return None

        engine = self._capstone_engine
        if engine is not None:
            try:
                for insn in engine.disasm(data, addr, count=1):
                    op_str = getattr(insn, "op_str", "")
                    if op_str:
                        mnemonic = f"{insn.mnemonic} {op_str}".strip()
                    else:
                        mnemonic = insn.mnemonic
                    return {
                        "addr": insn.address,
                        "size": insn.size,
                        "mnemonic": mnemonic,
                        "bytes": bytes(insn.bytes),
                    }
            except Exception:  # pragma: no cover - capstone runtime errors
                pass

        # ------------------- heuristic fallback -------------------------
        first = data[0]
        second = data[1] if len(data) > 1 else None
        third = data[2] if len(data) > 2 else None
        mnemonic: str | None = None
        size = 1

        # ret variants
        if first == 0xC3:
            mnemonic = "ret"
            size = 1
        elif first == 0xC2 and len(data) >= 3:
            mnemonic = f"ret {third << 8 | second:#06x}"
            size = 3

        regs_32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        regs_64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
        regs = regs_64 if self.pointer_size == 8 else regs_32
        # push r32/r64 (50-57)
        if 0x50 <= first <= 0x57:
            mnemonic = f"push {regs[first - 0x50]}"
            size = 1
        # pop r32/r64 (58-5F)
        elif 0x58 <= first <= 0x5F:
            mnemonic = f"pop {regs[first - 0x58]}"
            size = 1
        # jmp/call r32/r64 (FF /4, FF /2): requires ModRM byte
        elif first == 0xFF and second is not None:
            modrm = second
            rm = modrm & 0x07
            reg_group = (modrm >> 3) & 0x07
            # /4 = jmp r/m, /2 = call r/m
            if reg_group == 4:
                mnemonic = f"jmp {regs[rm]}"
            elif reg_group == 2:
                mnemonic = f"call {regs[rm]}"
            # FF + ModRM is at least 2 bytes; register-direct is 2 bytes.
            size = 2
        # xchg eax/rax, r32/r64 (90-97)
        elif 0x90 <= first <= 0x97:
            prefix = "eax" if self.pointer_size != 8 else "rax"
            mnemonic = f"xchg {prefix}, {regs[first - 0x90]}"
            size = 1
        elif first == 0x87 and second in (0xE4, 0xEC):
            if second == 0xE4:
                mnemonic = "xchg esp, eax"
            else:
                mnemonic = "xchg ebp, esp"
            size = 2
        elif first == 0x94:
            mnemonic = "xchg eax, esp"
            size = 1

        if mnemonic is None:
            return None
        return {
            "addr": addr,
            "size": size,
            "mnemonic": mnemonic,
            "bytes": data[:size],
        }

    def _disassemble_range(self, addr: int, data: bytes) -> list[dict]:
        """Disassemble a contiguous byte range into a list of instructions.

        Args:
            addr: Starting offset for display.
            data: Bytes to disassemble.

        Returns:
            List of decoded instruction dicts.
        """
        instructions: list[dict] = []
        offset = 0
        data_len = len(data)
        while offset < data_len:
            remaining = data_len - offset
            chunk = data[offset:]
            # Avoid feeding capstone huge slop: pass only remaining bytes.
            if len(chunk) > 16:
                chunk = chunk[:16]

            insn = self._disassemble_one(addr + offset, chunk)
            if insn is None:
                # Unknown byte: consume one byte as placeholder and continue
                instructions.append(
                    {
                        "addr": addr + offset,
                        "size": 1,
                        "mnemonic": f"db {data[offset]:02x}",
                        "bytes": data[offset : offset + 1],
                    }
                )
                offset += 1
                continue

            # Make sure we do not claim to consume more bytes than we have.
            size = min(insn["size"], remaining)
            insn["size"] = size
            insn["bytes"] = data[offset : offset + size]
            instructions.append(insn)
            offset += size

            # Stop once we hit a ret (do not include following bytes).
            if insn["mnemonic"].startswith("ret"):
                break
        return instructions

    # ------------------------------------------------------------------
    # Classification / scoring
    # ------------------------------------------------------------------
    def _classify(self, mnemonics: list[str], bytes_hex: str) -> tuple[str, float]:
        """Classify and score a gadget from its instruction mnemonics.

        Args:
            mnemonics: Ordered instruction mnemonic strings for the gadget.
            bytes_hex: Raw gadget bytes as a hex string (fallback).

        Returns:
            Tuple of (category, score).
        """
        joined = " ; ".join(mnemonics).lower()
        lower_bytes = bytes_hex.lower()

        if "xchg" in joined and ("ebp, esp" in joined or "esp, ebp" in joined):
            return "stack_pivot", 8.0
        if "jmp " in joined and any(r in joined for r in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")):
            return "jmp_reg", 8.0
        if "call " in joined and any(r in joined for r in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")):
            return "call_reg", 7.0
        if (
            "push " in joined
            and joined.endswith("ret")
            and any(b in lower_bytes for b in ("50 c3", "51 c3", "52 c3", "53 c3", "54 c3", "55 c3", "56 c3", "57 c3"))
        ):
            return "push_ret", 9.0
        if (
            "pop " in joined
            and joined.endswith("ret")
        ):
            return "pop_ret", 7.0
        if joined.endswith("ret"):
            return "other", 5.0
        return "other", 3.0

    # ------------------------------------------------------------------
    # Public search APIs
    # ------------------------------------------------------------------
    def find_exact_gadgets(
        self, gadget_signatures: dict[str, str] | None = None
    ) -> list[Gadget]:
        """Search for exact byte-signature gadgets.

        Args:
            gadget_signatures: Maps hex strings (e.g. ``"ff e4"``) to a
                representative mnemonic sequence. Defaults to
                ``DEFAULT_SIGNATURES``.

        Returns:
            List of matching ``Gadget`` objects.
        """
        signatures = gadget_signatures if gadget_signatures is not None else DEFAULT_SIGNATURES
        results: list[Gadget] = []

        for hex_sig, mnemonic in signatures.items():
            pattern = bytes.fromhex(hex_sig.replace(" ", ""))
            for offset in self._byte_search(pattern):
                bytes_hex = self._hex_dump(pattern)
                category, score = self._classify([mnemonic], bytes_hex)
                results.append(
                    Gadget(
                        address=f"0x{offset:08x}",
                        bytes_hex=bytes_hex,
                        mnemonic_sequence=mnemonic,
                        category=category,
                        score=score,
                        method="exact",
                    )
                )

        results.sort(key=lambda g: (-g.score, g.address))
        return results

    def find_ret_gadgets(self, max_len: int = 8) -> list[Gadget]:
        """Enumerate all gadgets ending in ``ret`` by walking backwards from
        each return instruction.

        For every ``c3`` (ret) or ``c2 NN NN`` (ret imm16) byte, the
        function slides a window from 1 up to ``max_len`` bytes before the
        return and disassembles the candidate snippet. Overlapping
        duplicates are removed: only the longest non-overlapping gadget at
        a given return offset is retained.

        Args:
            max_len: Maximum number of bytes before ``ret`` to include.

        Returns:
            List of unique ``Gadget`` objects discovered by this
            prefix-style scan.
        """
        data = self._read_file_bytes()
        if not data:
            return []

        # Locate every ret terminator.
        ret_offsets: list[int] = []
        for idx, b in enumerate(data):
            if b == 0xC3:
                ret_offsets.append((idx, 1))
            elif b == 0xC2 and idx + 2 < len(data):
                ret_offsets.append((idx, 3))

        gadgets: list[Gadget] = []
        seen_spans: set[tuple[int, int]] = set()

        for ret_off, ret_size in ret_offsets:
            # Build a gadget for every prefix length up to max_len bytes before ret.
            # Iterate longest-first so we keep the longest valid non-overlapping
            # gadget ending at each ret.
            ret_gadgets: list[Gadget] = []
            for prefix_len in range(max_len, 0, -1):
                start = ret_off - prefix_len
                if start < 0:
                    continue

                snippet = data[start : ret_off + ret_size]
                instructions = self._disassemble_range(start, snippet)

                # Valid gadgets must end exactly at the ret terminator and
                # contain no gap-filling "db" placeholders (instruction in
                # the middle makes no sense).
                if not instructions or not instructions[-1]["mnemonic"].startswith("ret"):
                    continue
                if any(i["mnemonic"].startswith("db ") for i in instructions[:-1]):
                    continue

                consumed = 0
                valid_len = 0
                for insn in instructions:
                    # Ensure decoded instructions land exactly inside the snippet.
                    if consumed + insn["size"] > len(snippet):
                        break
                    valid_len += insn["size"]
                    consumed += insn["size"]

                if valid_len != len(snippet):
                    continue

                mnemonics = [i["mnemonic"] for i in instructions]
                bytes_hex = self._hex_dump(snippet)

                # De-duplicate: skip if this exact start length overlaps a
                # kept gadget that ends at the same ret.
                span_key = (start, ret_off + ret_size)
                if any(
                    start < existing_end and (ret_off + ret_size) > existing_start
                    for existing_start, existing_end in seen_spans
                ):
                    continue

                category, score = self._classify(mnemonics, bytes_hex)
                # Sliding-window gadgets score lower than exact signatures.
                score *= 0.8
                ret_gadgets.append(
                    Gadget(
                        address=f"0x{start:08x}",
                        bytes_hex=bytes_hex,
                        mnemonic_sequence=" ; ".join(mnemonics),
                        category=category,
                        score=round(score, 2),
                        method="prefix",
                    )
                )
                seen_spans.add(span_key)
            gadgets.extend(ret_gadgets)

        # Stable order by score then address.
        gadgets.sort(key=lambda g: (-g.score, g.address))
        return gadgets

    def search_all(self) -> dict[str, list[Gadget]]:
        """Run all gadget searches and return grouped results.

        Returns:
            Mapping ``{"exact": [...], "ret": [...]}``.
        """
        return {
            "exact": self.find_exact_gadgets(),
            "ret": self.find_ret_gadgets(),
        }
