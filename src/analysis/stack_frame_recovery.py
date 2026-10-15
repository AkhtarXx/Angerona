"""Stack-frame recovery for the angerona reverse-engineering platform.

For every decoded function this module reconstructs the stack layout:
* total frame size (when determinable),
* offset of the saved return address relative to the frame base,
* saved/non-volatile registers and their offsets,
* local variables with negative offsets from the saved return address,
* arguments with positive offsets from the saved return address,
* a best-effort calling convention label.

The implementation follows the stack-frame model described in *The IDA Pro Book*,
Chapter 8 (stack frames) and adapts the processor-level idea of automatically
recording stack-pointer changes (``add_auto_stkpnt2`` / manual stack pointer
adjustment) to build the layout from disassembly and decompilation text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.models.analysis_graph import AnalysisGraph, Node


# --------------------------------------------------------------------------- constants

# x86/x64 stack-setup idioms
_PUSH_RBP = re.compile(r"\bpush\s+(?:rbp|ebp|RBP|EBP)\b", re.I)
_MOV_RBP_RSP = re.compile(r"\bmov\s+(?:rbp|ebp|RBP|EBP)\s*,\s*(?:rsp|esp|RSP|ESP)\b", re.I)
_SUB_RSP_IMM = re.compile(
    r"\bsub\s+(?:rsp|esp|RSP|ESP)\s*,\s*(?:0x)?([0-9a-fA-F]+)\b",
    re.I,
)
_SUB_RSP_REG = re.compile(
    r"\bsub\s+(?:rsp|esp|RSP|ESP)\s*,\s*(?:[a-z0-9_]+)\b",
    re.I,
)
_AND_RSP_ALIGN = re.compile(r"\band\s+(?:rsp|esp|RSP|ESP)\s*,\s*0x[fF]+0\b", re.I)
_LEAVE = re.compile(r"\bleave\b", re.I)
_RET = re.compile(r"\b(ret|retn)\b", re.I)

# Typical frame-relative memory references:
#   mov rax, [rbp+0x10]
#   mov dword ptr [rbp-0x2C], eax
#   lea rax, [rbp-0xNN]
#   movzx eax, byte ptr [rsp+0xNN]
FRAME_REL = re.compile(
    r"\[(?:rbp|ebp|rsp|esp|RBP|EBP|RSP|ESP)\s*([+-])\s*(?:0x)?([0-9a-fA-F]+)(?:\s*\+\s*[a-z0-9_]+)?\s*\]",
    re.I,
)

# Saved register pushes after the frame setup, e.g.:
#   push rdi
#   push rsi
#   push rbx
_PUSH_REG = re.compile(r"\bpush\s+([a-z0-9_]+)\b", re.I)
_POP_REG = re.compile(r"\bpop\s+([a-z0-9_]+)\b", re.I)

# Decompilation variable patterns used by Hex-Rays / Ghidra / LLM4Decompile.
#   local_28, local_10h, var_BC, var_28h, arg_0, arg_8
_LOCAL_VAR = re.compile(
    r"\b(local|var)_([0-9a-fA-F]+)(h?)\b",
    re.I,
)
_ARG_VAR = re.compile(
    r"\barg_([0-9a-fA-F]+)(h?)\b",
    re.I,
)
_PARAM_DECL = re.compile(
    r"\b(?:int|void|char|uint[0-9]*_t|int[0-9]*_t|long|unsigned|size_t|bool|BOOL|DWORD|HANDLE|LPSTR|LPCSTR|HINSTANCE|NTSTATUS|HMODULE)\s+\**\s*(arg_([0-9a-fA-F]+)h?)\b",
    re.I,
)

# Common x64 argument registers in Windows ABI order.
_WIN64_ARG_REGS = ["rcx", "rdx", "r8", "r9"]
_LINUX_AMD64_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_32BIT_ARG_REGS = ["ecx", "edx", "ebx", "esi", "edi"]

# Callee-saved registers by broad family.
_CALLEE_SAVED_64 = {"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15", "rsp"}
_CALLEE_SAVED_32 = {"ebx", "ebp", "edi", "esi", "esp"}


# --------------------------------------------------------------------------- data model


@dataclass
class StackFrame:
    """Reconstructed stack frame for one function.

    Offsets are expressed relative to the saved return address. On x86/x64 a
    standard stack frame looks like:

        [rbp + N]   arguments from caller
        [rbp + 0]   saved return address
        [rbp - N]   saved registers / locals

    Therefore locals carry negative offsets and arguments carry positive offsets.
    """

    function_id: str
    function_addr: str
    function_name: str | None = None
    size: int | None = None
    return_addr_offset: int | None = 0
    saved_regs: list[dict[str, Any]] = field(default_factory=list)
    locals: list[dict[str, Any]] = field(default_factory=list)
    args: list[dict[str, Any]] = field(default_factory=list)
    calling_convention: str | None = "unknown"
    confidence: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        """Serialize the frame to a plain dictionary."""
        return {
            "function_id": self.function_id,
            "function_addr": self.function_addr,
            "function_name": self.function_name,
            "size": self.size,
            "return_addr_offset": self.return_addr_offset,
            "saved_regs": self.saved_regs,
            "locals": self.locals,
            "args": self.args,
            "calling_convention": self.calling_convention,
            "confidence": round(self.confidence, 3),
        }


# --------------------------------------------------------------------------- recovery engine


class StackFrameRecovery:
    """Recover stack frames from function nodes stored in an ``AnalysisGraph``.

    The recovery process is intentionally lightweight and dependency-free. It
    fuses information from:

    1. The function node's properties (size, signature, decompiled text,
       disassembly list/string).
    2. Disassembly parsing for x86/x64 prologue/epilogue idioms.
    3. Decompilation text parsing for ``local_XX`` / ``var_XX`` / ``arg_XX``
       style symbols.

    Confidence is computed heuristically based on how many independent signals
    agree (prologue recovered, frame-relative references observed, decompilation
    available, calling convention inferred).
    """

    def __init__(self, graph: AnalysisGraph) -> None:
        """Initialize recovery over the provided analysis graph."""
        self.graph = graph

    # ---------------------------------------------------------------- public API

    def recover_all(self, max_functions: int = 0) -> dict[str, StackFrame]:
        """Recover frames for every function node in the graph.

        Parameters
        ----------
        max_functions:
            If > 0, only process up to this many functions. Zero means all.

        Returns
        -------
        A mapping from function id to ``StackFrame``.
        """
        frames: dict[str, StackFrame] = {}
        seen = 0

        for node in self.graph.nodes:
            if node.kind != "function":
                continue
            seen += 1
            if max_functions and seen > max_functions:
                break
            frame = self.recover(node)
            if frame is not None:
                frames[node.id] = frame

        return frames

    def recover(self, fn_node: Node) -> StackFrame | None:
        """Build a ``StackFrame`` for a single function node.

        The method reads the node's properties and fuses disassembly-based and
        decompilation-based recovery.

        Parameters
        ----------
        fn_node:
            A ``Node`` with ``kind == "function"``.

        Returns
        -------
        ``StackFrame`` on success, or ``None`` if the input is not a function
        node and no recovery can be attempted.
        """
        if fn_node.kind != "function":
            return None

        props = fn_node.properties or {}
        disasm_text = self._extract_disassembly(fn_node)
        decomp_text = self._extract_decompilation(props)
        arch_hint = self._architecture_hint()

        disasm_info = self._infer_from_disassembly(disasm_text, arch_hint)
        decomp_info = self._infer_from_decompilation(decomp_text)

        # Fuse frame size: prefer explicit disassembly prologue, then decomp estimate.
        frame_size: int | None = self._coalesce_size(disasm_info, decomp_info)

        # Merge locals. Disassembly gives rbp-relative offsets; decomp gives symbolic
        # names keyed by offset.
        locals_ = self._merge_locals(disasm_info, decomp_info)

        # Merge arguments.
        args_ = self._merge_args(disasm_info, decomp_info)

        # Saved registers.
        saved_regs = self._merge_saved_regs(disasm_info, decomp_info)

        # Return-address offset defaults to 0 (right at saved RBP).
        return_addr_offset = 0

        arg_names = [a.get("name", "") for a in args_]
        convention = self._calling_convention(fn_node, frame_size, arg_names)

        confidence = self._compute_confidence(
            has_disasm=bool(disasm_text.strip()),
            has_decomp=bool(decomp_text.strip()),
            has_prologue=disasm_info.get("has_frame_pointer", False),
            frame_size=frame_size,
            locals_count=len(locals_),
            args_count=len(args_),
        )

        return StackFrame(
            function_id=fn_node.id,
            function_addr=fn_node.address or "0x0",
            function_name=fn_node.name,
            size=frame_size,
            return_addr_offset=return_addr_offset,
            saved_regs=saved_regs,
            locals=locals_,
            args=args_,
            calling_convention=convention,
            confidence=confidence,
        )

    # ---------------------------------------------------------------- architecture hint

    def _architecture_hint(self) -> str:
        """Return the best-effort architecture label from graph metadata.

        Looks at the program-level processor/language_id metadata. Defaults to
        ``x64`` for unknown or empty inputs.
        """
        proc = (self.graph.metadata.get("processor") or "").lower()
        lang = (self.graph.metadata.get("language_id") or "").lower()
        ptr_size = self.graph.metadata.get("pointer_size") or 0

        if "x86" in proc or "80386" in proc or "metapc" in proc:
            if "64" in proc or ptr_size == 8 or "x86-64" in lang or "x64" in lang:
                return "x64"
            return "x86"

        if "arm" in proc or "aarch64" in proc or "arm64" in proc:
            return "arm64"

        if ptr_size == 8:
            return "x64"
        if ptr_size == 4:
            return "x86"

        return "x64"

    # ---------------------------------------------------------------- calling convention

    def _calling_convention(self, fn_node: Node, frame_size: int | None, arg_names: list[str]) -> str:
        """Infer a calling-convention label for ``fn_node``.

        The inference is deliberately coarse: if this is a tiny, leaf function
        with no stack frame and no named args we label it ``unknown``.  If x86
        functions exceed 8 bytes of arguments or use no register-layout hints,
        we prefer ``stdcall`` for Windows binaries and ``cdecl`` otherwise.
        x64 binaries default to the Microsoft x64 / System V AMD64 ABI.
        """
        arch = self._architecture_hint()
        name = (fn_node.name or "").lower()
        props = fn_node.properties or {}
        signature = (props.get("signature") or "")

        if arch == "x64":
            if "systemv" in signature.lower() or "sysv" in signature.lower():
                return "sysv_amd64"
            return "microsoft_x64"

        if arch == "x86":
            # Stripped binaries rarely carry calling-convention hints. Fall back
            # to name/import heuristics common in Windows malware.
            is_windows = (self.graph.metadata.get("executable_format") or "").lower() in {
                "pe",
                "pe32",
                "pe32+",
                "coff",
            }
            leading_underscore = name.startswith("_")
            stdcall_names = name.startswith(("__", "_imp__")) or name.endswith("@4")

            if stdcall_names or (is_windows and arg_names and not leading_underscore):
                return "stdcall"

            if leading_underscore and is_windows:
                return "cdecl"

            return "cdecl"

        if arch == "arm64":
            return "aarch64_aapcs"

        return "unknown"

    # ---------------------------------------------------------------- disassembly inference

    def _infer_from_disassembly(self, disasm_text: str, arch_hint: str) -> dict[str, Any]:
        """Parse x86/x64 stack idioms from raw disassembly text.

        Handles:
        * push rbp / mov rbp,rsp / sub rsp, imm prologues,
        * leave / ret epilogues,
        * frame-relative reads/writes to derive local/arg offsets,
        * simple saved-register pushes after the framepointer setup.

        Returns a dictionary with keys:

        * ``has_frame_pointer`` (bool)
        * ``frame_size`` (int | None)
        * ``local_offsets`` set[int]
        * ``arg_offsets`` set[int]
        * ``saved_regs`` list[dict]
        """
        info: dict[str, Any] = {
            "has_frame_pointer": False,
            "frame_size": None,
            "local_offsets": set(),
            "arg_offsets": set(),
            "saved_regs": [],
            "dynamic_alloc": False,
        }

        if not disasm_text.strip():
            return info

        has_push_rbp = bool(_PUSH_RBP.search(disasm_text))
        has_mov_rbp_rsp = bool(_MOV_RBP_RSP.search(disasm_text))
        has_sub_rsp_imm = _SUB_RSP_IMM.search(disasm_text)
        has_leave = bool(_LEAVE.search(disasm_text))
        has_ret = bool(_RET.search(disasm_text))
        has_dynamic = bool(_SUB_RSP_REG.search(disasm_text)) and has_sub_rsp_imm is None
        has_align = bool(_AND_RSP_ALIGN.search(disasm_text))

        info["has_frame_pointer"] = has_push_rbp and has_mov_rbp_rsp
        info["dynamic_alloc"] = has_dynamic

        if has_sub_rsp_imm:
            try:
                info["frame_size"] = int(has_sub_rsp_imm.group(1).replace("0x", ""), 16)
            except ValueError:
                info["frame_size"] = None
        elif has_align:
            # Aligning RSP in a frameless prologue implies a compiler-generated shadow space.
            info["frame_size"] = 32

        # Frame-relative offsets. For [rbp+X] the offset is +X from saved-RA;
        # for [rbp-X] it is a local. RSP-relative symbols count only for frameless
        # prologues and are re-based if a frame pointer exists.
        for m in FRAME_REL.finditer(disasm_text):
            base = m.group(0).lower()
            sign = m.group(1)
            try:
                off = int(m.group(2), 16)
            except ValueError:
                continue

            if "rbp" in base or "ebp" in base:
                if sign == "+":
                    if off == 0:
                        # saved return address / old frame pointer, skip
                        continue
                    info["arg_offsets"].add(off)
                else:
                    info["local_offsets"].add(-off)
            elif "rsp" in base or "esp" in base:
                if info["has_frame_pointer"]:
                    continue
                # In frameless code rsp+Ns are locals, rsp+8/16/etc are args.
                if sign == "-":
                    info["local_offsets"].add(-off)
                else:
                    if off >= 8:
                        info["arg_offsets"].add(off)

        # If we saw a real prologue but no negative rbp references, add a placeholder
        # local representing the saved old rbp slot.
        if info["has_frame_pointer"] and not info["local_offsets"]:
            ptr = 8 if arch_hint in ("x64", "arm64") else 4
            info["local_offsets"].add(-ptr)

        # Identify saved registers by scanning pushes/pops after frame setup.
        # We keep them only when they look like non-volatile register saves.
        pushed: dict[str, int] = {}
        offset_cursor = 8 if arch_hint == "x64" else 4
        callee_saved = _CALLEE_SAVED_64 if arch_hint == "x64" else _CALLEE_SAVED_32
        for line in disasm_text.splitlines():
            line = line.strip()
            m_push = _PUSH_REG.match(line)
            if m_push:
                reg = m_push.group(1).lower()
                if reg in callee_saved:
                    pushed[reg] = offset_cursor
                    offset_cursor += 8 if arch_hint == "x64" else 4
                continue
            m_pop = _POP_REG.match(line)
            if m_pop:
                reg = m_pop.group(1).lower()
                if reg in pushed:
                    info["saved_regs"].append({
                        "register": reg,
                        "offset": pushed.pop(reg),
                        "notes": "saved in prologue, restored by pop",
                    })

        return info

    # ---------------------------------------------------------------- decompilation inference

    def _infer_from_decompilation(self, decomp_text: str) -> dict[str, Any]:
        """Parse decompilation text for stack-related symbols.

        Recognises the common Hex-Rays/Ghidra conventions:
        * ``local_XX`` / ``var_XX``  => local variables,
        * ``arg_XX``                 => stack-passed arguments.

        Returns a dictionary with keys:

        * ``local_offsets`` set[int]
        * ``arg_offsets`` set[int]
        * ``local_names`` dict[int, str]
        * ``arg_names`` dict[int, str]
        * ``has_decompilation`` bool
        """
        info: dict[str, Any] = {
            "local_offsets": set(),
            "arg_offsets": set(),
            "local_names": {},
            "arg_names": {},
            "has_decompilation": False,
        }

        if not decomp_text.strip():
            return info

        info["has_decompilation"] = True

        for m in _LOCAL_VAR.finditer(decomp_text):
            name = m.group(0)
            kind = m.group(1).lower()
            off_str = m.group(2)
            hex_suffix = m.group(3).lower() == "h"
            try:
                # local_N forms in decompilation usually represent hex byte offsets.
                if kind == "local":
                    off_abs = int(off_str, 16)
                else:
                    off_abs = int(off_str, 16 if hex_suffix else 10)
            except ValueError:
                continue
            off = -off_abs
            info["local_offsets"].add(off)
            info["local_names"][off] = name

        for m in _ARG_VAR.finditer(decomp_text):
            name = m.group(0)
            off_str = m.group(1)
            hex_suffix = m.group(2).lower() == "h"
            try:
                off_abs = int(off_str, 16 if hex_suffix else 10)
            except ValueError:
                continue
            info["arg_offsets"].add(off_abs)
            info["arg_names"][off_abs] = name

        # Declared argument names from signatures like "void __fastcall f(int arg_0)".
        for m in _PARAM_DECL.finditer(decomp_text):
            name = m.group(1)
            off_abs_str = m.group(2)
            try:
                off_abs = int(off_abs_str, 16)
            except ValueError:
                continue
            info["arg_offsets"].add(off_abs)
            info["arg_names"][off_abs] = name

        return info

    # ---------------------------------------------------------------- fusion helpers

    def _extract_disassembly(self, fn_node: Node) -> str:
        """Return a single disassembly string from a function node."""
        props = fn_node.properties or {}
        raw = props.get("disassembly")
        if raw is not None:
            if isinstance(raw, list):
                return "\n".join(str(line) for line in raw)
            return str(raw)

        # Reconstruct from instruction nodes held by the graph if available.
        if self.graph is not None:
            lines: list[str] = []
            for edge in self.graph.edge_list(fn_node.id, edge_kind="contains", direction="out"):
                node = self.graph.get_node(edge.dst)
                if node is None or node.kind != "instruction":
                    continue
                p = node.properties or {}
                mnemonic = (p.get("mnemonic") or "nop").strip()
                operands = (p.get("operands") or "").strip()
                text = (p.get("text") or "").strip()
                line = text or (f"{mnemonic} {operands}".strip())
                if line:
                    lines.append(line)
            if lines:
                return "\n".join(lines)
        return ""

    @staticmethod
    def _extract_decompilation(props: dict[str, Any]) -> str:
        """Return a single decompilation string from a function properties dict."""
        raw = props.get("decompiled") or props.get("decompilation")
        if raw is None:
            return ""
        if isinstance(raw, list):
            return "\n".join(str(line) for line in raw)
        return str(raw)

    @staticmethod
    def _coalesce_size(disasm_info: dict[str, Any], decomp_info: dict[str, Any]) -> int | None:
        """Pick the most reliable frame size estimate from the two sources."""
        if disasm_info.get("frame_size") is not None:
            return disasm_info["frame_size"]

        local_offsets = disasm_info.get("local_offsets", set()) | decomp_info.get("local_offsets", set())
        arg_offsets = disasm_info.get("arg_offsets", set()) | decomp_info.get("arg_offsets", set())

        if local_offsets or arg_offsets:
            max_local = max((abs(o) for o in local_offsets), default=0)
            max_arg = max((abs(o) for o in arg_offsets), default=0)
            # Round up to 8 bytes, minimum shadow space on x64.
            total = ((max(max_local, max_arg) + 7) // 8) * 8
            return total or None

        return None

    @staticmethod
    def _merge_locals(disasm_info: dict[str, Any], decomp_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Merge local-variable offsets and attach names from decompilation."""
        all_offsets: set[int] = set()
        all_offsets |= disasm_info.get("local_offsets", set())
        all_offsets |= decomp_info.get("local_offsets", set())

        names = decomp_info.get("local_names", {})
        locals_: list[dict[str, Any]] = []
        for off in sorted(all_offsets):
            locals_.append({
                "offset": off,
                "name": names.get(off, f"local_{-off:x}"),
                "source": "decomp" if off in names else "disasm",
            })
        return locals_

    @staticmethod
    def _merge_args(disasm_info: dict[str, Any], decomp_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Merge argument offsets and attach names from decompilation."""
        all_offsets: set[int] = set()
        all_offsets |= disasm_info.get("arg_offsets", set())
        all_offsets |= decomp_info.get("arg_offsets", set())

        names = decomp_info.get("arg_names", {})
        args: list[dict[str, Any]] = []
        for off in sorted(all_offsets):
            args.append({
                "offset": off,
                "name": names.get(off, f"arg_{off:x}"),
                "source": "decomp" if off in names else "disasm",
            })
        return args

    @staticmethod
    def _merge_saved_regs(disasm_info: dict[str, Any], decomp_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Return saved-register records derived from disassembly pushes."""
        return list(disasm_info.get("saved_regs", []))

    @staticmethod
    def _compute_confidence(
        *,
        has_disasm: bool,
        has_decomp: bool,
        has_prologue: bool,
        frame_size: int | None,
        locals_count: int,
        args_count: int,
    ) -> float:
        """Compute an empirical confidence score between 0.0 and 1.0."""
        score = 0.0

        if has_disasm:
            score += 0.2
        if has_decomp:
            score += 0.25
        if has_prologue:
            score += 0.25
        if frame_size is not None and frame_size > 0:
            score += 0.15
        if locals_count > 0:
            score += 0.075
        if args_count > 0:
            score += 0.075

        return min(round(score, 3), 1.0)
