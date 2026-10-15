"""Type and structure recovery from analysis graph data.

This module implements static type inference roughly aligned with the
workflow described in *The IDA Pro Book*:

* function signature reconstruction (calling convention, parameters,
  return type, stack-frame locals),
* calling-convention estimation from architecture, register usage and
  name mangling,
* scaled-index / structure-offset access pattern detection,
* structure shape recovery from field access footprints,
* simple type propagation across call sites.

It consumes the engine-agnostic `AnalysisGraph` produced by
`src.models.analysis_graph` and is therefore independent of IDA or Ghidra.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def _addr_int(addr: str | int | None) -> int:
    if addr is None:
        return 0
    if isinstance(addr, int):
        return addr & 0xFFFFFFFFFFFFFFFF
    s = str(addr).strip()
    if s.lower().startswith("0x"):
        return int(s, 16) & 0xFFFFFFFFFFFFFFFF
    try:
        return int(s, 16) & 0xFFFFFFFFFFFFFFFF
    except ValueError:
        return 0


@dataclass
class FunctionSignature:
    """Recovered signature for a single function."""

    name: str
    entry: str
    calling_convention: str = "unknown"
    return_type: str = "unknown"
    parameters: list[dict[str, Any]] = field(default_factory=list)
    local_vars: list[dict[str, Any]] = field(default_factory=list)
    stack_frame_size: int | None = None
    confidence: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "entry": self.entry,
            "calling_convention": self.calling_convention,
            "return_type": self.return_type,
            "parameters": self.parameters,
            "local_vars": self.local_vars,
            "stack_frame_size": self.stack_frame_size,
            "confidence": self.confidence,
        }


@dataclass
class RecoveredStructure:
    """Recovered aggregate type shape derived from access patterns."""

    name: str
    size: int
    fields: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "fields": self.fields,
            "confidence": self.confidence,
        }


class TypeRecoveryAgent:
    """Recover types, signatures and structures from an `AnalysisGraph`.

    Parameters
    ----------
    graph:
        The populated `AnalysisGraph` instance to analyse.
    """

    # x86/x64 GP registers that participate in common calling conventions.
    _ARG_REGISTERS = {
        "x86": ["eax", "edx", "ecx"],          # cdecl/fastcall/thiscall
        "x64": ["rcx", "rdx", "r8", "r9"],       # Windows x64
        "x64_systemv": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],  # System V AMD64 ABI
        "arm": ["r0", "r1", "r2", "r3"],
        "aarch64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        "mips": ["$a0", "$a1", "$a2", "$a3"],
    }

    # Regexes for scaled-index access patterns.
    # x86/x64 AT&T style: 0x10(%rax,%rcx,8)
    # x86/x64 Intel style: [rax+rcx*8+10h]
    # Decompiler style used by IDA/Ghidra: a1[i].field, *(base + offset + i * 8)
    _SCALED_INDEX_PATTERNS = [
        re.compile(
            r"(?P<offset>-?0x[0-9a-fA-F]+|-?\d+)?\s*\(\s*(?P<base>%?[a-zA-Z0-9_]+)\s*,\s*(?P<index>%[a-zA-Z0-9_]+)\s*,\s*(?P<scale>1|2|4|8)\s*\)"
        ),
        re.compile(
            r"\[\s*(?P<base>[a-zA-Z0-9_]+)\s*\+\s*(?P<index>[a-zA-Z0-9_]+)\s*\*\s*(?P<scale>1|2|4|8)\s*(?:\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+))?\s*\]"
        ),
        re.compile(
            r"\[\s*(?P<base>[a-zA-Z0-9_]+)\s*(?:\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+))?\s*\+\s*(?P<index>[a-zA-Z0-9_]+)\s*\*\s*(?P<scale>1|2|4|8)\s*\]"
        ),
        re.compile(
            r"\*\s*\(\s*(?P<base>[a-zA-Z_$][a-zA-Z0-9_$]*)\s*\+\s*(?P<offset>-?0x[0-9a-fA-F]+|-?\d+)\s*\+\s*(?P<index>[a-zA-Z_$][a-zA-Z0-9_$]*)\s*\*\s*(?P<scale>1|2|4|8)\s*\)"
        ),
    ]

    # Direct decompiler field accesses:
    #   *(_QWORD *)(a1 + 8)          (IDA)
    #   *(undefined4 *)(param_1 + 4) (Ghidra)
    _DIRECT_OFFSET_PATTERN = re.compile(
        r"\*\s*\(\s*(?P<type>"
        r"_QWORD|_DWORD|_WORD|_BYTE|"
        r"undefined8|undefined4|undefined2|undefined1|"
        r"u?int64_t|u?int32_t|u?int16_t|u?int8_t|"
        r"ulong|long|uint|int|ushort|short|uchar|char|size_t"
        r")\s*\*\s*\)\s*"
        r"\(\s*(?P<base>[a-zA-Z_$][a-zA-Z0-9_$]*)"
        r"(?:\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)(?:LL|ULL|UL|L)?)?\s*\)"
    )
    _POINTER_DECL_PATTERN = re.compile(
        r"\b(?P<type>"
        r"_QWORD|_DWORD|_WORD|_BYTE|"
        r"undefined8|undefined4|undefined2|undefined1|"
        r"u?int64_t|u?int32_t|u?int16_t|u?int8_t|"
        r"ulong|long|uint|int|ushort|short|uchar|char|size_t"
        r")\s*\*\s*(?P<name>[a-zA-Z_$][a-zA-Z0-9_$]*)"
    )
    _CONSTANT_ARRAY_PATTERN = re.compile(
        r"\b(?P<base>[a-zA-Z_$][a-zA-Z0-9_$]*)"
        r"\s*\[\s*(?P<index>0x[0-9a-fA-F]+|\d+)\s*\]"
    )

    _STACK_LOCAL_PATTERNS = [
        # IDA/Ghidra decompiler: int local_14;
        re.compile(r"(?P<type>[a-zA-Z_][a-zA-Z0-9_\s\*]*)\s+local_(?P<off>[0-9a-fA-F]+)\s*;"),
        # Microsoft-style: var_18= dword ptr -18h
        re.compile(r"var_(?P<off>[0-9a-fA-F]+)\s*=\s*(?P<type>[a-zA-Z_][a-zA-Z0-9_\s\*]*)"),
        # -0x14(%rbp) or [rbp-14h]
        re.compile(r"[\[\(]\s*(?:rbp|ebp|rbp rbx)?\s*-\s*(?P<off>0x[0-9a-fA-F]+|\d+)h?\s*[\]\)]"),
    ]

    _CALLSITE_PATTERNS = [
        # Function style calls
        re.compile(r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<args>[^)]*)\)"),
        # push arg / call target style
        re.compile(r"call\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_@]+)"),
    ]

    def __init__(self, graph: "AnalysisGraph") -> None:  # type: ignore[name-defined]
        self.graph = graph
        self._fn_nodes_cache: list[Any] | None = None

    # ------------------------------------------------------------------ helpers

    def _function_nodes(self) -> list[Any]:
        if self._fn_nodes_cache is None:
            self._fn_nodes_cache = [
                n for n in self.graph.nodes
                if n.kind == "function" and not bool((n.properties or {}).get("synthetic"))
            ]
        return self._fn_nodes_cache

    def _architecture_hint(self) -> str:
        """Return a normalized architecture token for the loaded program."""
        md = getattr(self.graph, "metadata", {}) or {}
        proc = (md.get("processor") or md.get("architecture") or "").lower()
        lang = (md.get("language_id") or "").lower()
        ptr = md.get("pointer_size") or 0
        if "x86:64" in proc or "x86_64" in proc or "amd64" in proc or lang.startswith("x86:LE:64"):
            return "x64"
        if "x86" in proc or lang.startswith("x86:LE:32"):
            return "x86"
        if "arm" in proc and "64" not in proc and "aarch64" not in proc:
            return "arm"
        if "aarch64" in proc or "arm64" in proc:
            return "aarch64"
        if "mips" in proc:
            return "mips"
        if ptr == 8:
            return "x64"
        if ptr == 4:
            return "x86"
        return "x64"  # default to modern 64-bit assumption

    def _platform_hint(self) -> str:
        md = getattr(self.graph, "metadata", {}) or {}
        fmt = (md.get("executable_format") or "").lower()
        if "pe" in fmt or "coff" in fmt:
            return "windows"
        if "elf" in fmt:
            return "elf"
        if "mach" in fmt:
            return "macho"
        return "unknown"

    @staticmethod
    def _likely_pointer_size() -> int:
        return 8  # analysis graph normalizes 64-bit addresses

    @staticmethod
    def _mangled_name_cc(name: str | None) -> str:
        """Detect calling convention from MSVC/Itanium mangled names."""
        if not name:
            return "unknown"
        # MSVC __stdcall: _FunctionName@0 or _FunctionName@4
        if re.fullmatch(r"_[a-zA-Z_$][a-zA-Z0-9_$@]*@\d+", name):
            return "stdcall"
        # MSVC __fastcall: @FunctionName@0
        if re.fullmatch(r"@[a-zA-Z_$][a-zA-Z0-9_$@]*@\d+", name):
            return "fastcall"
        # C++ Itanium member function encodings often imply thiscall
        if name.startswith("_ZN") and name.count("C2") + name.count("C1") + name.count("D2") + name.count("D1") > 0:
            return "thiscall"
        return "unknown"

    # ----------------------------------------------------------- public API

    def estimate_calling_convention(self, fn_node: Any) -> str:
        """Estimate the calling convention for a function node.

        The decision combines mangled-name hints (MSVC __stdcall/__fastcall,
        Itanium member functions), architecture-specific register usage
        patterns at call sites, and explicit metadata if supplied by the
        analysis engine.

        Parameters
        ----------
        fn_node:
            A `Node` of kind ``function`` from the analysis graph.

        Returns
        -------
        str
            One of ``cdecl``, ``stdcall``, ``fastcall``, ``thiscall`` or
            ``unknown``.
        """
        props = fn_node.properties or {}
        name = fn_node.name or props.get("name", "")

        explicit = props.get("calling_convention") or props.get("cc")
        if explicit and str(explicit).lower() in {
            "cdecl", "stdcall", "fastcall", "thiscall", "unknown", "vectorcall",
            "systemv", "ms_abi", "thiscall",
        }:
            cc = str(explicit).lower()
            if cc in {"vectorcall", "ms_abi"}:
                return "fastcall"
            if cc == "systemv":
                return "fastcall"
            return cc

        cc = self._mangled_name_cc(name)
        if cc != "unknown":
            return cc

        arch = self._architecture_hint()
        callers = self.graph.edge_list(fn_node.id, edge_kind="calls", direction="in")

        if arch == "x86" and callers:
            # Count bytes of arguments pushed by callers.  A constant stack
            # cleanup footprint strongly suggests __stdcall on Windows PE.
            cleanup_amounts: dict[int, int] = {}
            for edge in callers:
                caller = self.graph.get_node(edge.src)
                if not caller:
                    continue
                caller_props = caller.properties or {}
                decomp = caller_props.get("decompiled", "")
                disasm = caller_props.get("disassembly", "")
                text = f"{decomp}\n{disasm}"
                for m in re.finditer(rf"{re.escape(name or '')}\s*\(([^)]*)\)", text):
                    arg_bytes = len([a for a in m.group(1).split(",") if a.strip()]) * 4
                    cleanup_amounts[arg_bytes] = cleanup_amounts.get(arg_bytes, 0) + 1
            if len(cleanup_amounts) == 1 and name and cleanup_amounts:
                return "stdcall"

        if arch in {"x64", "x64_systemv"}:
            # x64 always uses a register-based calling convention; fastcall is
            # the closest umbrella name.
            return "fastcall"

        if arch == "x86":
            # Member function names or ecx/this usage imply thiscall.
            if name and not name.startswith("sub_") and ("::" in name or name.startswith("?") or name.startswith("_Z")):
                return "thiscall"
            return "cdecl"

        return "unknown"

    def extract_stack_locals(self, fn_node: Any) -> list[dict[str, Any]]:
        """Infer local variables from node properties or textual artefacts.

        Prefer explicit ``local_vars`` metadata, otherwise parse decompiled
        and disassembly text for stack-frame references such as
        ``local_14``, ``var_18`` or ``[rbp-0x18]``.

        Parameters
        ----------
        fn_node:
            A `Node` of kind ``function``.

        Returns
        -------
        list[dict]
            Dictionaries with ``name``, ``offset``, ``size`` and
            ``inferred_type``.  Returns an empty list when no artefacts are
            available.
        """
        props = fn_node.properties or {}
        explicit = props.get("local_vars")
        if isinstance(explicit, list):
            result: list[dict[str, Any]] = []
            for lv in explicit:
                if isinstance(lv, dict):
                    result.append(
                        {
                            "name": lv.get("name", "unknown"),
                            "offset": _addr_int(lv.get("offset")),
                            "size": int(lv.get("size", 4) or 4),
                            "inferred_type": lv.get("type", "unknown"),
                        }
                    )
            return result

        decomp = props.get("decompiled", "") or ""
        disasm = props.get("disassembly", "") or ""
        text = f"{decomp}\n{disasm}"

        if not text.strip():
            return []

        # Look for explicit local variable declarations.
        declarations = re.findall(
            r"(?P<type>[a-zA-Z_][a-zA-Z0-9_\s\*]*)\s+(?P<name>local_\w+|var_\w+)\s*;?",
            text,
        )
        found: dict[int, dict[str, Any]] = {}
        for decl in declarations:
            type_str, name = decl
            type_str = type_str.strip() or "unknown"
            hex_off = name.split("_")[-1]
            try:
                offset = int(hex_off, 16)
            except ValueError:
                continue
            if offset not in found:
                found[offset] = {
                    "name": name,
                    "offset": -offset,
                    "size": self._size_from_type_hint(type_str),
                    "inferred_type": type_str,
                }

        # Bracket-style stack references.
        for pattern in self._STACK_LOCAL_PATTERNS[2:]:
            for m in pattern.finditer(text):
                groups = m.groupdict()
                off_str = groups.get("offset") or groups.get("off")
                if not off_str:
                    continue
                size = 4
                inferred = "int32"
                try:
                    if off_str.lower().startswith("0x"):
                        offset = int(off_str, 16)
                    else:
                        offset = int(off_str, 16) if m.group(0).lower().rstrip().endswith("h]") else int(off_str)
                except ValueError:
                    continue
                offset = -offset
                if offset not in found:
                    found[offset] = {
                        "name": f"local_{-offset:x}",
                        "offset": offset,
                        "size": size,
                        "inferred_type": inferred,
                    }

        return list(found.values())

    @staticmethod
    def _size_from_type_hint(type_hint: str) -> int:
        t = (type_hint or "").lower().replace(" ", "")
        if "int64" in t or "longlong" in t or "double" in t or t == "uint64_t" or t == "int64_t":
            return 8
        if "int32" in t or t == "int" or t == "uint32_t" or t == "dword" or "float" in t:
            return 4
        if "int16" in t or t == "short" or t == "uint16_t" or t == "word":
            return 2
        if "int8" in t or t == "char" or t == "uint8_t" or t == "byte":
            return 1
        if "*" in type_hint:
            return TypeRecoveryAgent._likely_pointer_size()
        return 4

    def find_scaled_index_access(self) -> list[dict[str, Any]]:
        """Scan the graph for array/structure scaled-index access patterns.

        IDA/Ghidra commonly emit access forms such as:
        ``*(base + offset + index * scale)`` (decompiler),
        ``0x10(%rax,%rcx,8)`` (AT&T disassembly),
        ``[rax+rcx*8+10h]`` (Intel disassembly).

        Returns
        -------
        list[dict]
            Each dict contains ``base``, ``index``, ``scale``, ``offset``,
            ``access_kind`` (``array`` or ``struct``), ``size_guess``,
            ``source_node`` and the fragment of text matched.
        """
        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        for n in self.graph.nodes:
            props = n.properties or {}
            fragments: list[str] = []
            for value in (
                props.get("decompiled", ""),
                props.get("disassembly", ""),
                props.get("signature", ""),
            ):
                if isinstance(value, (list, tuple)):
                    fragments.extend(str(item) for item in value)
                elif value:
                    fragments.append(str(value))
            text = " ".join(fragments)
            for pattern in self._SCALED_INDEX_PATTERNS:
                for m in pattern.finditer(text):
                    base = (m.group("base") or "").strip()
                    index = (m.group("index") or "").strip()
                    scale = int(m.group("scale") or 1)
                    offset = 0
                    if m.group("offset"):
                        off_str = m.group("offset").replace("h", "").replace("H", "")
                        try:
                            offset = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str, 0)
                        except ValueError:
                            try:
                                offset = int(off_str, 16)
                            except ValueError:
                                offset = 0

                    kind = "array" if scale > 1 and offset == 0 else "struct"
                    if scale > 1 and offset > 0:
                        kind = "struct_array"  # array inside a struct

                    key = f"{n.id}:{base}:{index}:{scale}:{offset}:{kind}"
                    if key in seen:
                        continue
                    seen.add(key)

                    access = {
                        "base": base,
                        "index": index,
                        "scale": scale,
                        "offset": offset,
                        "access_kind": kind,
                        "size_guess": scale,
                        "source_node": n.id,
                        "matched_text": m.group(0),
                    }
                    results.append(access)

            pointer_widths = {
                m.group("name"): self._width_for_c_type(m.group("type"))
                for m in self._POINTER_DECL_PATTERN.finditer(text)
            }

            # Constant pointer offsets are the most common structure signal in
            # optimized decompiler output and do not necessarily contain a
            # scaled index.
            for m in self._DIRECT_OFFSET_PATTERN.finditer(text):
                base = m.group("base")
                if self._is_pseudo_struct_base(base):
                    continue
                offset = int(m.group("offset") or "0", 0)
                # Preserve C pointer-arithmetic semantics.  ``long *p; p + 2``
                # addresses byte offset 16, while integer-like ``a1 + 8``
                # remains byte offset 8.
                if base in pointer_widths:
                    offset *= pointer_widths[base]
                size = self._width_for_c_type(m.group("type"))
                key = f"{n.id}:{base}:direct:{offset}:{size}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "base": base,
                    "index": "",
                    "scale": 1,
                    "offset": offset,
                    "access_kind": "struct",
                    "size_guess": size,
                    "source_node": n.id,
                    "matched_text": m.group(0),
                    "evidence_kind": "direct_pointer_offset",
                })

            # Typed ``ptr[index]`` is equivalent to a constant byte offset.
            # Restrict this to variables proven pointer-typed by the emitted C
            # declaration so local byte arrays are not mislabeled as structs.
            for m in self._CONSTANT_ARRAY_PATTERN.finditer(text):
                base = m.group("base")
                if base not in pointer_widths or self._is_pseudo_struct_base(base):
                    continue
                size = pointer_widths[base]
                offset = int(m.group("index"), 0) * size
                key = f"{n.id}:{base}:typed_array:{offset}:{size}"
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "base": base,
                    "index": m.group("index"),
                    "scale": size,
                    "offset": offset,
                    "access_kind": "struct",
                    "size_guess": size,
                    "source_node": n.id,
                    "matched_text": m.group(0),
                    "evidence_kind": "typed_constant_index",
                })

        return results

    @staticmethod
    def _width_for_c_type(type_name: str) -> int:
        normalized = type_name.strip().lower().lstrip("_")
        if normalized in {"qword", "undefined8", "uint64_t", "int64_t", "ulong", "long", "size_t"}:
            return 8
        if normalized in {"dword", "undefined4", "uint32_t", "int32_t", "uint", "int"}:
            return 4
        if normalized in {"word", "undefined2", "uint16_t", "int16_t", "ushort", "short"}:
            return 2
        return 1

    @staticmethod
    def _is_pseudo_struct_base(base: str) -> bool:
        """Reject architectural/TLS pseudo-bases that are not aggregates."""
        normalized = base.lower()
        return (
            "fs_offset" in normalized
            or "gs_offset" in normalized
            or normalized in {"fs", "gs", "tls", "stack_chk_guard"}
        )

    def recover_signatures(self) -> dict[str, FunctionSignature]:
        """Recover a `FunctionSignature` for every function in the graph.

        The method combines:

        * explicit ``signature`` property if the analysis engine supplied one,
        * calling-convention estimation,
        * stack-frame local extraction,
        * rough parameter count estimation from instructions/call-site text.

        Returns
        -------
        dict[str, FunctionSignature]
            Mapping from function node id to recovered signature.
        """
        sigs: dict[str, FunctionSignature] = {}
        pointer_size = self._likely_pointer_size()

        for fn_node in self._function_nodes():
            props = fn_node.properties or {}
            entry = fn_node.address or props.get("entry", "0x0")

            cc = self.estimate_calling_convention(fn_node)
            ret_type = props.get("return_type", "unknown") or "unknown"
            local_vars = self.extract_stack_locals(fn_node)

            # Explicit signature object provided by engine (e.g. IDA type info).
            explicit_sig = props.get("signature")
            parameters: list[dict[str, Any]] = []
            if isinstance(explicit_sig, dict):
                parameters = [
                    {
                        "name": p.get("name", f"arg_{i}"),
                        "type": p.get("type", "unknown"),
                        "reg_or_stack_offset": p.get("reg_or_stack_offset", p.get("loc", "unknown")),
                    }
                    for i, p in enumerate(explicit_sig.get("parameters", []))
                ]
                ret_type = explicit_sig.get("return_type", ret_type)
                cc = explicit_sig.get("calling_convention", cc)
            elif isinstance(explicit_sig, str):
                # Best-effort parse of C-like declarations:  int foo(int a, char *b)
                parameters = self._parse_c_signature(explicit_sig)

            # No parameters?  Infer count from arg-register footprint in text.
            if not parameters:
                parameters = self._parameters_from_text(props, cc)

            # Improve argument locations for register-based conventions.
            arg_regs = self._ARG_REGISTERS.get(cc if cc in self._ARG_REGISTERS else self._architecture_hint(), [])
            for i, p in enumerate(parameters):
                if p.get("reg_or_stack_offset") is None or p["reg_or_stack_offset"] == "unknown":
                    if i < len(arg_regs):
                        p["reg_or_stack_offset"] = arg_regs[i]
                    else:
                        p["reg_or_stack_offset"] = f"stack+{i * pointer_size}"

            frame_size = props.get("frame_size")
            if frame_size is None:
                frame_size = props.get("stack_frame_size")
            if frame_size is not None:
                try:
                    frame_size = int(frame_size)
                except (TypeError, ValueError):
                    frame_size = None

            confidence = self._signature_confidence(cc, bool(parameters), bool(local_vars), explicit_sig)

            sigs[fn_node.id] = FunctionSignature(
                name=fn_node.name or props.get("name", "unknown"),
                entry=entry,
                calling_convention=cc,
                return_type=ret_type,
                parameters=parameters,
                local_vars=local_vars,
                stack_frame_size=frame_size,
                confidence=confidence,
            )

        return sigs

    def _parse_c_signature(self, text: str) -> list[dict[str, Any]]:
        """Naive parser for C function signatures."""
        parameters: list[dict[str, Any]] = []
        # Find the parenthesised argument list.
        m = re.search(r"\(([^)]*)\)", text)
        if not m:
            return parameters
        args = m.group(1)
        if args.strip() in {"void", ""}:
            return parameters
        for i, part in enumerate(args.split(",")):
            part = part.strip()
            if not part:
                continue
            # Try to split type and name.
            tokens = part.split()
            if len(tokens) >= 2:
                param_type = " ".join(tokens[:-1])
                param_name = tokens[-1].lstrip("*")
            else:
                param_type = part
                param_name = f"arg_{i}"
            parameters.append(
                {
                    "name": param_name,
                    "type": param_type,
                    "reg_or_stack_offset": "unknown",
                }
            )
        return parameters

    def _parameters_from_text(self, props: dict[str, Any], cc: str) -> list[dict[str, Any]]:
        """Estimate parameter count from textual artefacts."""
        text = f"{props.get('decompiled', '')}\n{props.get('disassembly', '')}"
        if not text.strip():
            return []

        arch = self._architecture_hint()
        arg_regs = self._ARG_REGISTERS.get(arch, [])

        # Count argument-register initialisations as upper bound.
        reg_args = 0
        for reg in arg_regs:
            if re.search(rf"\b{re.escape(reg)}\b", text):
                reg_args += 1

        # Count push instructions as stack arguments on x86 cdecl/stdcall.
        pushes = len(re.findall(r"\bpush\b", text.lower())) if arch == "x86" else 0
        count = max(reg_args, pushes)

        confidence_boost = 1.0 if (reg_args or pushes) else 0.0
        parameters = []
        for i in range(count):
            loc = arg_regs[i] if i < len(arg_regs) else f"stack+{i * 4}"
            parameters.append(
                {
                    "name": f"arg_{i}",
                    "type": "unknown",
                    "reg_or_stack_offset": loc,
                }
            )
        if not parameters:
            return []
        # Attach a lightweight confidence marker in the type for consumers.
        for p in parameters:
            if confidence_boost == 0.0:
                p["type"] = "unknown (inferred)"
        return parameters

    def _signature_confidence(
        self, cc: str, has_params: bool, has_locals: bool, explicit_sig: Any
    ) -> float:
        conf = 0.3
        if explicit_sig:
            conf += 0.4
        if cc != "unknown":
            conf += 0.2
        if has_params:
            conf += 0.05
        if has_locals:
            conf += 0.05
        return round(min(conf, 1.0), 2)

    def recover_structures(self, max_structs: int = 200) -> list[RecoveredStructure]:
        """Build candidate structures from scaled-index and offset access.

        Access footprints are grouped by base register/variable.  Fields are
        placed at discovered offsets and padded according to natural alignment
        rules; array accesses share a single field with ``is_array`` set.

        Parameters
        ----------
        max_structs:
            Upper bound on the number of structures returned.

        Returns
        -------
        list[RecoveredStructure]
        """
        accesses = self.find_scaled_index_access()
        by_base: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for a in accesses:
            # Local names such as ``a1`` repeat across unrelated functions.
            # Do not merge them without cross-function type/data-flow proof.
            key = (str(a.get("source_node") or "unknown"), a["base"])
            by_base.setdefault(key, []).append(a)

        structs: list[RecoveredStructure] = []
        idx = 0
        for (source_node, base), items in by_base.items():
            if idx >= max_structs:
                break
            fields_map: dict[int, dict[str, Any]] = {}
            max_offset = 0
            for a in items:
                off = a["offset"]
                size = a["size_guess"]
                kind = a["access_kind"]
                if off in fields_map:
                    kinds = set(str(fields_map[off]["access_kind"]).split(","))
                    kinds.add(kind)
                    fields_map[off]["access_kind"] = ",".join(sorted(kinds))
                    fields_map[off]["confidence_count"] = fields_map[off].get("confidence_count", 1) + 1
                    if size > int(fields_map[off]["size"]):
                        fields_map[off]["size"] = size
                        fields_map[off]["type"] = self._type_for_size(size)
                    evidence = fields_map[off].setdefault("evidence", [])
                    if len(evidence) < 8:
                        evidence.append({
                            "source_node": source_node,
                            "matched_text": a.get("matched_text"),
                            "kind": a.get("evidence_kind", "scaled_index"),
                        })
                else:
                    fields_map[off] = {
                        "offset": off,
                        "size": size,
                        "type": self._type_for_size(size),
                        "access_kind": kind,
                        "confidence_count": 1,
                        "evidence": [{
                            "source_node": source_node,
                            "matched_text": a.get("matched_text"),
                            "kind": a.get("evidence_kind", "scaled_index"),
                        }],
                    }
                max_offset = max(max_offset, off + size)

            # Pad structure size to largest accessed offset plus element size.
            struct_size = self._align_up(max_offset, self._sizes([v["size"] for v in fields_map.values()] or [4]))
            fields = sorted(fields_map.values(), key=lambda f: f["offset"])

            confidence = min(0.95, 0.4 + 0.05 * len(fields))
            safe_source = re.sub(r"[^a-zA-Z0-9_]+", "_", source_node).strip("_")
            safe_base = re.sub(r"[^a-zA-Z0-9_]+", "_", base).strip("_")
            structs.append(
                RecoveredStructure(
                    name=f"struct_{safe_source}_{safe_base}",
                    size=struct_size,
                    fields=fields,
                    confidence=round(confidence, 2),
                )
            )
            idx += 1

        return structs

    @staticmethod
    def _type_for_size(size: int) -> str:
        if size == 8:
            return "uint64_t"
        if size == 4:
            return "uint32_t"
        if size == 2:
            return "uint16_t"
        if size == 1:
            return "uint8_t"
        return "unknown"

    @staticmethod
    def _align_up(value: int, align: int) -> int:
        return ((value + align - 1) // align) * align

    @staticmethod
    def _sizes(values: list[int]) -> int:
        if not values:
            return 4
        return max(values)

    def propagate_known_types(self, seed: dict[str, FunctionSignature]) -> dict[str, FunctionSignature]:
        """Propagate known return/argument types across direct call edges.

        For every call edge ``A -> B`` where ``B`` is present in ``seed``:

        * if ``A`` does not have a known return type and the only callee is
          ``B``,``A`` inherits ``B``'s return type with reduced confidence,
        * callee parameters typed in ``seed`` are copied into any call site
          metadata kept on the edge (non-destructive).

        Parameters
        ----------
        seed:
            Mapping from node id to authoritative `FunctionSignature`.

        Returns
        -------
        dict[str, FunctionSignature]
            A new mapping with propagated types.  The original ``seed`` is not
            mutated.
        """
        propagated: dict[str, FunctionSignature] = {}
        for node_id, sig in seed.items():
            propagated[node_id] = FunctionSignature(**sig.as_dict())

        for node_id, sig in list(propagated.items()):
            caller_node = self.graph.get_node(node_id)
            if not caller_node:
                continue

            callee_edges = self.graph.edge_list(node_id, edge_kind="calls", direction="out")
            for edge in callee_edges:
                callee = seed.get(edge.dst)
                if not callee:
                    continue

                # Strengthen caller return type if it currently looks unknown
                # and we can see a single well-typed callee.
                if sig.return_type in {"unknown", "void"} and callee.return_type not in {"unknown"}:
                    if len(callee_edges) == 1 or callee.return_type != "void":
                        propagated[node_id].return_type = callee.return_type
                        propagated[node_id].confidence = max(propagated[node_id].confidence - 0.1, 0.0)

                # Merge parameter hints from callee into caller callsite info.
                edge_props = edge.properties or {}
                callsite_params = edge_props.get("callsite_params", [])
                if not callsite_params:
                    callsite_params = []
                for cparam in callee.parameters:
                    if cparam.get("type") and cparam["type"] != "unknown":
                        callsite_params.append(
                            {
                                "callee": callee.name,
                                "name": cparam["name"],
                                "type": cparam["type"],
                            }
                        )
                if callsite_params:
                    edge_props["callsite_params"] = callsite_params

        return propagated

    # ------------------------------------------------------------------ iteration helpers

    def __iter__(self):
        """Yield function node ids when iterating the agent."""
        return iter(self._function_nodes())
