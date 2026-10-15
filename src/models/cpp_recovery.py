"""C++ / RTTI / vtable recovery for the Angerona analysis graph.

The heuristics in this module follow the material from *The IDA Pro Book*:

* vtable pointers are stored into objects by constructors and restored by
  destructors, so functions that take the address of a vtable symbol (or that
  reference it via ``offset``/``references`` edges) are strong ctor/dter
  candidates.
* GNU/Itanium compilers emit ``_ZTV``/``_ZTT`` (vtable tables), ``_ZTI``
  (``type_info`` objects) and ``_ZTS`` (typeinfo name strings).
* MSVC emits ``??_7`` vftable symbols and ``??_R0`` / ``??_R1`` / ``??_R2`` /
  ``??_R3`` RTTI descriptors.
* Class hierarchy can be approximated by checking whether one vtable's method
  pointer sequence is a prefix of another's (a common IDA Pro Book heuristic).

No mandatory third-party dependencies are introduced.  ``cxxfilt`` is used when
available; otherwise a small Itanium-mangling prefix decoder falls back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .analysis_graph import AnalysisGraph


@dataclass
class VTable:
    """A recovered virtual method table.

    Attributes:
        address: Hex address of the vtable symbol/table.
        class_name: Demangled class name, or ``None`` if it could not be
            recovered.
        method_entries: Ordered list of method pointer records.  Each record
            contains ``method_offset``, ``target_fn_id``, ``target_addr`` and
            ``target_name``; validated secondary-table entries also carry
            normalized ``this_adjustment`` evidence.
        rtti_ref: Node id of an associated RTTI object (e.g. ``_ZTI...``), or
            ``None``.
        confidence: Recovery confidence in ``[0.0, 1.0]``.
        address_point: ABI address point used in object vptrs.
        offset_to_top: Signed Itanium subobject-to-complete-object adjustment.
        table_kind: ``"primary"``, ``"secondary"`` or ``"unknown"``.
        prefix_entries: Validated Itanium vcall/vbase offset records before the
            offset-to-top header.
        vtt_info: Validated virtual table table (VTT) metadata, when present.
    """

    address: str
    class_name: str | None
    method_entries: list[dict[str, Any]]
    rtti_ref: str | None
    confidence: float = 0.0
    compiler: str = "unknown"
    source_node_id: str | None = None
    address_point: str | None = None
    offset_to_top: int | None = None
    table_kind: str = "unknown"
    first_method_target: str | None = None
    method_slots_validated: bool = False
    method_boundary_reason: str | None = None
    prefix_entries: list[dict[str, Any]] = field(default_factory=list)
    prefix_entries_validated: bool = False
    prefix_boundary_reason: str | None = None
    vtt_info: dict[str, Any] | None = None


@dataclass
class ClassHierarchy:
    """Aggregated C++ class information recovered from vtables and RTTI.

    Attributes:
        class_name: Reconstructed class name.
        vtables: List of vtable hex addresses associated with the class.
        constructors: Function node ids believed to be constructors.
        destructors: Function node ids believed to be destructors.
        parents: Parent class names inferred from vtable prefix overlap or
            RTTI base-class hints.
        children: Child class names inferred from vtable prefix overlap.
        rtti_type_info: Optional RTTI classification produced by
            :meth:`CppRecoveryAgent.classify_rtti`.
        compiler: ``"gnu"``, ``"msvc"`` or ``"unknown"``.
        confidence: Aggregated recovery confidence.
        role: ``"user_candidate"``, ``"runtime_support"`` or
            ``"library_support"``.
        role_reason: Evidence used to assign ``role``.
    """

    class_name: str
    vtables: list[str]
    constructors: list[str]
    destructors: list[str]
    parents: list[str]
    children: list[str]
    rtti_type_info: dict[str, Any] | None
    compiler: str = "unknown"
    confidence: float = 0.0
    role: str = "user_candidate"
    role_reason: str = "no_runtime_support_evidence"

    def as_dict(self) -> dict[str, Any]:
        """Return a stable JSON-ready class record."""
        return {
            "class_name": self.class_name,
            "vtables": list(self.vtables),
            "constructors": list(self.constructors),
            "destructors": list(self.destructors),
            "parents": list(self.parents),
            "children": list(self.children),
            "rtti_type_info": self.rtti_type_info,
            "compiler": self.compiler,
            "confidence": self.confidence,
            "role": self.role,
            "role_reason": self.role_reason,
        }


class CppRecoveryAgent:
    """Heuristic C++ recovery agent operating on an :class:`AnalysisGraph`.

    The agent locates vtable symbols, resolves method entries through graph
    edges and address-range scanning, links constructors/destructors and RTTI
    information, and finally builds a class hierarchy map.
    """

    # GNU/Itanium mangling prefixes.
    _GNU_VTABLE_PREFIXES = ("_ZTV", "_ZTT")
    _GNU_RTI_PREFIXES = ("_ZTI", "_ZTS")

    # General vtable-related naming patterns (IDA/Ghidra/IR).
    _VTABLE_NAME_PATTERNS = (
        re.compile(r"^_ZTV.*"),
        re.compile(r"^vtable.*"),
        re.compile(r"^vftable.*"),
        re.compile(r"^const\s+.*"),  # MSVC vftables may carry "const ..." names
        re.compile(r"^\?\?_7.*"),    # MSVC vftable pointer symbol
    )

    # MSVC RTTI mangling patterns.
    _MSVC_RTI_RE = re.compile(r"^\?\?_R[0-4].*")
    _MSVC_VFTABLE_RE = re.compile(r"^\?\?_7.*")

    # These types implement compiler RTTI itself.  They are useful evidence and
    # remain in raw recovery, but should not inflate the analyzed program's
    # user-class hierarchy.
    _RUNTIME_CLASS_PREFIXES = (
        "__cxxabiv1::",
        "__cxxabi::",
        "__abi::",
    )
    _RUNTIME_CLASS_NAMES = {
        "type_info",
        "std::type_info",
    }
    _LIBRARY_CLASS_PREFIXES = (
        "std::",
        "__gnu_cxx::",
    )

    # Constructor/destructor hints inside Itanium names.
    _CTOR_RE = re.compile(r"[CD]([0-3])E$")

    # Cap scanning: binaries sometimes have huge tables; do not run forever.
    _MAX_VTABLE_SLOTS = 128

    def __init__(self, graph: AnalysisGraph) -> None:
        self.graph = graph
        self._cxxfilt = self._try_import_cxxfilt()
        self._vtables: list[VTable] | None = None
        self._classes: dict[str, ClassHierarchy] | None = None

    # ------------------------------------------------------------------ helpers

    @property
    def vtables(self) -> list[VTable]:
        """Return recovered vtables without repeating a completed scan."""
        if self._vtables is None:
            self.find_vtables()
        return list(self._vtables or [])

    @staticmethod
    def _try_import_cxxfilt() -> Any:
        """Return the ``cxxfilt`` module if installed, otherwise ``None``."""
        try:
            import cxxfilt  # type: ignore[import]

            return cxxfilt
        except Exception:  # pragma: no cover - optional dependency
            return None

    @property
    def _pointer_size(self) -> int:
        """Best-effort pointer size, defaulting to 8."""
        ps = self.graph.metadata.get("pointer_size")
        if isinstance(ps, int) and ps > 0:
            return ps
        if isinstance(ps, str):
            try:
                return int(ps)
            except ValueError:
                pass
        return 8

    @staticmethod
    def _addr_int(value: str | int | None) -> int:
        """Convert an address value to an integer, returning 0 on failure."""
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        s = str(value).strip()
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except ValueError:
                return 0
        try:
            # Ghidra renders addresses as zero-padded hexadecimal without a
            # ``0x`` prefix.  Digit-only values such as ``00103200`` must not
            # silently become decimal; unpadded digit strings retain the
            # legacy decimal interpretation for direct API callers.
            is_hex = (
                any(c in s for c in "abcdefABCDEF")
                or (len(s) > 1 and s.startswith("0"))
            )
            return int(s, 16 if is_hex else 10)
        except ValueError:
            return 0

    @staticmethod
    def _addr_str(value: int) -> str:
        """Normalize an integer address to a canonical hex string."""
        return f"0x{value & 0xFFFFFFFFFFFFFFFF:x}"

    # --------------------------------------------------------------- demangling

    def demangle_name(self, name: str) -> str:
        """Return a human-readable form of a mangled C++ name.

        If ``cxxfilt`` is installed and the name is a GNU/Itanium mangled
        symbol, full demangling is attempted.  A small built-in decoder is used
        as a fallback for ``_Z`` prefixes; MSVC ``?`` names are returned
        largely unchanged because their encoding is too complex to decode
        safely without extra data.
        """
        if not name:
            return ""

        # Prefer cxxfilt for Itanium names.
        if self._cxxfilt and name.startswith("_Z"):
            try:
                demangled = self._cxxfilt.demangle(name)
                if demangled and demangled != name:
                    return demangled
            except Exception:  # pragma: no cover - optional/best-effort
                pass

        # Simple builtin demangler for common _ZN patterns.
        if name.startswith("_Z"):
            return self._simple_itanium_demangle(name)

        # MSVC mangled names are too baroque for a robust heuristic decoder.
        if name.startswith("?"):
            return name

        # Names that are already readable.
        return name

    def _simple_itanium_demangle(self, name: str) -> str:
        """Decode ``_ZN...E``/``_ZTV...`` style names with length prefixes."""
        body = name[2:]  # strip _Z
        prefix_kind = ""
        if body.startswith("TV"):
            prefix_kind = "vtable for "
            body = body[2:]
        elif body.startswith("TT"):
            prefix_kind = "VTT for "
            body = body[2:]
        elif body.startswith("TI"):
            prefix_kind = "typeinfo for "
            body = body[2:]
        elif body.startswith("TS"):
            prefix_kind = "typeinfo name for "
            body = body[2:]
        if body.startswith("N"):
            body = body[1:]  # nested-name marker

        # Consume exact length-prefixed identifiers. A greedy regex here used
        # to swallow the whole suffix and return only the first namespace.
        segments: list[str] = []
        while body:
            if body.startswith("E"):
                break
            m = re.match(r"(\d+)", body)
            if not m:
                break
            length = int(m.group(1))
            start = m.end()
            end = start + length
            if length <= 0 or end > len(body):
                break
            segments.append(body[start:end])
            body = body[end:]

        return prefix_kind + "::".join(segments)

    def _class_from_itanium_type_string(self, value: str | None) -> str | None:
        """Recover a class name from an ABI RTTI type-name string."""
        text = (value or "").strip()
        if not re.fullmatch(r"N(?:\d+[A-Za-z_][A-Za-z0-9_]*)+E", text):
            return None
        demangled = self.demangle_name("_ZTS" + text)
        prefix = "typeinfo name for "
        if demangled.startswith(prefix):
            demangled = demangled[len(prefix):]
        return demangled or None

    # ----------------------------------------------------- name-based inference

    def _is_vtable_name(self, name: str | None) -> bool:
        """Return ``True`` when ``name`` looks like a vtable symbol."""
        if not name:
            return False
        for pattern in self._VTABLE_NAME_PATTERNS:
            if pattern.match(name):
                return True
        return False

    def _extract_class_from_vtable_name(self, name: str) -> str | None:
        """Recover a class name from a vtable symbol name."""
        if not name:
            return None

        if name.startswith("vtable for "):
            return name[len("vtable for ") :].strip()
        if name.startswith("VTT for "):
            return name[len("VTT for ") :].strip()

        demangled = self.demangle_name(name)
        for prefix in ("vtable for ", "VTT for ", "typeinfo for ", "typeinfo name for "):
            if demangled.startswith(prefix):
                return demangled[len(prefix) :].strip()

        # MSVC style: ??_7ClassName@@6B@ or similar.
        m = re.match(r"\?\?_7(.+?)@@", name)
        if m:
            return m.group(1).replace("@", "::")

        return None

    def _classify_compiler_from_name(self, name: str) -> str:
        """Guess the toolchain from a vtable/RTTI symbol name."""
        if not name:
            return "unknown"
        if name.startswith(self._GNU_VTABLE_PREFIXES) or name.startswith(
            self._GNU_RTI_PREFIXES
        ):
            return "gnu"
        if self._MSVC_VFTABLE_RE.match(name) or self._MSVC_RTI_RE.match(name):
            return "msvc"
        if name.startswith("vtable") or name.startswith("VTT"):
            # Usually IDA's de-mangled GNU names.
            return "gnu"
        return "unknown"

    def _class_names_equal(self, a: str | None, b: str | None) -> bool:
        """Compare two possibly-demangled class names, tolerating whitespace."""
        if a is None or b is None:
            return False
        return a.strip().replace(" ", "") == b.strip().replace(" ", "")

    def _extract_class_from_ctor_dtor(self, name: str) -> str | None:
        """If ``name`` names a ctor/dtor, return the demangled class part."""
        if not name:
            return None
        # Fast path: explicit Itanium ctors/destructors contain C[1-3]E / D[0-2]E.
        if name.startswith("_ZN") and (self._is_ctor_name(name) or self._is_dtor_name(name)):
            base = self.demangle_name(name)
            # Heuristic: strip trailing ctor/dtor marker produced by cxxfilt.
            for suffix in (
                "::constructor",
                "::destructor",
                "::\x7e",  # tilde
            ):
                if suffix in base:
                    return base.split(suffix)[0].strip()
            if "::" not in base:
                return base
            parts = base.split("::")
            return "::".join(parts[:-1])

        # Already-demangled style, e.g. "MyClass::MyClass()" or "MyClass::~MyClass()".
        if "::" in name:
            parts = name.split("::")
            if len(parts) >= 2:
                # class::method; method is ctor if it equals class, dtor if ~class.
                cls = "::".join(parts[:-1])
                method = parts[-1].split("(")[0].strip()
                bare = method.lstrip("~")
                if bare == cls.split("::")[-1]:
                    return cls
        return None

    def _is_ctor_name(self, name: str) -> bool:
        """Return ``True`` when ``name`` names a constructor."""
        if not name:
            return False
        if "C1E" in name or "C2E" in name or "C3E" in name:
            return True
        # Demangled style: Class::Class(...) is a ctor.
        if "::" in name and "::~" not in name:
            parts = name.split("::")
            return parts[-1].split("(")[0].strip() == parts[-2].strip()
        return False

    def _is_dtor_name(self, name: str) -> bool:
        """Return ``True`` when ``name`` names a destructor."""
        if not name:
            return False
        if "D0E" in name or "D1E" in name or "D2E" in name:
            return True
        if "::~" in name or name.lstrip().startswith("~"):
            return True
        return False

    # --------------------------------------------------- RTTI classification

    def classify_rtti(self, info_node) -> dict[str, Any]:
        """Classify a potential RTTI node and return a metadata dictionary.

        The returned dictionary contains keys such as ``kind``,
        ``compiler``, ``name``, ``address`` and ``class_name``.
        """
        result: dict[str, Any] = {
            "node_id": getattr(info_node, "id", None),
            "name": None,
            "kind": "unknown",
            "compiler": "unknown",
            "address": None,
            "class_name": None,
        }
        if info_node is None:
            return result

        name = getattr(info_node, "name", None) or ""
        address = getattr(info_node, "address", None)
        result["name"] = name
        if address:
            result["address"] = self._addr_str(self._addr_int(address))

        if name.startswith("_ZTI"):
            result.update({"kind": "typeinfo", "compiler": "gnu"})
        elif name.startswith("_ZTS"):
            result.update({"kind": "typeinfo_name", "compiler": "gnu"})
        elif name.startswith("typeinfo for "):
            result.update({"kind": "typeinfo", "compiler": "gnu"})
        elif name.startswith("typeinfo name for "):
            result.update({"kind": "typeinfo_name", "compiler": "gnu"})
        elif self._MSVC_RTI_RE.match(name) or "RTTI" in name:
            result.update({"kind": "complete_object_locator", "compiler": "msvc"})
        elif "RTTICompleteObjectLocator" in name:
            result.update({"kind": "complete_object_locator", "compiler": "msvc"})

        if result["compiler"] == "gnu":
            result["class_name"] = self._extract_class_from_vtable_name(name)
        elif result["compiler"] == "msvc":
            # Best-effort: strip "??_R0?AU" style prefix and capture until '@@'.
            m = re.search(r"\?\?_R[0-4][^A-Za-z_]*(.+?)(?:@@|$)", name)
            if m:
                result["class_name"] = m.group(1).replace("@", "::")

        return result

    def _find_rtti_ref(
        self, class_name: str | None, vtable_node: Any, ps: int
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Locate an RTTI node associated with a vtable or class name."""
        if class_name:
            for n in self.graph.nodes:
                if not n.name:
                    continue
                if n.name.startswith("_ZTI") or n.name.startswith("typeinfo for "):
                    candidate = self._extract_class_from_vtable_name(n.name)
                    if self._class_names_equal(candidate, class_name):
                        return n.id, self.classify_rtti(n)
                if self._MSVC_RTI_RE.match(n.name):
                    info = self.classify_rtti(n)
                    if self._class_names_equal(info.get("class_name"), class_name):
                        return n.id, info

        # Address-proximity fallback.
        vtbl_addr = self._addr_int(getattr(vtable_node, "address", None))
        best: Any | None = None
        for n in self.graph.nodes:
            info = self.classify_rtti(n)
            if info["compiler"] == "unknown":
                continue
            addr = self._addr_int(getattr(n, "address", None))
            if addr and vtbl_addr and abs(addr - vtbl_addr) <= ps * 4:
                if best is None or abs(addr - vtbl_addr) < abs(
                    self._addr_int(getattr(best, "address", None)) - vtbl_addr
                ):
                    best = n
        if best is not None:
            return best.id, self.classify_rtti(best)
        return None, None

    # ----------------------------------------------------------- vtable search

    def _function_nodes_sorted(self) -> list[tuple[int, Any]]:
        """Return all function nodes sorted by integer address."""
        result: list[tuple[int, Any]] = []
        for n in self.graph.nodes:
            if n.kind == "function" and n.address:
                result.append((self._addr_int(n.address), n))
        result.sort(key=lambda x: x[0])
        return result

    def _method_entries_from_edges(self, vtable_node: Any) -> list[dict[str, Any]]:
        """Collect method pointers referenced by graph edges from a vtable."""
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for edge in self.graph.edge_list(vtable_node.id, direction="out"):
            if edge.kind not in ("references", "offset", "calls", "data_read"):
                continue
            target = self.graph.get_node(edge.dst)
            if target is None or target.kind != "function":
                continue
            if target.id in seen:
                continue
            seen.add(target.id)
            taddr = self._addr_int(target.address)
            vaddr = self._addr_int(vtable_node.address)
            offset = max(0, taddr - vaddr)
            entries.append(
                {
                    "method_offset": self._addr_str(offset),
                    "target_fn_id": target.id,
                    "target_addr": self._addr_str(taddr),
                    "target_name": self.demangle_name(target.name or ""),
                }
            )
        return entries

    def _method_entries_from_range(
        self, vtable_addr: int, ps: int
    ) -> list[dict[str, Any]]:
        """Infer vtable entries by scanning nearby function addresses."""
        entries: list[dict[str, Any]] = []
        for faddr, fn in self._function_nodes_sorted():
            max_offset = ps * self._MAX_VTABLE_SLOTS
            if ps <= faddr - vtable_addr <= max_offset:
                offset = faddr - vtable_addr
                # Functions must be pointer-aligned; skip obvious noise.
                if offset % ps != 0:
                    continue
                entries.append(
                    {
                        "method_offset": self._addr_str(offset),
                        "target_fn_id": fn.id,
                        "target_addr": self._addr_str(faddr),
                        "target_name": self.demangle_name(fn.name or ""),
                    }
                )
        return entries

    def _validated_vtable_prefix(
        self,
        candidate: dict[str, Any],
        *,
        vtable_address: int,
        address_point: int,
        offset_to_top: int,
        pointer_size: int,
    ) -> tuple[list[dict[str, Any]], str | None] | None:
        keys = {
            "prefix_entry_count",
            "prefix_entries",
            "prefix_boundary_reason",
        }
        present = keys.intersection(candidate)
        if not present:
            return ([], None)
        if present != keys:
            return None
        raw_entries = candidate.get("prefix_entries")
        boundary_reason = candidate.get("prefix_boundary_reason")
        try:
            entry_count = int(candidate.get("prefix_entry_count"))
        except (TypeError, ValueError):
            return None
        if (
            not isinstance(raw_entries, list)
            or entry_count < 0
            or entry_count != len(raw_entries)
        ):
            return None
        if entry_count == 0:
            return ([], None) if boundary_reason is None else None
        expected_kind = (
            "vbase_offset"
            if offset_to_top == 0 else "vcall_or_vbase_offset"
        )
        expected_boundary = (
            "vmi_virtual_base_slots"
            if offset_to_top == 0
            else "preceding_callable_vtable_slot"
        )
        if boundary_reason != expected_boundary:
            return None
        normalized = []
        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                return None
            try:
                entry_index = int(raw_entry.get("entry_index"))
                relative_offset = int(
                    raw_entry.get("relative_to_address_point")
                )
                pointer_address = self._addr_int(
                    raw_entry.get("pointer_address")
                )
                value = int(raw_entry.get("value"))
            except (TypeError, ValueError):
                return None
            entry_kind = str(raw_entry.get("entry_kind") or "")
            base_typeinfo = raw_entry.get("base_typeinfo_address")
            base_typeinfo_address = (
                self._addr_int(base_typeinfo)
                if base_typeinfo is not None else None
            )
            if (
                entry_index != index
                or relative_offset >= -2 * pointer_size
                or pointer_address != address_point + relative_offset
                or pointer_address
                != vtable_address - pointer_size * (entry_count - index)
                or entry_kind != expected_kind
                or (
                    expected_kind == "vbase_offset"
                    and (
                        base_typeinfo_address is None
                        or base_typeinfo_address <= 0
                    )
                )
                or (
                    expected_kind == "vcall_or_vbase_offset"
                    and base_typeinfo is not None
                )
            ):
                return None
            normalized.append({
                "entry_index": entry_index,
                "relative_to_address_point": relative_offset,
                "pointer_address": self._addr_str(pointer_address),
                "value": value,
                "entry_kind": entry_kind,
                "base_typeinfo_address": (
                    self._addr_str(base_typeinfo_address)
                    if base_typeinfo_address is not None else None
                ),
            })
        return (normalized, str(boundary_reason))

    @staticmethod
    def _signed_mangled_offset(token: str) -> int:
        return -int(token[1:]) if token.startswith("n") else int(token)

    def _validated_exported_this_adjustments(
        self,
        raw_slot: dict[str, Any],
        *,
        pointer_size: int,
    ) -> list[dict[str, Any]] | None:
        if "this_adjustment_candidates" not in raw_slot:
            return []
        raw_candidates = raw_slot.get("this_adjustment_candidates")
        if not isinstance(raw_candidates, list):
            return None
        normalized = []
        seen = set()
        for raw_candidate in raw_candidates:
            if not isinstance(raw_candidate, dict):
                return None
            kind = str(raw_candidate.get("kind") or "")
            evidence = str(raw_candidate.get("evidence") or "")
            source_name = raw_candidate.get("source_name")
            try:
                fixed_delta = int(raw_candidate.get("fixed_delta"))
                confidence = float(raw_candidate.get("confidence"))
            except (TypeError, ValueError):
                return None
            raw_vcall_slot = raw_candidate.get("vcall_offset_slot")
            try:
                vcall_slot = (
                    int(raw_vcall_slot)
                    if raw_vcall_slot is not None else None
                )
            except (TypeError, ValueError):
                return None
            if (
                kind not in {"fixed", "virtual_vcall"}
                or evidence not in {
                    "itanium_mangled_thunk_symbol",
                    "x86_sysv_this_adjustment_instruction_pattern",
                }
                or confidence < 0.99
                or (
                    kind == "fixed"
                    and vcall_slot is not None
                )
                or (
                    kind == "virtual_vcall"
                    and (
                        vcall_slot is None
                        or vcall_slot >= -2 * pointer_size
                        or vcall_slot % pointer_size != 0
                    )
                )
            ):
                return None
            if evidence == "itanium_mangled_thunk_symbol":
                if not isinstance(source_name, str):
                    return None
                if kind == "fixed":
                    match = re.search(
                        r"_ZTh(?P<fixed>n?\d+)_",
                        source_name,
                    )
                    if (
                        match is None
                        or self._signed_mangled_offset(
                            match.group("fixed")
                        ) != fixed_delta
                    ):
                        return None
                else:
                    match = re.search(
                        r"_ZTv(?P<fixed>n?\d+)_"
                        r"(?P<vcall>n?\d+)_",
                        source_name,
                    )
                    if (
                        match is None
                        or self._signed_mangled_offset(
                            match.group("fixed")
                        ) != fixed_delta
                        or self._signed_mangled_offset(
                            match.group("vcall")
                        ) != vcall_slot
                    ):
                        return None
            elif source_name is not None:
                return None
            key = (kind, fixed_delta, vcall_slot)
            if key in seen:
                continue
            seen.add(key)
            normalized.append({
                "kind": kind,
                "fixed_delta": fixed_delta,
                "vcall_offset_slot": vcall_slot,
                "evidence": evidence,
                "source_name": source_name,
                "confidence": confidence,
            })
        return normalized

    @staticmethod
    def _method_this_adjustment(
        exported_candidates: list[dict[str, Any]],
        *,
        table_kind: str,
        offset_to_top: int,
        prefix_entries: list[dict[str, Any]],
        has_vtt: bool,
        secondary_is_nonvirtual_base: bool,
    ) -> dict[str, Any] | None:
        if table_kind == "primary":
            return None if not exported_candidates else {}
        if secondary_is_nonvirtual_base:
            if any(
                candidate["kind"] != "fixed"
                or candidate["fixed_delta"] != offset_to_top
                for candidate in exported_candidates
            ):
                return {}
            strongest = max(
                exported_candidates,
                key=lambda candidate: candidate["confidence"],
                default=None,
            )
            return {
                "kind": "fixed",
                "resolved": True,
                "fixed_delta": offset_to_top,
                "vcall_offset_slot": None,
                "vcall_offset_value": None,
                "candidate_vcall_offsets": [],
                "evidence": (
                    strongest["evidence"]
                    if strongest is not None
                    else "rtti_nonvirtual_base_object_offset"
                ),
                "confidence": (
                    strongest["confidence"]
                    if strongest is not None else 1.0
                ),
            }
        fixed_candidates = [
            candidate for candidate in exported_candidates
            if candidate["kind"] == "fixed"
        ]
        if fixed_candidates:
            if (
                len(fixed_candidates) != len(exported_candidates)
                or any(
                    candidate["fixed_delta"] != offset_to_top
                    for candidate in fixed_candidates
                )
            ):
                return {}
            strongest = max(
                fixed_candidates,
                key=lambda candidate: candidate["confidence"],
            )
            return {
                "kind": "fixed",
                "resolved": True,
                "fixed_delta": offset_to_top,
                "vcall_offset_slot": None,
                "vcall_offset_value": None,
                "candidate_vcall_offsets": [],
                "evidence": strongest["evidence"],
                "confidence": strongest["confidence"],
            }
        if not prefix_entries:
            if any(
                candidate["kind"] != "fixed"
                or candidate["fixed_delta"] != offset_to_top
                for candidate in exported_candidates
            ):
                return {}
            strongest = max(
                exported_candidates,
                key=lambda candidate: candidate["confidence"],
                default=None,
            )
            return {
                "kind": "fixed",
                "resolved": True,
                "fixed_delta": offset_to_top,
                "vcall_offset_slot": None,
                "vcall_offset_value": None,
                "candidate_vcall_offsets": [],
                "evidence": (
                    strongest["evidence"]
                    if strongest is not None
                    else "secondary_vtable_offset_to_top"
                ),
                "confidence": (
                    strongest["confidence"]
                    if strongest is not None else 0.98
                ),
            }
        if not has_vtt:
            return {}
        prefix_by_slot = {
            int(entry["relative_to_address_point"]): int(entry["value"])
            for entry in prefix_entries
        }
        if any(
            candidate["kind"] != "virtual_vcall"
            or candidate["vcall_offset_slot"] not in prefix_by_slot
            for candidate in exported_candidates
        ):
            return {}
        if exported_candidates:
            semantic_candidates = {
                (
                    candidate["fixed_delta"],
                    candidate["vcall_offset_slot"],
                )
                for candidate in exported_candidates
            }
            if len(semantic_candidates) != 1:
                return {}
            strongest = max(
                exported_candidates,
                key=lambda candidate: candidate["confidence"],
            )
            vcall_slot = int(strongest["vcall_offset_slot"])
            return {
                "kind": "virtual_vcall",
                "resolved": True,
                "fixed_delta": int(strongest["fixed_delta"]),
                "vcall_offset_slot": vcall_slot,
                "vcall_offset_value": prefix_by_slot[vcall_slot],
                "candidate_vcall_offsets": [{
                    "slot": vcall_slot,
                    "value": prefix_by_slot[vcall_slot],
                }],
                "evidence": strongest["evidence"],
                "confidence": strongest["confidence"],
            }
        candidate_offsets = [
            {"slot": slot, "value": prefix_by_slot[slot]}
            for slot in sorted(prefix_by_slot)
        ]
        return {
            "kind": "virtual_vcall",
            "resolved": False,
            "fixed_delta": None,
            "vcall_offset_slot": None,
            "vcall_offset_value": None,
            "candidate_vcall_offsets": candidate_offsets,
            "evidence": "validated_secondary_virtual_prefix_candidates",
            "confidence": 0.85,
        }

    def _validated_rtti_base_graph(self) -> dict[int, set[int]]:
        variants: dict[int, set[frozenset[int]]] = {}
        for node in self.graph.nodes:
            if node.kind != "string":
                continue
            for raw in (
                node.properties.get("rtti_typeinfo_candidates") or []
            ):
                if not isinstance(raw, dict):
                    continue
                try:
                    typeinfo = self._addr_int(
                        raw.get("typeinfo_address")
                    )
                    confidence = float(raw.get("confidence"))
                    base_count = int(raw.get("base_count") or 0)
                except (TypeError, ValueError):
                    continue
                kind = str(raw.get("typeinfo_kind") or "")
                evidence = str(raw.get("evidence") or "")
                bases: set[int] = set()
                if (
                    typeinfo <= 0
                    or confidence < 1.0
                    or kind not in {
                        "class_type_info",
                        "si_class_type_info",
                        "vmi_class_type_info",
                    }
                ):
                    continue
                if kind == "class_type_info":
                    if (
                        evidence
                        != "itanium_type_name_vptr_kind_and_base_pointer"
                    ):
                        continue
                elif kind == "si_class_type_info":
                    base = self._addr_int(
                        raw.get("base_typeinfo_address")
                    )
                    if (
                        evidence
                        != "itanium_type_name_vptr_kind_and_base_pointer"
                        or base <= 0
                    ):
                        continue
                    bases.add(base)
                else:
                    raw_bases = raw.get("bases")
                    if (
                        evidence
                        != "itanium_type_name_vptr_kind_and_base_array"
                        or not isinstance(raw_bases, list)
                        or base_count <= 0
                        or base_count != len(raw_bases)
                    ):
                        continue
                    valid = True
                    for raw_base in raw_bases:
                        if not isinstance(raw_base, dict):
                            valid = False
                            break
                        base = self._addr_int(
                            raw_base.get("base_typeinfo_address")
                        )
                        if base <= 0:
                            valid = False
                            break
                        bases.add(base)
                    if not valid or len(bases) != base_count:
                        continue
                variants.setdefault(typeinfo, set()).add(
                    frozenset(bases)
                )
        return {
            typeinfo: set(next(iter(base_variants)))
            for typeinfo, base_variants in variants.items()
            if len(base_variants) == 1
        }

    @staticmethod
    def _rtti_base_closure(
        root_typeinfo: int,
        base_graph: dict[int, set[int]],
    ) -> set[int]:
        allowed = {root_typeinfo}
        pending = [root_typeinfo]
        while pending:
            current = pending.pop()
            for base in base_graph.get(current, set()):
                if base not in allowed:
                    allowed.add(base)
                    pending.append(base)
        return allowed

    def _validated_virtual_base_typeinfos(
        self,
        base_graph: dict[int, set[int]],
    ) -> set[int]:
        direct_virtual: set[int] = set()
        for node in self.graph.nodes:
            if node.kind != "string":
                continue
            for raw in (
                node.properties.get("rtti_typeinfo_candidates") or []
            ):
                if not isinstance(raw, dict):
                    continue
                try:
                    typeinfo = self._addr_int(
                        raw.get("typeinfo_address")
                    )
                    confidence = float(raw.get("confidence"))
                    base_count = int(raw.get("base_count") or 0)
                except (TypeError, ValueError):
                    continue
                raw_bases = raw.get("bases")
                if (
                    typeinfo not in base_graph
                    or confidence < 1.0
                    or raw.get("typeinfo_kind")
                    != "vmi_class_type_info"
                    or raw.get("evidence")
                    != "itanium_type_name_vptr_kind_and_base_array"
                    or not isinstance(raw_bases, list)
                    or base_count != len(raw_bases)
                ):
                    continue
                candidate_bases = {
                    self._addr_int(base.get("base_typeinfo_address"))
                    for base in raw_bases
                    if isinstance(base, dict)
                }
                if (
                    candidate_bases != base_graph[typeinfo]
                    or any(base <= 0 for base in candidate_bases)
                ):
                    continue
                virtual_base = False
                for base in raw_bases:
                    if not isinstance(base, dict):
                        continue
                    try:
                        flags = int(base.get("flags") or 0)
                    except (TypeError, ValueError):
                        continue
                    if bool(base.get("is_virtual")) and flags & 0x1:
                        virtual_base = True
                        break
                if virtual_base:
                    direct_virtual.add(typeinfo)
        has_virtual = set(direct_virtual)
        changed = True
        while changed:
            changed = False
            for typeinfo, bases in base_graph.items():
                if (
                    typeinfo not in has_virtual
                    and any(base in has_virtual for base in bases)
                ):
                    has_virtual.add(typeinfo)
                    changed = True
        return has_virtual

    def _validated_nonvirtual_base_offsets(
        self,
    ) -> dict[int, set[int]]:
        variants: dict[int, set[frozenset[int]]] = {}
        for node in self.graph.nodes:
            if node.kind != "string":
                continue
            for raw in (
                node.properties.get("rtti_typeinfo_candidates") or []
            ):
                if not isinstance(raw, dict):
                    continue
                try:
                    typeinfo = self._addr_int(
                        raw.get("typeinfo_address")
                    )
                    confidence = float(raw.get("confidence"))
                except (TypeError, ValueError):
                    continue
                kind = str(raw.get("typeinfo_kind") or "")
                if typeinfo <= 0 or confidence < 1.0:
                    continue
                offsets: set[int] = set()
                if kind == "class_type_info":
                    offsets = set()
                elif kind == "si_class_type_info":
                    offsets = {0}
                elif kind == "vmi_class_type_info":
                    raw_bases = raw.get("bases")
                    try:
                        base_count = int(raw.get("base_count") or 0)
                    except (TypeError, ValueError):
                        continue
                    if (
                        not isinstance(raw_bases, list)
                        or base_count != len(raw_bases)
                    ):
                        continue
                    valid = True
                    for base in raw_bases:
                        if not isinstance(base, dict):
                            valid = False
                            break
                        if bool(base.get("is_virtual")):
                            continue
                        try:
                            offset = int(base.get("offset"))
                            object_offset = int(
                                base.get("object_offset")
                            )
                            flags = int(base.get("flags") or 0)
                        except (TypeError, ValueError):
                            valid = False
                            break
                        if (
                            base.get("offset_kind") != "object_offset"
                            or offset != object_offset
                            or flags & 0x1
                            or offset < 0
                        ):
                            valid = False
                            break
                        offsets.add(offset)
                    if not valid:
                        continue
                else:
                    continue
                variants.setdefault(typeinfo, set()).add(
                    frozenset(offsets)
                )
        return {
            typeinfo: set(next(iter(offset_variants)))
            for typeinfo, offset_variants in variants.items()
            if len(offset_variants) == 1
        }

    def _validated_vtt_candidate(
        self,
        candidate: dict[str, Any],
        *,
        current_vtable_address: int,
        current_address_point: int,
        current_offset_to_top: int,
        current_typeinfo_address: int,
        allowed_typeinfo_addresses: set[int],
        construction_typeinfo_addresses: set[int],
        pointer_size: int,
    ) -> dict[str, Any] | None:
        if "vtt_candidate" not in candidate:
            return {}
        raw_vtt = candidate.get("vtt_candidate")
        if raw_vtt is None:
            return {}
        if not isinstance(raw_vtt, dict):
            return None
        try:
            vtt_address = self._addr_int(raw_vtt.get("vtt_address"))
            entry_count = int(raw_vtt.get("entry_count"))
            confidence = float(raw_vtt.get("confidence"))
        except (TypeError, ValueError):
            return None
        raw_entries = raw_vtt.get("entries")
        evidence = str(raw_vtt.get("evidence") or "")
        same_rtti_evidence = (
            "contiguous_data_pointers_cover_distinct_"
            "same_rtti_vtable_address_points"
        )
        construction_evidence = (
            "contiguous_data_pointers_start_at_complete_object_"
            "and_cover_valid_base_construction_address_points"
        )
        if (
            vtt_address <= 0
            or entry_count < 2
            or not isinstance(raw_entries, list)
            or entry_count != len(raw_entries)
            or evidence not in {
                same_rtti_evidence,
                construction_evidence,
            }
            or confidence < 0.99
        ):
            return None
        role_fields = {
            "typeinfo_address",
            "table_role",
            "leading_null_slot_count",
        }
        entries_with_role_metadata = sum(
            1
            for entry in raw_entries
            if isinstance(entry, dict)
            and role_fields.issubset(entry)
        )
        if (
            evidence == construction_evidence
            and entries_with_role_metadata != entry_count
        ):
            return None
        if entries_with_role_metadata not in {0, entry_count}:
            return None
        has_role_metadata = entries_with_role_metadata == entry_count
        normalized_entries = []
        distinct_address_points = set()
        current_matches = 0
        construction_entries = 0
        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                return None
            try:
                entry_index = int(raw_entry.get("entry_index"))
                pointer_address = self._addr_int(
                    raw_entry.get("pointer_address")
                )
                address_point = self._addr_int(
                    raw_entry.get("address_point_address")
                )
                vtable_address = self._addr_int(
                    raw_entry.get("vtable_address")
                )
                offset_to_top = int(raw_entry.get("offset_to_top"))
            except (TypeError, ValueError):
                return None
            table_kind = str(raw_entry.get("table_kind") or "")
            expected_kind = (
                "primary" if offset_to_top == 0 else "secondary"
            )
            typeinfo_address = 0
            table_role = ""
            leading_null_slot_count = 0
            if has_role_metadata:
                try:
                    typeinfo_address = self._addr_int(
                        raw_entry.get("typeinfo_address")
                    )
                    leading_null_slot_count = int(
                        raw_entry.get("leading_null_slot_count")
                    )
                except (TypeError, ValueError):
                    return None
                table_role = str(raw_entry.get("table_role") or "")
                expected_role = (
                    "complete_object"
                    if typeinfo_address == current_typeinfo_address
                    else "construction"
                )
                if (
                    current_typeinfo_address <= 0
                    or current_typeinfo_address
                    not in allowed_typeinfo_addresses
                    or typeinfo_address
                    not in allowed_typeinfo_addresses
                    or (
                        expected_role == "construction"
                        and typeinfo_address
                        not in construction_typeinfo_addresses
                    )
                    or table_role != expected_role
                    or leading_null_slot_count < 0
                    or leading_null_slot_count > 2
                    or (
                        table_role == "complete_object"
                        and leading_null_slot_count != 0
                    )
                    or (
                        evidence == same_rtti_evidence
                        and table_role != "complete_object"
                    )
                ):
                    return None
                if table_role == "construction":
                    construction_entries += 1
            if (
                entry_index != index
                or pointer_address != vtt_address + index * pointer_size
                or address_point <= 0
                or vtable_address != address_point - 2 * pointer_size
                or offset_to_top > 0
                or offset_to_top % pointer_size != 0
                or table_kind != expected_kind
            ):
                return None
            distinct_address_points.add(address_point)
            if (
                address_point == current_address_point
                and vtable_address == current_vtable_address
                and offset_to_top == current_offset_to_top
            ):
                current_matches += 1
            normalized_entries.append({
                "entry_index": entry_index,
                "pointer_address": self._addr_str(pointer_address),
                "address_point_address": self._addr_str(address_point),
                "vtable_address": self._addr_str(vtable_address),
                "offset_to_top": offset_to_top,
                "table_kind": table_kind,
                **(
                    {
                        "typeinfo_address": self._addr_str(
                            typeinfo_address
                        ),
                        "table_role": table_role,
                        "leading_null_slot_count": (
                            leading_null_slot_count
                        ),
                    }
                    if has_role_metadata else {}
                ),
            })
        if (
            len(distinct_address_points) < 2
            or current_matches < 1
            or (
                evidence == construction_evidence
                and (
                    construction_entries < 1
                    or normalized_entries[0]["table_role"]
                    != "complete_object"
                    or self._addr_int(
                        normalized_entries[0]["typeinfo_address"]
                    )
                    != current_typeinfo_address
                    or normalized_entries[0]["offset_to_top"] != 0
                )
            )
        ):
            return None
        return {
            "vtt_address": self._addr_str(vtt_address),
            "entry_count": entry_count,
            "entries": normalized_entries,
            "evidence": evidence,
            "confidence": confidence,
        }

    def find_vtables(self) -> list[VTable]:
        """Locate candidate vtables in the graph and return them as a list.

        Vtables are identified by symbol-name patterns (``_ZTV...``,
        ``vtable ...``, ``??_7...``).  Method entries are resolved through
        outgoing graph edges first, and through address-range scanning when
        the engine did not emit explicit vtable-to-method edges.
        """
        vtables: list[VTable] = []
        ps = self._pointer_size
        functions_by_address = dict(self._function_nodes_sorted())
        rtti_base_graph = self._validated_rtti_base_graph()
        virtual_base_typeinfos = self._validated_virtual_base_typeinfos(
            rtti_base_graph
        )
        nonvirtual_base_offsets = (
            self._validated_nonvirtual_base_offsets()
        )

        for node in self.graph.nodes:
            if node.kind in {"string", "import"}:
                continue
            if not self._is_vtable_name(node.name):
                continue

            class_name = self._extract_class_from_vtable_name(node.name or "")
            if not class_name:
                # Generic labels such as "vtable" without a class identity are
                # commonly GOT/import artifacts, not recoverable class tables.
                continue
            compiler = self._classify_compiler_from_name(node.name or "")
            addr = self._addr_int(node.address)

            entries = self._method_entries_from_edges(node)
            if not entries:
                entries = self._method_entries_from_range(addr, ps)

            rtti_ref, _ = self._find_rtti_ref(class_name, node, ps)

            # Confidence: high when edges exist, lower when only range scan.
            confidence = 0.4
            if self._method_entries_from_edges(node):
                confidence += 0.25
            confidence += min(0.3, 0.03 * len(entries))
            confidence = round(min(0.95, confidence), 2)

            vtables.append(
                VTable(
                    address=self._addr_str(addr),
                    class_name=class_name,
                    method_entries=entries,
                    rtti_ref=rtti_ref,
                    confidence=confidence,
                    compiler=compiler,
                    source_node_id=node.id,
                )
            )

        # Stripped Itanium binaries can lose user `_ZTV` labels while retaining
        # the complete RTTI layout.  Exporters may provide a structural
        # conjunction recovered from:
        #   type-name string <- type_info.name pointer,
        #   type_info object <- vtable RTTI slot,
        #   zero offset-to-top word immediately before that slot.
        # Consume only that high-confidence evidence; generic `vtable` labels
        # alone are intentionally insufficient.
        for node in self.graph.nodes:
            if node.kind != "string":
                continue
            class_name = self._class_from_itanium_type_string(node.name)
            if not class_name:
                continue
            for candidate in (
                node.properties.get("rtti_vtable_candidates") or []
            ):
                if not isinstance(candidate, dict):
                    continue
                try:
                    offset_to_top = int(candidate.get("offset_to_top") or 0)
                    confidence = float(candidate.get("confidence") or 0.0)
                except (TypeError, ValueError):
                    continue
                evidence = str(candidate.get("evidence") or "")
                address = candidate.get("vtable_address")
                addr = self._addr_int(address)
                if addr <= 0:
                    continue
                rtti_pointer = self._addr_int(
                    candidate.get("rtti_pointer_address")
                )
                typeinfo_address = self._addr_int(
                    candidate.get("typeinfo_address")
                )
                address_point = self._addr_int(
                    candidate.get("address_point_address")
                )
                first_method_pointer = self._addr_int(
                    candidate.get("first_method_pointer_address")
                )
                first_method_target = self._addr_int(
                    candidate.get("first_method_target_address")
                )
                table_kind = str(candidate.get("table_kind") or "")
                method_entries: list[dict[str, Any]] = []
                method_slots_validated = False
                boundary_reason = candidate.get("slot_boundary_reason")
                raw_slots = candidate.get("method_slots")
                if raw_slots is not None:
                    try:
                        slot_count = int(candidate.get("slot_count"))
                    except (TypeError, ValueError):
                        continue
                    if (
                        not isinstance(raw_slots, list)
                        or slot_count <= 0
                        or slot_count != len(raw_slots)
                        or boundary_reason not in {
                            "non_callable_pointer",
                            "code_reference_to_next_data_object",
                            "memory_block_end",
                        }
                    ):
                        continue
                    valid_slots = True
                    for index, raw_slot in enumerate(raw_slots):
                        if not isinstance(raw_slot, dict):
                            valid_slots = False
                            break
                        try:
                            slot_index = int(raw_slot.get("slot_index"))
                            method_offset = int(
                                raw_slot.get("method_offset")
                            )
                            pointer_address = self._addr_int(
                                raw_slot.get("pointer_address")
                            )
                            target_address = self._addr_int(
                                raw_slot.get("target_address")
                            )
                        except (TypeError, ValueError):
                            valid_slots = False
                            break
                        if (
                            slot_index != index
                            or method_offset != index * ps
                            or pointer_address != addr + 2 * ps + index * ps
                            or target_address <= 0
                        ):
                            valid_slots = False
                            break
                        exported_adjustments = (
                            self._validated_exported_this_adjustments(
                                raw_slot,
                                pointer_size=ps,
                            )
                        )
                        if exported_adjustments is None:
                            valid_slots = False
                            break
                        target_fn = functions_by_address.get(target_address)
                        method_entries.append({
                            "slot_index": slot_index,
                            "method_offset": self._addr_str(method_offset),
                            "pointer_address": self._addr_str(
                                pointer_address
                            ),
                            "target_fn_id": (
                                target_fn.id if target_fn is not None else None
                            ),
                            "target_addr": self._addr_str(target_address),
                            "target_name": (
                                self.demangle_name(target_fn.name or "")
                                if target_fn is not None else ""
                            ),
                            "_exported_this_adjustments": (
                                exported_adjustments
                            ),
                        })
                    if not valid_slots:
                        continue
                    method_slots_validated = True
                    if (
                        first_method_target
                        != self._addr_int(
                            raw_slots[0].get("target_address")
                        )
                    ):
                        continue
                primary = (
                    evidence
                    == "itanium_name_pointer_and_zero_offset_vtable_header"
                    and offset_to_top == 0
                    and confidence >= 0.9
                    and table_kind in {"", "primary"}
                )
                secondary = (
                    evidence
                    == (
                        "itanium_name_pointer_negative_offset_and_"
                        "callable_vtable_header"
                    )
                    and offset_to_top < 0
                    and offset_to_top % ps == 0
                    and confidence >= 0.95
                    and table_kind == "secondary"
                    and rtti_pointer == addr + ps
                    and address_point == addr + 2 * ps
                    and first_method_pointer == address_point
                    and first_method_target > 0
                    and method_slots_validated
                )
                if not primary and not secondary:
                    continue
                if primary:
                    table_kind = "primary"
                    if rtti_pointer and rtti_pointer != addr + ps:
                        continue
                    if address_point and address_point != addr + 2 * ps:
                        continue
                    if (
                        first_method_pointer
                        and first_method_pointer != addr + 2 * ps
                    ):
                        continue
                    address_point = address_point or addr + 2 * ps
                prefix_validation = self._validated_vtable_prefix(
                    candidate,
                    vtable_address=addr,
                    address_point=address_point,
                    offset_to_top=offset_to_top,
                    pointer_size=ps,
                )
                if prefix_validation is None:
                    continue
                prefix_entries, prefix_boundary_reason = prefix_validation
                vtt_info = self._validated_vtt_candidate(
                    candidate,
                    current_vtable_address=addr,
                    current_address_point=address_point,
                    current_offset_to_top=offset_to_top,
                    current_typeinfo_address=typeinfo_address,
                    allowed_typeinfo_addresses=self._rtti_base_closure(
                        typeinfo_address,
                        rtti_base_graph,
                    ),
                    construction_typeinfo_addresses=(
                        virtual_base_typeinfos
                    ),
                    pointer_size=ps,
                )
                if vtt_info is None:
                    continue
                valid_adjustments = True
                for method_entry in method_entries:
                    exported_adjustments = method_entry.pop(
                        "_exported_this_adjustments",
                        [],
                    )
                    this_adjustment = self._method_this_adjustment(
                        exported_adjustments,
                        table_kind=table_kind,
                        offset_to_top=offset_to_top,
                        prefix_entries=prefix_entries,
                        has_vtt=bool(vtt_info),
                        secondary_is_nonvirtual_base=(
                            offset_to_top < 0
                            and -offset_to_top
                            in nonvirtual_base_offsets.get(
                                typeinfo_address,
                                set(),
                            )
                        ),
                    )
                    if this_adjustment == {}:
                        valid_adjustments = False
                        break
                    if this_adjustment is not None:
                        method_entry["this_adjustment"] = this_adjustment
                if not valid_adjustments:
                    continue
                vtables.append(VTable(
                    address=self._addr_str(addr),
                    class_name=class_name,
                    method_entries=method_entries,
                    rtti_ref=node.id,
                    confidence=confidence,
                    compiler="gnu",
                    source_node_id=node.id,
                    address_point=self._addr_str(address_point),
                    offset_to_top=offset_to_top,
                    table_kind=table_kind,
                    first_method_target=(
                        self._addr_str(first_method_target)
                        if first_method_target > 0 else None
                    ),
                    method_slots_validated=method_slots_validated,
                    method_boundary_reason=(
                        str(boundary_reason)
                        if method_slots_validated else None
                    ),
                    prefix_entries=prefix_entries,
                    prefix_entries_validated=bool(prefix_entries),
                    prefix_boundary_reason=prefix_boundary_reason,
                    vtt_info=vtt_info or None,
                ))

        # IDA can expose the same table as both a symbol and a named data item.
        # Merge those aliases by engine-neutral class/address identity while
        # retaining the richest method list and strongest evidence.
        deduplicated: dict[tuple[str, str], VTable] = {}
        for candidate in vtables:
            key = (candidate.class_name or "<unknown>", candidate.address)
            existing = deduplicated.get(key)
            if existing is None:
                deduplicated[key] = candidate
                continue
            if (
                candidate.method_slots_validated
                and not existing.method_slots_validated
            ):
                existing.method_entries = list(candidate.method_entries)
                existing.method_slots_validated = True
                existing.method_boundary_reason = (
                    candidate.method_boundary_reason
                )
            known_entries = {
                (
                    entry.get("method_offset"),
                    entry.get("target_fn_id"),
                    entry.get("target_addr"),
                    entry.get("target_name"),
                )
                for entry in existing.method_entries
            }
            for entry in candidate.method_entries:
                entry_key = (
                    entry.get("method_offset"),
                    entry.get("target_fn_id"),
                    entry.get("target_addr"),
                    entry.get("target_name"),
                )
                if entry_key not in known_entries:
                    existing.method_entries.append(entry)
                    known_entries.add(entry_key)
            existing.confidence = max(existing.confidence, candidate.confidence)
            if existing.rtti_ref is None:
                existing.rtti_ref = candidate.rtti_ref
            if existing.compiler == "unknown":
                existing.compiler = candidate.compiler
            if existing.address_point is None:
                existing.address_point = candidate.address_point
            if existing.offset_to_top is None:
                existing.offset_to_top = candidate.offset_to_top
            if existing.table_kind == "unknown":
                existing.table_kind = candidate.table_kind
            if existing.first_method_target is None:
                existing.first_method_target = candidate.first_method_target
            if existing.method_boundary_reason is None:
                existing.method_boundary_reason = (
                    candidate.method_boundary_reason
                )
            if (
                candidate.prefix_entries_validated
                and not existing.prefix_entries_validated
            ):
                existing.prefix_entries = list(candidate.prefix_entries)
                existing.prefix_entries_validated = True
                existing.prefix_boundary_reason = (
                    candidate.prefix_boundary_reason
                )
            if existing.vtt_info is None and candidate.vtt_info is not None:
                existing.vtt_info = dict(candidate.vtt_info)

        # A VTT is an array of address points, not itself a dispatch vtable.
        # Some engines additionally label a construction-table address point
        # with the base class's ordinary `_ZTV` symbol.  Keep that table in the
        # validated VTT metadata, but do not publish the unresolved alias as a
        # complete class vtable.
        construction_vtable_addresses = {
            self._addr_str(
                self._addr_int(entry.get("vtable_address"))
            )
            for candidate in deduplicated.values()
            if isinstance(candidate.vtt_info, dict)
            for entry in candidate.vtt_info.get("entries", [])
            if (
                isinstance(entry, dict)
                and entry.get("table_role") == "construction"
                and self._addr_int(entry.get("vtable_address")) > 0
            )
        }
        self._vtables = [
            candidate
            for candidate in deduplicated.values()
            if not (
                not candidate.method_slots_validated
                and candidate.address in construction_vtable_addresses
            )
        ]
        return self._vtables

    @classmethod
    def classify_class_role(cls, class_name: str) -> tuple[str, str]:
        """Classify compiler RTTI implementation types without discarding them."""
        normalized = str(class_name or "").strip().lstrip(":")
        lowered = normalized.lower()
        if any(
            lowered.startswith(prefix.lower())
            for prefix in cls._RUNTIME_CLASS_PREFIXES
        ):
            return "runtime_support", "compiler_abi_namespace"
        if lowered in {name.lower() for name in cls._RUNTIME_CLASS_NAMES}:
            return "runtime_support", "rtti_runtime_type"
        if any(
            lowered.startswith(prefix.lower())
            for prefix in cls._LIBRARY_CLASS_PREFIXES
        ):
            return "library_support", "standard_library_namespace"
        return "user_candidate", "no_runtime_support_evidence"

    # ------------------------------------------------- ctor/dtor / class build

    def _functions_referencing_vtables(self, vtable_addresses: list[str]) -> set[str]:
        """Return function node ids that reference any of the given addresses."""
        target_addrs = {self._addr_int(a) for a in vtable_addresses}
        result: set[str] = set()
        for edge in self.graph.edges:
            if edge.kind not in ("references", "offset", "data_write"):
                continue
            edge_addr = self._addr_int(edge.address)
            if edge_addr in target_addrs:
                src = self.graph.get_node(edge.src)
                if src and src.kind == "function":
                    result.add(src.id)
        return result

    def _collect_constructors_destructors(
        self, class_name: str, vtable_addresses: list[str]
    ) -> tuple[list[str], list[str]]:
        """Return (constructors, destructors) function ids for a class."""
        ctors: set[str] = set()
        dtors: set[str] = set()

        # Name-based: scan all functions for ctor/dtor names matching the class.
        for n in self.graph.nodes:
            if n.kind != "function" or not n.name:
                continue
            candidate_class = self._extract_class_from_ctor_dtor(n.name)
            if not self._class_names_equal(candidate_class, class_name):
                continue
            if self._is_ctor_name(n.name):
                ctors.add(n.id)
            elif self._is_dtor_name(n.name):
                dtors.add(n.id)

        # Reference-based: functions that point at this class's vtable are
        # likely ctor/dtor candidates.  When the name does not let us decide, we
        # conservatively treat them as constructors.
        for fn_id in self._functions_referencing_vtables(vtable_addresses):
            if fn_id in ctors or fn_id in dtors:
                continue
            fn = self.graph.get_node(fn_id)
            if fn and self._is_dtor_name(fn.name or ""):
                dtors.add(fn_id)
            else:
                ctors.add(fn_id)

        return sorted(ctors), sorted(dtors)

    # ---------------------------------------------------------- RTTI/helpers

    def _rtti_type_info_for_class(self, class_name: str) -> dict[str, Any] | None:
        """Return the best RTTI classification associated with a class name."""
        best: dict[str, Any] | None = None
        for n in self.graph.nodes:
            if not n.name:
                continue
            info = self.classify_rtti(n)
            if info.get("class_name") and self._class_names_equal(
                info["class_name"], class_name
            ):
                if best is None or info.get("kind") == "typeinfo":
                    best = info
        return best

    # ---------------------------------------------------- hierarchy inference

    def _method_addr_list(self, vtable: VTable) -> list[int]:
        """Return ordered method target addresses for prefix comparison."""
        return [
            self._addr_int(entry["target_addr"])
            for entry in vtable.method_entries
        ]

    @staticmethod
    def _is_prefix(list_a: list[int], list_b: list[int]) -> bool:
        """Return True when ``list_a`` is a strict prefix of ``list_b``."""
        if not list_a or len(list_a) >= len(list_b):
            return False
        return list_a == list_b[: len(list_a)]

    def _infer_prefix_hierarchy(
        self, classes: dict[str, ClassHierarchy]
    ) -> None:
        """Populate parents/children using vtable prefix overlap."""
        def needs_heuristic_parent(class_name: str) -> bool:
            rtti = classes[class_name].rtti_type_info
            if not isinstance(rtti, dict):
                return True
            try:
                confidence = float(
                    rtti.get("hierarchy_confidence") or 0.0
                )
            except (TypeError, ValueError):
                return True
            return not (
                confidence >= 1.0
                and str(rtti.get("typeinfo_kind") or "") in {
                    "class_type_info",
                    "si_class_type_info",
                    "vmi_class_type_info",
                }
            )

        names = list(classes.keys())
        for i, name_a in enumerate(names):
            for name_b in names[i + 1 :]:
                if (
                    classes[name_a].role != "user_candidate"
                    or classes[name_b].role != "user_candidate"
                ):
                    continue
                vtables_a = [
                    vt for vt in (self._vtables or []) if vt.class_name == name_a
                ]
                vtables_b = [
                    vt for vt in (self._vtables or []) if vt.class_name == name_b
                ]
                if not vtables_a or not vtables_b:
                    continue

                # Use the longest vtable for each class for a stable comparison.
                a_addrs = self._method_addr_list(max(vtables_a, key=lambda v: len(v.method_entries)))
                b_addrs = self._method_addr_list(max(vtables_b, key=lambda v: len(v.method_entries)))

                if (
                    needs_heuristic_parent(name_b)
                    and self._is_prefix(a_addrs, b_addrs)
                ):
                    classes[name_b].parents.append(name_a)
                    classes[name_a].children.append(name_b)
                elif (
                    needs_heuristic_parent(name_a)
                    and self._is_prefix(b_addrs, a_addrs)
                ):
                    classes[name_a].parents.append(name_b)
                    classes[name_b].children.append(name_a)

    @staticmethod
    def _validated_vmi_base_offset_semantics(
        raw_base: dict[str, Any],
        *,
        offset: int,
        flags: int,
    ) -> dict[str, Any] | None:
        """Validate whether a VMI offset describes an object or ABI slot."""
        is_virtual = bool(flags & 0x1)
        semantic_keys = {
            "offset_kind",
            "object_offset",
            "vbase_offset_slot_offset",
        }
        present_keys = semantic_keys.intersection(raw_base)

        if not is_virtual and not present_keys:
            return {
                "offset_kind": "object_offset",
                "object_offset": offset,
                "vbase_offset_slot_offset": None,
            }
        if present_keys != semantic_keys:
            return None

        offset_kind = raw_base.get("offset_kind")
        object_offset = raw_base.get("object_offset")
        vbase_slot_offset = raw_base.get("vbase_offset_slot_offset")
        if is_virtual:
            try:
                normalized_slot_offset = int(vbase_slot_offset)
            except (TypeError, ValueError):
                return None
            if (
                offset_kind != "vbase_offset_slot"
                or object_offset is not None
                or normalized_slot_offset != offset
            ):
                return None
            return {
                "offset_kind": "vbase_offset_slot",
                "object_offset": None,
                "vbase_offset_slot_offset": normalized_slot_offset,
            }

        try:
            normalized_object_offset = int(object_offset)
        except (TypeError, ValueError):
            return None
        if (
            offset_kind != "object_offset"
            or normalized_object_offset != offset
            or vbase_slot_offset is not None
        ):
            return None
        return {
            "offset_kind": "object_offset",
            "object_offset": normalized_object_offset,
            "vbase_offset_slot_offset": None,
        }

    def _infer_itanium_rtti_hierarchy(
        self, classes: dict[str, ClassHierarchy]
    ) -> None:
        """Populate direct inheritance edges from validated Itanium RTTI."""
        typeinfo_names: dict[int, set[str]] = {}
        records: list[
            tuple[str, dict[str, Any], list[dict[str, Any]]]
        ] = []
        for node in self.graph.nodes:
            if node.kind != "string":
                continue
            class_name = self._class_from_itanium_type_string(node.name)
            if not class_name or class_name not in classes:
                continue
            for candidate in (
                node.properties.get("rtti_typeinfo_candidates") or []
            ):
                if not isinstance(candidate, dict):
                    continue
                try:
                    confidence = float(candidate.get("confidence") or 0.0)
                    typeinfo_address = self._addr_int(
                        candidate.get("typeinfo_address")
                    )
                except (TypeError, ValueError):
                    continue
                kind = str(candidate.get("typeinfo_kind") or "")
                evidence = str(candidate.get("evidence") or "")
                if (
                    confidence < 1.0
                    or typeinfo_address <= 0
                    or kind not in {
                        "class_type_info",
                        "si_class_type_info",
                        "vmi_class_type_info",
                    }
                ):
                    continue
                base_records: list[dict[str, Any]] = []
                if kind in {"class_type_info", "si_class_type_info"}:
                    if (
                        evidence
                        != "itanium_type_name_vptr_kind_and_base_pointer"
                    ):
                        continue
                    if kind == "si_class_type_info":
                        base_address = self._addr_int(
                            candidate.get("base_typeinfo_address")
                        )
                        if base_address <= 0:
                            continue
                        base_records.append({
                            "base_typeinfo_address": (
                                candidate.get("base_typeinfo_address")
                            ),
                        })
                else:
                    if (
                        evidence
                        != "itanium_type_name_vptr_kind_and_base_array"
                    ):
                        continue
                    raw_bases = candidate.get("bases")
                    try:
                        base_count = int(candidate.get("base_count"))
                        vmi_flags = int(candidate.get("vmi_flags"))
                    except (TypeError, ValueError):
                        continue
                    if (
                        not isinstance(raw_bases, list)
                        or base_count <= 0
                        or base_count != len(raw_bases)
                        or vmi_flags < 0
                        or vmi_flags > 0xFFFFFFFF
                    ):
                        continue
                    valid = True
                    for raw_base in raw_bases:
                        if not isinstance(raw_base, dict):
                            valid = False
                            break
                        try:
                            base_address = self._addr_int(
                                raw_base.get("base_typeinfo_address")
                            )
                            base_pointer = self._addr_int(
                                raw_base.get("base_pointer_address")
                            )
                            offset_flags_address = self._addr_int(
                                raw_base.get("offset_flags_address")
                            )
                            offset = int(raw_base.get("offset"))
                            flags = int(raw_base.get("flags"))
                        except (TypeError, ValueError):
                            valid = False
                            break
                        offset_semantics = (
                            self._validated_vmi_base_offset_semantics(
                                raw_base,
                                offset=offset,
                                flags=flags,
                            )
                        )
                        if (
                            base_address <= 0
                            or base_pointer <= 0
                            or offset_flags_address <= 0
                            or flags < 0
                            or flags > 0xFF
                            or offset_semantics is None
                            or raw_base.get("is_virtual")
                            is not bool(flags & 0x1)
                            or raw_base.get("is_public")
                            is not bool(flags & 0x2)
                        ):
                            valid = False
                            break
                        base_records.append({
                            "base_typeinfo_address": (
                                raw_base.get("base_typeinfo_address")
                            ),
                            "base_pointer_address": (
                                raw_base.get("base_pointer_address")
                            ),
                            "offset_flags_address": (
                                raw_base.get("offset_flags_address")
                            ),
                            "offset": offset,
                            **offset_semantics,
                            "flags": flags,
                            "is_virtual": bool(flags & 0x1),
                            "is_public": bool(flags & 0x2),
                        })
                    if not valid:
                        continue
                typeinfo_names.setdefault(
                    typeinfo_address, set()
                ).add(class_name)
                records.append((class_name, candidate, base_records))

        typeinfo_to_class = {
            address: next(iter(names))
            for address, names in typeinfo_names.items()
            if len(names) == 1
        }

        for class_name, candidate, base_records in records:
            child = classes[class_name]
            info = dict(child.rtti_type_info or {})
            info.update({
                "typeinfo_address": candidate.get("typeinfo_address"),
                "typeinfo_kind": candidate.get("typeinfo_kind"),
                "hierarchy_evidence": candidate.get("evidence"),
                "hierarchy_confidence": float(candidate["confidence"]),
            })
            if not base_records:
                child.rtti_type_info = info
                continue
            resolved_bases: list[dict[str, Any]] = []
            for base_record in base_records:
                base_address = self._addr_int(
                    base_record.get("base_typeinfo_address")
                )
                base_name = typeinfo_to_class.get(base_address)
                if (
                    not base_name
                    or base_name == class_name
                    or base_name not in classes
                    or child.role != "user_candidate"
                    or classes[base_name].role != "user_candidate"
                ):
                    continue
                parent = classes[base_name]
                if base_name not in child.parents:
                    child.parents.append(base_name)
                if class_name not in parent.children:
                    parent.children.append(class_name)
                resolved = dict(base_record)
                resolved["base_class"] = base_name
                resolved_bases.append(resolved)
            if not resolved_bases:
                child.rtti_type_info = info
                continue
            if candidate.get("typeinfo_kind") == "si_class_type_info":
                info.update({
                    "base_typeinfo_address": (
                        resolved_bases[0]["base_typeinfo_address"]
                    ),
                    "base_class": resolved_bases[0]["base_class"],
                })
            else:
                info.update({
                    "vmi_flags": int(candidate["vmi_flags"]),
                    "base_count": int(candidate["base_count"]),
                    "base_typeinfo_addresses": [
                        record["base_typeinfo_address"]
                        for record in resolved_bases
                    ],
                    "base_classes": [
                        record["base_class"]
                        for record in resolved_bases
                    ],
                    "bases": resolved_bases,
                })
            child.rtti_type_info = info

    # --------------------------------------------------------- public builders

    def recover_classes(self) -> dict[str, ClassHierarchy]:
        """Recover a class hierarchy map from vtables and RTTI.

        Returns a dictionary mapping class names to :class:`ClassHierarchy`
        objects.  Constructors and destructors are recovered through both
        mangled-name analysis and vtable reference edges.  ``compiler`` is set
        based on the dominant vtable naming convention.
        """
        vtables = self.find_vtables()
        classes: dict[str, ClassHierarchy] = {}

        # Group by class name.
        by_class: dict[str, list[VTable]] = {}
        for vt in vtables:
            cn = vt.class_name or "<unknown>"
            by_class.setdefault(cn, []).append(vt)

        for class_name, vts in by_class.items():
            compiler_votes: dict[str, int] = {}
            total_confidence = 0.0
            vtable_addresses: list[str] = []
            for vt in vts:
                if vt.address not in vtable_addresses:
                    vtable_addresses.append(vt.address)
                if vt.compiler != "unknown":
                    compiler_votes[vt.compiler] = (
                        compiler_votes.get(vt.compiler, 0) + 1
                    )
                total_confidence += vt.confidence

            # Determine compiler from the original vtable node names.  We do not
            # store the original node id in VTable, so classify by RTTI ref plus
            # names that demangled to this class.
            guessed_compiler = "unknown"
            for n in self.graph.nodes:
                candidate = self._extract_class_from_vtable_name(n.name or "")
                if self._class_names_equal(candidate, class_name):
                    c = self._classify_compiler_from_name(n.name or "")
                    if c != "unknown":
                        compiler_votes[c] = compiler_votes.get(c, 0) + 1
            if compiler_votes:
                guessed_compiler = max(compiler_votes, key=compiler_votes.get)

            ctors, dtors = self._collect_constructors_destructors(
                class_name, vtable_addresses
            )
            rtti_info = self._rtti_type_info_for_class(class_name)
            vtt_infos = [
                vt.vtt_info for vt in vts if vt.vtt_info is not None
            ]
            if (
                vtt_infos
                and all(info == vtt_infos[0] for info in vtt_infos)
            ):
                rtti_info = dict(rtti_info or {})
                rtti_info["vtt"] = dict(vtt_infos[0])
            role, role_reason = self.classify_class_role(class_name)

            conf = round(min(0.95, total_confidence / max(1, len(vts))), 2)
            classes[class_name] = ClassHierarchy(
                class_name=class_name,
                vtables=vtable_addresses,
                constructors=ctors,
                destructors=dtors,
                parents=[],
                children=[],
                rtti_type_info=rtti_info,
                compiler=guessed_compiler,
                confidence=conf,
                role=role,
                role_reason=role_reason,
            )

        # Stripped Itanium binaries often retain RTTI type-name strings even
        # when the disassembler does not create _ZTV/_ZTI symbols. Preserve
        # these as lower-confidence RTTI-only classes instead of fabricating a
        # vtable address or original function names.
        for node in self.graph.nodes:
            if node.kind != "string":
                continue
            class_name = self._class_from_itanium_type_string(node.name)
            if not class_name:
                continue
            string_rtti = {
                "kind": "itanium_type_name_string",
                "address": node.address,
                "raw_name": node.name,
            }
            if class_name in classes:
                if classes[class_name].rtti_type_info is None:
                    classes[class_name].rtti_type_info = string_rtti
                continue
            role, role_reason = self.classify_class_role(class_name)
            classes[class_name] = ClassHierarchy(
                class_name=class_name,
                vtables=[],
                constructors=[],
                destructors=[],
                parents=[],
                children=[],
                rtti_type_info=string_rtti,
                compiler="gnu",
                confidence=0.55,
                role=role,
                role_reason=role_reason,
            )

        self._classes = classes
        self._infer_itanium_rtti_hierarchy(classes)
        self._infer_prefix_hierarchy(classes)
        return classes

    def build_hierarchy(self) -> dict[str, ClassHierarchy]:
        """Build and return the class hierarchy.

        This is the primary entry point for hierarchy reconstruction.  It
        calls :meth:`recover_classes` and then refines inheritance edges from
        RTTI base-class hints when available.  The returned map contains the
        final ``parents`` and ``children`` lists.
        """
        classes = self.recover_classes()

        # Use any RTTI info that explicitly encodes bases (rare in the graph IR
        # but possible via typeinfo descriptors or strings).
        for class_name, ch in classes.items():
            info = ch.rtti_type_info or {}
            for n in self.graph.nodes:
                if n.kind != "string" or not n.name:
                    continue
                text = n.name
                if class_name in text and "base class" in text.lower():
                    # Very weak heuristic -- only use it if we already have a
                    # prefix-match parent to confirm.
                    for maybe_base in list(ch.parents):
                        if maybe_base in text:
                            break

        return classes
