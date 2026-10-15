"""TIL/IDS-equivalent type library for the Angerona reverse-engineering platform.

This module provides a small, serializable repository of function prototypes,
structure layouts, and enumerations.  It is intended as the analogue to IDA's
FLIRT/TIL/IDS layers: recognized library or syscall names can be grounded to
concrete parameter and return types *before* downstream LLM reasoning.

The design is intentionally dependency-light: only ``dataclasses`` and ``json``
are required.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


def _std_types() -> dict[str, str]:
    """Common C-like type aliases used when building bootstrap prototypes."""
    return {
        "void": "void",
        "void_p": "void*",
        "void_pp": "void**",
        "char_p": "char*",
        "const_char_p": "const char*",
        "size_t": "size_t",
        "int": "int",
        "uint": "unsigned int",
        "long": "long",
        "ulong": "unsigned long",
        "ssize_t": "ssize_t",
        "FILE_p": "FILE*",
        "socklen_t": "socklen_t",
        "va_list": "va_list",
    }


@dataclass
class Parameter:
    """A single function parameter.

    Attributes:
        name: The formal parameter name.
        type: A C-like type string, e.g. ``"const char*"``.
        reg_or_stack: Optional ABI location (e.g. ``"rdi"``, ``"rcx"``,
            ``"stack:0"``).  Not required for reasoning, but useful when the
            type library is produced from a loader/IDA database.
    """

    name: str
    type: str
    reg_or_stack: str | None = None


@dataclass
class FunctionType:
    """A grounded function prototype.

    Attributes:
        name: Demangled/exported function name.
        return_type: C-like return type.
        calling_convention: Calling convention string, e.g. ``"cdecl"``,
            ``"stdcall"``, ``"fastcall"``, ``"systemv_amd64"``.
        parameters: Ordered list of :class:`Parameter`.
        library: Source library/dll name, e.g. ``"msvcrt.dll"``,
            ``"libc.so.6"``.
        ordinal: Optional import ordinal for IDS-style lookup.
        comment: Optional free-text annotation.
    """

    name: str
    return_type: str
    calling_convention: str
    parameters: list[Parameter]
    library: str | None = None
    ordinal: int | None = None
    comment: str | None = None


@dataclass
class StructField:
    """A single field inside a struct or union.

    Attributes:
        name: Field name.
        offset: Byte offset from the beginning of the struct.
        size: Size of the field in bytes.
        type: C-like type string.
    """

    name: str
    offset: int
    size: int
    type: str


@dataclass
class StructType:
    """A structure (or union) layout.

    Attributes:
        name: Struct name.
        size: Total size in bytes.
        fields: Ordered list of :class:`StructField`.
        packed: Whether the struct is packed (no padding).
    """

    name: str
    size: int
    fields: list[StructField]
    packed: bool = False


@dataclass
class EnumType:
    """A simple enum mapping member names to integer values."""

    name: str
    members: dict[str, int]


@dataclass
class _TypeLibraryData:
    """Internal serialized shape for JSON round-trips."""

    functions: list[dict[str, Any]]
    structs: list[dict[str, Any]]
    enums: list[dict[str, Any]]


class TypeLibrary:
    """In-memory TIL/IDS-equivalent type repository.

    Stores function prototypes, struct types, enums, and import metadata so
    that recognized library/syscall names get grounded parameter/return types
    before later analysis passes (type recovery, decompilation, LLM summarisation).

    The library is intentionally JSON-serializable and mergeable so it can be
    shipped as a fixture, generated from a loader, or combined with engine-specific
    exports.
    """

    def __init__(self) -> None:
        """Create an empty type library."""
        self._functions: dict[str, FunctionType] = {}
        self._structs: dict[str, StructType] = {}
        self._enums: dict[str, EnumType] = {}

    # --------------------------------------------------------------------- adders

    def add_function_type(self, func: FunctionType) -> None:
        """Add or replace a function prototype."""
        self._functions[func.name] = func

    def add_struct_type(self, struct: StructType) -> None:
        """Add or replace a struct type."""
        self._structs[struct.name] = struct

    def add_enum_type(self, enum: EnumType) -> None:
        """Add or replace an enum type."""
        self._enums[enum.name] = enum

    # -------------------------------------------------------------------- lookups

    def lookup_function(self, name: str) -> FunctionType | None:
        """Return the :class:`FunctionType` for ``name`` if known."""
        return self._functions.get(name)

    def lookup_struct(self, name: str) -> StructType | None:
        """Return the :class:`StructType` for ``name`` if known."""
        return self._structs.get(name)

    def lookup_enum(self, name: str) -> EnumType | None:
        """Return the :class:`EnumType` for ``name`` if known."""
        return self._enums.get(name)

    # ----------------------------------------------------------------- properties

    @property
    def function_names(self) -> Iterable[str]:
        return iter(self._functions.keys())

    @property
    def struct_names(self) -> Iterable[str]:
        return iter(self._structs.keys())

    @property
    def enum_names(self) -> Iterable[str]:
        return iter(self._enums.keys())

    # ---------------------------------------------------------------- graph apply

    def apply_to_graph(self, graph: "AnalysisGraph") -> dict[str, FunctionType]:  # type: ignore[name-defined]
        """Annotate matching function nodes with their grounded signatures.

        For every ``function`` node whose ``name`` matches a name in the
        library, this method sets ``node.properties["signature"]`` to the
        :class:`FunctionType` (converted to a dict) and returns a mapping of
        ``node_id -> FunctionType`` for all nodes touched.

        Args:
            graph: An :class:`AnalysisGraph` instance.

        Returns:
            Mapping from node id to the applied :class:`FunctionType`.
        """
        applied: dict[str, FunctionType] = {}
        for node in graph.nodes:
            if node.kind != "function" or not node.name:
                continue
            sig = self.lookup_function(node.name)
            # Also try a stripped/minimal name if the exact export differs.
            if sig is None:
                sig = self._lookup_fuzzy(node.name)
            if sig is not None:
                node.properties["signature"] = self._function_to_dict(sig)
                applied[node.id] = sig
        return applied

    def _lookup_fuzzy(self, name: str) -> FunctionType | None:
        """Try common stripped variations of an import/export name.

        This catches prefixes like ``__imp_``, ``__libc_``, trailing
        thunk/PLT markers, and symbol-versioning suffixes such as
        ``strcpy@@GLIBC_2.2.5`` or ``strcpy@plt``.
        """
        base = name.split("@@")[0].split("@")[0]
        if base in self._functions:
            return self._functions[base]
        prefixes = ("__imp_", "__libc_", "_imp__", "j_", "loc_", "thunk_")
        for prefix in prefixes:
            if base.startswith(prefix):
                short = base[len(prefix) :]
                if short in self._functions:
                    return self._functions[short]
        # Try without leading underscore(s).
        stripped = base.lstrip("_")
        if stripped != base and stripped in self._functions:
            return self._functions[stripped]
        return None

    # ---------------------------------------------------------------- serialization

    def save_json(self, path: str | Path) -> None:
        """Serialize the entire library to ``path`` as JSON."""
        payload = {
            "functions": [self._function_to_dict(f) for f in self._functions.values()],
            "structs": [self._struct_to_dict(s) for s in self._structs.values()],
            "enums": [self._enum_to_dict(e) for e in self._enums.values()],
        }
        Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load_json(self, path: str | Path) -> None:
        """Load a library previously saved with :meth:`save_json`."""
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        self._functions.clear()
        self._structs.clear()
        self._enums.clear()

        for func_dict in payload.get("functions", []):
            self.add_function_type(self._function_from_dict(func_dict))
        for struct_dict in payload.get("structs", []):
            self.add_struct_type(self._struct_from_dict(struct_dict))
        for enum_dict in payload.get("enums", []):
            self.add_enum_type(self._enum_from_dict(enum_dict))

    # ---------------------------------------------------------------- merge

    def merge(self, other: "TypeLibrary") -> "TypeLibrary":
        """Return a new type library containing entries from both libraries.

        ``other`` takes precedence on name collisions.
        """
        merged = TypeLibrary()
        for name, func in self._functions.items():
            merged.add_function_type(func)
        for name, func in other._functions.items():
            merged.add_function_type(func)
        for name, struct in self._structs.items():
            merged.add_struct_type(struct)
        for name, struct in other._structs.items():
            merged.add_struct_type(struct)
        for name, enum in self._enums.items():
            merged.add_enum_type(enum)
        for name, enum in other._enums.items():
            merged.add_enum_type(enum)
        return merged

    # ---------------------------------------------------------- common_ground

    @staticmethod
    def common_ground(
        types: dict[str, FunctionType] | list[str],
    ) -> set[str]:
        """Return the set of common / canonical names in ``types``.

        When a mapping is supplied, its keys are returned.  When a list is
        supplied, a normalized set is returned.  This is a small helper for
        downstream passes that need to know which names are shared between a
        type library and a symbol set.
        """
        if isinstance(types, dict):
            return set(types.keys())
        return set(types)

    # ---------------------------------------------------------------- bootstrap

    @classmethod
    def bootstrap_stdlib(cls, arch: str = "x64") -> "TypeLibrary":
        """Create a small pre-populated standard-library type library.

        The current bootstrap covers the most common C runtime functions used in
        native reverse engineering samples.  Calling convention defaults follow
        the requested architecture:

        * ``x64`` / ``amd64`` -> ``systemv_amd64``.
        * ``x86`` / ``i386`` -> ``cdecl``.
        * ``aarch64`` / ``arm64`` -> ``aarch64".
        * ``arm`` -> ``arm32``.

        Args:
            arch: Target architecture hint.

        Returns:
            A :class:`TypeLibrary` pre-loaded with standard prototypes.
        """
        arch_norm = arch.lower().replace("amd64", "x64").replace("arm64", "aarch64")
        cc_map = {
            "x64": "systemv_amd64",
            "x86": "cdecl",
            "aarch64": "aarch64",
            "arm": "arm32",
        }
        cc = cc_map.get(arch_norm, "systemv_amd64")
        lib = cls()
        t = _std_types()

        # String/memory helpers ------------------------------------------------
        lib.add_function_type(
            FunctionType(
                "strcpy",
                t["char_p"],
                cc,
                [Parameter("dest", t["char_p"]), Parameter("src", t["const_char_p"])],
                library="libc",
                comment="Copies null-terminated string from src to dest.",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strcat",
                t["char_p"],
                cc,
                [Parameter("dest", t["char_p"]), Parameter("src", t["const_char_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strlen",
                t["size_t"],
                cc,
                [Parameter("s", t["const_char_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strcmp",
                t["int"],
                cc,
                [Parameter("s1", t["const_char_p"]), Parameter("s2", t["const_char_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strncmp",
                t["int"],
                cc,
                [
                    Parameter("s1", t["const_char_p"]),
                    Parameter("s2", t["const_char_p"]),
                    Parameter("n", t["size_t"]),
                ],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strstr",
                t["char_p"],
                cc,
                [Parameter("haystack", t["const_char_p"]), Parameter("needle", t["const_char_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strchr",
                t["char_p"],
                cc,
                [Parameter("s", t["const_char_p"]), Parameter("c", t["int"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strdup",
                t["char_p"],
                cc,
                [Parameter("s", t["const_char_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "strdupa",
                t["char_p"],
                cc,
                [Parameter("s", t["const_char_p"])],
                library="libc",
                comment="alloca-based duplicate; GNU extension.",
            )
        )

        # Variadic format helpers ---------------------------------------------
        lib.add_function_type(
            FunctionType(
                "sprintf",
                t["int"],
                cc,
                [
                    Parameter("buf", t["char_p"]),
                    Parameter("fmt", t["const_char_p"]),
                    Parameter("...", t["void"]),
                ],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "printf",
                t["int"],
                cc,
                [Parameter("fmt", t["const_char_p"]), Parameter("...", t["void"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "fprintf",
                t["int"],
                cc,
                [
                    Parameter("stream", t["FILE_p"]),
                    Parameter("fmt", t["const_char_p"]),
                    Parameter("...", t["void"]),
                ],
                library="libc",
            )
        )

        # Memory helpers -------------------------------------------------------
        lib.add_function_type(
            FunctionType(
                "memcpy",
                t["void_p"],
                cc,
                [
                    Parameter("dest", t["void_p"]),
                    Parameter("src", t["const_char_p"]),
                    Parameter("n", t["size_t"]),
                ],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "memmove",
                t["void_p"],
                cc,
                [
                    Parameter("dest", t["void_p"]),
                    Parameter("src", t["const_char_p"]),
                    Parameter("n", t["size_t"]),
                ],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "memset",
                t["void_p"],
                cc,
                [Parameter("s", t["void_p"]), Parameter("c", t["int"]), Parameter("n", t["size_t"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "memcpy_s",
                t["int"],
                cc,
                [
                    Parameter("dest", t["void_p"]),
                    Parameter("destsz", t["size_t"]),
                    Parameter("src", t["const_char_p"]),
                    Parameter("count", t["size_t"]),
                ],
                library="msvcrt",
                comment="C11 Annex K bounded memcpy.",
            )
        )
        lib.add_function_type(
            FunctionType(
                "memmove_s",
                t["int"],
                cc,
                [
                    Parameter("dest", t["void_p"]),
                    Parameter("destsz", t["size_t"]),
                    Parameter("src", t["const_char_p"]),
                    Parameter("count", t["size_t"]),
                ],
                library="msvcrt",
            )
        )

        # Heap helpers ---------------------------------------------------------
        lib.add_function_type(
            FunctionType(
                "malloc",
                t["void_p"],
                cc,
                [Parameter("size", t["size_t"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "calloc",
                t["void_p"],
                cc,
                [Parameter("nmemb", t["size_t"]), Parameter("size", t["size_t"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "realloc",
                t["void_p"],
                cc,
                [Parameter("ptr", t["void_p"]), Parameter("size", t["size_t"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "free",
                t["void"],
                cc,
                [Parameter("ptr", t["void_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "alloca",
                t["void_p"],
                cc,
                [Parameter("size", t["size_t"])],
                library="libc",
                comment="Stack allocation; compiler intrinsic on most toolchains.",
            )
        )

        # Stream I/O -----------------------------------------------------------
        lib.add_function_type(
            FunctionType(
                "fopen",
                t["FILE_p"],
                cc,
                [Parameter("pathname", t["const_char_p"]), Parameter("mode", t["const_char_p"])],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "fread",
                t["size_t"],
                cc,
                [
                    Parameter("ptr", t["void_p"]),
                    Parameter("size", t["size_t"]),
                    Parameter("nmemb", t["size_t"]),
                    Parameter("stream", t["FILE_p"]),
                ],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "fwrite",
                t["size_t"],
                cc,
                [
                    Parameter("ptr", t["const_char_p"]),
                    Parameter("size", t["size_t"]),
                    Parameter("nmemb", t["size_t"]),
                    Parameter("stream", t["FILE_p"]),
                ],
                library="libc",
            )
        )
        lib.add_function_type(
            FunctionType(
                "fclose",
                t["int"],
                cc,
                [Parameter("stream", t["FILE_p"])],
                library="libc",
            )
        )

        # Line input -----------------------------------------------------------
        lib.add_function_type(
            FunctionType(
                "gets",
                t["char_p"],
                cc,
                [Parameter("s", t["char_p"])],
                library="libc",
                comment="Deprecated; unsafe buffer overflow source.",
            )
        )
        lib.add_function_type(
            FunctionType(
                "fgets",
                t["char_p"],
                cc,
                [
                    Parameter("s", t["char_p"]),
                    Parameter("size", t["int"]),
                    Parameter("stream", t["FILE_p"]),
                ],
                library="libc",
            )
        )

        # POSIX / socket helpers -----------------------------------------------
        lib.add_function_type(
            FunctionType(
                "recv",
                t["ssize_t"],
                cc,
                [
                    Parameter("sockfd", t["int"]),
                    Parameter("buf", t["void_p"]),
                    Parameter("len", t["size_t"]),
                    Parameter("flags", t["int"]),
                ],
                library="libc",
                comment="POSIX recv.",
            )
        )
        lib.add_function_type(
            FunctionType(
                "send",
                t["ssize_t"],
                cc,
                [
                    Parameter("sockfd", t["int"]),
                    Parameter("buf", t["const_char_p"]),
                    Parameter("len", t["size_t"]),
                    Parameter("flags", t["int"]),
                ],
                library="libc",
                comment="POSIX send.",
            )
        )
        lib.add_function_type(
            FunctionType(
                "read",
                t["ssize_t"],
                cc,
                [Parameter("fd", t["int"]), Parameter("buf", t["void_p"]), Parameter("count", t["size_t"])],
                library="libc",
                comment="POSIX read.",
            )
        )
        lib.add_function_type(
            FunctionType(
                "write",
                t["ssize_t"],
                cc,
                [
                    Parameter("fd", t["int"]),
                    Parameter("buf", t["const_char_p"]),
                    Parameter("count", t["size_t"]),
                ],
                library="libc",
                comment="POSIX write.",
            )
        )

        # Process control ------------------------------------------------------
        lib.add_function_type(
            FunctionType(
                "exit",
                t["void"],
                cc,
                [Parameter("status", t["int"])],
                library="libc",
            )
        )

        # Microsoft/secure variants -------------------------------------------
        lib.add_function_type(
            FunctionType(
                "printf_s",
                t["int"],
                cc,
                [Parameter("fmt", t["const_char_p"]), Parameter("...", t["void"])],
                library="msvcrt",
                comment="C11 Annex K secure printf.",
            )
        )

        return lib

    # ---------------------------------------------------------------- internal to_dict / from_dict helpers

    @staticmethod
    def _function_to_dict(func: FunctionType) -> dict[str, Any]:
        return {
            "name": func.name,
            "return_type": func.return_type,
            "calling_convention": func.calling_convention,
            "parameters": [asdict(p) for p in func.parameters],
            "library": func.library,
            "ordinal": func.ordinal,
            "comment": func.comment,
        }

    @staticmethod
    def _function_from_dict(data: dict[str, Any]) -> FunctionType:
        return FunctionType(
            name=data["name"],
            return_type=data["return_type"],
            calling_convention=data["calling_convention"],
            parameters=[Parameter(**p) for p in data.get("parameters", [])],
            library=data.get("library"),
            ordinal=data.get("ordinal"),
            comment=data.get("comment"),
        )

    @staticmethod
    def _struct_to_dict(struct: StructType) -> dict[str, Any]:
        return {
            "name": struct.name,
            "size": struct.size,
            "packed": struct.packed,
            "fields": [asdict(f) for f in struct.fields],
        }

    @staticmethod
    def _struct_from_dict(data: dict[str, Any]) -> StructType:
        return StructType(
            name=data["name"],
            size=data["size"],
            packed=data.get("packed", False),
            fields=[StructField(**f) for f in data.get("fields", [])],
        )

    @staticmethod
    def _enum_to_dict(enum: EnumType) -> dict[str, Any]:
        return {"name": enum.name, "members": enum.members}

    @staticmethod
    def _enum_from_dict(data: dict[str, Any]) -> EnumType:
        return EnumType(name=data["name"], members=data.get("members", {}))


__all__ = [
    "Parameter",
    "FunctionType",
    "StructField",
    "StructType",
    "EnumType",
    "TypeLibrary",
]
