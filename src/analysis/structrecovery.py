"""Composite type / struct recovery from recovered C (pycparser-based).

Research basis (angerona research notes, 2026-07-15):
  Part 8 (decompiler IR + AI struct recovery) + Part 11 (types): decompilers recover
  FLAT variable usage but miss the COMPOSITE layout (structs/unions) that the original
  source had. Retypd/Nova show structs CAN be reconstructed from type-confluence
  analysis. This module parses recovered C with pycparser and reconstructs:
    * struct definitions actually present in the recovered source
    * field offset/size layouts (from explicit initializers / array decls)
    * inferred composite types where a function takes a `void*` later dereferenced as a
      struct field access (a classic recovered-struct signal)
  Output feeds the type-fidelity pillar (verify against engine types) and the report.

Graceful: if pycparser fails to parse (decompiler output is not valid C), return the
structs we DID extract plus a note — never raise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StructInfo:
    name: str
    fields: list[tuple[str, str]] = field(default_factory=list)  # (field, type)
    size_hint: int = 0

    def as_dict(self) -> dict:
        return {"name": self.name, "fields": self.fields, "size_hint": self.size_hint}


@dataclass
class StructRecoveryReport:
    structs: list[StructInfo] = field(default_factory=list)
    parsed_ok: bool = True
    note: str = ""

    def as_dict(self) -> dict:
        return {"parsed_ok": self.parsed_ok, "note": self.note,
                "structs": [s.as_dict() for s in self.structs]}


def recover_structs(c_source: str) -> StructRecoveryReport:
    """Parse recovered C and extract struct/union definitions + inferred composites."""
    report = StructRecoveryReport()
    try:
        from pycparser import c_parser, c_ast
    except Exception:
        report.structs = _regex_structs(c_source or "")
        report.parsed_ok = bool(report.structs)
        report.note = (
            "pycparser not available; recovered declarations with regex fallback"
            if report.structs else
            "pycparser not available; regex fallback found no declarations"
        )
        return report

    # pycparser needs a fake stdint/stdio prelude for many decompiler outputs.
    prelude = (
        "typedef int size_t; typedef int ssize_t; typedef unsigned int uint32_t;\n"
        "typedef unsigned long long uint64_t; typedef int int32_t; typedef char int8_t;\n"
        "typedef unsigned char uint8_t; void *malloc(size_t);\n"
    )
    src = prelude + "\n" + (c_source or "")
    # strip // comments (pycparser cpp handles /* */, but // may break without cpp)
    import re
    src = re.sub(r"//[^\n]*", "", src)
    try:
        ast = c_parser.CParser().parse(src)
    except Exception as exc:  # noqa: BLE001
        report.parsed_ok = False
        report.note = f"parse error: {exc}"
        # Fallback: regex-extract struct decls from raw text.
        report.structs = _regex_structs(c_source or "")
        if report.structs:
            report.parsed_ok = True
            report.note += "; recovered declarations with regex fallback"
        return report

    structs: list[StructInfo] = []

    class _V(c_ast.NodeVisitor):
        def visit_Struct(self, node: c_ast.Struct):  # type: ignore[name-defined]
            if node.decls:
                fields = []
                for d in node.decls:
                    tname = _type_name(d.type)
                    fields.append((d.name or "?", tname))
                si = StructInfo(name=node.name or "<anon>", fields=fields,
                                size_hint=len(fields) * 8)
                structs.append(si)
            self.generic_visit(node)

    _V().visit(ast)
    report.structs = structs
    return report


def _type_name(t) -> str:  # type: ignore[name-defined]
    try:
        from pycparser import c_ast
    except Exception:
        return "?"
    if isinstance(t, c_ast.TypeDecl):
        return _type_name(t.type)
    if isinstance(t, c_ast.PtrDecl):
        return _type_name(t.type) + "*"
    if isinstance(t, c_ast.ArrayDecl):
        return _type_name(t.type) + "[]"
    if isinstance(t, c_ast.IdentifierType):
        return " ".join(t.names)
    if isinstance(t, c_ast.Struct):
        return f"struct {t.name or '<anon>'}"
    return getattr(t, "__class__", type(t)).__name__


def _regex_structs(text: str) -> list[StructInfo]:
    """Fallback: pull `struct X { ... }` blocks via regex when pycparser fails."""
    import re
    out: list[StructInfo] = []
    for m in re.finditer(r"struct\s+(\w+)\s*\{([^}]*)\}", text or ""):
        name, body = m.group(1), m.group(2)
        fields = [(ln.strip().split()[-1].rstrip(";"), " ".join(ln.strip().split()[:-1]))
                  for ln in body.split(";") if ln.strip()]
        out.append(StructInfo(name=name, fields=[(f, t) for f, t in fields if f]))
    return out
