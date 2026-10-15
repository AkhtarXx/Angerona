"""P-code struct-layout recovery (Part 8, decompiler IR / struct recovery).

Research basis (angerona research notes, 2026-07-15, Part 8):
  Ghidra's P-code is the analysis backbone for struct recovery. Per opcodes.hh
  (verified locally), CPUI_PTRSUB (66) and CPUI_PTRADD (65) are *typed structure
  operations* -- a field access is emitted as PTRSUB(base, offset) rather than a
  bare INT_ADD. CPUI_LOAD/STORE (2/3) every field access; CPUI_NEW (69) is the
  heap-object seed. Recovering structs = rebuilding the type that justifies those
  PTRSUB/PTRADD nodes and merging per-access fragments into one layout.

  Angerona already exports decompiled C (IdaEngine / Ghidra export). Ghidra can
  also emit raw P-code via `decompile` debug actions; absent that, this module
  mines the *decompiled C* for the structural signatures that P-code PTRSUB/PTRADD
  produce -- `base->field`, `base.field`, `&(base.field)`, array `[i]` indexing --
  and aggregates them into a candidate layout (offset/width/field-type) the LLM
  worker can then COMPLETE under IR constraints (Idioms-style neuro-symbolic).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Ghidra decompiler emits "ptr->field" / "ptr.field" when it has deduced a struct.
_FIELD_ACCESS = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)", re.S)
# array indexing of a base: base[i] (suggests PTRADD / array of struct)
_ARRAY_IDX = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]")
# assignment into a deref: *(TYPE*)ptr = ...  /  ptr->field = ...
_ASSIGN_FIELD = re.compile(
    r"(\w+)\s*(?:->|\.)\s*(\w+)\s*=")


@dataclass
class Field:
    offset: Optional[int]
    name: str
    width_hint: Optional[int] = None
    reads: int = 0
    writes: int = 0

    def as_dict(self) -> dict:
        return {"offset": self.offset, "name": self.name,
                "width_hint": self.width_hint,
                "reads": self.reads, "writes": self.writes}


@dataclass
class StructCandidate:
    base_var: str
    fields: dict[str, Field] = field(default_factory=dict)
    array_access: bool = False
    array_index_var: Optional[str] = None

    def as_dict(self) -> dict:
        return {"base": self.base_var, "array_access": self.array_access,
                "array_index_var": self.array_index_var,
                "fields": {k: v.as_dict() for k, v in self.fields.items()}}


def _infer_width(token: str) -> Optional[int]:
    """Heuristic width from a cast/size keyword in the surrounding text."""
    m = re.search(r"\b(u?int(\d+)|char|short|long|float|double|ptr)\b", token)
    if not m:
        return None
    if m.group(2):
        return int(m.group(2)) // 8
    name = m.group(1)
    return {"char": 1, "short": 2, "long": 8, "float": 4, "double": 8,
            "ptr": 8, "uint": 4, "int": 4}.get(name)


def recover_structs_from_decompiled(code_dir: str | Path) -> list[StructCandidate]:
    """Mine decompiled C (and any .pcode files) for struct-like field accesses."""
    d = Path(code_dir)
    files: list[Path] = []
    if (d / "decompiled").is_dir():
        files = list((d / "decompiled").glob("*.c"))
    files += list(d.glob("*.c"))
    structs: dict[str, StructCandidate] = {}

    for f in files:
        text = f.read_text(errors="ignore")
        # field accesses; writes pre-computed once from the real source text
        writes = {(m.group(1), m.group(2)) for m in _ASSIGN_FIELD.finditer(text)}
        for m in _FIELD_ACCESS.finditer(text):
            base, fieldname = m.group(1), m.group(2)
            sc = structs.setdefault(base, StructCandidate(base_var=base))
            fl = sc.fields.get(fieldname)
            if fl is None:
                fl = Field(offset=None, name=fieldname)
                sc.fields[fieldname] = fl
            if (base, fieldname) in writes:
                fl.writes += 1
            else:
                fl.reads += 1
            # width from this field access's local context, not the whole file
            ctx = text[max(0, m.start() - 24):m.end() + 24]
            w = _infer_width(ctx)
            if w:
                fl.width_hint = w
        # array indexing of a base var -> PTRADD / array-of-struct signal
        for base, idx in _ARRAY_IDX.findall(text):
            sc = structs.setdefault(base, StructCandidate(base_var=base))
            sc.array_access = True
            sc.array_index_var = idx.strip()
    return [sc for sc in structs.values() if len(sc.fields) >= 2
            or sc.array_access]


def merge_layouts(candidates: list[StructCandidate]) -> list[dict]:
    """Downstream consumption: present each candidate as a flat dict."""
    return [c.as_dict() for c in candidates]
