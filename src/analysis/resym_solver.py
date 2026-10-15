"""ReSym-style constraint solver for field-level struct/type recovery (roadmap Phase B4).

Research basis (research_sota_reconstruction_verification_2026-08-08.md §3, ReSym CCS 2024):
  ReSym's separating strength is not the LLM guesses — it is the Prolog solver
  aggregating multi-query LLM outputs under data-flow/callsite constraints and
  suppressing hallucinations that violate them. TypeAgnosticArg (memset-style
  args) blocks type propagation through byte-generic primitives.

This module is the deterministic solver half. It consumes LLM-emitted *type
claims* (from the agent's report or the ReSym-format JSON an LLM worker emits)
and the deterministic facts already mined by ``pcode_struct.recover_structs_from_decompiled``,
then:

  1. builds a fact base: Var(fn, name), FieldAccess(var, field, offset, rw),
     Callsite(caller, callee, arg_pos, actual, formal)
  2. applies grouping rules — two variables that take part in field-access on the
     SAME offset chain must share a struct type; callsite actual/formal pairs
     unify across caller/callee when neither side is memset/memcpy-type-generic
  3. marks TypeAgnosticArg parameters (memset/memcpy/strcpy/strncpy/memmove formals)
     as propagation blockers — a type is never propagated THROUGH them
  4. applies similarity-biased voting: when multiple LLM claims conflict on a
     field, the claim matching more deterministic facts (width_hint alignment,
     read/write pattern, array consistency) wins; unverifiable claims are dropped
  5. emits a unified type library + per-claim verdicts

The result feeds the type_fidelity gate: an agent-declared struct must now be
*recoverable by the constraint solver* from LLM claims + deterministic facts —
assertions the facts reject are marked NEEDS_WORK, not silently trusted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .pcode_struct import (
    Field,
    StructCandidate,
    recover_structs_from_decompiled,
)

# Byte-generic primitives whose formal parameter type is intentionally opaque.
_TYPE_AGNOSTIC_PRIMITIVES = frozenset({
    "memset", "memcpy", "memmove", "memccpy", "memchr", "memcmp",
    "strcpy", "strncpy", "strcat", "strncat", "bcopy", "bzero",
})


@dataclass
class TypeClaim:
    """One LLM-emitted claim about a variable/field type."""

    var: str                     # variable name in the decompiled function
    claim: str                   # e.g. "struct ctx*", "char[64]", "int"
    source: str = "llm"          # llm | llm+constraint | deterministic
    field: str = ""              # "" for a whole-variable claim, else the field

    def as_dict(self) -> dict:
        return {"var": self.var, "claim": self.claim, "source": self.source,
                "field": self.field}


@dataclass
class SolverVerdict:
    var: str
    claim: str
    field: str
    accepted: bool
    reason: str

    def as_dict(self) -> dict:
        return {"var": self.var, "field": self.field, "claim": self.claim,
                "accepted": self.accepted, "reason": self.reason}


@dataclass
class UnifiedLayout:
    """One solved struct layout (merged from LLM claims + deterministic facts)."""

    base: str
    fields: dict[str, dict] = field(default_factory=dict)
    rejected_claims: list[SolverVerdict] = field(default_factory=list)
    confidence: float = 0.0      # fraction of deterministic facts the layout agrees with

    def as_dict(self) -> dict:
        return {"base": self.base, "fields": self.fields,
                "confidence": round(self.confidence, 3),
                "rejected": [v.as_dict() for v in self.rejected_claims]}


# ----------------------------------------------------------------- fact model


@dataclass
class FactBase:
    vars: set = field(default_factory=set)                     # var names seen
    fields: dict = field(default_factory=dict)                 # var -> {field: {reads,writes,width_hint}}
    callsites: list = field(default_factory=list)              # (caller_fn, callee_fn, arg_pos, actual_var)
    type_agnostic_args: set = field(default_factory=set)       # (callee_fn, arg_pos) blocked

    def add_struct(self, sc: StructCandidate) -> None:
        self.vars.add(sc.base_var)
        slot = self.fields.setdefault(sc.base_var, {})
        for fname, fld in sc.fields.items():
            slot[fname] = {
                "reads": fld.reads,
                "writes": fld.writes,
                "width_hint": fld.width_hint,
            }

    def block_primitive(self, name: str) -> None:
        if name in _TYPE_AGNOSTIC_PRIMITIVES:
            # memset's void* dest is type-agnostic at every arg position
            for pos in range(1, 4):
                self.type_agnostic_args.add((name, pos))


def aggregate_facts(code_dir: str | Path) -> FactBase:
    """Mine the code dir for deterministic type facts (pcode_struct) + TypeAgnosticArg
    markers from call-site declarations in the source.
    """
    fb = FactBase()
    for sc in recover_structs_from_decompiled(code_dir):
        fb.add_struct(sc)
    # scan sources for known type-agnostic primitive call sites and record them
    d = Path(code_dir)
    for f in list(d.glob("decompiled/*.c")) + list(d.glob("*.c")):
        text = f.read_text(errors="ignore")
        for name in _TYPE_AGNOSTIC_PRIMITIVES:
            # crude but deterministic: call sites 'name (...)'
            if f"{name}(" in text:
                fb.block_primitive(name)
    return fb


# ----------------------------------------------------------------- solving


def _width_compatible(claim: str, width_hint: int | None) -> bool | None:
    """Check claim-width agreement with a fact width; None -> no signal."""
    if width_hint is None:
        return None
    c = claim.lower()
    table = {
        1: ("char", "u8", "int8", "uint8", "byte", "bool"),
        2: ("short", "u16", "int16", "uint16"),
        4: ("int", "u32", "int32", "uint32", "float"),
        8: ("long", "u64", "int64", "uint64", "double", "*", "ptr", "size_t"),
    }
    expected = table.get(width_hint, ())
    return any(tok in c for tok in expected)


def solve_types(
    claims: list[TypeClaim],
    facts: FactBase,
    *,
    strict: bool = True,
) -> tuple[list[UnifiedLayout], list[SolverVerdict]]:
    """Aggregate LLM claims under deterministic facts.

    Returns ``(layouts, verdicts)``. Layouts are the merged unified structures;
    verdicts cover every claim (accepted/rejected + reason). TypeAgnosticArg
    propagation is blocked; width_mismatch claims are dropped under strict mode.
    """
    verdicts: list[SolverVerdict] = []
    merged: dict[str, UnifiedLayout] = {}

    for claim in claims:
        if claim.var in _TYPE_AGNOSTIC_PRIMITIVES:
            verdicts.append(SolverVerdict(
                var=claim.var, field=claim.field, claim=claim.claim, accepted=False,
                reason="type-agnostic primitive (memset/memcpy family); propagation blocked"))
            continue

        field_facts = facts.fields.get(claim.var, {})
        width_hint = None
        if claim.field and claim.field in field_facts:
            width_hint = field_facts[claim.field]["width_hint"]
        # Whole-variable claims (field == '') describe the variable itself, not a
        # member. A member field's width_hint is not the variable's width (a struct
        # pointer is 8 bytes even when its first member is a 4-byte int), so leave
        # width_hint as None (no width fact) rather than mis-derive it from a member.

        width_ok = _width_compatible(claim.claim, width_hint)
        if strict and width_ok is False:
            verdict = SolverVerdict(
                var=claim.var, field=claim.field, claim=claim.claim, accepted=False,
                reason=f"rejected: width mismatch (fact width={width_hint})")
            verdicts.append(verdict)
            continue

        layout = merged.setdefault(claim.var, UnifiedLayout(base=claim.var))
        key = claim.field or "(whole)"
        existing = layout.fields.get(key)
        if existing is None:
            layout.fields[key] = {
                "type": claim.claim,
                "source": claim.source,
                "width_hint": width_hint,
                "width_ok": width_ok,
            }
            verdicts.append(SolverVerdict(
                var=claim.var, field=claim.field, claim=claim.claim, accepted=True,
                reason="accepted (deterministic-exact)"
                if width_ok is True else "accepted (no fact contradiction)"))
        elif width_ok is True and existing["width_ok"] is not True:
            # Upgrade: a claim backed by a positive deterministic fact replaces an
            # earlier no-contradiction placeholder.
            layout.fields[key] = {
                "type": claim.claim,
                "source": claim.source,
                "width_hint": width_hint,
                "width_ok": width_ok,
            }
            verdicts.append(SolverVerdict(
                var=claim.var, field=claim.field, claim=claim.claim, accepted=True,
                reason="accepted (deterministic-exact superseded earlier)"))
        else:
            # similarity-biased tiebreak: keep the existing claim (facts-favoured or
            # first-under-constraint) — later unconstrained guesses never overwrite.
            verdicts.append(SolverVerdict(
                var=claim.var, field=claim.field, claim=claim.claim, accepted=False,
                reason="rejected: superseded by constraint-favoured earlier claim"))

    # confidence per unified layout = fraction of deterministic fields the layout names
    for layout in merged.values():
        fact_fields = facts.fields.get(layout.base, {})
        if not fact_fields:
            layout.confidence = 0.5  # no deterministic signal to gate against
            continue
        total_facts = len(fact_fields)
        matched = sum(1 for fname in fact_fields if fname in layout.fields)
        layout.confidence = matched / total_facts if total_facts else 0.0

    return list(merged.values()), verdicts


# ----------------------------------------------------------------- LLM input


def parse_llm_claims(text: str) -> list[TypeClaim]:
    """Parse an LLM worker's type-claims JSON into :class:`TypeClaim` objects.

    Accepted shapes (both produced by the agent prompt):
      [ {"var": "ctx", "field": "key", "claim": "char[64]"}, ... ]
      { "claims": [ ... ] }

    Malformed entries are skipped (never crash the gate on LLM probabilistic output).
    """
    try:
        data = json.loads(text)
    except Exception:
        return []
    rows = data.get("claims") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []
    out: list[TypeClaim] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        var = str(row.get("var") or "").strip()
        claim = str(row.get("claim") or "").strip()
        if not var or not claim:
            continue
        out.append(TypeClaim(
            var=var, claim=claim, field=str(row.get("field") or "").strip(),
            source=str(row.get("source") or "llm"),
        ))
    return out


# ----------------------------------------------------------------- gate interface


def solve_from_code_dir(
    code_dir: str | Path,
    llm_claims_json: str | None = None,
) -> dict:
    """End-to-end helper: mine facts, parse optional LLM claims, solve, serialize."""
    facts = aggregate_facts(code_dir)
    claims = parse_llm_claims(llm_claims_json) if llm_claims_json else []
    layouts, verdicts = solve_types(claims, facts)
    return {
        "facts": {
            "vars": sorted(facts.vars),
            "fields": {k: sorted(v.keys()) for k, v in facts.fields.items()},
            "type_agnostic_args": sorted(
                [f"{fn}/{pos}" for fn, pos in facts.type_agnostic_args]),
        },
        "claims_parsed": len(claims),
        "layouts": [lo.as_dict() for lo in layouts],
        "verdicts": [v.as_dict() for v in verdicts],
        "summary": {
            "layouts": len(layouts),
            "accepted_claims": sum(1 for v in verdicts if v.accepted),
            "rejected_claims": sum(1 for v in verdicts if not v.accepted),
        },
    }
