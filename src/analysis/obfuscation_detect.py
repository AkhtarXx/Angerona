"""Obfuscation pre-pass classifier (Part 10, G1 — obfuscation-aware verification).

Research basis (angerona research notes, 2026-07-15, Part 10):
  Obfuscation (control-flow flattening, virtualization/VM-based, packing, opaque
  predicates) defeats both decompilers AND naive LLM decompilation. Angerona's CFG
  pillar compares block/edge COUNTS, so a flattened function looks "divergent" and
  may never converge; a virtualized function has a synthetic CFG. Recommendation:
  add a lightweight pre-classifier that labels functions flattened / virtualized /
  packed / clean from STRUCTURAL signatures, and route flagged functions to a
  deobfuscation-aware path instead of the standard convergence loop.

  This module is deterministic and sandbox-safe (no emulation required). It scores
  each function's asm for flattening/vm/packing signals and emits a label + reasons.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# control-flow flattening: a big dispatcher switch with a state var + many case blocks
_DISPATCH = re.compile(r"\bswitch\s*\(\s*\w+\s*\)", re.I)
_STATE_VAR = re.compile(r"\b(while|for)\s*\(\s*\w+\s*!=\s*\w+\s*\)", re.I)
# virtualization: dense indirect jumps through a handler table, unusual opcode ranges
_INDIRECT_JMP = re.compile(r"\b(jmp|br)\s*\*?\s*\(?\s*\w+\s*\[", re.I)
_VM_HANDLER = re.compile(r"\b(handler|dispatch|vm_|opcode|operand)\b", re.I)
# many unconditional jumps between basic blocks (flattening artifact)
_JMP = re.compile(r"^\s*(jmp|br|b)\s+", re.I | re.M)
# opaque predicate: useless conditional that's always true/false
_OPAQUE = re.compile(r"(test\s+\w+\s*,\s*\w+|cmp\s+\w+\s*,\s*\w+)\s*\n\s*(j\w+)\s+", re.I)
# packing / self-decrypt: suspicious section entropy (caller supplies section data)
_PACKER_MAGIC = re.compile(r"UPX!|\.vmp0|themida|\.tsp0|\.petite|nsp0", re.I)


@dataclass
class ObfResult:
    name: str
    label: str  # clean | flattened | virtualized | packed | mixed
    score: float
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "label": self.label,
                "score": round(self.score, 3), "reasons": self.reasons}


def classify_function(name: str, asm: str) -> ObfResult:
    reasons: list[str] = []
    score = 0.0
    jmps = len(_JMP.findall(asm))
    blocks = asm.count("\n")
    jmp_density = jmps / max(1, blocks)

    if _DISPATCH.search(asm) or _STATE_VAR.search(asm):
        reasons.append("dispatcher switch / state-var loop (flattening)")
        score += 0.5
    if jmp_density > 0.35:
        reasons.append(f"high jump density ({jmp_density:.2f})")
        score += 0.3
    if _INDIRECT_JMP.search(asm):
        reasons.append("indirect jump through computed base (vm-like)")
        score += 0.4
    if _VM_HANDLER.search(asm):
        reasons.append("vm/handler/opcode naming")
        score += 0.3
    if _OPAQUE.search(asm):
        reasons.append("opaque-predicate pattern")
        score += 0.2

    if score >= 0.6:
        if _VM_HANDLER.search(asm) or _INDIRECT_JMP.search(asm):
            label = "virtualized"
        else:
            label = "flattened"
    elif score >= 0.3:
        label = "mixed"
    else:
        label = "clean"
    return ObfResult(name=name, label=label, score=score, reasons=reasons)


def detect_in_export(code_dir: str | Path) -> list[ObfResult]:
    """Classify every exported function's asm. Returns a sorted report (worst first)."""
    d = Path(code_dir)
    asm_dir = d / "asm"
    results: list[ObfResult] = []
    if asm_dir.is_dir():
        for af in asm_dir.glob("*.asm"):
            asm = af.read_text(errors="ignore")
            name = af.stem
            results.append(classify_function(name, asm))
    else:
        # fall back to functions.csv + per-candidate asm if present
        fc = d / "functions.csv"
        if fc.is_file():
            for line in fc.read_text(errors="ignore").splitlines()[1:]:
                parts = line.split(",")
                if parts:
                    results.append(classify_function(parts[0].strip(), ""))
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def packed_binary_hint(raw_bytes: bytes) -> Optional[str]:
    """Cheap whole-binary packer hint from section/magic strings."""
    m = _PACKER_MAGIC.search(raw_bytes[:0x2000].decode("latin1", "ignore"))
    return m.group(0).lower() if m else None
