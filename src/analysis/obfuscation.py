"""Obfuscation-detection pre-pass — routes hardened binaries to a deobf-aware path.

Research basis (angerona research notes, 2026-07-15):
  Part 10 (obfuscation): control-flow flattening, opaque predicates, and VM-protected
  binaries (VMProtect/Themida/Sorbox) DEFEAT the structural gates. A flattened CFG
  "diverges" from any clean reconstruction, inflating false positives on the
  claims/CFG/BinDiff pillars. The right move is a DETECTION pre-pass that flags
  obfuscation so the pipeline can (a) down-weight structural signals, (b) route to a
  deobfuscation-aware path (angr/Unicorn emulation + LLM simplification), and (c) warn
  the reviewer not to trust CFG-divergence as a contradiction.

This is a heuristic detector (no external deps): it scores signals from the exported
facts (imports, string entropy, call-graph shape). It degrades gracefully — no facts
=> no obfuscation suspected (clean), never an error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Packer / protector tell-tale imports (Windows PE + cross-platform).
_PROTECTOR_IMPORTS = re.compile(
    r"(vmprotect|themida|winlicense|enigma|obsidium|aspack|upx|mpress|"
    r"themida64|safengine| armadillo|execompress|petite|fsg|kkrunchy)", re.I)

# Virtualization-obfuscation markers in recovered strings / symbols.
_VM_MARKERS = re.compile(r"(virtual\s*machine|vm_|handler|dispatch|obfuscat|junk\s*code)", re.I)

# Opaque-predicate / flattening signatures in decompiled C.
_FLATTENING = re.compile(r"(while\s*\(1\)\s*\{|switch\s*\(.*state|case\s*0x[0-9a-f]+:|"
                         r"state\s*=\s*.*\?\s*.*:\s*.*;)", re.I)

_BASE64_ENTROPY = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


@dataclass
class ObfuscationReport:
    suspected: bool
    score: float                      # 0.0 (clean) .. 1.0 (heavily obfuscated)
    signals: list[str] = field(default_factory=list)
    tier: str = "clean"               # clean | light | heavy | vm

    def as_dict(self) -> dict:
        return {"suspected": self.suspected, "score": round(self.score, 3),
                "tier": self.tier, "signals": self.signals[:20]}


def detect_obfuscation(export_dir: str | Path, decompiled_text: str = "") -> ObfuscationReport:
    """Heuristic obfuscation detection from exported facts + optional decompiled text.

    Signals (each adds weight):
      +0.30  protector import (VMProtect/Themida/UPX/...)
      +0.20  VM/virtualization marker strings
      +0.20  control-flow flattening pattern in decompiled C
      +0.15  high-entropy base64 blobs (packed payload)
      +0.15  many opaque/junk constructs
    Graceful: missing files -> clean.
    """
    d = Path(export_dir)
    signals: list[str] = []
    score = 0.0

    # imports
    imp = d / "imports.txt"
    if imp.is_file():
        text = imp.read_text(errors="ignore")
        if _PROTECTOR_IMPORTS.search(text):
            score += 0.30
            signals.append("protector import detected")

    # strings / symbols for VM markers
    for fname in ("strings.txt", "symbols.txt"):
        f = d / fname
        if f.is_file():
            text = f.read_text(errors="ignore")
            if _VM_MARKERS.search(text):
                score += 0.20
                signals.append("virtualization/obfuscation marker string")
                break
            if len(_BASE64_ENTROPY.findall(text)) >= 3:
                score += 0.15
                signals.append("high-entropy base64 blobs (packed payload)")

    # flattening in decompiled C
    if decompiled_text and _FLATTENING.search(decompiled_text):
        score += 0.35
        signals.append("control-flow flattening pattern in decompiled C")

    score = min(score, 1.0)
    suspected = score >= 0.30
    tier = "clean"
    if score >= 0.70:
        tier = "vm"
    elif score >= 0.50:
        tier = "heavy"
    elif suspected:
        tier = "light"
    return ObfuscationReport(suspected=suspected, score=score, signals=signals, tier=tier)
