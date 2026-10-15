"""SLEIGH spec-draft harness (Part 6, P1 / Tier-1 obscure-arch playbook).

Research basis (angerona research notes, 2026-07-15, Part 6):
  For an arch with a reference manual but no Ghidra spec, use an LLM to DRAFT a SLEIGH
  ``.slaspec`` from the ISA doc, then VERIFY the draft by encoding a few known
  instruction sequences and checking the p-code output against the manual (a BinDiff-
  style structural check on hand-written test vectors). This is generation-WITH-ground-
  truth -- the safe quadrant of AI-RE. Part 6 P1 turns "write a processor spec" into a
  first-class Angerona worker pattern, verified before promotion.

What this module does (production, deterministic verification core):
  - ``draft_slaspec_prompt(isa_manual, instructions)`` builds the structured prompt an
    LLM worker receives (the spec-authoring task), so the supervisor can spawn a
    spec-authoring worker reproducibly.
  - ``verify_slaspec_draft(draft_text, reference_vectors)`` checks the drafted spec for
    the structural REQUIREMENTS of a valid SLEIGH file (define token/space/register/
    constructor sections, balanced braces) WITHOUT needing Ghidra installed -- a cheap,
    deterministic pre-check that catches the most common draft failures before any
    expensive p-code emulation. Each reference vector's expected mnemonic must appear in
    the draft. This is the "verify before promote" gate.
  - Emits a structured verification result the supervisor consumes.

Graceful: empty draft -> fails verification with a clear reason (never auto-promotes a
bad spec).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


_REQUIRED_SECTIONS = ["define token", "define space", "define register", "define instruction"]


@dataclass
class SpecVerification:
    valid: bool
    reasons: list[str] = field(default_factory=list)
    vectors_passed: int = 0
    vectors_total: int = 0

    def as_dict(self) -> dict:
        return {"valid": self.valid, "reasons": self.reasons,
                "vectors_passed": self.vectors_passed,
                "vectors_total": self.vectors_total}


def draft_slaspec_prompt(isa_manual: str, instructions: list[str],
                         arch_name: str = "custom") -> str:
    """Build the prompt an LLM spec-authoring worker should receive (reproducible)."""
    inst_block = "\n".join(f"  - {i}" for i in instructions)
    return (
        f"You are authoring a Ghidra SLEIGH processor specification for the "
        f"'{arch_name}' architecture. Use the reference ISA manual below.\n\n"
        f"=== ISA MANUAL (ground truth) ===\n{isa_manual}\n\n"
        f"=== INSTRUCTIONS TO SPECIFY FIRST ===\n{inst_block}\n\n"
        "Produce a single .slaspec containing: `define token` (bit-fields), "
        "`define space` (address spaces), `define register` (register file), and "
        "`define instruction` constructors mapping bit-patterns to p-code. "
        "Output ONLY the SLEIGH source inside a ```sleigh code block. Every "
        "constructor must be brace-balanced and emit valid p-code."
    )


def verify_slaspec_draft(draft_text: str,
                         reference_vectors: Optional[list[dict]] = None) -> SpecVerification:
    """Deterministic pre-check of a drafted SLEIGH spec (no Ghidra needed).

    Checks: (1) all required SLEIGH sections present; (2) braces balanced; (3) each
    reference vector's expected mnemonic/opcode token appears in the draft. This is the
    cheap gate that runs BEFORE expensive p-code emulation verification.
    """
    res = SpecVerification(valid=False)
    if not draft_text or not draft_text.strip():
        res.reasons.append("empty draft")
        return res
    low = draft_text.lower()
    for sec in _REQUIRED_SECTIONS:
        if sec not in low:
            res.reasons.append(f"missing section: {sec}")
    # brace balance
    if draft_text.count("{") != draft_text.count("}"):
        res.reasons.append("unbalanced braces")
    # reference vectors: expected mnemonic must appear
    vectors = reference_vectors or []
    res.vectors_total = len(vectors)
    for vec in vectors:
        expected = (vec.get("mnemonic") or vec.get("opcode") or "").lower()
        if expected and expected in low:
            res.vectors_passed += 1
        else:
            res.reasons.append(f"reference mnemonic not found in draft: {expected!r}")
    res.valid = (not res.reasons)
    return res
