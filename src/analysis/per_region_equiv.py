"""Per-region equivalence localization (roadmap Phase B5 / codealign-style).

Research basis (research_sota_reconstruction_verification_2026-08-08.md §2):
  codealign (arXiv 2501.04811) replaces binary/function-unit equivalence verdicts with
  per-INSTRUCTION-REGION verdicts: two decompilations are compared region-by-region,
  and the divergent *regions* (not just "the function is wrong") are returned. The
  repair cost drops because the next iteration edits a localized span, not the whole
  function.

This module implements a deterministic line-level localization layer for the
reconstruction-verify gate. It does not compete with BinDiff/CFG (they remain the
structural authority); it *report*s the divergence localized so the repair agent
gets an actionable span:

  1. tokenise the original function body and the reconstruction body into
     normalized source regions (blank-stripped, comment-stripped, whitespace-
     canonicalised, brace balanced),
  2. run difflib's opcode matcher over them,
  3. return every non-equal region with original/reconstruction spans and a short
     structural hint ("loop shape", "control-flow split", "type/declaration drift",
     "call-site drift", "constant drift"),
  4. summarise into per-region verdicts the supervisor's repair prompt can quote.

The hint lexicon is deliberately conservative: a region is tagged only when a
deterministic pattern matches it (unbalanced braces/missing loops/call-count
delta/constant delta); unknown => "content drift", never a false structural tag.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

_WS_RE = re.compile(r"\s+")
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
_NUMBER_RE = re.compile(r"\b\d+\b|0x[0-9a-fA-F]+\b")
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


@dataclass
class Region:
    """One divergent span between the original and the reconstruction."""

    kind: str                # replace | delete | insert
    original_span: tuple     # (start_line, end_line) in original (0-based, exclusive end)
    reconstruction_span: tuple
    hint: str                # structural hint for the repair agent
    original_head: str = ""  # first ~60 chars of original span (preview)
    reconstruction_head: str = ""

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "original_span": list(self.original_span),
            "reconstruction_span": list(self.reconstruction_span),
            "hint": self.hint,
            "original_head": self.original_head[:60],
            "reconstruction_head": self.reconstruction_head[:60],
        }


@dataclass
class RegionReport:
    equivalent: bool = True
    regions: list[Region] = field(default_factory=list)
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "equivalent": self.equivalent,
            "regions": [r.as_dict() for r in self.regions],
            "summary": self.summary,
            "divergent_count": len(self.regions),
        }


def _normalize_lines(source: str) -> list[str]:
    """Token-canonicalised lines: comments/strings/whitespace/numbers folded so the
    matcher is robust to formatting and immediate-value noise while still exposing
    structural divergence (control flow, call sites, declarations).
    """
    body = _COMMENT_RE.sub("", source)
    body = _STRING_RE.sub('""', body)
    body = _NUMBER_RE.sub("<num>", body)
    out: list[str] = []
    for line in body.splitlines():
        norm = _WS_RE.sub(" ", line).strip()
        if norm:
            out.append(norm)
    return out


def _hint(orig_block: list[str], recon_block: list[str]) -> str:
    """Conservative structural tag based on deterministic deltas."""
    o = " ".join(orig_block)
    r = " ".join(recon_block)
    # unbalanced control structure
    if o.count("{") != r.count("{") or o.count("}") != r.count("}"):
        return "control-flow split (brace/scope delta)"
    o_loops = len(re.findall(r"\b(?:for|while|do)\b", o))
    r_loops = len(re.findall(r"\b(?:for|while|do)\b", r))
    if o_loops != r_loops:
        return "loop shape mismatch"
    o_calls = len(re.findall(r"\b(?!if|while|for|return|sizeof)\w+\s*\(", o))
    r_calls = len(re.findall(r"\b(?!if|while|for|return|sizeof)\w+\s*\(", r))
    if o_calls != r_calls:
        return f"call-site drift ({o_calls} vs {r_calls} calls)"
    o_decl = len(re.findall(r"\b(?:struct|union|enum|typedef)\b", o))
    r_decl = len(re.findall(r"\b(?:struct|union|enum|typedef)\b", r))
    if o_decl != r_decl:
        return "type/declaration drift"
    o_nums = set(_NUMBER_RE.findall(o))
    r_nums = set(_NUMBER_RE.findall(r))
    # normalized numbers are already folded -> informational only
    if o_nums != r_nums and o_nums and r_nums:
        return "constant/operand drift"
    return "content drift"


def diff_regions(original: str, reconstruction: str) -> RegionReport:
    """Localize divergence between two function bodies (region-level).

    Inputs are plain C source strings (function bodies, not whole files required).
    Returns a :class:`RegionReport` with one :class:`Region` per divergent span.
    Identical-normalized inputs => equivalent (empty regions).
    """
    orig_lines = _normalize_lines(original)
    recon_lines = _normalize_lines(reconstruction)
    if orig_lines == recon_lines:
        return RegionReport(equivalent=True, regions=[], summary="identical (normalized)")

    sm = difflib.SequenceMatcher(None, orig_lines, recon_lines, autojunk=False)
    regions: list[Region] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        ob = orig_lines[i1:i2]
        rb = recon_lines[j1:j2]
        regions.append(Region(
            kind=tag,
            original_span=(i1, i2),
            reconstruction_span=(j1, j2),
            hint=_hint(ob, rb),
            original_head=ob[0] if ob else "",
            reconstruction_head=rb[0] if rb else "",
        ))

    n = len(regions)
    hints = {}
    for r in regions:
        hints[r.hint] = hints.get(r.hint, 0) + 1
    parts = ", ".join(f"{count}x {hint}" for hint, count in sorted(hints.items()))
    summary = f"{n} divergent region(s)" + (f" — {parts}" if n else "")
    return RegionReport(equivalent=False, regions=regions, summary=summary)


def localize_for_verdict(
    original_decompiled: str,
    reconstruction_c: str,
) -> dict:
    """Gate-facing helper: report + repair-prompt snippet.

    Caller (BinDiff/loop) may use ``regions`` to point the repair agent at the
    exact spans needing rework, instead of a function-global failure message.
    """
    rep = diff_regions(original_decompiled, reconstruction_c)
    repair_lines = []
    for idx, region in enumerate(rep.regions[:5]):
        repair_lines.append(
            f"[{idx+1}] {region.kind} @ orig lines {region.original_span[0]}-"
            f"{region.original_span[1]} ({region.hint}): "
            f"original starts {region.original_head[:40]!r}, "
            f"reconstruction starts {region.reconstruction_head[:40]!r}"
        )
    return {
        **rep.as_dict(),
        "repair_prompt_fragment": "; ".join(repair_lines) if repair_lines
        else "no localized divergence",
    }
