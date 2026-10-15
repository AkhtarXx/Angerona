"""Token accounting + cost estimation for RE runs (P3-11 / P3-12, research Part 17).

Research basis (angerona research notes, 2026-07-15):
  Part 17 (cost/scalability/privacy): cost is TOKEN-BOUND, not CPU-bound. The single
  biggest lever is PROMPT-CACHING the shared `code/` export (~10x input-cost drop),
  because every worker re-reads the same exported binary context. This module (a) gives
  a cheap token estimate (4 chars/token heuristic, no heavy dep) for reporting, and
  (b) computes the prompt-cache savings estimate so the harness can decide cache policy.

It is pure and dependency-free so it runs anywhere. Estimates are clearly labelled as
estimates (per-binary token counts should be measured by the actual LLM client when
available — this is the fallback).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Rough chars-per-token for code (English-ish mixed). Conservative for C/asm.
_CHARS_PER_TOKEN = 4.0

# 2026 list prices (USD per 1M tokens), live-fetched by research Part 17. Point-in-time.
# Used only for the cost ESTIMATE; real billing comes from the LLM client.
_PRICING_PER_MTOK = {
    "haiku": {"in": 1.0, "out": 5.0, "cache_read": 0.1},
    "sonnet": {"in": 2.0, "out": 10.0, "cache_read": 0.2},
    "fable5": {"in": 5.0, "out": 25.0, "cache_read": 0.5},
    "opus": {"in": 5.0, "out": 25.0, "cache_read": 0.5},
    "gpt56": {"in": 5.0, "out": 30.0, "cache_read": 0.5},
    "rex86-local": {"in": 0.0, "out": 0.0, "cache_read": 0.0},  # local = no per-token cost
}


@dataclass
class CostReport:
    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    model: str = "unknown"
    est_usd: float = 0.0
    est_usd_with_cache: float = 0.0
    savings_pct: float = 0.0
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "total_tokens": self.total_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "est_usd": round(self.est_usd, 4),
            "est_usd_with_cache": round(self.est_usd_with_cache, 4),
            "savings_pct": round(self.savings_pct, 1),
            "note": "estimates only; measure via LLM client for exact billing",
        }


def estimate_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token). No dependency."""
    if not text:
        return 0
    return max(1, int(len(text) / _CHARS_PER_TOKEN))


def estimate_code_dir(code_dir: str | Path) -> int:
    """Estimate total tokens across the shared `code/` export (the cacheable context)."""
    d = Path(code_dir)
    total = 0
    for f in d.rglob("*"):
        if f.is_file() and f.suffix in (".c", ".json", ".txt", ".csv", ".md"):
            try:
                total += estimate_tokens(f.read_text(errors="ignore"))
            except Exception:
                pass
    return total


def compute_cost(model: str, input_tokens: int, output_tokens: int,
                 cached_fraction: float = 0.0) -> CostReport:
    """Compute estimated cost with vs without prompt caching.

    ``cached_fraction`` = fraction of input tokens served from cache (prompt-caching the
    shared code/ export). With caching, those tokens bill at cache_read rate (~10x cheaper).
    """
    key = _model_key(model)
    price = _PRICING_PER_MTOK.get(key, _PRICING_PER_MTOK["haiku"])
    cached = int(input_tokens * max(0.0, min(1.0, cached_fraction)))
    uncached = input_tokens - cached
    est = (uncached / 1_000_000) * price["in"] + (cached / 1_000_000) * price["cache_read"] \
        + (output_tokens / 1_000_000) * price["out"]
    # without cache: all input at full rate
    est_no_cache = (input_tokens / 1_000_000) * price["in"] \
        + (output_tokens / 1_000_000) * price["out"]
    savings = (1 - est / est_no_cache) * 100 if est_no_cache > 0 else 0.0
    return CostReport(
        total_tokens=input_tokens + output_tokens,
        input_tokens=input_tokens, output_tokens=output_tokens, cached_tokens=cached,
        model=model, est_usd=est_no_cache, est_usd_with_cache=est,
        savings_pct=savings,
        detail=f"model={key} cache={cached_fraction:.0%}",
    )


def _model_key(model: str) -> str:
    m = (model or "").lower()
    if "haiku" in m:
        return "haiku"
    if "sonnet" in m:
        return "sonnet"
    if "opus" in m:
        return "opus"
    if "fable" in m:
        return "fable5"
    if "gpt-5" in m or "gpt5" in m:
        return "gpt56"
    if "rex86" in m or "local" in m:
        return "rex86-local"
    return "haiku"  # conservative default
