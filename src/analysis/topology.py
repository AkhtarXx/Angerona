"""Part 18 (P5) — automatic agent/topology discovery for the supervisor.

AgentSquare (arXiv:2410.06153) and G-Designer (arXiv:2410.11782) show that the
*team topology* (how many workers, how the work is split, what communication graph)
should be DISCOVERED from the task, not hand-picked or left entirely to an LLM
planner. A full GNN search over the design space is a later research part; this
module is the documented first, cheap, grounded step:

  Read the binary's MEASURED traits (function count, obfuscation flags, structural
  uncertainty tier) and adapt the supervisor's worker plan:
    * OBFUSCATED functions (obfuscation.json, Part 10) get their OWN focused worker
      per cluster -- a single worker struggles with control-flow flattening, so we
      split them out instead of burying them in a big unit.
    * LARGE binaries get more workers (capped at max_parallel), tiny ones may run
      directly.
    * HIGH-UNCERTAINTY (low lift-confidence / coverage tier, Part 2) gets an extra
      worker to double-check the hard slice.

Everything is GRACEFUL: missing artifacts -> the plan is returned unchanged (the
LLM supervisor's decision stands). The function is pure and unit-testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TopologyPlan:
    suggested_workers: int
    extra_worker_ids: list[str] = field(default_factory=list)
    note: str = ""
    traits: dict = field(default_factory=dict)


def _safe_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(errors="ignore")) if path.is_file() else {}
    except Exception:
        return {}


def count_functions(facts_dir: str | Path) -> int:
    """Best-effort function count from symbols.txt (tab-separated, 1st field = addr)."""
    p = Path(facts_dir) / "symbols.txt"
    if not p.is_file():
        return 0
    try:
        n = 0
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # symbol lines look like "0x401000\tfunc\tname" or "addr\tname"
            if "\t" in line and any(c.isdigit() for c in line.split("\t", 1)[0]):
                n += 1
        return n
    except Exception:
        return 0


def discover_topology(
    *,
    facts_dir: str | Path | None = None,
    code_dir: str | Path | None = None,
    re_analysis_dir: str | Path | None = None,
    obfuscation_json: str | Path | None = None,
    max_parallel: int = 3,
) -> TopologyPlan:
    """Return an adjusted topology derived from measured binary traits.

    Pure / side-effect free. Graceful: any missing artifact simply contributes
    nothing. ``suggested_workers`` is a SOFT hint (the supervisor may still follow
    its LLM plan); ``extra_worker_ids`` are concrete obfuscation-driven splits the
    supervisor should ADD.
    """
    traits: dict = {}
    extra: list[str] = []
    base_workers = 1

    # ---- trait 1: function count (size) ----
    n_funcs = count_functions(facts_dir) if facts_dir else 0
    traits["functions"] = n_funcs
    if n_funcs > 0:
        # ~1 worker per 40 functions, clamped to [1, max_parallel*2]
        base_workers = max(1, min(max_parallel * 2, round(n_funcs / 40)))
    traits["base_workers_by_size"] = base_workers

    # ---- trait 2: obfuscation (Part 10) ----
    obf = _safe_json(Path(obfuscation_json)) if obfuscation_json else (
        _safe_json(Path(code_dir) / "obfuscation.json") if code_dir else {})
    flagged = []
    if obf:
        # obfuscation_detect writes {"flagged": [{"function": "0x...", ...}, ...]}
        for item in obf.get("flagged", []) or []:
            fn = item.get("function") or item.get("name") or item.get("address")
            if fn:
                flagged.append(str(fn))
    traits["obfuscated_functions"] = len(flagged)
    # Give each obfuscated function its OWN focused worker (capped) -- flattening
    # defeats a single worker, so split them out.
    for i, fn in enumerate(flagged[: max_parallel]):
        extra.append(f"wob{i+1}")  # wob = worker-obfuscated
    traits["obf_extra_workers"] = len(extra)

    # ---- trait 3: structural uncertainty (Part 2 lift-confidence/coverage tier) ----
    rea = _safe_json(Path(re_analysis_dir) / "re_analysis.json") if re_analysis_dir else {}
    tier = (rea.get("coverage_tier") or {}).get("tier") if isinstance(rea, dict) else None
    traits["coverage_tier"] = tier
    uncertainty_bonus = 0
    if tier in ("LOW", "MEDIUM"):
        # high uncertainty -> one more worker to double-check the hard slice
        uncertainty_bonus = 1
    traits["uncertainty_bonus"] = uncertainty_bonus

    suggested = max(base_workers, 1) + uncertainty_bonus
    suggested = min(suggested, max_parallel * 2)

    note_parts = []
    if flagged:
        note_parts.append(f"{len(flagged)} obfuscated fn(s) -> {len(extra)} dedicated worker(s)")
    if tier in ("LOW", "MEDIUM"):
        note_parts.append(f"coverage tier {tier} -> +{uncertainty_bonus} worker")
    if n_funcs:
        note_parts.append(f"{n_funcs} functions -> base {base_workers} worker(s)")
    note = "; ".join(note_parts) if note_parts else "no traits measured (LLM plan stands)"

    return TopologyPlan(suggested_workers=suggested, extra_worker_ids=extra,
                        note=note, traits=traits)
