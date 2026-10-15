"""Part 19 — multi-agent spawning improvements (U1/U4/U5/U6/U7).

Pure, side-effect-free helpers that decide HOW MANY agents to spawn, HOW to split
the work, WHICH agent per slice, and HOW MANY candidates to spend — replacing the
single greedy LLM plan with searched / scored / budgeted decisions (AgentSquare
arXiv:2410.06153, GPTSwarm, RouteLLM arXiv:2406.18665, More-Agents arXiv:2402.05120).

Everything is GRACEFUL: missing artifacts -> sane defaults, never raises.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SliceDifficulty:
    """Per-slice difficulty signal used for routing (U4) and budget (U6)."""
    obf_functions: int = 0
    uncertainty_tier: str = "HIGH"   # HIGH/MEDIUM/LOW (lift-confidence)
    size_bytes: int = 0

    @property
    def score(self) -> float:
        s = 0.0
        s += min(self.obf_functions, 5) * 0.3
        s += {"LOW": 0.6, "MEDIUM": 0.3, "HIGH": 0.0}.get(self.uncertainty_tier, 0.0)
        s += min(self.size_bytes / 4096.0, 1.0) * 0.1
        return round(min(s, 1.0), 3)


# ----------------------------------------------------------------- U1: spawn-plan search

def score_split(
    specs: list[dict],
    *,
    n_functions: int,
    n_obf: int,
    max_parallel: int = 3,
) -> float:
    """Objective coverage scorer for a candidate split (U1).

    Higher = better division. Rewards: (a) full function coverage (every function
    belongs to some unit), (b) obfuscated functions isolated in their own unit
    (they defeat a shared worker), (c) balanced unit sizes, (d) useful available
    parallelism, and (e) non-overlapping ownership. Pure + deterministic.
    """
    if not specs:
        return 0.0
    covered: set[str] = set()
    assignments = 0
    obf_isolated = 0
    sizes: list[int] = []
    described_units = 0
    for spec in specs:
        fns = spec.get("functions") or []
        has_non_function_scope = bool(
            spec.get("objective") or spec.get("focus") or spec.get("slice_id") or spec.get("title")
        )
        if fns or has_non_function_scope:
            described_units += 1
        if fns:
            sizes.append(len(fns))
        elif has_non_function_scope:
            # Security slices and subsystem objectives often start without a
            # concrete function list.  They are still real bounded work units;
            # scoring them as size=0 made every candidate score 0.000 and the
            # search silently accepted arbitrary plans.
            sizes.append(1)
        assignments += len(fns)
        covered.update(str(f) for f in fns)
        # a unit flagged as obfuscation-focused that actually holds >=1 obf fn
        if spec.get("obf_focus") and any("obf" in str(f).lower() for f in fns):
            obf_isolated += 1

    if covered and n_functions:
        coverage = min(len(covered) / n_functions, 1.0)
    elif described_units:
        # Non-function work units cannot claim whole-binary function coverage,
        # but they should receive a positive score so the planner can compare
        # candidate splits instead of selecting a 0.000 plan.
        coverage = 0.35
    else:
        coverage = 1.0 if not n_functions else 0.0
    balance = (
        1.0 - (max(sizes) - (sum(sizes) / len(sizes))) / max(max(sizes), 1)
        if sizes else 0.0
    )
    obf_term = min(obf_isolated / max(n_obf, 1), 1.0)
    # Roughly four functions per worker is a useful lower-overhead target for
    # these small deterministic plans; never reward workers beyond concurrency.
    target_workers = min(max(max_parallel, 1), max(1, (n_functions + 3) // 4))
    parallelism = min(len(sizes) / target_workers, 1.0)
    non_overlap = (len(covered) / assignments) if assignments else (1.0 if described_units else 0.0)
    return round(
        0.40 * coverage
        + 0.15 * balance
        + 0.25 * obf_term
        + 0.15 * parallelism
        + 0.05 * non_overlap,
        3,
    )


def search_spawn_plans(
    base_specs: list[dict],
    *,
    n_functions: int,
    n_obf: int,
    k: int = 4,
    max_parallel: int = 3,
) -> tuple[list[dict], float]:
    """Generate K candidate splits and keep the highest-scoring one (U1).

    Starts from ``base_specs`` (the LLM plan + P5 heuristic) and produces variants:
      * variant 0: the base plan as-is
      * variant 1: split the largest unit in two
      * variant 2: merge tiny units (<3 fns) into neighbours
      * variant 3: isolate each obfuscated function into its own unit
    Returns (best_specs, best_score). Deterministic, no LLM calls.
    """
    variants: list[list[dict]] = []

    # variant 0: base
    variants.append([dict(s) for s in base_specs])

    # variant 1: split largest unit
    if base_specs:
        v1 = [dict(s) for s in base_specs]
        largest = max(range(len(v1)), key=lambda i: len(v1[i].get("functions") or []))
        fns = list(v1[largest].get("functions") or [])
        if len(fns) >= 4:
            half = len(fns) // 2
            v1[largest]["functions"] = fns[:half]
            v1.append({**v1[largest], "id": f"{v1[largest]['id']}_b",
                       "title": v1[largest]["title"] + " (part 2)",
                       "functions": fns[half:]})
        variants.append(v1)

    # variant 2: merge tiny units
    v2 = []
    merged = None
    for s in base_specs:
        if len(s.get("functions") or []) < 3:
            if merged is None:
                merged = dict(s)
            else:
                merged["functions"] = (merged.get("functions") or []) + (s.get("functions") or [])
                merged["title"] = merged["title"] + " + " + s.get("title", "")
        else:
            v2.append(dict(s))
    if merged is not None:
        v2.append(merged)
    if len(v2) < len(base_specs):
        variants.append(v2)

    # variant 3: isolate obfuscated functions
    v3: list[dict] = []
    for source in base_specs:
        s = dict(source)
        fns = list(s.get("functions") or [])
        obf_here = [f for f in fns if "obf" in str(f).lower()]
        if not obf_here:
            v3.append(s)
            continue

        remaining = [f for f in fns if f not in obf_here]
        if remaining:
            s["functions"] = remaining
            s.pop("obf_focus", None)
            v3.append(s)

        # Iterate only over the source unit's obfuscated functions. Appending
        # children while iterating ``v3`` made every new child spawn another
        # identical child forever, eventually exhausting host memory.
        for j, of in enumerate(obf_here):
            v3.append({
                **source,
                "id": f"{source['id']}_obf{j}",
                "title": source["title"] + " obf",
                "functions": [of],
                "obf_focus": True,
            })
    variants.append(v3)

    # score + pick best (cap total workers at max_parallel*2+obf)
    best = None
    best_score = -1.0
    cap = max_parallel * 2 + n_obf
    for v in variants[:k]:
        if len(v) > cap:
            v = v[:cap]
        sc = score_split(
            v,
            n_functions=n_functions,
            n_obf=n_obf,
            max_parallel=max_parallel,
        )
        if sc > best_score:
            best_score, best = sc, v
    return best or base_specs, best_score


# ----------------------------------------------------------------- U4: difficulty routing

def route_agent(spec: dict, difficulty: SliceDifficulty, *,
                strong_agent: str, cheap_agent: str) -> str:
    """Pick the agent for a slice by difficulty (U4, RouteLLM-style).

    Obfuscated / uncertain slices get the STRONG agent (or more K-candidates);
    clean slices get the CHEAP agent to save cost. Graceful: default strong.
    """
    if difficulty.score >= 0.4:
        return strong_agent
    return cheap_agent


# ----------------------------------------------------------------- U5: DAG ordering

def order_by_dependencies(specs: list[dict]) -> list[list[dict]]:
    """Topologically group specs into execution waves by `depends_on` (U5).

    Returns a list of waves; wave N may run in parallel, wave N+1 waits for N.
    Specs without deps all go in wave 0. Cycles are broken (specs with an
    unsatisfied dep run after their predecessors' best effort). Pure.
    """
    by_id = {str(s.get("id")): s for s in specs}
    done: set[str] = set()
    waves: list[list[dict]] = []
    remaining = list(specs)
    while remaining:
        wave = []
        next_remaining = []
        for s in remaining:
            deps = s.get("depends_on") or []
            if all(d in done for d in deps):
                wave.append(s)
            else:
                next_remaining.append(s)
        if not wave:  # cycle guard: force-progress
            wave = [next_remaining[0]]
            next_remaining = next_remaining[1:]
        for s in wave:
            done.add(s.get("id"))
        waves.append(wave)
        remaining = next_remaining
    return waves


# ----------------------------------------------------------------- U6/U7: budget + parallelism

def global_candidate_budget(
    specs: list[dict],
    *,
    base_k: int,
    total_budget: int,
    max_per_worker: int | None = None,
    difficulty_of: "callable" = None,  # callable(spec)->SliceDifficulty
) -> dict[str, int]:
    """Distribute a GLOBAL K-candidate budget across workers by difficulty (U6).

    Spend candidates where verifier uncertainty is highest; clean slices get base_k,
    hard slices get more, capped so sum <= total_budget. Returns {worker_id: k}.
    """
    if (
        type(base_k) is not int
        or type(total_budget) is not int
        or base_k < 1
        or total_budget < 0
        or (
            max_per_worker is not None
            and (type(max_per_worker) is not int or max_per_worker < base_k)
        )
    ):
        raise ValueError("candidate budget bounds are invalid")
    if base_k * len(specs) > total_budget:
        # Seeding every worker with base_k would already exceed total_budget;
        # the documented "sum <= total_budget" cap cannot hold, so reject the
        # bounds rather than silently returning an over-budget allocation.
        raise ValueError("candidate budget is too small to seed every worker with base_k")
    if difficulty_of is None:
        difficulty_of = lambda s: SliceDifficulty()  # all-zero -> everyone base_k
    alloc: dict[str, int] = {}
    remaining = total_budget - base_k * len(specs)
    # seed everyone with base_k
    for s in specs:
        alloc[str(s.get("id"))] = base_k
    # rank by difficulty, add surplus
    ranked = sorted(specs, key=lambda s: difficulty_of(s).score, reverse=True)
    for s in ranked:
        if remaining <= 0:
            break
        capacity = (
            remaining
            if max_per_worker is None
            else max(0, max_per_worker - alloc[str(s.get("id"))])
        )
        add = min(
            remaining,
            capacity,
            max(1, int(difficulty_of(s).score * base_k * 2)),
        )
        alloc[str(s.get("id"))] += add
        remaining -= add
    return alloc


def adaptive_parallelism(*, complexity_tier: str, max_parallel: int,
                         budget_cap: int = 12) -> int:
    """Scale parallel workers with binary complexity (U7). Small/clean -> fewer;
    large/uncertain -> more, capped by budget_cap. Graceful default = max_parallel.
    """
    tier_par = {"LOW": 1, "MEDIUM": max(2, max_parallel // 2),
                "HIGH": max_parallel, "UNKNOWN": max_parallel}
    return min(budget_cap, tier_par.get(complexity_tier, max_parallel))
