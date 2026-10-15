"""Behavior tests for Part 18 SOTA agent upgrades:
  P1 Reflexion lesson log (gaps fed forward across rounds)
  P4 Trajectory search (K-candidate analyst + verifier-select)
  P3 Adversarial 2nd reviewer (must disprove claims)

All driven through the real ConvergenceLoop with a fake dispatcher. No engine/Ghidra.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.agents.loop import (
    ConvergenceLoop,
    attest_isolation_capable_dispatch,
    parse_verdict,
)
from src.agents.runtime import AgentResult
from src.workspace import RunWorkspace


def _facts(d, *, strings=(), symbols=(), types=(), binary=None):
    d.mkdir(parents=True, exist_ok=True)
    (d / "strings.txt").write_text("\n".join(strings) + "\n")
    (d / "symbols.txt").write_text("\n".join(symbols) + "\n")
    if types:
        (d / "types.txt").write_text("\n".join(types) + "\n")
    if binary is not None:
        digest = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        (d / "EXPORT_MANIFEST.json").write_text(
            json.dumps({"metadata": {"sha256": digest}})
        )


def test_reflexion_lesson_log_written_and_fed_forward(tmp_path):
    """When a reviewer returns NEEDS_WORK, the gap is logged as a lesson and the
    next analyst task includes it (so the agent does not repeat the mistake)."""
    facts = tmp_path / "facts"
    _facts(facts, symbols=["0x401000\tfunc\tmain"])
    seen_tasks = []

    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        seen_tasks.append(task)
        if "REVIEW_VERDICT" in sp or "DISPROVE" in sp:
            # friendly reviewer: round 1 gaps, round 2 satisfied
            if "DISPROVE" in sp:
                return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                                   events=[], returncode=0, seconds=0.1)
            # determine round from how many analyst tasks seen
            n_analyst = sum(
                1 for t in seen_tasks
                if "Prior reviewer prose" in t or "REVISION" in t
            )
            if n_analyst < 1:
                return AgentResult(ok=True,
                                   final_text="## Gaps to address\n- explain the crypto\n"
                                              "REVIEW_VERDICT: NEEDS_WORK",
                                   events=[], returncode=0, seconds=0.1)
            return AgentResult(ok=True, final_text="all fixed\nREVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # analyst
        return AgentResult(ok=True, final_text="report text", events=[],
                           returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=dispatch, max_rounds=2,
                          claims_dir=str(facts)).run()
    # lesson log file created
    lessons = (ws.docs_dir / "lessons.md").read_text()
    assert "LESSONS FROM PRIOR ROUNDS" not in lessons  # that's the analyst echo, not the file
    assert "explain the crypto" in lessons  # the gap was persisted
    # the persisted lesson was fed into a later analyst task
    assert any(
        "explain the crypto" in t
        for t in seen_tasks
        if "Prior reviewer prose" in t
    )
    assert res.converged is True


def test_k_candidate_picks_best_scoring_report(tmp_path):
    """With k>1 the loop runs the analyst K times and keeps the highest-scoring
    report (cheap content-pillar scorer, no BinDiff needed)."""
    facts = tmp_path / "facts"
    # strings present so the scorer can corroborate a cited string
    _facts(
        facts,
        strings=["config_path=/etc/x"],
        symbols=["0x401000\tfunc\tmain"],
        binary="/bin/true",
    )
    analyst_calls = []

    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        if "REVIEW_VERDICT" in sp or "DISPROVE" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # analyst: alternate good/bad reports
        analyst_calls.append(1)
        k = len(analyst_calls)
        if k % 2 == 1:
            # good: cites a string that exists in the binary (verbatim)
            return AgentResult(
                ok=True,
                final_text="binary evidence references the string 'config_path=/etc/x'",
                events=[], returncode=0, seconds=0.1,
            )
        # bad: cites a string NOT in the binary
        return AgentResult(
            ok=True,
            final_text="binary evidence references the string 'nonexistent_setting=xyz'",
            events=[], returncode=0, seconds=0.1,
        )

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    attest_isolation_capable_dispatch(dispatch)
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=dispatch, max_rounds=1, k_candidates=4,
                          claims_dir=str(facts)).run()
    # 4 analyst candidates were generated
    assert len(analyst_calls) == 4
    # the kept report is the GOOD one (cites the real string)
    assert "config_path=/etc/x" in res.final_report
    assert "nonexistent_setting" not in res.final_report
    # the chosen candidate count is logged
    log = (ws.docs_dir / "progress.md").read_text() if (ws.docs_dir / "progress.md").is_file() else ""
    # score-based selection happened (no exception); converged
    assert res.converged is True


def test_adversarial_reviewer_forces_needs_work(tmp_path):
    """When --adversarial-review and the hostile reviewer disproves a claim, the
    loop overrides SATISFIED -> NEEDS_WORK (Crawford/RARE defense)."""
    facts = tmp_path / "facts"
    _facts(facts, symbols=["0x401000\tfunc\tmain"])

    def dispatch(agent, task, sp, oe):
        if "DISPROVE" in sp:
            # hostile reviewer: claim cannot be reproduced -> NEEDS_WORK
            return AgentResult(ok=True,
                               final_text="## Claims I could NOT reproduce\n- the cited "
                                          "vulnerability has no sink\nREVIEW_VERDICT: NEEDS_WORK",
                               events=[], returncode=0, seconds=0.1)
        if "REVIEW_VERDICT" in sp:
            # friendly reviewer: satisfied
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="report claims a vuln at 0x401000",
                           events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=dispatch, max_rounds=1,
                          adversarial_review=True,
                          claims_dir=str(facts)).run()
    # friendly said SATISFIED, but adversarial disproved -> must NOT converge
    assert res.converged is False
    # adversarial review artifact saved
    assert (ws.raw_dir / "round_1_adversarial.md").is_file()


def test_adversarial_reviewer_passes_when_no_contradiction(tmp_path):
    """Adversarial reviewer that finds nothing to disprove lets convergence proceed."""
    facts = tmp_path / "facts"
    _facts(facts, symbols=["0x401000\tfunc\tmain"])

    def dispatch(agent, task, sp, oe):
        if "DISPROVE" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        if "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="clean report", events=[],
                           returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=dispatch, max_rounds=1,
                          adversarial_review=True,
                          claims_dir=str(facts)).run()
    assert res.converged is True


# ------------------------------------------------------------------- Part 18 P5 (topology)

def test_discover_topology_no_traits_is_noop():
    """With no artifacts, the planner stands (no extra workers, benign note)."""
    from src.analysis.topology import discover_topology
    tp = discover_topology(max_parallel=3)
    assert tp.extra_worker_ids == []
    assert tp.suggested_workers == 1
    assert "LLM plan stands" in tp.note


def test_discover_topology_obfuscation_splits_workers(tmp_path):
    """Obfuscated functions (obfuscation.json) yield dedicated worker ids."""
    from src.analysis.topology import discover_topology
    code = tmp_path / "code"
    code.mkdir()
    (code / "obfuscation.json").write_text(json.dumps({
        "flagged": [{"function": "0x401000"}, {"function": "0x401200"},
                    {"function": "0x401400"}]
    }))
    tp = discover_topology(code_dir=str(code), max_parallel=3)
    assert tp.extra_worker_ids == ["wob1", "wob2", "wob3"]
    assert tp.traits["obfuscated_functions"] == 3


def test_discover_topology_size_scales_workers(tmp_path):
    """More functions -> more base workers (capped)."""
    from src.analysis.topology import discover_topology
    facts = tmp_path / "facts"
    facts.mkdir()
    # 200 functions -> ~5 workers, capped at max_parallel*2 = 6
    lines = "\n".join(f"0x{0x400000 + i*16:08x}\tfunc\tf{i}" for i in range(200))
    (facts / "symbols.txt").write_text(lines + "\n")
    tp = discover_topology(facts_dir=str(facts), max_parallel=3)
    assert tp.suggested_workers >= 5
    assert tp.suggested_workers <= 6


def test_supervisor_auto_topology_adds_obf_workers(tmp_path):
    """SupervisorLoop with topo_strategy=auto injects obfuscation workers into the
    plan (without needing a real LLM planner)."""
    from src.agents.supervisor import SupervisorLoop, WorkerSpec, SwarmResult
    from src.workspace import RunWorkspace

    code = tmp_path / "code"
    code.mkdir()
    (code / "obfuscation.json").write_text(json.dumps({
        "flagged": [{"function": "0x401000"}, {"function": "0x401200"}]}))

    calls = {}

    def dispatch(agent, task, sp, oe):
        # supervisor planner -> a single LLM unit
        if "WORK UNITS" in task or "plan" in sp.lower():
            calls.setdefault("plan", 0)
            calls["plan"] += 1
            return AgentResult(ok=True, final_text='```plan\n{"coverage_complete": true, '
                               '"workers": [{"id": "w1", "title": "all", "objective": "x"}]}\n```',
                               events=[], returncode=0, seconds=0.1)
        # workers + consolidate -> trivial converged
        return AgentResult(ok=True, final_text="done\nREVIEW_VERDICT: SATISFIED",
                           events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    sup = SupervisorLoop(binary="/bin/true", objective="x", overview="ov", workspace=ws,
                         dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
                         engine="ida", claims_dir=str(code), topo_strategy="auto")
    result = sup.run()
    # plan now has the LLM's w1 PLUS 2 obfuscation workers (wob1, wob2)
    worker_ids = [w["id"] for w in ws.meta.get("swarm", {}).get("workers", [])]
    assert "wob1" in worker_ids and "wob2" in worker_ids
    assert "topology" in ws.meta  # recorded the auto-discovery


def test_supervisor_fixed_topology_keeps_llm_plan(tmp_path):
    """topo_strategy=fixed does NOT inject obfuscation workers (trusts LLM plan)."""
    from src.agents.supervisor import SupervisorLoop
    from src.workspace import RunWorkspace

    code = tmp_path / "code"
    code.mkdir()
    (code / "obfuscation.json").write_text(json.dumps({
        "flagged": [{"function": "0x401000"}]}))

    def dispatch(agent, task, sp, oe):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(ok=True, final_text='```plan\n{"coverage_complete": true, '
                               '"workers": [{"id": "w1", "title": "all", "objective": "x"}]}\n```',
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="done\nREVIEW_VERDICT: SATISFIED",
                           events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    sup = SupervisorLoop(binary="/bin/true", objective="x", overview="ov", workspace=ws,
                         dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
                         engine="ida", claims_dir=str(code), topo_strategy="fixed")
    sup.run()
    worker_ids = [w["id"] for w in ws.meta.get("swarm", {}).get("workers", [])]
    assert "wob1" not in worker_ids  # NOT injected
