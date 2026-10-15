"""Behavior tests for the Part 11/12/13 verification wiring (symbol/type, semantics,
provenance) and the Part 14 RE-core orchestrator (coverage_tier, corpus_caveat,
evidence_ledger) — the gap-closing work that makes the research recommendations
run inside the actual convergence gate instead of sitting as orphaned helpers.

These are pure-Python: no Ghidra/BinDiff, no LLM. They drive the real
``ConvergenceLoop`` / ``SupervisorLoop`` with a fake dispatcher and assert that the
new pillars fire (and fire gracefully) on synthetic exported facts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.agents.loop import ConvergenceLoop, parse_verdict
from src.agents.runtime import AgentResult
from src.agents.supervisor import SupervisorLoop
from src.workspace import RunWorkspace


# ---------------------------------------------------------------- fixtures

def _make_facts(d: Path, *, strings=(), symbols=(), types=()) -> None:
    """Write a minimal export fact tree like src.analysis.export.write_*."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "strings.txt").write_text("\n".join(strings) + "\n")
    (d / "symbols.txt").write_text("\n".join(symbols) + "\n")
    digest = hashlib.sha256(Path("/bin/true").read_bytes()).hexdigest()
    (d / "EXPORT_MANIFEST.json").write_text(
        json.dumps({"metadata": {"sha256": digest}})
    )
    if types:
        (d / "types.txt").write_text("\n".join(types) + "\n")


def _satisfied_review(extra: str = "") -> str:
    return f"## Verification\nall confirmed {extra}\nREVIEW_VERDICT: SATISFIED"


def _fake_dispatch(reports: list[str], reviews: list[str]):
    """Dispatcher returning canned analyst reports / reviewer verdicts in order."""
    ri = iter(reviews)

    def dispatch(agent, task, system_prompt, on_event):
        is_review = "REVIEW_VERDICT" in system_prompt
        if is_review:
            return AgentResult(ok=True, final_text=next(ri), events=[], returncode=0, seconds=0.1)
        # analyst: return the next canned report (cycling if reviews outlast reports)
        txt = reports[0]
        return AgentResult(ok=True, final_text=txt, events=[], returncode=0, seconds=0.1)

    return dispatch


# ----------------------------------------------------- 1. type-fidelity (P11 B1)

def test_type_fidelity_gate_blocks_fabricated_struct(tmp_path):
    """A report that declares a struct the binary never recovered is forced to
    NEEDS_WORK (closes the Part 11 'un-gated hallucination surface')."""
    facts = tmp_path / "facts"
    _make_facts(facts, symbols=["0x401000\tstruct\treal_config_t"])
    review = _fake_dispatch(
        reports=["I recovered struct user_settings { char name[32]; int uid; } used by main."],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1, claims_dir=str(facts)).run()
    # reviewer said SATISFIED but type-fidelity pillar catches the fabricated struct
    assert res.converged is False
    # the override reason is recorded in the run progress log
    progress = (ws.docs_dir / "progress.md").read_text()
    assert "type-fidelity" in progress


def test_type_fidelity_gate_passes_when_declared_type_recovered(tmp_path):
    """A report whose declared struct IS present in the recovered types passes."""
    facts = tmp_path / "facts"
    _make_facts(facts, symbols=["0x401000\tstruct\tuser_settings"])
    review = _fake_dispatch(
        reports=["main uses struct user_settings { char name[32]; int uid; }."],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1, claims_dir=str(facts)).run()
    assert res.converged is True


def test_type_fidelity_graceful_skip_without_facts(tmp_path):
    """No symbols.txt/types.txt -> pillar is a no-op, never a hard NEEDS_WORK."""
    review = _fake_dispatch(
        reports=["struct phantom { int x; };"],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1, claims_dir=str(tmp_path / "nofacts")).run()
    assert res.converged is True


# ----------------------------------------------------- 2. semantics tier (P13 B1)

def test_semantics_tier_recorded_in_meta(tmp_path):
    """High-level semantics claims are tiered by corroboration and recorded, but do
    NOT block convergence (semantics can be legitimately inferred)."""
    facts = tmp_path / "facts"
    # a real string token the report can anchor to (substring match), plus an import
    # so the capability pillar (triggered by "network") does not force NEEDS_WORK.
    _make_facts(facts, strings=["0x10\tconfig_blob", "0x20\tdecrypt_buffer"],
                symbols=["0x401000\tfunc\tmain"],
                types=[])  # imports.txt absent is fine; no capability keyword here
    review = _fake_dispatch(
        reports=["this function reads the config_blob and decrypts the decrypt_buffer"],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1, claims_dir=str(facts)).run()
    tiers = ws.meta.get("semantics_tiers", [])
    assert tiers, "semantics tier should be recorded"
    assert tiers[0]["tier"] in ("HIGH", "MEDIUM", "LOW")
    # does NOT block: reviewer SATISFIED + no contradictory pillar -> converges
    assert res.converged is True


def test_semantics_low_tier_when_unsupported(tmp_path):
    """A semantics claim with zero corroboration is recorded as LOW (hypothesis),
    never silently presented as fact."""
    facts = tmp_path / "facts"
    _make_facts(facts, strings=["0x10\ttotally unrelated string"],
                symbols=["0x401000\tfunc\tmain"])
    review = _fake_dispatch(
        reports=["this routine implements a custom blockchain consensus and a novel AI model"],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                    dispatch=review, analyst="claude", reviewer="claude",
                    max_rounds=1, claims_dir=str(facts)).run()
    tiers = ws.meta.get("semantics_tiers", [])
    assert tiers and tiers[0]["tier"] == "LOW"


# ----------------------------------------------------- 3. provenance (P12 B3)

def test_supervisor_surfaces_worker_contradictions(tmp_path):
    """Two workers assigning different purposes to the same address are surfaced as
    cross-worker contradictions (the RARE provenance defense), not silently merged."""
    ws = RunWorkspace.create(tmp_path / "sup", "fake")

    def dispatch(agent, task, system_prompt, on_event):
        if "SUPERVISOR" in (system_prompt or "").upper() or "PLAN" in task[:40].upper():
            # supervisor plan: one worker
            if "plan" in (task or "").lower() or "WORKER REPORTS" not in task:
                return AgentResult(ok=True, final_text='```plan\n'
                                    '{"coverage_complete": false, "workers": '
                                    '[{"id": "w1", "title": "crypto", '
                                    '"functions": ["0x1000"], "objective": "x"}]}\n```',
                                    events=[], returncode=0, seconds=0.1)
            # consolidate call
            return AgentResult(ok=True, final_text="consolidated report", events=[],
                               returncode=0, seconds=0.1)
        # workers
        if "w1" in (task or ""):
            return AgentResult(ok=True,
                               final_text="func@0x1000 is AES_encrypt (custom impl)",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(
            ok=True, final_text="report", events=[],
            returncode=0, seconds=0.1,
        )

    # We don't need a real second worker for the ledger test; drive _consolidate
    # directly with two contradictory worker reports.
    from src.agents.supervisor import WorkerOutcome, WorkerSpec

    sup = SupervisorLoop(binary="/bin/true", objective="x", overview="ov",
                         workspace=ws, dispatch=dispatch, max_supervisor_rounds=1,
                         max_worker_rounds=1)
    outcomes = [
        WorkerOutcome(spec=WorkerSpec(id="w1", title="crypto"),
                      converged=True, rounds=1,
                      report="func@0x1000 is AES_encrypt", workspace_root=""),
        WorkerOutcome(spec=WorkerSpec(id="w2", title="crypto2"),
                      converged=True, rounds=1,
                      report="func@0x1000 is DES_encrypt", workspace_root=""),
    ]
    final = sup._consolidate(outcomes)
    assert "0x1000" in final
    # ledger normalizes claim values to lowercase (see evidence_ledger._norm_claim)
    assert "aes_encrypt" in final and "des_encrypt" in final
    assert "CONTRADICTIONS" in final


# ----------------------------------------------------- 4. RE-core orchestrator (P14)

def test_re_analysis_runs_verification_completeness_passes(tmp_path):
    """The RE-core orchestrator (now wired into the worker loop) produces the
    coverage_tier and corpus_caveat passes —- honest coverage + corpus honesty (B3/B4)."""
    from src.analysis import re_analysis as rea

    code = tmp_path / "code"
    code.mkdir()
    (code / "strings.txt").write_text("0x10\thello\n")
    (code / "symbols.txt").write_text("0x401000\tfunc\tmain\n")
    (code / "functions.csv").write_text(
        "name,entry,size,signature\nmain,0x401000,128,\"int main(void)\"\n"
        "FUN_00401050,0x401050,6,\"\"\n")
    (code / "decompiled").mkdir()
    (code / "decompiled" / "main.c").write_text("int main(void){return 0;}\n")

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "ref.BinExport").write_text("x")  # count = 1 for caveat
    (corpus / "decompiled").mkdir()
    (corpus / "decompiled" / "known_main.c").write_text(
        "mov eax, 1\nxor edx, edx\ncall init\nret\n"
    )
    (corpus / "functions.csv").write_text(
        "name,entry,size,signature\nknown_main,0x401000,16,x\n"
    )

    out = rea.run_re_analysis(code, corpus_dirs=[corpus])
    assert "coverage_tier" in out["passes"]
    assert out["passes"]["coverage_tier"]["total"] == 2
    assert out["passes"]["coverage_tier"]["evalable_ratio"] > 0.0
    assert "corpus_caveat" in out["passes"]
    assert out["passes"]["corpus_caveat"]["corpus_size"] == 1


def test_re_analysis_evidence_ledger_on_worker_reports(tmp_path):
    """When worker reports are supplied, the evidence ledger (Part 3 / RARE defense)
    is computed and contradictions are surfaced."""
    from src.analysis import re_analysis as rea

    code = tmp_path / "code"
    code.mkdir()
    (code / "strings.txt").write_text("0x10\thi\n")
    (code / "symbols.txt").write_text("")

    out = rea.run_re_analysis(
        code,
        worker_reports=[("w1", "func@0x1000 is AES_encrypt"),
                        ("w2", "func@0x1000 is DES_encrypt")],
    )
    assert "evidence_ledger" in out["passes"]
    assert out["passes"]["evidence_ledger"]["contradictions"], \
        "worker disagreement on 0x1000 should be flagged"


# ----------------------------------------------------- 5. full gate, no facts

def test_loop_converges_without_any_facts_gracefully(tmp_path):
    """When no exported facts exist at all, every pillar is a no-op and the loop
    converges on reviewer SATISFIED (graceful-skip contract)."""
    review = _fake_dispatch(
        reports=["I analyzed the binary and found nothing suspicious."],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1).run()
    assert res.converged is True


def test_parse_verdict_conservative_without_explicit():
    assert parse_verdict("all good") == (False, "Reviewer emitted no explicit verdict; "
                                           "treating as unresolved.")
    assert parse_verdict("REVIEW_VERDICT: SATISFIED") == (True, "")
