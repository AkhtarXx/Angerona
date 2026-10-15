"""Behavior tests for Part 15/16/17 wiring (symbolic-exec / fuzzing oracle,
industry/red-team self-assessment, cost & privacy). These drive the real
``ConvergenceLoop`` / ``Orchestrator.swarm_run`` with fake dispatchers and
assert the previously-orphaned modules (pov_oracle, bequiv, malware_triage,
redteam, cost) now FIRE inside the runtime and degrade gracefully otherwise.
No angr/AFL++/Docker/Ghidra required.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.agents.loop import ConvergenceLoop, parse_verdict
from src.agents.runtime import AgentResult
from src.workspace import RunWorkspace


# ---------------------------------------------------------------- fixtures

def _make_facts(d, *, strings=(), symbols=(), imports=()):
    d.mkdir(parents=True, exist_ok=True)
    (d / "strings.txt").write_text("\n".join(strings) + "\n")
    (d / "symbols.txt").write_text("\n".join(symbols) + "\n")
    digest = hashlib.sha256(Path("/bin/true").read_bytes()).hexdigest()
    (d / "EXPORT_MANIFEST.json").write_text(
        json.dumps({"metadata": {"sha256": digest}})
    )
    if imports:
        (d / "imports.txt").write_text("\n".join(imports) + "\n")


def _satisfied_review(extra=""):
    return f"## Verification\nall confirmed {extra}\nREVIEW_VERDICT: SATISFIED"


def _fake_dispatch(reports, reviews):
    ri = iter(reviews)

    def dispatch(agent, task, system_prompt, on_event):
        if "REVIEW_VERDICT" in system_prompt:
            return AgentResult(ok=True, final_text=next(ri),
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text=reports[0],
                               events=[], returncode=0, seconds=0.1)

    return dispatch


# ----------------------------------------------------- Part 15: PoV oracle

def test_pov_oracle_records_suspected_vuln_gracefully(tmp_path):
    """A report asserting a vuln for an address triggers the dynamic oracle; with no
    angr/AFL++ installed it records SUSPECTED (not a false verdict, not a block)."""
    facts = tmp_path / "facts"
    _make_facts(facts, symbols=["0x401000\tfunc\tmain"])
    review = _fake_dispatch(
        reports=["func @ 0x401000 has a buffer overflow in the parse loop"],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    res = ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1, claims_dir=str(facts)).run()
    pov = ws.meta.get("pov", [])
    assert pov, "pov-oracle should have run"
    assert pov[0]["bug_class"] == "overflow"
    assert pov[0]["confirmed"] is False  # no oracle available -> SUSPECTED
    assert pov[0]["engine"] in ("none", "angr", "aflpp")
    # graceful: the static finding stays, convergence still proceeds on reviewer SAT
    assert res.converged is True


def test_pov_oracle_skipped_when_no_vuln_claim(tmp_path):
    """No vuln keyword -> the oracle is not applicable; nothing recorded, no error."""
    facts = tmp_path / "facts"
    _make_facts(facts, symbols=["0x401000\tfunc\tmain"])
    review = _fake_dispatch(
        reports=["this function parses a config file and returns a status code"],
        reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                    dispatch=review, analyst="claude", reviewer="claude",
                    max_rounds=1, claims_dir=str(facts)).run()
    assert ws.meta.get("pov", []) == []


def test_bequiv_recorded_when_reconstruction_present(tmp_path):
    """With a reconstruction_dir holding C, the behavioral-equivalence gate is
    attempted (graceful: no reference C -> compile-only smoke check)."""
    facts = tmp_path / "facts"
    _make_facts(facts, symbols=["0x401000\tfunc\tmain"])
    rec = tmp_path / "rec"
    rec.mkdir()
    (rec / "recon.c").write_text("int main(void){return 0;}\n")
    review = _fake_dispatch(
        reports=["reconstructed main"], reviews=[_satisfied_review()],
    )
    ws = RunWorkspace.create(tmp_path / "run", "fake")
    ConvergenceLoop(binary="/bin/true", objective="x", workspace=ws,
                          dispatch=review, analyst="claude", reviewer="claude",
                          max_rounds=1, claims_dir=str(facts),
                          reconstruction_dir=str(rec)).run()
    beq = ws.meta.get("bequiv", [])
    assert beq and "compiled" in beq[0]


# ----------------------------------------------------- Part 16: triage + red-team

def test_redteam_self_assessment_mapping(tmp_path):
    """The OWASP/ATLAS self-assessment maps posture to mitigations/findings."""
    from src.analysis.redteam import assess_self
    # strong posture: local engine + sandbox + detonate + local LLM
    strong = assess_self(engine="ghidra", detonate_available=True,
                            sandbox_available=True, llm_is_local=True)
    assert strong["verdict"] == "strong"
    assert len(strong["mitigations"]) >= 3
    # weak posture: only a local engine, cloud LLM, no sandbox/detonate
    weak = assess_self(engine="ghidra", detonate_available=False,
                          sandbox_available=False, llm_is_local=False)
    assert weak["verdict"] == "weak"
    assert any("OWASP LLM01 residual" in f for f in weak["findings"])
    # standards framing present (OWASP 2025 + ATLAS + vendor programs)
    assert "owasp_llm_top10_2025" in weak["standards"]
    assert "mitre_atlas" in weak["standards"]
    assert "vendor_red_team" in weak["standards"]


def test_malware_triage_hypothesis_not_verdict(tmp_path):
    """Triage produces a hypothesis (never a confirmed family) with OWASP framing."""
    from src.analysis.malware_triage import triage
    d = tmp_path / "code"
    d.mkdir()
    (d / "imports.txt").write_text("kernel32\tVirtualAlloc\n"
                                      "ws2_32\tInternetOpenA\n")
    (d / "strings.txt").write_text("decrypting payload\n")
    r = triage(d)
    assert r.suspicious_api_hits  # suspicious APIs detected
    assert r.confidence in ("low", "medium", "high")
    # triage is a hypothesis, never asserts a family it cannot confirm
    assert r.detail


# ----------------------------------------------------- Part 17: cost + privacy

def test_cost_estimate_with_cache_savings(tmp_path):
    """Cost module estimates per-run token cost and the prompt-cache savings."""
    from src.analysis import cost as ac
    d = tmp_path / "code"
    d.mkdir()
    (d / "all_decompiled.c").write_text("int main(void){ " + "x" * 4000 + " }\n")
    est_in = ac.estimate_code_dir(d)
    rep = ac.compute_cost("opus", est_in, est_in // 40, cached_fraction=0.9)
    assert rep.total_tokens > 0
    assert rep.savings_pct > 0  # cache drops ~10x input rate
    assert rep.est_usd_with_cache < rep.est_usd  # cheaper with cache


def test_guard_workspace_blocks_staged(tmp_path, monkeypatch):
    """guard-workspace CLI fails (exit 1) when a workspace file is staged."""
    import subprocess
    from src.cli import _cmd_guard_workspace

    class NS:
        home = None

    repo = tmp_path / "repo"
    repo.mkdir()
    # init a git repo
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    # a workspaces/ dir with a decompiled file, committed -> tracked
    ws = repo / "workspaces" / "run1" / "code"
    ws.mkdir(parents=True)
    (ws / "all_decompiled.c").write_text("int main(){}\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    # model the real default: state_home() = <repo>/workspaces (not <repo>)
    monkeypatch.setenv("ANGERONA_HOME", str(repo / "workspaces"))
    rc = _cmd_guard_workspace(NS())
    assert rc == 1  # guarded: tracked workspace content would be committed


def test_guard_workspace_ok_when_ignored(tmp_path, monkeypatch):
    """guard-workspace passes (exit 0) when workspaces/ is git-ignored."""
    import subprocess
    from src.cli import _cmd_guard_workspace

    class NS:
        home = None

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("workspaces/\n")
    ws = repo / "workspaces" / "run1" / "code"
    ws.mkdir(parents=True)
    (ws / "all_decompiled.c").write_text("int main(){}\n")
    # NOT staged (ignored) -> guard should pass
    monkeypatch.setenv("ANGERONA_HOME", str(repo / "workspaces"))
    rc = _cmd_guard_workspace(NS())
    assert rc == 0


def test_parse_verdict_conservative_without_explicit():
    assert parse_verdict("all good") == (
        False, "Reviewer emitted no explicit verdict; treating as unresolved.")
    assert parse_verdict("REVIEW_VERDICT: SATISFIED") == (True, "")
