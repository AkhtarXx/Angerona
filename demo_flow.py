"""End-to-end DEMO of the real Angerona agent flow (no LLM/engine needed).

Uses the ACTUAL ConvergenceLoop + BinDiff-backed verify gate + Part 18 upgrades,
driven by a fake dispatcher that emits scripted analyst/reviewer text. This shows
the real code path: analyst -> agnostic reviewer -> BinDiff verify gate -> (optional)
Reflexion lesson + K-candidate + adversarial reviewer -> converge.

Run: .venv/bin/python demo_flow.py
"""

from __future__ import annotations

from pathlib import Path

from src.agents.loop import ConvergenceLoop
from src.agents.runtime import AgentResult
from src.workspace import RunWorkspace


def main() -> None:
    tmp = Path("/tmp/angerona_demo")
    if tmp.exists():
        import shutil
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    # ---- facts the binary "exported" (this is what BinDiff/verify checks against) ----
    facts = tmp / "facts"
    facts.mkdir()
    (facts / "strings.txt").write_text("config_path=/etc/x\nC2_server=1.2.3.4\n")
    (facts / "symbols.txt").write_text("0x401000\tfunc\tmain\n0x401a45\tfunc\taes_encrypt\n")
    # imports so capability-verify (e.g. network/C2) has something to corroborate
    (facts / "imports.txt").write_text("socket\nconnect\naes_encrypt\n")

    # ---- scripted agent behaviour ----
    # Round 1: analyst MISSES a cited string -> BinDiff claims check FAILS.
    # Round 2: analyst cites a real string -> BinDiff passes -> converged.
    seen = {"analyst": 0}

    def dispatch(agent: str, task: str, system_prompt: str, on_event):
        # adversarial reviewer pass
        if "DISPROVE" in system_prompt:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # friendly reviewer pass
        if "REVIEW_VERDICT" in system_prompt:
            # round 1: analyst forgot to cite the real C2 string -> gaps
            if seen["analyst"] == 1:
                return AgentResult(ok=True,
                                   final_text="## Gaps to address\n- cite the C2 string "
                                              "from the binary\nREVIEW_VERDICT: NEEDS_WORK",
                                   events=[], returncode=0, seconds=0.1)
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # analyst pass
        seen["analyst"] += 1
        if seen["analyst"] == 1:
            # BAD: claims a string NOT in the binary -> BinDiff claims gate will fail
            return AgentResult(ok=True,
                               final_text="reads nonexistent_setting=xyz and C2_server=1.2.3.4",
                               events=[], returncode=0, seconds=0.1)
        # GOOD: cites the real C2 string -> BinDiff claims gate passes
        return AgentResult(ok=True,
                           final_text="reads C2_server=1.2.3.4 and config_path=/etc/x",
                           events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp / "run", "demo")
    print("=" * 70)
    print("ANGERONA FLOW DEMO — binary given, real BinDiff verify gate active")
    print("=" * 70)
    loop = ConvergenceLoop(
        binary="/bin/true", objective="analyse the malware", workspace=ws,
        dispatch=dispatch, max_rounds=3, claims_dir=str(facts),
        # Part 18 upgrades ON:
        k_candidates=1, adversarial_review=True,
    )
    result = loop.run()
    print("-" * 70)
    print(f"CONVERGED: {result.converged}  (rounds={result.rounds})")
    print("-" * 70)
    print("What the run produced (real files on disk):")
    for p in sorted((ws.root).rglob("*")):
        if p.is_file():
            rel = p.relative_to(ws.root)
            print(f"  {rel}")
    print("-" * 70)
    print("Progress log (the actual decision trail):")
    print((ws.docs_dir / "progress.md").read_text())
    print("-" * 70)
    print("BinDiff verify gate result (from progress log above):")
    print("  -> if you see 'claim-verify: UNSUPPORTED claims -> NEEDS_WORK' then the")
    print("     binary (not the LLM) rejected round 1. That is the BinDiff gate.")


if __name__ == "__main__":
    main()
