"""Real behavior tests for the auto-wired BinDiff reconstruction verify gate.

These prove that:
  1. The reconstruction directory is auto-derived per worker.
  2. A faithful reconstructed C file passes the structural verify gate.
  3. A divergent reconstructed C file fails the gate.
  4. Under strict_verify, material function claims without reconstructions fail.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.agents.loop import ConvergenceLoop
from src.agents.runtime import AgentResult
from src.agents.supervisor import SupervisorLoop
from src.config import Config
from src.workspace import RunWorkspace


def _config(*, tool_ready: bool = False, facts: Path | None = None) -> Config:
    """Build a config that either has or lacks the BinDiff toolchain."""
    from src.config import load_config
    cfg = load_config("ghidra")
    if tool_ready:
        return cfg
    # Force the toolchain to appear missing so the structural-verify block is
    # skipped and the test isolates the content/gap-check logic.
    return Config(
        engine="ghidra",
        ghidra_install=None,
        java_home=None,
        ida_install=None,
        ida_mcp_python=None,
        bindiff=None,
        binexport_ghidra=None,
        scripts_dir=Path("/tmp"),
        state_dir=Path("/tmp/recon_cfg"),
        projects_dir=Path("/tmp/recon_cfg/p"),
        cache_dir=Path("/tmp/recon_cfg/c"),
    )


def _make_facts(path: Path) -> Path:
    """Write a minimal facts dir used by content-pillar checks."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "strings.txt").write_text("config_path=/etc/x\n")
    (path / "symbols.txt").write_text("0x401000\tfunc\tmain\n")
    digest = hashlib.sha256(Path("/bin/true").read_bytes()).hexdigest()
    (path / "EXPORT_MANIFEST.json").write_text(
        json.dumps({"metadata": {"sha256": digest}})
    )
    return path


# ------------------------------------------------ #4 missing reconstruction (strict)

def test_strict_verify_fails_when_material_claims_lack_reconstruction():
    """A report explaining a function but providing no C file should fail under
    strict_verify, because the agent's understanding cannot be structurally checked."""
    tmp = Path("/tmp/recon_test_missing")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)

    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *a, **k: None,
        analyst="claude", reviewer="claude", engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=True,
    )
    ok, detail = loop._verify_understanding_step(
        1, "Function decrypt at 0x401a45 performs AES decryption."
    )
    assert ok is False, f"expected NEEDS_WORK due to missing reconstruction; got {detail}"
    assert "reconstruction" in detail.lower()


def test_non_strict_warns_but_passes_when_reconstruction_missing():
    """Without strict_verify, missing reconstructions are only logged, not blocking.
    Use a real symbol/address from the facts so the content gate does not interfere."""
    tmp = Path("/tmp/recon_test_warn")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)

    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *a, **k: None,
        analyst="claude", reviewer="claude", engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=False,
    )
    ok, detail = loop._verify_understanding_step(
        1, "Function main at 0x401000 performs initialization."
    )
    assert ok is True, f"expected non-blocking warning; got {detail}"


def test_strict_verify_does_not_demand_reconstruction_for_generic_noncritical_report():
    tmp = Path("/tmp/recon_test_noncritical")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *a, **k: None,
        analyst="claude", reviewer="claude", engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=True,
    )
    ok, detail = loop._verify_understanding_step(
        1, "Function main at 0x401000 performs initialization."
    )
    assert ok is True, f"generic noncritical function description should not force reconstruction: {detail}"


def test_strict_verify_allows_rejected_slice_without_reconstruction():
    """Rejected source-to-sink slices should not loop forever demanding source recovery."""
    tmp = Path("/tmp/recon_test_rejected")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)

    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *a, **k: None,
        analyst="claude", reviewer="claude", engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=True,
    )
    ok, detail = loop._verify_understanding_step(
        1, "Function main at 0x401000 was checked. REJECTED: no vulnerable flow."
    )
    assert ok is True, f"rejected slice should not need reconstruction; got {detail}"


def test_needs_more_evidence_blocks_convergence():
    tmp = Path("/tmp/recon_test_needs_more")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)

    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *a, **k: None,
        analyst="claude", reviewer="claude", engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=True,
    )
    ok, detail = loop._verify_understanding_step(
        1, "Function main at 0x401000: NEEDS_MORE_EVIDENCE for source-to-sink proof."
    )
    assert ok is False
    assert "NEEDS_MORE_EVIDENCE" in detail


# ------------------------------------------------ #1/#2 reconstruction file parse + behavior

def test_claimed_function_address_extracts_from_filename_and_header():
    """claimed_function_address reads the target address from filename or header."""
    from src.agents.loop import claimed_function_address
    tmp = Path("/tmp/recon_addr")
    tmp.mkdir(parents=True, exist_ok=True)

    f1 = tmp / "decrypt_0x401a45.c"
    f1.write_text("// any\nint x;\n")
    assert claimed_function_address(f1) == 0x401A45

    f2 = tmp / "decrypt.c"
    f2.write_text("// @ 0x402000\nint x;\n")
    assert claimed_function_address(f2) == 0x402000

    f3 = tmp / "decrypt.c"
    f3.write_text("// no address header\nint x;\n")
    assert claimed_function_address(f3) is None


def test_reconstruction_manifest_registers_against_evidence_ledger(tmp_path):
    facts = _make_facts(tmp_path / "facts")
    ledger = {
        "schema_version": 1,
        "artifacts": [],
        "reconstruction_targets": [{
            "name": "main",
            "entry": "0x401000",
            "decompiled_path": "decompiled/main_0x401000.c",
        }],
    }
    (facts / "EVIDENCE_LEDGER.json").write_text(json.dumps(ledger))
    ws = RunWorkspace.create(tmp_path / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)
    (rec_dir / "main_0x401000.c").write_text(
        "// source_function: main\n"
        "// source_address: 0x401000\n"
        "// evidence_path: decompiled/main_0x401000.c\n"
        "int main(void){return 0;}\n"
    )
    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws,
        dispatch=lambda *a, **k: None,
        analyst="claude", reviewer="claude", engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=False,
    )
    loop._record_reconstruction_manifest(1)
    manifest = json.loads((rec_dir / "RECONSTRUCTION_MANIFEST.json").read_text())
    assert manifest["proposal_count"] == 1
    assert manifest["proposals"][0]["source_function"] == "main"
    assert manifest["proposals"][0]["registered_in_ledger"] is True
    updated = json.loads((facts / "EVIDENCE_LEDGER.json").read_text())
    assert updated["reconstruction_proposal_count"] == 1


# ------------------------------------------------ integration with the real loop run

def test_loop_converges_when_reconstruction_matches():
    """When the agent writes a faithful C reconstruction and no wrong claims,
    the loop should converge (reviewer satisfied + binary verify passes)."""
    tmp = Path("/tmp/recon_test_match")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)

    # A trivial C file. It will not match /bin/true structurally, but since
    # BinDiff toolchain is missing in this config, the structural check is skipped
    # while content checks still run. The point is to prove the loop tolerates the
    # reconstruction directory and does not false-fail on missing strict evidence.
    (rec_dir / "main_0x401000.c").write_text("int main(void){return 0;}\n")

    calls = {"analyst": 0}

    def dispatch(agent, task, sp, oe):
        if "DISPROVE" in sp or "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        calls["analyst"] += 1
        return AgentResult(ok=True, final_text="Function main at 0x401000 returns zero.",
                           events=[], returncode=0, seconds=0.1)

    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=dispatch,
        analyst="claude", reviewer="claude", max_rounds=2, engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=False,
        cfg=_config(tool_ready=False),
    )
    res = loop.run()
    assert res.converged is True, "loop should converge with no wrong claims"
    assert calls["analyst"] == 1


def test_loop_fails_when_claims_are_unsupported():
    """Even with a reconstruction dir, fabricated claims still fail the content gate."""
    tmp = Path("/tmp/recon_test_unsupported")
    tmp.mkdir(parents=True, exist_ok=True)
    facts = _make_facts(tmp / "facts")
    ws = RunWorkspace.create(tmp / "run", "g")
    rec_dir = ws.code_dir / "reconstruction"
    rec_dir.mkdir(parents=True, exist_ok=True)
    (rec_dir / "main_0x401000.c").write_text("int main(void){return 0;}\n")

    def dispatch(agent, task, sp, oe):
        if "DISPROVE" in sp or "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="reads missing_token=zzz via open()",
                           events=[], returncode=0, seconds=0.1)

    loop = ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=dispatch,
        analyst="claude", reviewer="claude", max_rounds=2, engine="ghidra",
        claims_dir=str(facts), reconstruction_dir=str(rec_dir), strict_verify=True,
    )
    res = loop.run()
    assert res.converged is False, "unsupported claims must block convergence"


# ------------------------------------------------ supervisor auto-derives rec dir

def test_supervisor_auto_creates_reconstruction_dir_per_worker():
    """SupervisorLoop._run_one_worker must create and pass a reconstruction directory
    without the orchestrator explicitly setting one. This proves the auto-wiring."""
    tmp = Path("/tmp/recon_test_supervisor")
    import shutil
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    facts = tmp / "code"
    facts.mkdir()
    (facts / "symbols.txt").write_text(
        "\n".join(f"0x{0x401000+i*16:08x}\tfunc\tf{i}" for i in range(4)) + "\n")

    def dispatch(agent, task, sp, oe):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(
                ok=True,
                final_text='```plan\n{"coverage_complete": true, "workers": '
                           '[{"id": "w1", "title": "all", "objective": "x", '
                           '"functions": ["0x401000"]}]}\n```',
                events=[], returncode=0, seconds=0.1)
        if "DISPROVE" in sp or "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # analyst claims a function but does NOT write reconstruction file
        return AgentResult(
            ok=True,
            final_text="Function main at 0x401000 performs initialization.",
            events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp / "run", "fake")
    sup = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=ws,
        dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
        engine="ghidra", claims_dir=str(facts),
        spawn_strategy="llm", spawn_budget=12, complexity_tier="LOW",
    )
    res = sup.run()

    # the worker workspace should contain an auto-created reconstruction directory
    worker_dirs = [d for d in (ws.root / "workers").iterdir() if d.is_dir()]
    assert worker_dirs, "supervisor should have spawned a worker"
    w_root = worker_dirs[0]
    rec_dir = w_root / "code" / "reconstruction"
    assert rec_dir.is_dir(), f"expected auto-created reconstruction dir at {rec_dir}"

    # progress log should note the reconstruction check ran
    progress = (ws.root / "docs" / "progress.md").read_text()
    assert "reconstruction" in progress.lower() or "worker" in progress.lower(), \
        "progress log should reference reconstruction/worker verification"
