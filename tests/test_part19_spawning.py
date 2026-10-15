"""Behavior tests for Part 19 multi-agent spawning improvements (U1-U7).

These drive the REAL SupervisorLoop + ConvergenceLoop with a fake dispatcher and
assert the spawning DECISIONS (search, routing, DAG waves, blackboard, adaptive
re-spawn, budget, parallelism) actually happen in the live flow -- not unit mocks.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.agents.supervisor import SupervisorLoop
from src.agents.loop import ConvergenceLoop, attest_isolation_capable_dispatch
from src.agents.spawn_plan import (
    search_spawn_plans, score_split, order_by_dependencies,
    global_candidate_budget, adaptive_parallelism, route_agent, SliceDifficulty,
)
from src.agents.runtime import AgentResult
from src.workspace import RunWorkspace


def test_cli_defaults_cheap_agent_to_selected_agent():
    from src.cli import build_parser

    ns = build_parser().parse_args(["full-re", "/tmp/sample.bin", "--agent", "claude"])
    assert ns.agent == "claude"
    assert ns.cheap_agent is None


# ----------------------------------------------------------- U1: spawn search (pure)

def test_spawn_search_prefers_obf_isolation():
    base = [
        {"id": "w1", "title": "all", "functions": ["0x1", "0x2", "0x3", "obf_0x9"]},
    ]
    best, score = search_spawn_plans(base, n_functions=4, n_obf=1, k=4, max_parallel=3)
    # the variant that isolates obf_0x9 into its own unit should win or tie
    obf_units = [s for s in best if s.get("obf_focus")]
    assert obf_units, "spawn search should isolate the obfuscated function"
    assert [s["functions"] for s in obf_units] == [["obf_0x9"]]
    assert all("obf_0x9" not in s["functions"] for s in best if not s.get("obf_focus"))
    # score is deterministic and in [0,1]
    assert 0.0 <= score <= 1.0


def test_spawn_search_splits_large_unit():
    base = [{"id": "w1", "title": "big", "functions": [f"0x{i}" for i in range(10)]}]
    best, _ = search_spawn_plans(base, n_functions=10, n_obf=0, k=4, max_parallel=3)
    # base has 1 unit; split variant should produce >=2
    assert len(best) >= 2


def test_spawn_search_scores_security_slice_without_function_list():
    base = [
        {
            "id": "slice_1",
            "title": "CPI security slice",
            "focus": "source-to-sink path",
            "objective": "Validate the machine-built security slice",
            "slice_id": "solana_cpi_001",
            "functions": [],
        }
    ]
    best, score = search_spawn_plans(base, n_functions=1050, n_obf=0, k=4, max_parallel=3)
    assert best[0]["id"] == "slice_1"
    assert score > 0.0


# ----------------------------------------------------------- U4: routing (pure)

def test_route_agent_picks_strong_for_obf():
    diff = SliceDifficulty(obf_functions=2, uncertainty_tier="MEDIUM")
    assert route_agent({"obf_focus": True}, diff, strong_agent="claude", cheap_agent="codex") == "claude"


def test_route_agent_picks_cheap_for_clean():
    diff = SliceDifficulty(obf_functions=0, uncertainty_tier="HIGH")
    assert route_agent({"obf_focus": False}, diff, strong_agent="claude", cheap_agent="codex") == "codex"


# ----------------------------------------------------------- U5: DAG (pure)

def test_order_by_dependencies_respects_edges():
    specs = [
        {"id": "w2", "depends_on": ["w1"]},
        {"id": "w1", "depends_on": []},
        {"id": "w3", "depends_on": ["w2"]},
    ]
    waves = order_by_dependencies(specs)
    flat = [s["id"] for wave in waves for s in wave]
    assert flat.index("w1") < flat.index("w2") < flat.index("w3")


# ----------------------------------------------------------- U6/U7: budget/parallel (pure)

def test_global_budget_concentrates_on_hard_slices():
    specs = [{"id": "a"}, {"id": "b"}]
    def diff_of(d):
        return SliceDifficulty(obf_functions=5 if d["id"] == "a" else 0)
    alloc = global_candidate_budget(specs, base_k=1, total_budget=10, difficulty_of=diff_of)
    assert alloc["a"] > alloc["b"]  # hard slice gets more candidates


def test_global_budget_rejects_seed_exceeding_total_budget():
    # 64 planned workers vs a budget of 12: seeding every worker with base_k=1
    # would already exceed total_budget, so the bounds must be rejected rather
    # than silently returning a 64-slot allocation (docstring: sum <= total_budget).
    specs = [{"id": f"w{i}"} for i in range(64)]
    with pytest.raises(ValueError):
        global_candidate_budget(specs, base_k=1, total_budget=12)


def test_adaptive_parallelism_scales_with_tier():
    assert adaptive_parallelism(complexity_tier="HIGH", max_parallel=6) == 6
    assert adaptive_parallelism(complexity_tier="LOW", max_parallel=6) == 1


# ----------------------------------------------------------- REAL FLOW: U1+U4+U5+U2+U3

def _facts_dir(tmp):
    code = tmp / "code"
    code.mkdir()
    binary = Path("/bin/true")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (code / "symbols.txt").write_text(
        "\n".join(f"0x{0x401000 + i*16:08x}\tfunc\tf{i}" for i in range(6)) + "\n")
    (code / "strings.txt").write_text("0x402000\tknown_setting=ok\n")
    (code / "EXPORT_MANIFEST.json").write_text(
        json.dumps({"metadata": {"sha256": digest}})
    )
    (code / "obfuscation.json").write_text(json.dumps({
        "flagged": [{"name": "f0", "function": "0x401000"}]}))
    return code


def _supervisor_dispatch(seen):
    """Fake dispatcher: supervisor plans 1 unit; workers converge after 1 round;
    we force one worker to FAIL so U3 (adaptive re-spawn) triggers."""
    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(ok=True, final_text='```plan\n{"coverage_complete": true, '
                               '"workers": [{"id": "w1", "title": "all", '
                               '"objective": "x", "functions": ["0x401000","0x401010",'
                               '"0x401020","0x401030"]}]}\n```',
                               events=[], returncode=0, seconds=0.1)
        if "DISPROVE" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        if "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # analyst: make the FIRST worker fail convergence by emitting a bad claim
        return AgentResult(ok=True,
                           final_text="reads 'nonexistent_setting=xyz' for the slice",
                           events=[], returncode=0, seconds=0.1)
    return attest_isolation_capable_dispatch(dispatch)


def test_full_flow_spawn_search_routing_dag_blackboard_respawn(tmp_path):
    code = _facts_dir(tmp_path)
    dispatch = _supervisor_dispatch(None)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    sup = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=ws,
        dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
        engine="ida", claims_dir=str(code),
        spawn_strategy="search", search_k=4, cheap_agent="codex",
        spawn_budget=12, complexity_tier="HIGH",
        k_candidates=1, adversarial_review=True,
    )
    result = sup.run()

    # U1: spawn search ran and logged
    assert "spawn_search" in ws.meta
    # U4: routing happened (workers got an agent assigned)
    agents = {w["agent"] for w in ws.meta["swarm"]["workers"]}
    assert agents  # at least one agent assigned
    # U2: blackboard was written with shared findings
    assert (ws.root / "blackboard.md").is_file()
    assert "Shared blackboard" in (ws.root / "blackboard.md").read_text()
    # U5: executed in >=1 wave (implicitly via run completing)
    assert result.final_report
    # the run produced worker outcomes
    assert ws.meta["swarm"]["workers"]


def test_worker_dispatch_uses_isolated_worker_code_dir(tmp_path):
    parent_ws = RunWorkspace.create(tmp_path / "run", "fake")
    (parent_ws.code_dir / "all_decompiled.c").write_text("int main(void){return 0;}\n")
    (parent_ws.raw_dir / "solana_utilities").mkdir(parents=True, exist_ok=True)
    (parent_ws.raw_dir / "solana_utilities.json").write_text('{"model":"solana_utility_evidence"}')
    (parent_ws.raw_dir / "solana_fusion.json").write_text('{"primary":"ida"}')
    (parent_ws.raw_dir / "solana_utilities" / "llvm-objdump.stdout.txt").write_text("disasm")
    seen_worker_cwds: list[Path] = []
    seen_worker_scopes: list[dict] = []

    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(
                ok=True,
                final_text='```plan\n{"coverage_complete": false, "workers": '
                           '[{"id": "w1", "title": "all", "objective": "x", '
                           '"functions": ["0x401000"]}]}\n```',
                events=[], returncode=0, seconds=0.1)
        if cwd:
            worker_cwd = Path(cwd)
            seen_worker_cwds.append(worker_cwd)
            assert (worker_cwd / "all_decompiled.c").is_file()
            assert (worker_cwd.parent / "raw" / "solana_utilities.json").is_file()
            assert (worker_cwd.parent / "raw" / "solana_fusion.json").is_file()
            assert (
                worker_cwd.parent / "raw" / "solana_utilities" /
                "llvm-objdump.stdout.txt"
            ).read_text() == "disasm"
            assert (worker_cwd / "RUN_SCOPE.json").is_file()
            seen_worker_scopes.append(
                json.loads((worker_cwd / "RUN_SCOPE.json").read_text())
            )
        if "DISPROVE" in sp or "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="Function 0x401000 is present.",
                           events=[], returncode=0, seconds=0.1)

    attest_isolation_capable_dispatch(dispatch)
    sup = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=parent_ws,
        dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
        engine="ida", spawn_strategy="llm", k_candidates=1,
    )
    sup.run()
    assert seen_worker_cwds
    assert all(cwd != parent_ws.code_dir for cwd in seen_worker_cwds)
    for cwd, scope in zip(seen_worker_cwds, seen_worker_scopes, strict=True):
        assert scope["allowed_roots"] == [str(cwd), str(cwd.parent)]
        assert "old workspaces/runs entries are archives" in scope["old_runs_policy"]
        if "candidates" in cwd.parts:
            assert "do not read sibling candidates" in scope["policy"]
            assert not cwd.exists()
        else:
            assert scope["raw_copied_from"] == [str(parent_ws.raw_dir)]
            assert "do not read sibling worker outputs" in scope["policy"]


def test_worker_verification_uses_local_export_not_parent_shared_dir(tmp_path):
    parent_ws = RunWorkspace.create(tmp_path / "run", "fake")
    (parent_ws.code_dir / "strings.txt").write_text("0x402000\tknown_setting=ok\n")
    (parent_ws.code_dir / "symbols.txt").write_text("")
    (parent_ws.code_dir / "imports.txt").write_text("")
    (parent_ws.code_dir / "all_decompiled.c").write_text("int main(void){return 0;}\n")

    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(
                ok=True,
                final_text='```plan\n{"coverage_complete": false, "workers": '
                           '[{"id": "w1", "title": "settings", "objective": "x", '
                           '"functions": []}]}\n```',
                events=[], returncode=0, seconds=0.1)
        if "DISPROVE" in sp or "REVIEW_VERDICT" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # If verification later used the parent/shared directory, this removal
        # would hide the fact files. The worker-local copy must keep working.
        (parent_ws.code_dir / "strings.txt").unlink(missing_ok=True)
        return AgentResult(ok=True, final_text="Binary evidence observed `known_setting=ok`.",
                           events=[], returncode=0, seconds=0.1)

    attest_isolation_capable_dispatch(dispatch)
    sup = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=parent_ws,
        dispatch=dispatch, max_supervisor_rounds=1, max_worker_rounds=1,
        engine="ida", spawn_strategy="llm", k_candidates=1,
        strict_verify=False,
    )
    sup.run()
    worker_dirs = [d for d in (parent_ws.root / "workers").iterdir() if d.is_dir()]
    assert worker_dirs
    progress = "\n".join((d / "docs" / "progress.md").read_text() for d in worker_dirs)
    assert "export fact-verify:" in progress
    assert "BinDiff claim-verify" not in progress


def test_k_candidates_get_isolated_code_dirs(tmp_path):
    ws = RunWorkspace.create(tmp_path / "loop", "fake")
    (ws.code_dir / "all_decompiled.c").write_text("int target(void){return 7;}\n")
    seen_candidate_cwds: list[Path] = []
    seen_candidate_scopes: list[dict] = []

    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        if cwd and "REVIEW_VERDICT" not in sp and "DISPROVE" not in sp:
            candidate_cwd = Path(cwd)
            seen_candidate_cwds.append(candidate_cwd)
            assert (candidate_cwd / "all_decompiled.c").is_file()
            assert (candidate_cwd / "RUN_SCOPE.json").is_file()
            seen_candidate_scopes.append(
                json.loads((candidate_cwd / "RUN_SCOPE.json").read_text())
            )
        if "REVIEW_VERDICT" in sp or "DISPROVE" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="Function 0x401000 is present.",
                           events=[], returncode=0, seconds=0.1)

    attest_isolation_capable_dispatch(dispatch)
    ConvergenceLoop(
        binary="/bin/true", objective="x", workspace=ws, dispatch=dispatch,
        analyst="claude", reviewer="claude", max_rounds=1, engine="ida",
        k_candidates=2,
    ).run()
    assert len(seen_candidate_cwds) == 2
    assert len(set(seen_candidate_cwds)) == 2
    for cwd, scope in zip(seen_candidate_cwds, seen_candidate_scopes, strict=True):
        assert scope["allowed_roots"] == [str(cwd), str(cwd.parent)]
        assert "old workspaces/runs entries are archives" in scope["old_runs_policy"]
        assert "do not read sibling candidates" in scope["policy"]
        assert not cwd.exists()  # non-authoritative scratch is not checkpointed


def test_adaptive_respawn_replans_failed_slice(tmp_path):
    """Force a worker to NOT converge; supervisor must re-plan that slice (U3)."""
    code = _facts_dir(tmp_path)

    def dispatch(agent, task, sp, oe, cwd=None, **_kwargs):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(ok=True, final_text='```plan\n{"coverage_complete": false, '
                               '"workers": [{"id": "w1", "title": "all", "objective": "x", '
                               '"functions": ["0x401000","0x401010","0x401020","0x401030"]}]}\n```',
                               events=[], returncode=0, seconds=0.1)
        if "REVIEW_VERDICT" in sp or "DISPROVE" in sp:
            # friendly + adversarial both SATISFIED -> but the claims gate fails
            # because the report cites a non-existent string
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        # analyst cites a string NOT in the binary -> BinDiff gate forces NEEDS_WORK
        return AgentResult(ok=True, final_text="reads 'nonexistent_setting=xyz'",
                           events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    attest_isolation_capable_dispatch(dispatch)
    sup = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=ws,
        dispatch=dispatch, max_supervisor_rounds=2, max_worker_rounds=1,
        engine="ida", claims_dir=str(code),
        spawn_strategy="search", search_k=2, cheap_agent="codex",
        spawn_budget=12, complexity_tier="MEDIUM", k_candidates=1,
    )
    sup.run()
    # U3: a non-converged worker must have triggered a re-spawn (new _r1/_r2 ids)
    ids = [w["id"] for w in ws.meta["swarm"]["workers"]]
    assert any("_r1" in i or "_r2" in i for i in ids), \
        f"adaptive re-spawn should create re-planned slices; got {ids}"
    assert "adaptive re-spawn" in (ws.docs_dir / "progress.md").read_text()


def test_adaptive_respawn_does_not_retry_historical_failures_each_round(tmp_path):
    code = _facts_dir(tmp_path)

    def dispatch(agent, task, sp, oe):
        if "WORK UNITS" in task or "plan" in sp.lower():
            return AgentResult(ok=True, final_text='```plan\n{"coverage_complete": false, '
                               '"workers": [{"id": "w1", "title": "all", "objective": "x", '
                               '"functions": ["0x401000","0x401010"]}]}\n```',
                               events=[], returncode=0, seconds=0.1)
        if "REVIEW_VERDICT" in sp or "DISPROVE" in sp:
            return AgentResult(ok=True, final_text="REVIEW_VERDICT: SATISFIED",
                               events=[], returncode=0, seconds=0.1)
        return AgentResult(ok=True, final_text="reads 'nonexistent_setting=xyz'",
                           events=[], returncode=0, seconds=0.1)

    ws = RunWorkspace.create(tmp_path / "run", "fake")
    sup = SupervisorLoop(
        binary="/bin/true", objective="x", overview="ov", workspace=ws,
        dispatch=dispatch, max_supervisor_rounds=2, max_worker_rounds=1,
        engine="ida", claims_dir=str(code), spawn_strategy="llm",
        k_candidates=1,
    )
    sup.run()
    ids = [w["id"] for w in ws.meta["swarm"]["workers"]]
    # Historical failed workers should not be re-expanded on round 2 into
    # w1_r1_r1 / w1_r2_r1 style runaway retry trees.
    assert not any(i.count("_r") >= 2 for i in ids), ids
    # Topology auto-discovery may add one independent fallback worker (wob1);
    # that is allowed. What must not happen is recursive retry-tree growth.
    assert len(ids) <= 5, ids


def test_slice_worker_materializes_only_declared_inputs(tmp_path: Path) -> None:
    from src.agents.supervisor import WorkerSpec
    from src.config import load_config

    parent_ws = RunWorkspace.create(tmp_path / "parent", "parent")
    allowed = parent_ws.code_dir / "android_artifacts" / "evidence" / "allowed.txt"
    unrelated = parent_ws.code_dir / "android_artifacts" / "evidence" / "unrelated.txt"
    allowed.parent.mkdir(parents=True, exist_ok=True)
    allowed.write_text("allowed\n", encoding="utf-8")
    unrelated.write_text("unrelated\n", encoding="utf-8")
    for name in (
        "ANGERONA_EVIDENCE_READ.py",
        "ANGERONA_FINDING_ADJUDICATE.py",
        "ANDROID_TARGET_OVERVIEW.json",
    ):
        (parent_ws.code_dir / name).write_text("{}\n", encoding="utf-8")

    slices = {
        "schema_version": 1,
        "slices": [
            {
                "slice_id": "android-files-01",
                "ai_scope": {
                    "allowed_inputs": ["android_artifacts/evidence/allowed.txt"]
                },
            },
            {
                "slice_id": "android-files-02",
                "ai_scope": {
                    "allowed_inputs": ["android_artifacts/evidence/unrelated.txt"]
                },
            },
        ],
    }
    (parent_ws.raw_dir / "security_slices.json").write_text(
        json.dumps(slices), encoding="utf-8"
    )
    supervisor = SupervisorLoop(
        binary="/bin/true",
        objective="x",
        overview="ov",
        workspace=parent_ws,
        dispatch=lambda _agent, _task, _sp, _oe: AgentResult(
            ok=True, final_text="unused", events=[], returncode=0, seconds=0.1
        ),
        spawn_strategy="slices", engine="android", cfg=load_config("ghidra"),
        k_candidates=1,
    )
    supervisor._security_slices = slices
    worker_ws = RunWorkspace.create(tmp_path / "worker", "worker")
    spec = WorkerSpec(
        id="sec_android_files_01",
        title="Android files 01",
        slice_id="android-files-01",
    )

    supervisor._prepare_worker_code_dir(worker_ws, spec)

    assert (worker_ws.code_dir / "android_artifacts/evidence/allowed.txt").is_file()
    assert not (worker_ws.code_dir / "android_artifacts/evidence/unrelated.txt").exists()
    assert (worker_ws.code_dir / "ANGERONA_EVIDENCE_READ.py").is_file()
    assert (worker_ws.code_dir / "ANGERONA_FINDING_ADJUDICATE.py").is_file()
    assert (worker_ws.code_dir / "ANDROID_TARGET_OVERVIEW.json").is_file()
    worker_slices = json.loads(
        (worker_ws.raw_dir / "security_slices.json").read_text(encoding="utf-8")
    )
    assert [item["slice_id"] for item in worker_slices["slices"]] == [
        "android-files-01"
    ]
    worker_scope = json.loads(
        (worker_ws.raw_dir / "RUN_SCOPE.json").read_text(encoding="utf-8")
    )
    assert worker_scope["input_mode"] == "slice-scoped-v1"
    assert worker_scope["slice_id"] == "android-files-01"
