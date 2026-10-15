from __future__ import annotations

import json
from pathlib import Path

from src.agents.audit_state import AuditStateStore
from src.agents.loop import attest_isolation_capable_dispatch
from src.agents.orchestrator import Orchestrator
from src.agents.runtime import AgentResult
from src.agents.supervisor import SupervisorLoop
from src.analysis.export import export_analysis
from src.analysis.security_slices import build_security_slices
from src.analysis.sink_hunter import SinkHunter
from src.analysis.xref_graph import XrefGraph
from src.orchestration.batch_spine import BatchJobSpec, BatchSpine
from src.workspace import RunWorkspace


class FakeExportEngine:
    def analyze(self, binary, decompile=True, max_functions=0):
        return {
            "metadata": {"engine": "fake", "entry_point": "0x401000"},
            "functions": [
                {
                    "name": "main",
                    "entry": "0x401000",
                    "size": 64,
                    "signature": "int main(void)",
                    "decompiled": "int main(void) { return gets(buf); }",
                    "callers": [],
                    "callees": ["gets"],
                }
            ],
            "strings": [{"address": "0x402000", "value": "prompt"}],
            "imports": [{"library": "libc", "name": "gets"}],
            "exports": [{"address": "0x401000", "name": "main"}],
            "symbols": [{"address": "0x401000", "type": "FUNC", "name": "main"}],
        }


class FakeGraphEngine:
    def analyze(self, binary, decompile=True, max_functions=0):
        return {
            "metadata": {"engine": "fake", "entry_point": "0x401000", "function_count": 2},
            "functions": [
                {
                    "name": "main",
                    "entry": "0x401000",
                    "size": 64,
                    "signature": "int main(void)",
                    "decompiled": "int main(void) { return gets(buf); }",
                    "callers": [],
                    "callees": ["gets"],
                },
                {
                    "name": "gets",
                    "entry": "0x500000",
                    "size": 8,
                    "signature": "char *gets(char *)",
                    "decompiled": "",
                    "callers": ["main"],
                    "callees": [],
                },
            ],
            "strings": [{"address": "0x402000", "value": "prompt"}],
            "imports": [{"library": "libc", "name": "gets"}],
            "exports": [{"address": "0x401000", "name": "main"}],
            "symbols": [{"address": "0x401000", "type": "FUNC", "name": "main"}],
        }


class FakeConfig:
    engine = "ghidra"

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir

    def ready(self):
        return True, "ready"


def _sample_xref_graph() -> XrefGraph:
    graph = XrefGraph()
    graph.metadata = {"entry_point": "0x401000"}
    graph.g.add_node(
        "function:0x401000",
        kind="function",
        name="main",
        address="0x401000",
        properties={"memory_block": ".text"},
    )
    graph.g.add_node(
        "import:gets",
        kind="import",
        name="gets",
        address=None,
        properties={"library": "libc", "is_external": True},
    )
    graph.g.add_edge("function:0x401000", "import:gets", kind="calls", address=None)
    return graph


def test_security_slices_bind_sink_path_to_decompiled_evidence(tmp_path: Path) -> None:
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    code_dir = tmp_path / "code"
    export_analysis(FakeExportEngine(), str(binary), code_dir, producer="unit-test")

    sink_report = {
        "total_sinks": 1,
        "reachable_sinks": 1,
        "high_risk_reachable": [{
            "node_id": "import:gets",
            "name": "gets",
            "category": "memory_unsafe_copy",
            "severity": "CRITICAL",
            "description": "unbounded input",
            "source_distance": 1,
            "semantic_source_distance": 1,
            "shortest_path": ["function:0x401000", "import:gets"],
            "semantic_shortest_path": ["function:0x401000", "import:gets"],
            "reachable": True,
            "evidence": {
                "reachability_source_node_id": "function:0x401000",
                "reachability_source_provenance": "metadata_entry_point",
                "reachability_target_node_id": "import:gets",
                "reachability_target_is_boundary": True,
                "semantic_raw_path": ["function:0x401000", "import:gets"],
            },
        }],
    }

    report = build_security_slices(
        xref_graph=_sample_xref_graph(),
        sink_report=sink_report,
        evidence_ledger=code_dir / "EVIDENCE_LEDGER.json",
    )

    assert report["summary"]["candidate_slices"] == 1
    slice_ = report["slices"][0]
    assert slice_["status"] == "candidate"
    assert slice_["risk"]["severity"] == "CRITICAL"
    assert slice_["source"]["name"] == "main"
    assert slice_["sink"]["name"] == "gets"
    assert slice_["reconstruction_targets"][0]["decompiled_path"] == "decompiled/main_0x401000.c"
    decompiled = slice_["evidence"]["decompiled_files"][0]
    assert decompiled["path"] == "decompiled/main_0x401000.c"
    assert len(decompiled["sha256"]) == 64
    assert not any(ref.get("missing") for ref in slice_["evidence"]["required_raw_artifacts"])
    assert slice_["validation"]["state"] == "not_started"
    assert "decompiled/main_0x401000.c" in slice_["ai_scope"]["allowed_inputs"]


def test_batch_sink_stage_writes_security_slices(tmp_path: Path) -> None:
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    workspace = RunWorkspace.create(tmp_path / "runs", str(binary))
    export_analysis(FakeExportEngine(), str(binary), workspace.code_dir, producer="unit-test")

    spine = BatchSpine(state_dir=tmp_path / "state")
    spine._workspace = workspace
    spine._xref_graph = _sample_xref_graph()
    artifacts: dict[str, str] = {}

    result = spine._stage_sinks(
        BatchJobSpec(binary=str(binary), engine="ghidra", stages=["sinks"]),
        artifacts,
    )

    security_slices = Path(artifacts["security_slices"])
    assert security_slices.is_file()
    data = json.loads(security_slices.read_text())
    assert result["security_slices"] == 1
    assert data["summary"]["candidate_slices"] == 1
    assert data["slices"][0]["risk"]["sink_name"] == "gets"


def test_solana_syscall_sinks_create_reachable_security_slices(tmp_path: Path) -> None:
    binary = tmp_path / "program.so"
    binary.write_bytes(b"\x7fELF fake")
    code_dir = tmp_path / "code"
    export_analysis(FakeExportEngine(), str(binary), code_dir, producer="unit-test")

    graph = XrefGraph()
    graph.metadata = {
        "engine": "solana-fused",
        "architecture": "Solana SBF/eBPF",
        "entry_point": "0x401000",
    }
    graph.g.add_node(
        "function:0x401000",
        kind="function",
        name="entrypoint",
        address="0x401000",
        properties={"memory_block": ".text"},
    )
    graph.g.add_node(
        "import:sol_invoke_signed_c",
        kind="import",
        name="sol_invoke_signed_c",
        address=None,
        properties={"library": "solana", "is_external": True},
    )
    graph.g.add_edge(
        "function:0x401000",
        "import:sol_invoke_signed_c",
        kind="calls",
        address="0x401020",
    )

    sink_report = SinkHunter(graph).run(max_depth=4)
    assert sink_report["reachable_sinks"] == 1
    assert sink_report["high_risk_reachable"][0]["category"] == "solana_cpi"

    report = build_security_slices(
        xref_graph=graph,
        sink_report=sink_report,
        evidence_ledger=code_dir / "EVIDENCE_LEDGER.json",
    )

    assert report["summary"]["candidate_slices"] == 1
    slice_ = report["slices"][0]
    assert slice_["risk"]["category"] == "solana_cpi"
    assert slice_["sink"]["name"] == "sol_invoke_signed_c"


def _write_supervisor_slice(workspace: RunWorkspace) -> None:
    report = {
        "schema_version": 1,
        "model": "focused_security_slices",
        "summary": {"candidate_slices": 1},
        "slices": [{
            "slice_id": "slice-0001-deadbeefcafe",
            "status": "candidate",
            "risk": {
                "severity": "CRITICAL",
                "category": "memory_unsafe_copy",
                "sink_name": "gets",
            },
            "source": {"node_id": "function:0x401000", "name": "main"},
            "sink": {"node_id": "import:gets", "name": "gets"},
            "reconstruction_targets": [{
                "name": "main",
                "entry": "0x401000",
                "state": "raw_decompiled",
                "decompiled_path": "decompiled/main_0x401000.c",
            }],
            "ai_scope": {
                "allowed_inputs": ["decompiled/main_0x401000.c", "imports.txt"],
            },
        }],
    }
    (workspace.raw_dir / "security_slices.json").write_text(json.dumps(report), encoding="utf-8")


def test_supervisor_adds_security_slice_workers_even_when_llm_says_complete(tmp_path: Path) -> None:
    ws = RunWorkspace.create(tmp_path / "runs", "/bin/true")
    _write_supervisor_slice(ws)

    def dispatch(agent, task, system_prompt, on_event, cwd=None, **_kwargs):
        if "```plan" in system_prompt:
            assert "SECURITY SLICES" in task
            text = '```plan\n{"coverage_complete": true, "workers": []}\n```'
        elif "consolidated" in system_prompt.lower():
            text = "## Summary\nsecurity slice worker ran"
        elif "REVIEW_VERDICT" in system_prompt:
            text = "verified\nREVIEW_VERDICT: SATISFIED"
        else:
            assert "../raw/security_slices.json" in task
            assert "slice-0001-deadbeefcafe" in task
            text = (
                "## Summary\nSecurity slice slice-0001-deadbeefcafe: no confirmed issue.\n"
                "## Security findings\nREJECTED: gets path not exploitable."
            )
        return AgentResult(ok=True, final_text=text, events=[], returncode=0, seconds=0.01)

    attest_isolation_capable_dispatch(dispatch)
    result = SupervisorLoop(
        binary="/bin/true",
        objective="find vulnerabilities",
        overview="small test target",
        workspace=ws,
        dispatch=dispatch,
        max_supervisor_rounds=1,
        max_worker_rounds=1,
        max_parallel=1,
        strict_verify=False,
    ).run()

    assert len(result.workers) == 1
    assert result.workers[0].spec.slice_id == "slice-0001-deadbeefcafe"
    assert result.workers[0].spec.functions == ["0x401000"]
    saved_plan = json.loads((ws.raw_dir / "plan_1.json").read_text())
    assert saved_plan["coverage_complete"] is False
    assert saved_plan["workers"][0]["slice_id"] == "slice-0001-deadbeefcafe"
    updated_slices = json.loads((ws.raw_dir / "security_slices.json").read_text())
    assert updated_slices["slices"][0]["status"] == "rejected"
    assert updated_slices["slices"][0]["assigned_worker"] == "sec_slice_0001_deadbeefcafe"
    validation = json.loads((ws.raw_dir / "validation_status.json").read_text())
    assert validation["model"] == "swarm_validation_status"
    assert validation["summary"]["workers_total"] == 1
    assert validation["summary"]["workers_converged"] == 1
    assert validation["summary"]["security_slice_status_counts"]["rejected"] == 1
    assert validation["summary"]["blocking_slice_ids"] == []
    assert validation["workers"][0]["slice_id"] == "slice-0001-deadbeefcafe"


def test_slice_mode_converges_from_all_authoritative_active_slices(tmp_path: Path) -> None:
    ws = RunWorkspace.create(tmp_path / "runs", "/bin/true")
    _write_supervisor_slice(ws)
    (ws.code_dir / "decompiled").mkdir()
    (ws.code_dir / "decompiled/main_0x401000.c").write_text("int main(void) { return 0; }\n")
    (ws.code_dir / "imports.txt").write_text("gets\n")

    def dispatch(agent, task, system_prompt, on_event, cwd=None, **_kwargs):
        if "consolidated" in system_prompt.lower():
            text = "## Summary\nauthoritative slice completed"
        elif "REVIEW_VERDICT" in system_prompt:
            text = "## Verification\nindependently verified\nREVIEW_VERDICT: SATISFIED"
        else:
            text = (
                "## Security findings\n"
                "slice-0001-deadbeefcafe\n"
                "REJECTED: cited path is not exploitable."
            )
        return AgentResult(ok=True, final_text=text, events=[], returncode=0, seconds=0.01)

    attest_isolation_capable_dispatch(dispatch)
    result = SupervisorLoop(
        binary="/bin/true",
        objective="find vulnerabilities",
        overview="small test target",
        workspace=ws,
        dispatch=dispatch,
        max_supervisor_rounds=1,
        max_worker_rounds=1,
        max_parallel=1,
        spawn_strategy="slices",
        strict_verify=False,
    ).run()

    assert result.converged is True
    assert result.incomplete_reason == ""
    assert ws.meta["swarm"]["coverage_complete"] is True
    validation = json.loads((ws.raw_dir / "validation_status.json").read_text())
    assert validation["summary"]["coverage_complete"] is True


def test_orchestrator_swarm_builds_security_slices_before_supervisor(tmp_path: Path, monkeypatch) -> None:
    import src.agents.supervisor as supervisor_mod

    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    ws = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = FakeGraphEngine()

    def fake_run(self):
        return supervisor_mod.SwarmResult(
            converged=False,
            supervisor_rounds=0,
            workers=[],
            workspace=self.ws,
            final_report="",
        )

    monkeypatch.setattr(supervisor_mod.SupervisorLoop, "run", fake_run)

    orchestrator.swarm_run(
        str(binary),
        workspace=ws,
        pre_analyze=False,
        max_supervisor_rounds=1,
        max_worker_rounds=1,
        strict_verify=False,
    )

    slices_path = ws.raw_dir / "security_slices.json"
    assert slices_path.is_file()
    data = json.loads(slices_path.read_text())
    assert data["summary"]["candidate_slices"] >= 1
    assert (ws.raw_dir / "sinks.json").is_file()


def test_orchestrator_reuses_prebuilt_security_slices(tmp_path: Path, monkeypatch) -> None:
    import src.agents.supervisor as supervisor_mod

    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    ws = RunWorkspace.create(tmp_path / "runs", str(binary))
    (ws.raw_dir / "sinks.json").write_text(
        json.dumps({"total_sinks": 99, "reachable_sinks": 99}),
        encoding="utf-8",
    )
    (ws.raw_dir / "security_slices.json").write_text(
        json.dumps({
            "schema_version": 1,
            "model": "focused_security_slices",
            "summary": {"candidate_slices": 7},
            "slices": [],
        }),
        encoding="utf-8",
    )
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = FakeGraphEngine()

    def fake_run(self):
        return supervisor_mod.SwarmResult(
            converged=False,
            supervisor_rounds=0,
            workers=[],
            workspace=self.ws,
            final_report="",
        )

    monkeypatch.setattr(supervisor_mod.SupervisorLoop, "run", fake_run)

    orchestrator.swarm_run(
        str(binary),
        workspace=ws,
        pre_analyze=False,
        max_supervisor_rounds=1,
        max_worker_rounds=1,
        strict_verify=False,
    )

    data = json.loads((ws.raw_dir / "security_slices.json").read_text())
    sinks = json.loads((ws.raw_dir / "sinks.json").read_text())
    assert data["summary"]["candidate_slices"] == 7
    assert sinks["total_sinks"] == 99


def test_orchestrator_resume_restores_promoted_context_policy(
    tmp_path: Path, monkeypatch
) -> None:
    import src.agents.supervisor as supervisor_mod

    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x7fELF fake")
    ws = RunWorkspace.create(tmp_path / "runs", str(binary))
    orchestrator = Orchestrator(FakeConfig(tmp_path / "state"))
    orchestrator.engine = FakeGraphEngine()
    monkeypatch.setenv("ANGERONA_CODEX_MODEL", "pinned-codex-model")
    supervisor_runs = 0
    resumed_dispatch_windows: list[int] = []

    def fake_run(self):
        nonlocal supervisor_runs
        supervisor_runs += 1
        if supervisor_runs == 2:
            self.dispatch("claude", "resume task", "system", None)
        return supervisor_mod.SwarmResult(
            converged=False, supervisor_rounds=0, workers=[],
            workspace=self.ws, final_report="", paused=True,
        )

    def fake_dispatch(*args, **kwargs):
        resumed_dispatch_windows.append(kwargs["context_window_tokens"])
        return AgentResult(ok=True, final_text="resumed")

    monkeypatch.setattr(supervisor_mod.SupervisorLoop, "run", fake_run)
    monkeypatch.setattr(orchestrator, "_dispatch", fake_dispatch)
    orchestrator.swarm_run(
        str(binary), workspace=ws, pre_analyze=False,
        model="pinned-model", max_supervisor_rounds=1,
        max_worker_rounds=1, strict_verify=False,
    )

    store = AuditStateStore(ws.root)
    snapshot = store.load_latest()
    policy = store.load_context_policy(required=True)
    assert snapshot.payload["context_policy"]["genesis_sha256"] == policy.genesis_digest
    initial = policy.windows["claude"]
    limit = initial * 2 if initial * 2 <= 10_000_000 else initial // 2
    total = limit + 1_000
    promoted, changed = store.promote_context_window(
        base_contract_sha256=policy.base_contract_sha256,
        agent="claude",
        observation={
            "source": "typed_provider_error", "agent_family": "claude",
            "model_name": "pinned-model",
            "configured_context_window_tokens": initial,
            "context_limit_tokens": limit,
            "requested_total_tokens": total,
            "requested_input_tokens": total - 2_000,
            "requested_output_tokens": 2_000,
        },
    )
    assert changed and promoted.windows["claude"] == limit
    store.close()

    resumed_ws = RunWorkspace.open(ws.root)
    orchestrator.swarm_run(
        str(binary), workspace=resumed_ws, pre_analyze=False,
        model="ignored-on-resume", max_supervisor_rounds=1,
        max_worker_rounds=1, strict_verify=False,
    )
    restored_store = AuditStateStore(ws.root)
    assert restored_store.load_context_policy(required=True).windows["claude"] == limit
    restored_store.close()
    assert resumed_dispatch_windows == [limit]
