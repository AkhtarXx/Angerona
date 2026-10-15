"""Angerona command-line interface.

One unified analysis command — the AI decides everything:

  run <target>        Analyze a target. An AI SUPERVISOR inspects it and decides how many
                      worker agents to spawn and how to divide the work; each worker runs
                      analyze -> agnostic review until satisfied; results are consolidated.
                      Small targets are analyzed directly (supervisor spawns 0 workers).

The reverse-engineering engine is selectable with ``--engine`` (default: ida):
  ida     IDA Pro headless via idalib + the ida-pro-mcp (idalib-mcp) MCP server.
  ghidra  Ghidra headless (analyzeHeadless + REDump.java) + our stdlib MCP server.

Low-level helpers:
  status              Show IDA + Ghidra engine status.
  install             Register the engine's MCP server with Claude Code / Codex.
  analyze <bin>       Raw headless analysis summary (no agent).
  decompile <bin> <f> Decompile one function (no agent).
  mcp-serve           Run the stdio MCP server (used by agents).
  update-ghidra       Check/install the newest Ghidra release.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path as _Path

from .config import default_engine, load_config
from .engines.ghidra import EngineError, GhidraEngine

Path = _Path  # expose for helper usage without circular imports


def _resolve_engine(ns) -> str:
    return getattr(ns, "engine", None) or default_engine()


def _apply_privacy_mode(ns) -> str | None:
    """Apply the privacy preset and fail closed unless the agent is local."""
    if not getattr(ns, "privacy_mode", False):
        return None
    from .config import local_model_config

    ns.sandbox = True
    os.environ["ANGERONA_SANDBOX"] = "1"
    os.environ["ANGERONA_LOCAL_ONLY"] = "1"
    os.environ["ANGERONA_LOCAL_MODEL"] = "1"
    os.environ["ANGERONA_MCP_ALLOW_WRITE"] = "0"
    os.environ["ANGERONA_DISABLE_DYNAMIC"] = "1"
    local = local_model_config()
    if getattr(ns, "agent", None) != "codex":
        return "privacy mode requires --agent codex with a local OpenAI-compatible endpoint"
    assert local is not None
    from urllib.parse import urlsplit
    host = urlsplit(str(local["base_url"])).hostname or ""
    if host.lower() not in {"localhost", "ip6-localhost", "127.0.0.1", "::1"}:
        return "privacy mode requires ANGERONA_LOCAL_BASE_URL to use a loopback host"
    os.environ["OPENAI_BASE_URL"] = str(local["base_url"])
    os.environ["OPENAI_API_KEY"] = str(local["api_key"])
    if not getattr(ns, "model", None):
        ns.model = str(local["model"])
    return None


def _add_engine_arg(p: argparse.ArgumentParser, *, with_both: bool = False) -> None:
    choices = ["ida", "ghidra"] + (["both"] if with_both else [])
    p.add_argument("--engine", choices=choices, default=None,
                   help="Explicit RE engine override; omit for the command's automatic/default routing.")


def _add_audit_budget_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--max-agent-calls", type=int, default=None,
        help="Whole-audit provider-attempt limit (default: 64; retries count).",
    )
    p.add_argument(
        "--audit-wall-timeout", type=float, default=None,
        help="Whole-audit wall-clock deadline in seconds (default: 21600; 0 disables).",
    )
    p.add_argument(
        "--max-agent-tokens", type=int, default=None,
        help="Whole-audit token limit; 0 disables when provider usage is unavailable.",
    )
    p.add_argument(
        "--max-agent-cost-usd", type=float, default=None,
        help="Whole-audit cost limit in USD; 0 disables.",
    )
    p.add_argument(
        "--budget-verification-reserve-calls", type=int, default=None,
        help=("Provider attempts held back for final consolidation (default: at least "
              "one full retry/context-recovery dispatch)."),
    )


# --------------------------------------------------------------- helpers (no agent)

def _cmd_status(ns) -> int:
    from .engines.ida import IdaEngine
    active = _resolve_engine(ns)
    ida = IdaEngine(load_config("ida")).status()
    ghidra = GhidraEngine(load_config("ghidra")).status()
    out = {"active_engine": active, "ida": ida, "ghidra": ghidra}
    print(json.dumps(out, indent=2))
    return 0 if (ida if active == "ida" else ghidra)["ready"] else 1


def _doctor_engine(name: str, binary: str, timeout: int) -> dict:
    """Run a minimal real analysis, not merely a path/config check."""
    from .engines.ida import IdaEngine

    cfg = load_config(name)
    ready, message = cfg.ida_ready() if name == "ida" else cfg.ghidra_ready()
    result = {
        "engine": name,
        "configured": ready,
        "configuration": message,
        "operational": False,
    }
    if not ready:
        return result
    engine = IdaEngine(cfg) if name == "ida" else GhidraEngine(cfg)
    try:
        payload = engine.analyze(
            binary, decompile=False, max_functions=1, force=True, timeout=timeout,
        )
        result.update({
            "operational": isinstance(payload, dict),
            "binary": str(Path(binary).expanduser().resolve()),
            "cache": payload.get("_cache") if isinstance(payload, dict) else None,
        })
    except Exception as exc:  # noqa: BLE001 - diagnostics must report engine failures
        result["error"] = str(exc)
    return result


def _cmd_doctor(ns) -> int:
    binary = ns.binary or sys.executable
    names = ["ida", "ghidra"] if ns.engine == "all" else [ns.engine]
    results = [_doctor_engine(name, binary, ns.timeout) for name in names]
    payload = {"ok": all(item["operational"] for item in results), "results": results}
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


def _android_readiness(
    *, require_runtime: bool, require_ai: bool = False,
    runtime_provider: str = "auto", runtime_api: int = 35,
    runtime_sdk_root: str = "", device_serial: str = "",
) -> dict:
    """Report concrete Android audit dependencies and the resulting gate."""
    import shutil

    from .analysis.apksigner_bridge import find_apk_verifier
    from .analysis.apktool_bridge import find_apktool
    from .analysis.jadx_bridge import find_jadx_cli
    from .execution.adb_probe import find_adb, list_devices
    from .execution.runtime_dex_extractor import find_frida

    ida_ready, _ida_message = load_config("ida").ida_ready()
    ida_install = load_config("ida").ida_install

    tools = {
        "apktool": str(find_apktool() or ""),
        "jadx": str(find_jadx_cli() or ""),
        "apksigner": str((find_apk_verifier() or ("", []))[0]),
        "adb": str(find_adb() or ""),
        "frida": str(find_frida() or ""),
        "claude": str(shutil.which("claude") or ""),
        "codex": str(shutil.which("codex") or ""),
        "ida_pro": str(ida_install or "") if ida_ready else "",
        "llvm_objdump": str(shutil.which("llvm-objdump") or shutil.which("objdump") or ""),
        "readelf": str(shutil.which("readelf") or ""),
    }
    missing_static = [name for name in ("apktool", "jadx", "apksigner") if not tools[name]]
    if not tools["ida_pro"] and not tools["llvm_objdump"]:
        missing_static.append("native-analysis-backend")
    missing_runtime = [name for name in ("adb", "frida") if not tools[name]]
    devices = list_devices(tools["adb"]) if tools["adb"] else []
    managed_runtime = None
    if require_runtime and runtime_provider in {"auto", "avd"}:
        from .execution.android_runtime_manager import (
            AndroidRuntimePolicy,
            managed_runtime_readiness,
        )
        managed_runtime = managed_runtime_readiness(AndroidRuntimePolicy(
            provider="avd", api=runtime_api, sdk_root=runtime_sdk_root,
        ))
    runtime_tools_ready = (
        bool(managed_runtime and managed_runtime["ready"])
        if managed_runtime is not None else not missing_runtime
    )
    toolchain_ready = not missing_static and (not require_runtime or runtime_tools_ready)
    blockers = []
    if require_runtime and runtime_provider == "connected":
        if not device_serial:
            blockers.append("connected runtime provider requires --device-serial")
        elif device_serial not in devices:
            blockers.append("explicit authorized adb device is not online")
    if managed_runtime is not None and not managed_runtime["ready"]:
        blockers.extend(managed_runtime["blockers"])
    if require_ai and not (tools["claude"] or tools["codex"]):
        blockers.append("neither Claude nor Codex CLI is installed")
    return {
        "ready": toolchain_ready and not blockers,
        "toolchain_ready": toolchain_ready,
        "mode": "static+runtime" if require_runtime else "static",
        "tools": tools,
        "missing_static": missing_static,
        "missing_runtime": missing_runtime,
        "adb_devices": devices,
        "runtime_provider": runtime_provider,
        "managed_runtime": managed_runtime,
        "blockers": blockers,
        "note": (
            "runtime was requested; device authorization, target installation, and "
            "Frida server health are verified during the audit"
            if require_runtime else
            "direct APK static audit is ready; no connected device is required"
        ),
    }


def _cmd_android_doctor(ns) -> int:
    payload = _android_readiness(
        require_runtime=ns.runtime and not ns.static_only,
        require_ai=ns.require_ai,
        runtime_provider=ns.runtime_provider,
        runtime_api=ns.runtime_api,
        runtime_sdk_root=ns.runtime_sdk_root,
        device_serial=ns.device_serial,
    )
    print(json.dumps(payload, indent=2))
    return 0 if payload["ready"] else 1


def _cmd_android_audit(ns) -> int:
    from .pipeline.android_audit import run_android_audit

    output = Path(ns.output).expanduser().resolve() if ns.output else None
    ai_workspace = None
    artifact_output_dir = None
    if ns.ai_review:
        if output is None:
            print("error: --ai-review requires --output", file=sys.stderr)
            return 2
        from .pipeline.android_ai_audit import create_android_ai_workspace

        ai_workspace = create_android_ai_workspace(ns.apk, output.parent)
        artifact_output_dir = ai_workspace.code_dir / "android_artifacts"
        prepared_workspace_root = Path(
            getattr(ai_workspace, "root", Path(ai_workspace.code_dir).parent)
        ).resolve()
        print(f"AI workspace prepared: {prepared_workspace_root}", flush=True)
        print(
            "Mid-run instruction: angerona audit-instruct "
            f"{prepared_workspace_root} '<instruction>'",
            flush=True,
        )

    report = run_android_audit(
        ns.apk,
        expected_package=ns.expected_package,
        try_runtime_extract=ns.runtime and not ns.no_runtime,
        device_serial=ns.device_serial,
        runtime_provider=ns.runtime_provider,
        runtime_api=ns.runtime_api,
        runtime_abi=ns.runtime_abi,
        runtime_image_tag=ns.runtime_image_tag,
        runtime_auto_provision=ns.runtime_auto_provision,
        runtime_sdk_root=ns.runtime_sdk_root,
        allow_native_translation=ns.allow_native_translation,
        runtime_network=ns.runtime_network,
        timeout_per_step=ns.timeout,
        run_rules=not ns.no_rules,
        related_apks=ns.related_apk,
        baseline_path=ns.baseline,
        authorization_ref=ns.authorization_ref,
        artifact_output_dir=artifact_output_dir,
        audit_input_snapshot_dir=(
            getattr(ai_workspace, "raw_dir", output.parent / ".angerona-input")
            / "input_snapshot"
            if ai_workspace is not None else None
        ),
        native_ownership_manifest=ns.native_ownership_manifest,
        native_universe=ns.native_universe,
        native_lane_epoch_id=ns.native_lane_epoch_id,
    )
    rendered = json.dumps(report.as_dict(), indent=2, default=str)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        print(f"android audit report: {output}")
        print(report.summary_line())
    else:
        print(rendered)
    if ns.ai_review and ai_workspace is not None and output is not None:
        if report.status == "error":
            ai_workspace.finish(
                converged=False,
                rounds=0,
                note="deterministic Android audit failed before AI dispatch",
                status="incomplete",
            )
            print("error: Android evidence generation failed; AI swarm was not started", file=sys.stderr)
            return 4
        from .pipeline.android_ai_audit import run_android_ai_swarm

        outcome = run_android_ai_swarm(
            apk_path=report.metadata.get("audit_input_snapshot", {}).get(
                "path", report.apk_path
            ),
            report=report,
            workspace=ai_workspace,
            agent=ns.ai_agent,
            model=ns.model,
            reviewer_agent=ns.ai_reviewer_agent,
            reviewer_model=ns.ai_reviewer_model,
            reviewer_reasoning_effort=ns.ai_reviewer_reasoning,
            dangerous_skip_permissions=ns.ai_dangerous_skip_permissions,
            rounds=ns.ai_rounds,
            parallel=ns.ai_parallel,
        )
        review_path = output.with_suffix(output.suffix + ".ai-review.md")
        review_path.write_text(outcome.swarm.final_report.strip() + "\n", encoding="utf-8")
        report.metadata["ai_swarm"] = {
            "workspace": str(outcome.workspace),
            "converged": outcome.swarm.converged,
            "supervisor_rounds": outcome.swarm.supervisor_rounds,
            "workers": len(outcome.swarm.workers),
            "coverage": outcome.coverage,
            "incomplete_reason": outcome.swarm.incomplete_reason,
        }
        output.write_text(
            json.dumps(report.as_dict(), indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        print(f"AI review: {review_path}")
        print(f"AI workspace: {outcome.workspace}")
        if not outcome.swarm.converged:
            return 3
    if report.status == "error":
        return 2
    return 0 if report.status == "completed" else 3


def _cmd_install(ns) -> int:
    from .mcp import config as mcp_config
    engines = ["ida", "ghidra"] if _resolve_engine(ns) == "both" else [_resolve_engine(ns)]
    agents = ns.agent or ["claude", "codex"]
    rc = 0
    for engine in engines:
        cfg = load_config(engine)
        print(f"\n=== engine: {engine} ===")
        if engine == "ida":
            ok, msg = mcp_config.ensure_ida_mcp_env(cfg)
            print(f"[ida-mcp] {'OK' if ok else 'FAILED'}: {msg}")
            if not ok:
                rc = rc or 1
                continue
            cfg = load_config("ida")  # re-discover the freshly-created venv python
        if "claude" in agents:
            ok, msg = mcp_config.install_claude_user(ns.binary, cfg)
            print(f"[claude] {'OK' if ok else 'FAILED'}: {msg}")
            rc = rc or (0 if ok else 1)
        if "codex" in agents:
            ok, msg = mcp_config.install_codex(ns.binary, cfg)
            print(f"[codex] {'OK' if ok else 'FAILED'}: {msg}")
            rc = rc or (0 if ok else 1)
        cfg_path = cfg.state_dir / f"{mcp_config.server_name(engine)}-mcp.json"
        mcp_config.write_claude_mcp_config(cfg_path, ns.binary, cfg)
        print(f"[config] wrote portable MCP config: {cfg_path}")
    return rc


def _cmd_analyze(ns) -> int:
    from .engines import make_engine
    if getattr(ns, "sandbox", False):
        os.environ["ANGERONA_SANDBOX"] = "1"
    engine = make_engine(load_config(_resolve_engine(ns)))
    try:
        data = engine.analyze(ns.binary, decompile=ns.decompile,
                              max_functions=ns.max_functions, force=ns.force,
                              timeout=0 if getattr(ns, "no_timeout", False) else None)
    except EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    md = data.get("metadata", {})
    funcs = data.get("functions", [])
    if ns.json:
        print(json.dumps({**data, "function_count": len(funcs)}, indent=2))
        return 0
    print(f"engine        : {_resolve_engine(ns)}")
    print(f"binary        : {ns.binary}")
    print(f"format        : {md.get('executable_format')}  ({md.get('language_id')})")
    print(f"sha256        : {md.get('sha256')}")
    print(f"functions     : {len(funcs)}  strings: {len(data.get('strings', []))}  "
          f"imports: {len(data.get('imports', []))}  exports: {len(data.get('exports', []))}")
    print(f"cache         : {data.get('_cache')}  (cached={data.get('_cached')})")
    return 0


def _cmd_decompile(ns) -> int:
    from .engines import make_engine
    engine = make_engine(load_config(_resolve_engine(ns)))
    try:
        fn = engine.decompile_function(ns.binary, ns.function)
    except EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if ns.json:
        print(json.dumps(fn, indent=2))
    else:
        print(f"// {fn.get('signature')}  @ {fn.get('entry')}")
        print(f"// callers={fn.get('callers')} callees={fn.get('callees')}")
        print(fn.get("decompiled", "(no output)"))
    return 0


def _cmd_sota_analyze(ns) -> int:
    from .workspace import RunWorkspace
    from .models.analysis_graph import AnalysisGraph
    from .models.checkpoint_db import CheckpointDB
    from .models.triage_profile import MultiSourceTriager
    from .models.type_recovery import TypeRecoveryAgent
    from .models.cpp_recovery import CppRecoveryAgent
    from .analysis.xref_graph import XrefGraph
    from .analysis.sink_hunter import SinkHunter
    from .analysis.library_signatures import (
        SignatureDB,
        library_classification_report,
        quick_library_mark,
    )
    from .engines import make_engine

    if ns.sandbox:
        os.environ["ANGERONA_SANDBOX"] = "1"
    engine_cfg = load_config(_resolve_engine(ns))
    engine = make_engine(engine_cfg)

    ws = RunWorkspace.create(engine_cfg.state_dir / "runs", ns.binary)
    ckpt = CheckpointDB(ws.checkpoint_db_path)
    root_ck = ckpt.create_checkpoint("sota-analyze", "Create workspace and start state-of-the-art analysis")

    # Phase 2 Step 0: multi-source triage with confidence scoring
    triager = MultiSourceTriager()
    triage_profile = triager.triage(ns.binary)
    ws.save_raw("triage_profile.json", json.dumps(triage_profile.__dict__, indent=2, default=str))

    try:
        data = engine.analyze(
            ns.binary,
            decompile=True,
            max_functions=ns.max_functions,
            force=ns.force,
            timeout=0 if getattr(ns, "no_timeout", False) else None,
        )
        ws.save_raw("engine_export_full.json", json.dumps(data, indent=2))
    except Exception as exc:
        print(f"error: engine analysis failed: {exc}", file=sys.stderr)
        return 1

    graph = AnalysisGraph()
    graph.from_engine_json(data)
    ws.save_raw("analysis_graph.json", json.dumps(graph.to_json(), indent=2))

    # Library noise suppression
    sig_db = None
    functions = data.get("functions", [])
    lib_marks = quick_library_mark(functions)
    library_report = library_classification_report(functions)
    if ns.signature_db:
        try:
            sig_db = SignatureDB.load_json(ns.signature_db)
        except Exception:
            sig_db = None
    if sig_db:
        matches = sig_db.match_many(functions, threshold=0.75)
        for name, match in matches.items():
            if match.get("matched"):
                lib_marks[name] = True
        ws.save_raw("library_matches.json", json.dumps(matches, indent=2))
    ws.save_raw("library_classification.json", json.dumps(library_report, indent=2))

    xref = XrefGraph(graph, library_marks=lib_marks)
    xref.save_json(ws.graph_dir / "xref_graph.json")

    # Phase 2 Step 1: type/structure recovery
    type_agent = TypeRecoveryAgent(graph)
    signatures = type_agent.recover_signatures()
    ws.save_raw("type_signatures.json", json.dumps({k: v.as_dict() for k, v in signatures.items()}, indent=2))
    structures = type_agent.recover_structures(max_structs=200)
    ws.save_raw("recovered_structures.json", json.dumps([s.as_dict() for s in structures], indent=2))

    # Phase 2 Step 2: C++/RTTI/vtable recovery
    cpp_agent = CppRecoveryAgent(graph)
    classes = cpp_agent.build_hierarchy()
    ws.save_raw(
        "cpp_classes.json",
        json.dumps(
            {name: recovered.as_dict() for name, recovered in classes.items()},
            indent=2,
            default=str,
        ),
    )

    hunter = SinkHunter(xref)
    sink_report = hunter.run(max_depth=16)
    ws.save_raw("sink_report.json", json.dumps(sink_report, indent=2))

    summary = xref.summary()
    ws.save_raw("graph_summary.json", json.dumps(summary, indent=2))

    ckpt.record_mutations(
        root_ck.id,
        [
            ("graph", "xref", "nodes", 0, summary["nodes"]),
            ("graph", "xref", "edges", 0, summary["edges"]),
            ("graph", "xref", "library_functions", 0, summary["library_functions"]),
            ("sinks", "all", "count", 0, sink_report["total_sinks"]),
            ("sinks", "all", "reachable", 0, sink_report["reachable_sinks"]),
            ("types", "all", "signatures", 0, len(signatures)),
            ("types", "all", "structures", 0, len(structures)),
            ("cpp", "all", "classes", 0, len(classes)),
        ]
    )

    if ns.json:
        print(json.dumps({"workspace": str(ws.root), **summary, **sink_report}, indent=2, default=str))
        return 0
    print(f"engine        : {_resolve_engine(ns)}")
    print(f"binary        : {ns.binary}")
    print(f"workspace     : {ws.root}")
    print(f"nodes/edges   : {summary['nodes']} / {summary['edges']}")
    print(f"functions     : {summary['functions']} (library-marked: {summary['library_functions']})")
    print(f"signatures    : {len(signatures)}")
    print(f"structures    : {len(structures)}")
    print(f"cpp classes   : {len(classes)}")
    print(f"sinks         : {sink_report['total_sinks']} ({sink_report['reachable_sinks']} reachable)")
    if ns.json:
        print(json.dumps({"workspace": str(ws.root),
                          "triage": triage_profile.__dict__,
                          "summary": summary,
                          "signatures_count": len(signatures),
                          "structures_count": len(structures),
                          "cpp_classes_count": len(classes),
                          **sink_report}, indent=2, default=str))
    return 0


def _cmd_graph_query(ns) -> int:
    from pathlib import Path
    from .analysis.xref_graph import XrefGraph
    from .analysis.sink_hunter import SinkHunter

    graph_path = Path(ns.workspace) / "graph" / "xref_graph.json"
    if not graph_path.exists():
        print(f"error: no graph found at {graph_path}", file=sys.stderr)
        return 1
    xref = XrefGraph.load_json(graph_path)

    result: dict | list = {}
    if ns.query == "summary":
        result = xref.summary()
    elif ns.query == "callers":
        if not ns.target:
            print("error: --target required for callers query", file=sys.stderr)
            return 1
        nid = xref.function_by_name(ns.target) or xref.function_by_address(ns.target)
        if not nid:
            print(f"error: target not found: {ns.target}", file=sys.stderr)
            return 1
        result = {"callers": xref.callers(nid), "all_callers": list(xref.all_callers(nid).keys())}
    elif ns.query == "callees":
        if not ns.target:
            print("error: --target required for callees query", file=sys.stderr)
            return 1
        nid = xref.function_by_name(ns.target) or xref.function_by_address(ns.target)
        if not nid:
            print(f"error: target not found: {ns.target}", file=sys.stderr)
            return 1
        result = {"callees": xref.callees(nid), "all_reachable": list(xref.all_reachable(nid, max_depth=10).keys())}
    elif ns.query == "paths":
        if not ns.target:
            print("error: --target required for paths query", file=sys.stderr)
            return 1
        nid = xref.function_by_name(ns.target) or xref.function_by_address(ns.target)
        sources = [n for n, d in xref.g.nodes(data=True) if d.get("kind") == "export" or n.startswith("program:")]
        paths = []
        for src in sources:
            p = xref.shortest_path(src, nid)
            if p:
                paths.append(p)
        result = {"target": ns.target, "paths_from_sources": paths[:20]}
    elif ns.query == "sinks":
        hunter = SinkHunter(xref)
        result = hunter.run()
    else:
        print(f"error: unknown query {ns.query}", file=sys.stderr)
        return 1

    if ns.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_checkpoint_list(ns) -> int:
    from pathlib import Path
    from .models.checkpoint_db import CheckpointDB

    db_path = Path(ns.workspace) / "checkpoints.db"
    if not db_path.exists():
        print(f"error: no checkpoint DB at {db_path}", file=sys.stderr)
        return 1
    ckpt = CheckpointDB(db_path)
    for row in ckpt.audit_log():
        print(f"{row['id']:3d}  parent={row['parent_id'] or 0:3d}  agent={row['agent']:20s}  "
              f"mutations={row['mutation_count']:4d}  {row['created_at']}  {row['rationale']}")
    return 0


def _cmd_checkpoint_revert(ns) -> int:
    from pathlib import Path
    from .models.checkpoint_db import CheckpointDB

    db_path = Path(ns.workspace) / "checkpoints.db"
    if not db_path.exists():
        print(f"error: no checkpoint DB at {db_path}", file=sys.stderr)
        return 1
    ckpt = CheckpointDB(db_path)
    rolled = ckpt.revert_to(ns.checkpoint_id, apply=True)
    print(f"Rolled back {len(rolled)} descendant checkpoint(s) of {ns.checkpoint_id}.")
    total_mutations = 0
    for ck_id, muts in rolled:
        print(f"  checkpoint {ck_id}: {len(muts)} mutation(s)")
        total_mutations += len(muts)
    print(f"Total {total_mutations} mutation(s) applied in reverse to restore checkpoint {ns.checkpoint_id}.")
    print(f"Generic state_kv values have been updated; external artifact files are not modified automatically.")
    return 0


def _run_sota_batch(ns):
    from pathlib import Path
    from .orchestration.batch_spine import BatchJobSpec, BatchSpine, DEFAULT_STAGES
    from .engines.selector import select_engine

    explicit_engine = getattr(ns, "engine", None)
    if explicit_engine:
        selected_engine = explicit_engine
        selection_reason = f"explicit --engine override ({explicit_engine})"
        auto_mode = False
    else:
        selected_engine, selection_reason = select_engine(
            ns.binary,
            default="ida",
        )
        auto_mode = True

    stages = ns.stages.split(",") if ns.stages else list(DEFAULT_STAGES)

    def run_engine(engine_name: str):
        cfg = load_config(engine_name)
        spec = BatchJobSpec(
            binary=ns.binary,
            engine=engine_name,
            max_functions=ns.max_functions,
            force=ns.force,
            sandbox=ns.sandbox,
            signature_db=ns.signature_db,
            type_library=ns.type_library,
            output_dir=ns.output_dir,
            stages=stages,
        )
        spine = BatchSpine(
            state_dir=cfg.state_dir / "runs",
            log_level=ns.log_level,
        )
        return spine.run(spec)

    def analyze_attempt(result, engine_name: str) -> dict:
        analyze_log = next(
            (
                log for log in result.stage_logs
                if log.get("stage") == "analyze"
            ),
            {},
        )
        return {
            "engine": engine_name,
            "workspace": result.workspace,
            "return_code": result.return_code,
            "analyze_status": analyze_log.get("status", "not_requested"),
            "analyze_error": analyze_log.get("error"),
        }

    result = run_engine(selected_engine)
    attempts = [analyze_attempt(result, selected_engine)]
    fallback_used = False
    analyze_failed = attempts[0]["analyze_status"] == "error"
    if auto_mode and selected_engine == "ida" and analyze_failed:
        fallback_used = True
        selection_reason += (
            "; IDA analysis could not load/analyze the target, "
            "so Ghidra fallback was activated"
        )
        result = run_engine("ghidra")
        attempts.append(analyze_attempt(result, "ghidra"))

    routing = {
        "mode": "auto" if auto_mode else "explicit",
        "preferred_engine": "ida",
        "selected_engine": selected_engine,
        "final_engine": attempts[-1]["engine"],
        "reason": selection_reason,
        "fallback_used": fallback_used,
        "attempts": attempts,
    }
    routing_path = Path(result.workspace) / "raw" / "engine_selection.json"
    routing_path.parent.mkdir(parents=True, exist_ok=True)
    routing_tmp = routing_path.with_suffix(".json.tmp")
    routing_tmp.write_text(
        json.dumps(routing, indent=2, default=str),
        encoding="utf-8",
    )
    routing_tmp.replace(routing_path)
    result.artifacts["engine_selection"] = str(routing_path)
    return result, routing


def _print_sota_batch_result(ns, result, routing) -> int:
    if ns.json:
        out = {
            "workspace": result.workspace,
            "return_code": result.return_code,
            "duration_seconds": result.duration_seconds,
            "engine_selection": routing,
            "stage_logs": result.stage_logs,
            "summary": result.summary,
            "artifacts": result.artifacts,
        }
        print(json.dumps(out, indent=2, default=str))
        return result.return_code
    print(f"engine         : {routing['final_engine']} ({routing['mode']})")
    print(f"routing        : {routing['reason']}")
    print(f"workspace      : {result.workspace}")
    print(f"return_code    : {result.return_code}")
    print(f"duration       : {result.duration_seconds:.2f}s")
    print("stages         :")
    for s in result.stage_logs:
        dur_ms = s.get('duration_seconds', 0) * 1000
        print(f"  {s['stage']:15s} {s['status']:10s} {dur_ms:.1f}ms")
    print(f"summary        : {json.dumps(result.summary, indent=2, default=str)}")
    return result.return_code


def _audit_store_and_snapshot(workspace_value):
    from .agents.audit_state import AuditStateError, AuditStateStore

    root = Path(workspace_value).expanduser().resolve()
    store = AuditStateStore(root)
    snapshot = store.load_latest()
    if snapshot is None:
        store.close()
        raise AuditStateError(f"workspace has no resumable audit snapshot: {root}")
    return root, store, snapshot


def _cmd_audit_status(ns) -> int:
    from .agents.budget_harness import load_budget_status
    from .observability import ledger_for_workspace

    try:
        root, store, snapshot = _audit_store_and_snapshot(ns.workspace)
        payload = snapshot.payload
        supervisor = dict(payload.get("supervisor") or {})
        policy_anchor = dict(payload.get("context_policy") or {})
        context_policy = store.load_context_policy(
            required=policy_anchor.get("required") is True
        )
        observability = ledger_for_workspace(root)
        imported_child_events = observability.import_child_spools(root)
        out = {
            "workspace": str(root),
            "generation": snapshot.generation,
            "snapshot": str(snapshot.path),
            "status": payload.get("status"),
            "phase": payload.get("phase"),
            "lease_active": store.lease_active(),
            "pause_requested": store.pause_requested(),
            "exact_resume_ready": bool(
                dict(payload.get("run_contract") or {}).get("exact_resume_ready", False)
            ),
            "supervisor_round": supervisor.get("round", 0),
            "next_round": supervisor.get("next_round", 1),
            "completed_workers": len(supervisor.get("outcomes") or []),
            "worker_workspaces": supervisor.get("worker_workspaces") or {},
            "context_policy_version": (
                context_policy.version if context_policy is not None else None
            ),
            "context_windows": (
                context_policy.windows if context_policy is not None else {}
            ),
            "audit_budget": load_budget_status(root),
            "observability": {
                **observability.verify(),
                "child_events_imported": imported_child_events,
            },
        }
        store.close()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if getattr(ns, "json", False):
        print(json.dumps(out, indent=2, default=str))
    else:
        for key, value in out.items():
            print(f"{key:20s}: {value}")
    return 0


def _cmd_audit_trace(ns) -> int:
    """Read and verify the supervisor-authoritative observability timeline."""

    from pathlib import Path

    from .observability import ledger_for_workspace

    root = Path(ns.workspace).expanduser().resolve()
    if not (root / "run.json").is_file():
        print(f"error: not an Angerona workspace: {root}", file=sys.stderr)
        return 1
    try:
        ledger = ledger_for_workspace(root)
        imported = 0
        if not ns.no_import_child:
            imported = ledger.import_child_spools(root)
        if ns.rebuild_mirror:
            ledger.rebuild_mirror()
        verification = ledger.verify()
        selected: list[dict] = []
        cursor = max(0, int(ns.since))
        while len(selected) < ns.limit:
            batch = ledger.events(since=cursor, limit=min(1000, ns.limit * 4))
            if not batch:
                break
            cursor = int(batch[-1]["sequence"])
            for event in batch:
                if ns.component and event.get("component") != ns.component:
                    continue
                if ns.action and event.get("action") != ns.action:
                    continue
                if ns.status and event.get("status") != ns.status:
                    continue
                selected.append(event)
                if len(selected) >= ns.limit:
                    break
        output = {
            "workspace": str(root),
            "verification": verification,
            "child_events_imported": imported,
            "filters": {
                "since": ns.since,
                "component": ns.component,
                "action": ns.action,
                "status": ns.status,
                "limit": ns.limit,
            },
            "events": selected,
        }
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if ns.json:
        print(json.dumps(output, indent=2, default=str))
        return 0
    print(
        f"trace={verification['trace_id']} events={verification['events']} "
        f"valid={verification['valid']} imported={imported}"
    )
    for event in selected:
        stamp = dt.datetime.fromtimestamp(
            int(event["time_ns"]) / 1_000_000_000, tz=dt.timezone.utc
        ).isoformat(timespec="milliseconds")
        parent = str(event.get("parent_span_id") or "-")[:8]
        attrs = json.dumps(event.get("attributes") or {}, sort_keys=True, default=str)
        if len(attrs) > 2000:
            attrs = attrs[:2000] + "…"
        print(
            f"{int(event['sequence']):07d} {stamp} "
            f"{event['component']}.{event['category']} {event['action']}/{event['phase']} "
            f"status={event['status']} span={str(event['span_id'])[:8]} parent={parent} {attrs}"
        )
    return 0


def _cmd_audit_pause(ns) -> int:
    try:
        root, store, snapshot = _audit_store_and_snapshot(ns.workspace)
        if snapshot.payload.get("status") in {
            "completed", "budget_exhausted", "incomplete",
        }:
            raise RuntimeError(
                f"audit is already terminal ({snapshot.payload.get('status')})"
            )
        control = store.request_pause(getattr(ns, "reason", "") or "manual pause")
        active = store.lease_active()
        store.close()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"pause requested: {root}")
    print(f"control record : {control}")
    print("state          : draining to a committed safe point" if active else
          "state          : pause recorded; audit is currently offline")
    return 0


def _cmd_audit_instruct(ns) -> int:
    """Submit a durable controller instruction for the next supervisor safe point."""

    from .agents.audit_state import AuditStateStore

    root = Path(ns.workspace).expanduser().resolve()
    store = None
    try:
        run_path = root / "run.json"
        if not run_path.is_file():
            raise RuntimeError(f"not an Angerona workspace: {root}")
        run_meta = json.loads(run_path.read_text(encoding="utf-8"))
        snapshot_status = ""
        store = AuditStateStore(root)
        snapshot = store.load_latest()
        if snapshot is not None:
            snapshot_status = str(snapshot.payload.get("status") or "")
        public_status = str(run_meta.get("status") or "")
        terminal = {
            "completed", "supervisor_completed", "budget_exhausted",
            "incomplete", "failed", "error",
        }
        if public_status in terminal or snapshot_status in terminal:
            raise RuntimeError(
                "audit is already terminal "
                f"(run={public_status or 'unknown'}, state={snapshot_status or 'none'})"
            )
        record = store.request_operator_instruction(
            ns.instruction,
            scope=ns.scope,
        )
        active = store.lease_active()
        instructions = store.operator_instructions()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.close()
    print(f"instruction queued : {root}")
    print(f"control record     : {record}")
    print(f"scope              : {ns.scope}")
    print(f"sequence           : {len(instructions)}")
    print(
        "delivery           : next supervisor safe point"
        if active else
        "delivery           : queued for the next supervisor start/resume"
    )
    return 0


def _cmd_audit_resume(ns) -> int:
    from .agents.audit_state import AuditLeaseError
    from .agents.orchestrator import Orchestrator
    from .workspace import RunWorkspace

    try:
        root, store, snapshot = _audit_store_and_snapshot(ns.workspace)
        if store.lease_active():
            raise AuditLeaseError("audit workspace is already active")
        payload = snapshot.payload
        if payload.get("status") in {"completed", "budget_exhausted", "incomplete"}:
            print(f"audit already terminal ({payload.get('status')}): {root}")
            store.close()
            return 0
        config = dict(payload.get("config") or {})
        identity = dict(payload.get("identity") or {})
        binary = store.validate_identity(
            identity,
            binary_override=getattr(ns, "binary", None),
        )
        store.acquire_lease()
        ws = RunWorkspace.open(root, binary=binary)
        engine = str(config.get("engine") or "ida")
        orch = Orchestrator(load_config(engine))
        result = orch.swarm_run(
            binary,
            objective=str(config.get("objective") or "") or None,
            supervisor=str(config.get("supervisor") or "claude"),
            worker_analyst=str(config.get("worker_analyst") or "claude"),
            worker_reviewer=str(config.get("worker_reviewer") or "claude"),
            model=config.get("model"),
            max_supervisor_rounds=int(config.get("max_supervisor_rounds") or 2),
            max_worker_rounds=int(config.get("max_worker_rounds") or 2),
            max_parallel=int(config.get("max_parallel") or 3),
            pre_analyze=False,
            workspace=ws,
            k_candidates=int(config.get("k_candidates") or 1),
            adversarial_review=bool(config.get("adversarial_review")),
            topo_strategy=str(config.get("topo_strategy") or "auto"),
            spawn_strategy=str(config.get("spawn_strategy") or "search"),
            search_k=int(config.get("search_k") or 4),
            cheap_agent=str(config.get("cheap_agent") or "claude"),
            spawn_budget=int(config.get("spawn_budget") or 12),
            complexity_tier=str(config.get("complexity_tier") or "UNKNOWN"),
            strict_verify=bool(config.get("strict_verify", True)),
            max_agent_calls=int(config.get("max_agent_calls") or 0) or None,
            audit_wall_timeout=(
                None if config.get("audit_wall_timeout") is None
                else float(config.get("audit_wall_timeout"))
            ),
            max_agent_tokens=int(config.get("max_agent_tokens") or 0),
            max_agent_cost_usd=float(config.get("max_agent_cost_usd") or 0.0),
            budget_verification_reserve_calls=(
                None
                if config.get("budget_verification_reserve_calls") is None
                else int(config.get("budget_verification_reserve_calls"))
            ),
            anchor_idl=getattr(ns, "anchor_idl", None),
            similarity_corpora=getattr(ns, "similarity_corpus", None),
            audit_state_store=store,
        )
    except Exception as exc:  # noqa: BLE001
        try:
            store.close()
        except (NameError, OSError):
            pass
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"workspace      : {result.workspace.root}")
    status = "paused" if result.paused else (
        result.terminal_status
        or ("incomplete" if result.incomplete_reason else "completed")
    )
    print(f"status         : {status}")
    print(f"workers        : {len(result.workers)}")
    return 4 if result.paused else (0 if result.converged else 3)


def _cmd_sota_batch(ns) -> int:
    result, routing = _run_sota_batch(ns)
    return _print_sota_batch_result(ns, result, routing)


def _cmd_analyze_any(ns) -> int:
    """Format-agnostic ingest → unpack → lift → analyze → verdict.

    Never exits non-zero on degraded analysis; exit 2 is reserved for machine-level
    failure (path missing, args malformed). Honest ``unresolved`` lists fill the gap.
    """
    from .analysis.format_detector import detect
    from .analysis.archive_router import route as archive_route
    from .analysis.blob_fingerprint import fingerprint as blob_fingerprint
    from .analysis.packing_detect import detect_packing_file
    from .analysis.refusal import decide_refusal
    from .analysis.lifters import LiftRequest
    from .analysis.lifters.registry import dual_lift

    binary = Path(ns.binary).expanduser().resolve()
    if not binary.is_file():
        print(f"error: binary not found: {binary}", file=sys.stderr)
        return 2

    # ---- L0: detect ----
    profile = detect(binary.read_bytes())
    layering: dict = {
        "l0_detect": profile.as_dict(),
        "l1_unpack": None, "l2_lift": None, "l3_analyze": None,
    }

    # ---- L1: unpack / unwrap / de-blob ----
    route_children: list[dict] = []
    if profile.container and ns.recursive:
        verdict = archive_route(binary)
        layering["l1_unpack"] = {
            "children": [
                {"name": c.name, "family": c.profile.family,
                 "confidence": c.profile.confidence}
                for c in verdict.children[:50]
            ],
            "depth_reached": verdict.depth_reached,
            "bytes_extracted": verdict.bytes_extracted,
            "truncated": verdict.truncated,
            "unresolved": verdict.unresolved[:20],
        }
        # if we produced children, analyze each child independently
        for child in verdict.children[:20]:
            if child.extracted_path:
                route_children.append({
                    "name": child.name,
                    "profile": child.profile.as_dict(),
                    "path": child.extracted_path,
                })

    packing = detect_packing_file(binary)
    layering["l1_unpack"] = layering["l1_unpack"] or {}
    layering["l1_unpack"]["packing"] = packing.as_dict()

    blob_facts = None
    if profile.family.startswith("blob") or profile.family in ("", "raw"):
        blob_facts = blob_fingerprint(binary.read_bytes())

    # ---- L2: lift ----
    # ISA-hint low-confidence block (critic HIGH): don't let a weak heuristic
    # (e.g. two x86-prologue bytes in random data) drive the lifter into flagging
    # an ARM blob as x86. Lifting requires CONFIRMED isa (>= 0.5) or explicit
    # recognised vector-table corroboration.
    lift_note = None
    isa_confident = False
    if blob_facts and blob_facts.isa_hint != "unknown":
        isa_evi = next((e for e in blob_facts.evidence
                        if e.get("signal") == "isa_hint"), {})
        isa_confident = float(isa_evi.get("confidence", 0.0)) >= 0.5 or \
            any(e.get("signal") in ("cortex-m-vector", "x86-reset-vector")
                for e in blob_facts.evidence)
    if blob_facts and isa_confident:
        req = LiftRequest(
            isa=blob_facts.isa_hint,
            bytes_code=binary.read_bytes()[: 256 * 1024],
            base_address=blob_facts.base_candidates[0] if blob_facts.base_candidates else 0,
        )
        try:
            best, alt = dual_lift(req)
            lift_note = {
                "provenance": best.provenance if best else None,
                "alt": alt.provenance if alt else None,
                "ops": len(best.ir) if best else 0,
                "confidence": best.confidence if best else 0.0,
            }
        except Exception as exc:  # noqa: BLE001
            lift_note = {"error": str(exc)}
    layering["l2_lift"] = lift_note

    # ---- L1 refusal ----
    refusal = decide_refusal(
        packing_strength=packing.strength,
        vm_region_ratio=0.0,
        iat_recoverable=True,
        decoy_suspected=False,
        packing_family=packing.family,
    )
    refusal_dict = refusal.as_dict() if refusal else None

    layering["l3_analyze"] = {
        "family": profile.family,
        "refusal": refusal_dict,
        "children_routed": len(route_children),
        "blob_facts": blob_facts.as_dict() if blob_facts else None,
    }

    out = {
        "binary": str(binary),
        "profile": profile.as_dict(),
        "layering": layering,
        "children": route_children,
        "refusal": refusal_dict,
    }

    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"[L0] family={profile.family} variant={profile.variant or '-'} "
              f"confidence={profile.confidence:.2f} container={profile.container}")
        if profile.polyglot:
            print(f"[L0] polyglot interpretations: {list(profile.polyglot)}")
        if packing.strength >= 0.5:
            print(f"[L1] packing: strength={packing.strength:.2f} family={packing.family or 'generic'}")
        if blob_facts and blob_facts.isa_hint != "unknown":
            print(f"[L1] blob: isa={blob_facts.isa_hint} endian={blob_facts.endianness} "
                  f"margin={blob_facts.base_margin:.2f}")
        if layering.get("l1_unpack", {}).get("children"):
            print(f"[L1] unpacked {len(layering['l1_unpack']['children'])} children")
        if lift_note and "error" not in lift_note:
            print(f"[L2] lifter: {lift_note['provenance']} (ops={lift_note['ops']}, "
                  f"conf={lift_note['confidence']:.2f})")
        if refusal_dict:
            print(f"[L3] REFUSAL: {refusal_dict['reason']}"
                  f" (strength={refusal_dict['strength']:.2f})")
        if profile.unresolved:
            print(f"[L3] unresolved: {list(profile.unresolved)}")
    # degraded analysis is fine; only explicit refusal marks a fail-closed state
    return 0 if refusal is None else 3


def _resolve_resume_workspace(ns) -> tuple["RunWorkspace" | None, dict | None]:
    """Load an existing workspace for deterministic-stage reuse in full-re.

    Returns:
        (workspace, routing) where routing is a synthetic engine-routing
        payload used only for progress output consistency.
    """
    from types import SimpleNamespace

    resume_path = getattr(ns, "resume_workspace", None)
    if not resume_path:
        return None, None

    from pathlib import Path

    workspace_root = Path(resume_path).expanduser().resolve()
    if not workspace_root.is_dir():
        print(
            f"error: resume workspace not found: {workspace_root}",
            file=sys.stderr,
        )
        return None, None

    from .workspace import RunWorkspace

    meta_path = workspace_root / "run.json"
    meta: dict = {}
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if not isinstance(meta, dict):
                meta = {}
        except Exception:  # noqa: BLE001
            meta = {}

    binary_path = str(Path(ns.binary).expanduser().resolve())
    meta_binary = str(meta.get("binary", ""))
    if meta_binary and Path(meta_binary).expanduser().resolve() != Path(binary_path):
        print(
            f"error: resume workspace binary mismatch: workspace has {meta_binary}, command has {binary_path}",
            file=sys.stderr,
        )
        return None, None

    # A resumable workspace must have at least exported analysis artifacts from
    # the deterministic phase; otherwise the AI pass cannot be meaningful.
    missing_artifacts = [
        "code/all_decompiled.c",
        "raw/analysis_graph.json",
        "raw/security_slices.json",
    ]
    missing = [
        f for f in missing_artifacts
        if not (workspace_root / f).is_file()
    ]
    if missing:
        print(
            f"error: resume workspace is incomplete (missing: {', '.join(missing)}). "
            "Re-run full-re without --resume-workspace to recreate artifacts.",
            file=sys.stderr,
        )
        return None, None

    routing = {
        "mode": "resume",
        "preferred_engine": "ida",
        "selected_engine": str(meta.get("engine") or _resolve_engine(ns) or "ida"),
        "final_engine": str(meta.get("engine") or _resolve_engine(ns) or "ida"),
        "reason": "resuming existing workspace (deterministic phase already complete)",
        "fallback_used": False,
        "attempts": [{"engine": str(meta.get("engine") or _resolve_engine(ns) or "ida"),
                     "workspace": str(workspace_root)}],
    }
    workspace = RunWorkspace(
        root=workspace_root,
        binary=binary_path,
        meta=meta if isinstance(meta, dict) else {},
    )
    workspace.docs_dir.mkdir(parents=True, exist_ok=True)
    workspace.log(
        "resume",
        f"resume-workspace={workspace_root}",
    )
    result = SimpleNamespace(
        workspace=str(workspace_root),
        return_code=0,
        duration_seconds=0.0,
        stage_logs=[],
        summary={"mode": "resume", "workspace": str(workspace_root)},
        artifacts={},
    )
    return workspace, {"routing": routing, "result": result}


def _cmd_full_re(ns) -> int:
    from pathlib import Path
    from .agents.orchestrator import Orchestrator
    from .workspace import RunWorkspace

    workspace, resume = _resolve_resume_workspace(ns)
    if workspace is None:
        result, routing = _run_sota_batch(ns)
        workspace = RunWorkspace(
            root=Path(result.workspace),
            binary=str(getattr(ns, "binary", "")),
            meta={},
        )
        meta_path = workspace.root / "run.json"
        try:
            workspace.meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
        except Exception:  # noqa: BLE001
            workspace.meta = {}
    else:
        result = resume["result"]
        routing = resume["routing"]

    if getattr(ns, "no_ai", False) or result.return_code != 0:
        return _print_sota_batch_result(ns, result, routing)

    workspace_root = workspace.root
    engine = routing["final_engine"]
    reviewer, note = pick_reviewer(getattr(ns, "agent", "claude"), None, allow_shell=True)
    if note:
        print(f"[angerona] {note}", file=sys.stderr)
    if getattr(ns, "json", False):
        print(json.dumps({
            "workspace": result.workspace,
            "return_code": result.return_code,
            "engine_selection": routing,
            "artifacts": result.artifacts,
            "ai": {"status": "starting", "engine": engine},
        }, indent=2, default=str))
    else:
        print(f"engine         : {engine} ({routing['mode']})")
        print(f"routing        : {routing['reason']}")
        print(f"workspace      : {result.workspace}")
        print("ai             : starting supervisor/worker analysis")

    orch = Orchestrator(load_config(engine))
    swarm = orch.swarm_run(
        ns.binary,
        objective=getattr(ns, "objective", None),
        supervisor=getattr(ns, "agent", "claude"),
        worker_analyst=getattr(ns, "agent", "claude"),
        worker_reviewer=reviewer,
        model=getattr(ns, "model", None),
        max_supervisor_rounds=getattr(ns, "rounds", 2),
        max_worker_rounds=getattr(ns, "rounds", 2),
        max_parallel=getattr(ns, "parallel", 3),
        pre_analyze=False,
        export_max_functions=getattr(ns, "max_functions", 0),
        idle_timeout=getattr(ns, "idle_timeout", 300.0),
        wall_timeout=getattr(ns, "wall_timeout", 1800.0),
        workspace=workspace,
        k_candidates=getattr(ns, "k_candidates", 1),
        adversarial_review=getattr(ns, "adversarial_review", False),
        topo_strategy=getattr(ns, "topo_strategy", "auto"),
        spawn_strategy=getattr(ns, "spawn_strategy", "search"),
        search_k=getattr(ns, "search_k", 4),
        cheap_agent=getattr(ns, "cheap_agent", None) or getattr(ns, "agent", "claude"),
        spawn_budget=getattr(ns, "spawn_budget", 12),
        complexity_tier=getattr(ns, "complexity_tier", "UNKNOWN"),
        strict_verify=not getattr(ns, "no_strict_verify", False),
        max_agent_calls=getattr(ns, "max_agent_calls", None),
        audit_wall_timeout=getattr(ns, "audit_wall_timeout", None),
        max_agent_tokens=getattr(ns, "max_agent_tokens", None),
        max_agent_cost_usd=getattr(ns, "max_agent_cost_usd", None),
        budget_verification_reserve_calls=getattr(
            ns, "budget_verification_reserve_calls", None
        ),
        anchor_idl=getattr(ns, "anchor_idl", None),
        similarity_corpora=getattr(ns, "similarity_corpus", None),
    )
    return 0 if swarm.converged else 3


def _cmd_backend_select(ns) -> int:
    from pathlib import Path
    from .execution.backend_selector import BackendSelector
    from .models.triage_profile import MultiSourceTriager

    triager = MultiSourceTriager()
    profile = triager.triage(ns.binary)
    pdict = {
        "format": profile.format.lower(),
        "stripped": profile.stripped,
        "has_interpreter": bool(profile.linker or profile.format == "ELF"),
        "has_debug_symbols": not profile.stripped if profile.stripped is not None else False,
        "is_dynamic": True,
        "is_driver": profile.compiler == "driver" or Path(ns.binary).suffix.lower() == ".sys",
        "is_boot": profile.format.lower() == "boot" or Path(ns.binary).suffix.lower() in {".img", ".iso", ".rom", ".fw"},
        "function_isolation": Path(ns.binary).suffix.lower() in {".bin", ".raw", ".shellcode"},
        "os_hint": "linux" if profile.format == "ELF" else ("windows" if profile.format == "PE" else None),
    }
    selector = BackendSelector()
    backend = selector.select(ns.binary, triage_profile=pdict)
    out = {
        "binary": ns.binary,
        "backend": backend.name,
        "fidelity": backend.fidelity,
        "os_context": backend.os_context,
        "supports_appcall": backend.supports_appcall,
        "supports_snapshot": backend.supports_snapshot,
        "requirements": backend.requirements,
        "reason": backend.reason,
    }
    print(json.dumps(out, indent=2, default=str))
    return 0


def _cmd_symbolic_probe(ns) -> int:
    from pathlib import Path
    from src.execution.backend_selector import EmulatorProbeRequest
    from src.execution.probe_runner import ProbeRunner
    from src.execution.runners.base import RunnerResult
    from src.execution.symbolic.models import SymbolicProbeRequest

    capture_ranges: list[tuple[str, int, int]] = []
    for cr in getattr(ns, "capture_range", []) or []:
        parts = cr.split(":")
        if len(parts) == 3:
            capture_ranges.append((parts[0], int(parts[1], 0), int(parts[2], 0)))

    target_addrs = []
    for ta in getattr(ns, "target_addr", []) or []:
        target_addrs.append(int(ta, 0))

    request = SymbolicProbeRequest(
        function_name=ns.function,
        function_address=int(ns.address, 0) if getattr(ns, "address", None) else None,
        args=list(ns.args or []),
        symbolic_args=list(ns.symbolic_arg or []),
        max_paths=ns.max_paths,
        max_steps=ns.max_steps,
        target_addresses=target_addrs,
        capture_memory_ranges=capture_ranges,
    )

    binary_path = Path(ns.binary)
    if (
        not binary_path.is_file()
        or binary_path.stat().st_size == 0
    ):
        # An installed angr backend still cannot load an empty/missing input.
        # Report a capability boundary instead of leaking a backend exception
        # or fabricating constraints with the offline fake runner.
        result = RunnerResult(
            status="unavailable",
            note="symbolic probe requires a non-empty binary file",
            detail={"backend": "symbolic", "binary": str(binary_path)},
        )
    else:
        runner = ProbeRunner()
        result = runner.run(
            request, binary_path=str(binary_path), backend_name="symbolic"
        )
    out = {
        "status": result.status,
        "note": result.note,
        "detail": result.detail,
        "snapshot": result.snapshot.as_dict() if result.snapshot else None,
    }
    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"status : {result.status}")
        print(f"note   : {result.note}")
        if result.snapshot:
            print(f"snapshot: {result.snapshot.address} source={result.snapshot.source}")
    return 0 if result.status == "success" else 1


def _cmd_pseudocode(ns) -> int:
    from pathlib import Path
    from src.models.analysis_graph import AnalysisGraph
    from src.summary.pseudocode_generator import PseudocodeGenerator
    from src.summary.models import SummaryReport

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    gen = PseudocodeGenerator(graph)
    structured = bool(getattr(ns, "structured", False))

    if ns.function:
        report = SummaryReport(workspace=str(ns.workspace))
        report.functions.append(gen.generate(ns.function, structured=structured))
    else:
        fns = gen.generate_all(structured=structured)
        report = SummaryReport(workspace=str(ns.workspace))
        report.functions = list(fns.values())

    out_path = Path(ns.output) if ns.output else Path(ns.workspace) / "raw" / "pseudocode.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report.write_json(out_path)
    if ns.json:
        print(json.dumps(report.as_dict(), indent=2, default=str))
    else:
        print(f"pseudocode: {len(report.functions)} function(s) -> {out_path}")
    return 0


def _cmd_function_summary(ns) -> int:
    from pathlib import Path
    from src.models.analysis_graph import AnalysisGraph
    from src.summary.function_summarizer import FunctionSummarizer
    from src.summary.models import SummaryReport

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    summarizer = FunctionSummarizer(graph)

    if ns.function:
        report = SummaryReport(workspace=str(ns.workspace))
        report.summaries = [summarizer.summarize(ns.function)]
    else:
        report = SummaryReport(workspace=str(ns.workspace))
        report.summaries = summarizer.summarize_all(top_n=ns.top_n)

    out_path = Path(ns.output) if ns.output else Path(ns.workspace) / "raw" / "function_summaries.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report.write_json(out_path)
    if ns.json:
        print(json.dumps(report.as_dict(), indent=2, default=str))
    else:
        print(f"summaries: {len(report.summaries)} function(s) -> {out_path}")
        for sm in report.summaries[:5]:
            print(f"  {sm.name or sm.function_id}: {sm.purpose[:80]}")
    return 0


def _cmd_enrich_function(ns) -> int:
    from pathlib import Path
    from .models.analysis_graph import AnalysisGraph
    from .execution.backend_selector import BackendSelector
    from .execution.enrichment_loop import EnrichmentLoop

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    selector = BackendSelector()
    loop = EnrichmentLoop(selector)
    probe_input = {}
    if ns.args:
        probe_input["args"] = ns.args
    # New behavior: capture memory ranges and backend hint.
    for cr in getattr(ns, "capture_range", []) or []:
        parts = cr.split(":")
        if len(parts) == 3:
            probe_input.setdefault("capture_memory_ranges", []).append(
                (parts[0], int(parts[1], 0), int(parts[2], 0))
            )
    if getattr(ns, "backend", None):
        probe_input["backend"] = ns.backend
    if getattr(ns, "symbolic", False):
        probe_input["backend"] = "symbolic"
        if ns.max_paths:
            probe_input.setdefault("symbolic_options", {})["max_paths"] = ns.max_paths
        if ns.max_steps:
            probe_input.setdefault("symbolic_options", {})["max_steps"] = ns.max_steps

    result = loop.enrich(graph, ns.function, probe_input=probe_input,
                         max_iterations=getattr(ns, "iterations", 1))
    out = {
        "status": result.status,
        "changes_count": len(result.changes),
        "discovered_types": result.discovered_types,
        "snapshot": None,
        "note": result.note,
        "detail": result.detail,
    }
    if result.snapshot:
        out["snapshot"] = {
            "address": result.snapshot.address,
            "length": result.snapshot.length,
            "source": result.snapshot.source,
        }
    if ns.apply and result.status == "success":
        graph_path.write_text(json.dumps(graph.to_json(), indent=2))
        out["saved"] = str(graph_path)
    print(json.dumps(out, indent=2, default=str))
    return 0 if result.status == "success" else 1


def _cmd_cfg_build(ns) -> int:
    from pathlib import Path
    from .models.analysis_graph import AnalysisGraph
    from .analysis.cfg_spine import CFGSpine

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    spine = CFGSpine(graph)

    if ns.function:
        fn = graph.get_node(ns.function)
        if fn is None:
            for n in graph.nodes:
                if n.kind == "function" and (n.name == ns.function or n.address == ns.function):
                    fn = n
                    break
        if fn is None:
            print(f"error: function not found: {ns.function}", file=sys.stderr)
            return 1
        cfgs = {fn.id: spine.build_function_cfg(fn)}
    else:
        cfgs = spine.build_all()

    out = {fid: cfg.as_dict() for fid, cfg in cfgs.items()}
    Path(ns.workspace).mkdir(parents=True, exist_ok=True)
    out_path = Path(ns.workspace) / "raw" / "cfgs.json"
    out_path.write_text(json.dumps(out, indent=2, default=str))
    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"built {len(out)} CFG(s) -> {out_path}")
    return 0


def _cmd_stack_frames(ns) -> int:
    from pathlib import Path
    from .models.analysis_graph import AnalysisGraph
    from .analysis.stack_frame_recovery import StackFrameRecovery

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    sfr = StackFrameRecovery(graph)

    if ns.function:
        fn = graph.get_node(ns.function)
        if fn is None:
            for n in graph.nodes:
                if n.kind == "function" and (n.name == ns.function or n.address == ns.function):
                    fn = n
                    break
        if fn is None:
            print(f"error: function not found: {ns.function}", file=sys.stderr)
            return 1
        frames = {fn.id: sfr.recover(fn)}
    else:
        frames = sfr.recover_all()

    out = {fid: fr.as_dict() for fid, fr in frames.items()}
    out_path = Path(ns.workspace) / "raw" / "stack_frames.json"
    out_path.write_text(json.dumps(out, indent=2, default=str))
    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"recovered {len(out)} stack frame(s) -> {out_path}")
    return 0


def _cmd_gadget_find(ns) -> int:
    from .analysis.gadget_finder import GadgetFinder

    finder = GadgetFinder(ns.binary, pointer_size=8)
    out = {
        "binary": ns.binary,
        "exact": [g.__dict__ for g in finder.find_exact_gadgets()],
        "ret": [g.__dict__ for g in finder.find_ret_gadgets(max_len=ns.max_ret_len)[:200]],
    }
    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"exact gadgets: {len(out['exact'])}")
        print(f"ret gadgets  : {len(out['ret'])}")
    return 0


def _cmd_indirect_flow(ns) -> int:
    from pathlib import Path
    from .models.analysis_graph import AnalysisGraph
    from .analysis.indirect_flow import IndirectFlowRecovery

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    ifr = IndirectFlowRecovery(graph)

    switches = ifr.find_switch_tables()
    ptr_tables = ifr.find_function_pointer_tables()
    out = {
        "switch_tables": [t.__dict__ for t in switches],
        "function_pointer_tables": [t.__dict__ for t in ptr_tables],
    }
    out_path = Path(ns.workspace) / "raw" / "indirect_flow.json"
    out_path.write_text(json.dumps(out, indent=2, default=str))
    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"switch tables: {len(switches)}")
        print(f"function-pointer tables: {len(ptr_tables)}")
    return 0


def _cmd_compiler_detect(ns) -> int:
    from pathlib import Path
    from src.analysis.compiler_personality import CompilerPersonalityDetector

    path = Path(ns.binary)
    sample_bytes = path.read_bytes() if path.exists() else b""
    strings = _extract_strings(sample_bytes)
    detector = CompilerPersonalityDetector(sample_bytes=sample_bytes, strings=strings)
    result = detector.detect()
    if ns.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        compiler = result.get("compiler", {})
        packer = result.get("packer", {})
        protector = result.get("protector", {})
        obf = result.get("obfuscation", {})
        print(f"compiler      : {compiler.get('name') or '-'} ({compiler.get('confidence')})")
        print(f"packer        : {packer.get('name') or '-'} ({packer.get('confidence')})")
        print(f"protector     : {protector.get('name') or '-'} ({protector.get('confidence')})")
        print(f"entropy       : {obf.get('entropy')}  high_entropy={obf.get('high_entropy')}")
        print(f"suggested     : {result.get('suggested_backend')}")
    return 0


def _extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Best-effort ASCII/UTF-8 string extraction for CLI triage."""
    import re
    ascii_strings = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    decoded: list[str] = []
    for s in ascii_strings:
        try:
            decoded.append(s.decode("ascii"))
        except Exception:
            pass
    # UTF-16LE common in Windows binaries.
    decoded.extend(re.findall(r"[\x20-\x7e]{%d,}" % min_len,
                              data.decode("utf-16le", errors="ignore")))
    return decoded


def _cmd_custom_isa_list(ns) -> int:
    from .processors._register_defaults import register_defaults
    register_defaults()
    from .processors.registry import ProcessorRegistry
    names = ProcessorRegistry.list()
    if getattr(ns, "json", False):
        print(json.dumps({"processors": names}, indent=2))
    else:
        print("registered custom ISA processors:")
        for name in names:
            print(f"  - {name}")
    return 0


def _cmd_analyze_custom(ns) -> int:
    from pathlib import Path
    from .processors._register_defaults import register_defaults
    register_defaults()
    from .processors.analyzer import CustomIsaAnalyzer

    analyzer = CustomIsaAnalyzer(ns.isa)
    result = analyzer.analyze(ns.binary, base_addr=ns.base_addr)
    graph = result["graph"]
    out = {
        "isa": result["processor"],
        "nodes": graph.node_count,
        "edges": graph.edge_count,
        "cfgs": len(result["cfgs"]),
        "frames": len(result["frames"]),
        "indirect_tables": len(result["indirect_tables"]),
    }
    if ns.json:
        # Also stream full graph JSON for programmatic use.
        print(json.dumps({**out, "graph": graph.to_json()}, indent=2, default=str))
    else:
        print(f"isa           : {out['isa']}")
        print(f"nodes/edges   : {out['nodes']} / {out['edges']}")
        print(f"cfgs/frames   : {out['cfgs']} / {out['frames']}")
        print(f"indirect      : {out['indirect_tables']}")
        dest = Path(ns.output) if ns.output else Path(ns.binary).with_suffix(".custom_graph.json")
        dest.write_text(json.dumps(graph.to_json(), indent=2, default=str))
        print(f"graph saved   : {dest}")
    return 0


# ------------------------------------------------------- the one unified analysis flow


def _cmd_execution_status(ns) -> int:
    from pathlib import Path
    from src.execution.backend_selector import BackendSelector
    from src.execution.probe_runner import ProbeRunner
    from src.execution.providers import ProviderRegistry
    from src.mcp.radare2_provider import Radare2McpProvider
    from src.models.triage_profile import MultiSourceTriager

    if not Path(ns.binary).exists():
        print(f"error: binary not found: {ns.binary}", file=sys.stderr)
        return 1

    selector = BackendSelector()
    runner = ProbeRunner(selector)

    profile = MultiSourceTriager().triage(ns.binary)
    selected = selector.select(ns.binary, triage_profile={
        "format": profile.format.lower(),
        "has_interpreter": bool(profile.linker or profile.format == "ELF"),
        "has_debug_symbols": not profile.stripped if profile.stripped is not None else False,
        "is_dynamic": True,
        "is_driver": profile.compiler == "driver" or Path(ns.binary).suffix.lower() == ".sys",
        "is_boot": profile.format.lower() == "boot",
        "os_hint": "linux" if profile.format == "ELF" else None,
    })
    available = runner.available()
    providers = ProviderRegistry().status()
    analysis_mcp = {"radare2": Radare2McpProvider().status()}
    out = {
        "binary": ns.binary,
        "selected_backend": selected.name,
        "fidelity": selected.fidelity,
        "supports_appcall": selected.supports_appcall,
        "available_runners": available,
        "runtime_providers": providers,
        "analysis_mcp": analysis_mcp,
    }
    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"selected backend: {selected.name} ({selected.fidelity})")
        print("available runners:")
        for name, ok in available.items():
            print(f"  {'✓' if ok else '✗'} {name}")
        print("runtime trace providers:")
        for name, row in providers.items():
            print(f"  {'✓' if row['available'] else '✗'} {name}")
        print("analysis MCP providers:")
        for name, row in analysis_mcp.items():
            print(f"  {'✓' if row['available'] else '✗'} {name}")
    return 0


def _print_provider_plan(plan) -> None:
    print(json.dumps({
        "provider": plan.provider,
        "executable": plan.executable,
        "argv": list(plan.argv),
        "capabilities": plan.capabilities.__dict__,
        "output_path": plan.output_path,
        "metadata": plan.metadata,
    }, indent=2))


def _cmd_qemu_plan(ns) -> int:
    from src.execution.providers import QemuUserProvider

    plan = QemuUserProvider().launch_plan(
        ns.binary,
        argv=ns.arg or [],
        architecture=ns.architecture,
        sysroot=ns.sysroot,
        cpu=ns.cpu,
        syscall_trace=ns.strace,
    )
    _print_provider_plan(plan)
    return 0


def _cmd_qemu_plugin_plan(ns) -> int:
    from src.execution.providers import QemuTcgPluginProvider

    kwargs = {
        "architecture": ns.architecture,
        "plugin_arguments": ns.plugin_arg or [],
    }
    if ns.qemu_arg is not None:
        kwargs["qemu_arguments"] = ns.qemu_arg
    plan = QemuTcgPluginProvider().plugin_plan(ns.plugin, **kwargs)
    _print_provider_plan(plan)
    return 0


def _cmd_bpftrace_plan(ns) -> int:
    from src.execution.providers import BpftraceProvider

    _print_provider_plan(BpftraceProvider().script_plan(
        ns.script,
        dry_run=ns.dry_run,
        privileged=True if ns.sudo else None,
    ))
    return 0


def _cmd_radare2_mcp_plan(ns) -> int:
    from src.mcp.radare2_provider import Radare2McpProvider

    plan = Radare2McpProvider().launch_plan(ns.allowed_root, minimal_tools=not ns.all_tools)
    print(json.dumps({
        "provider": "radare2-mcp",
        "executable": plan.executable,
        "argv": list(plan.argv),
        "metadata": plan.metadata,
    }, indent=2))
    return 0


def _cmd_probe_run(ns) -> int:
    from pathlib import Path
    from src.execution.backend_selector import EmulatorProbeRequest
    from src.execution.probe_runner import ProbeRunner

    capture_ranges: list[tuple[str, int, int]] = []
    for cr in getattr(ns, "capture_range", []) or []:
        parts = cr.split(":")
        if len(parts) == 3:
            capture_ranges.append((parts[0], int(parts[1], 0), int(parts[2], 0)))

    backend = ns.backend
    if getattr(ns, "symbolic", False):
        backend = "symbolic"
    probe = EmulatorProbeRequest(
        function_name=ns.function,
        args=list(ns.args or []),
        capture_memory_ranges=capture_ranges,
        expected_backend=backend,
        entry_address=int(ns.address, 0) if getattr(ns, "address", None) else None,
        isa=getattr(ns, "isa", None),
        max_instructions=getattr(ns, "max_instructions", 2_000),
        max_trace_events=getattr(ns, "max_trace_events", 16_384),
    )
    runner = ProbeRunner()
    result = runner.run(probe, binary_path=ns.binary, backend_name=backend)
    out = {
        "status": result.status,
        "note": result.note,
        "detail": result.detail,
        "snapshot": result.snapshot.as_dict() if result.snapshot else None,
        "snapshots": [snapshot.as_dict() for snapshot in result.snapshots],
        "memory_image": result.memory_image.as_dict() if result.memory_image else None,
        "events": [event.as_dict() for event in result.events],
    }
    if result.snapshot and ns.output:
        Path(ns.output).write_bytes(result.snapshot.to_bytes())
        out["saved_bytes"] = ns.output

    if ns.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"status : {result.status}")
        print(f"note   : {result.note}")
        if result.snapshot:
            print(f"snapshot: {result.snapshot.address} length={result.snapshot.length} source={result.snapshot.source}")
    return 0 if result.status == "success" else 1


def _cmd_enrich_workspace(ns) -> int:
    from pathlib import Path
    from .models.analysis_graph import AnalysisGraph
    from .execution.backend_selector import BackendSelector
    from .execution.enrichment_loop import EnrichmentLoop

    graph_path = Path(ns.workspace) / "raw" / "analysis_graph.json"
    if not graph_path.exists():
        print(f"error: no analysis graph at {graph_path}", file=sys.stderr)
        return 1
    graph = AnalysisGraph.load_json(graph_path)
    selector = BackendSelector()
    loop = EnrichmentLoop(selector)
    probe_input: dict = {}
    if ns.args:
        probe_input["args"] = ns.args
    if getattr(ns, "backend", None):
        probe_input["backend"] = ns.backend
    if getattr(ns, "symbolic", False):
        probe_input["backend"] = "symbolic"
    for cr in getattr(ns, "capture_range", []) or []:
        parts = cr.split(":")
        if len(parts) == 3:
            probe_input.setdefault("capture_memory_ranges", []).append(
                (parts[0], int(parts[1], 0), int(parts[2], 0))
            )
    result = loop.enrich(graph, ns.function, probe_input=probe_input,
                         max_iterations=getattr(ns, "iterations", 1))
    if result.status == "success" and ns.apply:
        graph_path.write_text(json.dumps(graph.to_json(), indent=2))
    out = {
        "status": result.status,
        "changes_count": len(result.changes),
        "snapshot": result.snapshot.as_dict() if result.snapshot else None,
        "note": result.note,
        "detail": result.detail,
    }
    print(json.dumps(out, indent=2, default=str))
    return 0 if result.status == "success" else 1


def _cmd_update_ghidra(ns) -> int:
    from . import updater

    def progress(done, total):
        print(f"\r  downloading... {done * 100 // total}% "
              f"({done // (1024*1024)}/{total // (1024*1024)} MB)", end="", file=sys.stderr, flush=True)

    try:
        res = updater.update(check_only=ns.check, force=ns.force, prune=ns.prune,
                             on_progress=None if ns.check else progress)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not ns.check:
        print("", file=sys.stderr)
    print(json.dumps(res, indent=2))
    return 0


def _cmd_mcp_serve(ns) -> int:
    engine = _resolve_engine(ns)
    if engine == "ida":
        from .mcp.config import server_launch_spec
        cfg = load_config("ida")
        ok, msg = cfg.ida_ready()
        if not ok:
            print(f"error: {msg}", file=sys.stderr)
            return 1
        command, args, env = server_launch_spec(ns.binary, cfg)
        full_env = dict(os.environ)
        full_env.update(env)
        os.execve(command, [command, *args], full_env)  # replace this process with the server
        return 0  # unreachable
    from .mcp.server import main as mcp_main
    return mcp_main(["--binary", ns.binary] if ns.binary else [])


# ------------------------------------------------------------- reviewer selection

def _agent_availability() -> dict:
    from .agents.runtime import ClaudeCodeAgent, CodexAgent
    return {"claude": ClaudeCodeAgent().available(), "codex": CodexAgent().available()}


def pick_reviewer(analyst: str, explicit: str | None, allow_shell: bool,
                  have: dict | None = None) -> tuple[str | None, str | None]:
    """Choose a reviewer that works with whatever agents are installed.

    Prefers a DIFFERENT agent (cross-model reality check) when available; otherwise a
    second independent session of the SAME agent. Codex only runs with full access
    (it cancels MCP calls otherwise), so it's usable only when allow_shell is set.
    """
    have = have if have is not None else _agent_availability()

    def usable(a: str) -> bool:
        if not have.get(a):
            return False
        if a == "codex" and not allow_shell:
            return False
        return True

    if explicit:
        if usable(explicit):
            return explicit, None
        for cand in (analyst, "claude", "codex"):
            if usable(cand):
                reason = f"reviewer '{explicit}' unavailable" + (
                    " (codex needs full access)" if explicit == "codex" and have.get("codex") else "")
                return cand, f"{reason}; using '{cand}' as reviewer instead."
        return None, f"reviewer '{explicit}' unavailable and no usable fallback; skipping review."

    # Rule: codex is unreliable (it hangs on MCP approval / picks the wrong
    # binary). Prefer an INDEPENDENT CLAUDE session as reviewer; only fall back to
    # codex when it is the only other usable agent AND full access is allowed.
    if analyst == "claude":
        # independent claude review is the safe default
        if usable("claude"):
            return "claude", ("codex reviewer is unreliable (hangs on MCP approval); "
                              "using an independent claude session for review instead.")
        if usable("codex"):
            return "codex", "only codex usable as reviewer; expect possible MCP-approval hang."
    else:
        # analyst is codex -> prefer claude as reviewer, else independent codex
        if usable("claude"):
            return "claude", None
        if usable("codex"):
            return "codex", "only codex usable; using a second independent codex session as reviewer."
    if usable(analyst):
        return analyst, (f"only one agent usable; using a second independent {analyst} session "
                         f"as the reviewer.")
    return None, "no usable reviewer agent available; skipping review."


# ------------------------------------------------------- the one unified analysis flow

def _cmd_run(ns) -> int:
    from .agents.orchestrator import Orchestrator
    if getattr(ns, "resume_workspace", None):
        ns.workspace = ns.resume_workspace
        return _cmd_audit_resume(ns)
    # ---- Part 17: privacy-mode preset ----
    # One flag = local engine + no-network sandbox + localhost-only UI + the
    # dynamic oracle off (no sample egress / execution unless explicit). This is
    # the configuration to mandate for customer/IP-sensitive or malware samples.
    privacy_error = _apply_privacy_mode(ns)
    if privacy_error:
        print(f"error: {privacy_error}", file=sys.stderr)
        return 1
    if getattr(ns, "privacy_mode", False):
        print("[angerona] privacy-mode: sample stays local; no-network sandbox on; "
              "local LLM enforced; dynamic execution disabled.",
              file=sys.stderr, flush=True)
    if ns.sandbox:
        os.environ["ANGERONA_SANDBOX"] = "1"
    engine = _resolve_engine(ns)
    # Fail fast on configuration problems before any target bytes are analyzed.
    if getattr(ns, "anchor_idl", None):
        from .analysis.anchor_idl import resolve_anchor_idl
        resolve_anchor_idl(ns.binary, ns.anchor_idl)
    from .boot_problems import check_boot
    boot = check_boot(engine=engine, agent=ns.agent, sandbox=bool(ns.sandbox),
                      binary=ns.binary, min_free_bytes=8 * 1024 * 1024)
    if not boot.ok:
        print(boot.format(), file=sys.stderr)
        return 1
    reviewer, note = pick_reviewer(ns.agent, None, allow_shell=True)
    if note:
        print(f"[angerona] {note}", file=sys.stderr)
    orch = Orchestrator(load_config(engine))
    try:
        res = orch.swarm_run(
            ns.binary, objective=ns.objective, supervisor=ns.agent,
            worker_analyst=ns.agent, worker_reviewer=reviewer, model=ns.model,
            max_supervisor_rounds=ns.rounds, max_worker_rounds=ns.rounds,
            max_parallel=ns.parallel, pre_analyze=not ns.no_pre_analyze,
            idle_timeout=ns.idle_timeout, wall_timeout=ns.wall_timeout,
            k_candidates=ns.k_candidates, adversarial_review=ns.adversarial_review,
            topo_strategy=ns.topo_strategy,
            spawn_strategy=ns.spawn_strategy, search_k=ns.search_k,
            cheap_agent=ns.cheap_agent or ns.agent, spawn_budget=ns.spawn_budget,
            complexity_tier=ns.complexity_tier,
            strict_verify=not ns.no_strict_verify,
            max_agent_calls=ns.max_agent_calls,
            audit_wall_timeout=ns.audit_wall_timeout,
            max_agent_tokens=ns.max_agent_tokens,
            max_agent_cost_usd=ns.max_agent_cost_usd,
            budget_verification_reserve_calls=ns.budget_verification_reserve_calls,
            anchor_idl=getattr(ns, "anchor_idl", None),
            similarity_corpora=getattr(ns, "similarity_corpus", None),
        )
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("\n" + "=" * 70)
    status = "COMPLETE" if res.converged else "PARTIAL (coverage not fully satisfied)"
    print(f"ANALYSIS {status} [engine={engine}] — supervisor ran {res.supervisor_rounds} round(s), "
          f"spawned {len(res.workers)} worker agent(s)")
    for w in res.workers:
        print(f"  - {w.spec.id}: {w.spec.title}  (converged={w.converged})")
    print(f"Workspace: {res.workspace.root}")
    print("  -> docs/consolidated_report.md  docs/findings.md  workers/<id>/  code/  raw/")
    print("=" * 70)
    print(res.final_report[:4000])
    return 0 if res.converged else 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="angerona",
                                description="Drive IDA Pro / Ghidra RE with subscription AI agents "
                                            "(Claude Code / Codex).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("run", help="Analyze a target — an AI supervisor decides how many worker agents to "
                                   "spawn and how to divide the work; each worker runs analyze->review until "
                                   "satisfied; results are consolidated. (Small targets analyzed directly.)")
    s.add_argument("binary")
    _add_engine_arg(s)
    s.add_argument("--agent", choices=["claude", "codex"], default="claude",
                   help="Which subscription agent drives the analysis (supervisor + workers).")
    s.add_argument("--objective", help="Custom research objective.")
    s.add_argument(
        "--resume-workspace",
        help="Resume this audit workspace from its latest verified safe-point snapshot.",
    )
    s.add_argument("--model", help="Override model (else the CLI's default subscription model).")
    s.add_argument(
        "--anchor-idl",
        help="Anchor IDL JSON. If omitted, only program-id-validated nearby IDLs are auto-associated.",
    )
    s.add_argument(
        "--similarity-corpus", action="append",
        help="Trusted named code-export directory for similarity/symbol recovery; repeatable.",
    )
    s.add_argument("--sandbox", action="store_true",
                   help="Run the RE parse step in a no-network, read-only bwrap sandbox (recommended for malware).")
    s.add_argument("--privacy-mode", action="store_true",
                   help="Enforce --agent codex through a local OpenAI-compatible endpoint, "
                         "no-network sandboxing, and disable dynamic/write tools.")
    s.add_argument("--rounds", type=int, default=2, help="Max iteration rounds (supervisor and per-worker).")
    s.add_argument("--parallel", type=int, default=3, help="Max worker agents running concurrently.")
    s.add_argument("--no-pre-analyze", action="store_true")
    s.add_argument("--idle-timeout", type=float, default=300.0)
    s.add_argument("--wall-timeout", type=float, default=1800.0)
    s.add_argument("--k-candidates", type=int, default=1,
                   help="Part 18 P4: run the analyst K times per round and keep the "
                         "best-scoring report (trajectory search). >1 costs more calls.")
    s.add_argument("--adversarial-review", action="store_true",
                   help="Part 18 P3: add a 2nd hostile reviewer pass that must DISPROVE "
                         "each claim (Crawford/RARE defense); forces NEEDS_WORK on contradiction.")
    s.add_argument("--topo-strategy", choices=["auto", "fixed"], default="auto",
                   help="Part 18 P5: auto-discover worker topology from binary traits "
                         "(obfuscation/size/uncertainty). 'fixed' = trust the LLM plan only.")
    s.add_argument("--spawn-strategy", choices=["search", "llm"], default="search",
                   help="Part 19 U1: 'search' evaluates K splits and keeps the best-scoring "
                         "one; 'llm' = legacy single greedy plan.")
    s.add_argument("--search-k", type=int, default=4,
                   help="Part 19 U1: candidate splits to evaluate in spawn search.")
    s.add_argument("--cheap-agent", default=None,
                   help="Part 19 U4: agent used for clean/low-difficulty slices. "
                        "Defaults to --agent; pass codex explicitly to enable mixed routing.")
    s.add_argument("--spawn-budget", type=int, default=12,
                   help="Part 19 U6: global K-candidate budget across workers.")
    s.add_argument("--complexity-tier", default="UNKNOWN",
                   choices=["UNKNOWN", "LOW", "MEDIUM", "HIGH"],
                   help="Part 19 U7: drives adaptive parallelism (HIGH => more parallel).")
    s.add_argument("--no-strict-verify", action="store_true",
                   help="Disable the strict verify gate. By default the binary reality-anchor "
                         "runs every round and treats missing/weak evidence as NEEDS_WORK.")
    _add_audit_budget_args(s)
    s.set_defaults(func=_cmd_run)

    s = sub.add_parser("status", help="Show IDA + Ghidra engine status.")
    _add_engine_arg(s)
    s.set_defaults(func=_cmd_status)

    s = sub.add_parser("doctor", help="Run a minimal real analysis to prove an engine is operational.")
    s.add_argument("binary", nargs="?", help="Probe binary; defaults to the current Python executable.")
    s.add_argument("--engine", choices=["ida", "ghidra", "all"], default="all")
    s.add_argument("--timeout", type=int, default=120)
    s.set_defaults(func=_cmd_doctor)

    s = sub.add_parser(
        "android-doctor",
        help="Verify the direct-APK static audit toolchain (runtime is optional).",
    )
    s.add_argument(
        "--runtime", action="store_true",
        help="Also require an ADB device and Frida for optional runtime validation.",
    )
    s.add_argument(
        "--static-only", action="store_true",
        help=argparse.SUPPRESS,
    )
    s.add_argument(
        "--require-ai", action="store_true",
        help="Also require a Claude or Codex CLI used by --ai-review.",
    )
    s.add_argument(
        "--runtime-provider", choices=["auto", "avd", "connected"], default="auto",
        help="Runtime target: owned official AVD by default, or an explicitly connected lab target.",
    )
    s.add_argument("--runtime-api", type=int, default=35, help="Pinned AOSP AVD API (default: 35).")
    s.add_argument("--runtime-sdk-root", default="", help="Coherent Android SDK root override.")
    s.add_argument(
        "--device-serial", default="",
        help="Required explicit authorized serial for --runtime-provider connected.",
    )
    s.set_defaults(func=_cmd_android_doctor)

    s = sub.add_parser(
        "android-audit",
        help="Run the evidence-tiered Android APK audit harness.",
    )
    s.add_argument("apk", help="Authorized APK artifact to audit.")
    s.add_argument("--expected-package", help="Expected Android application id.")
    s.add_argument("--device-serial", default="", help="ADB device serial for runtime witnesses.")
    s.add_argument(
        "--runtime", action="store_true",
        help="Opt in to ADB/Frida runtime validation; direct-APK static audit is the default.",
    )
    s.add_argument("--no-runtime", action="store_true", help=argparse.SUPPRESS)
    s.add_argument(
        "--runtime-provider", choices=["auto", "avd", "connected"], default="auto",
        help="auto/avd owns a disposable official headless AVD; connected requires a lab target.",
    )
    s.add_argument("--runtime-api", type=int, default=35, help="Pinned AOSP AVD API (default: 35).")
    s.add_argument(
        "--runtime-abi", choices=["auto", "x86_64", "arm64-v8a", "x86", "armeabi-v7a"],
        default="auto", help="AVD ABI; auto requires native host compatibility.",
    )
    s.add_argument("--runtime-image-tag", default="default", help="Rootable AOSP system-image tag.")
    s.add_argument("--runtime-sdk-root", default="", help="Coherent Android SDK root override.")
    s.add_argument(
        "--runtime-auto-provision", action="store_true",
        help="Download a missing pinned image/Frida server; SDK licenses must already be accepted.",
    )
    s.add_argument(
        "--allow-native-translation", action="store_true",
        help="Exploratory only: permit a non-native ABI lane; it cannot close native coverage.",
    )
    s.add_argument(
        "--runtime-network", choices=["deny", "allow"], default="deny",
        help="Guest egress policy; deny is the safe default, allow requires engagement approval.",
    )
    s.add_argument("--no-rules", action="store_true", help="Run inventory/provenance without security rules.")
    s.add_argument("--timeout", type=int, default=120, help="Per-tool timeout in seconds.")
    s.add_argument(
        "--related-apk", action="append", default=[],
        help="Related APK for cross-package/collusion analysis; repeatable.",
    )
    s.add_argument("--baseline", help="Trusted upstream baseline index JSON.")
    s.add_argument(
        "--authorization-ref",
        help="Engagement/ticket/authorization reference recorded in report metadata.",
    )
    s.add_argument("--output", help="Write the complete JSON report to this path.")
    s.add_argument("--native-ownership-manifest", help="Required before native-code analysis may launch.")
    s.add_argument("--native-universe", help="Required before native-code analysis may launch.")
    s.add_argument("--native-lane-epoch-id", default="", help="Required before native-code analysis may launch.")
    s.add_argument(
        "--ai-review", action="store_true",
        help="Run the full supervisor/worker/reviewer/adversarial-critic AI swarm.",
    )
    s.add_argument(
        "--ai-agent", choices=["claude", "codex"], default="claude",
        help="AI runtime for --ai-review (default: claude).",
    )
    s.add_argument("--model", help="Optional provider model override for --ai-review.")
    s.add_argument(
        "--ai-reviewer-agent", choices=["auto", "claude", "codex"], default="auto",
        help="Independent reviewer runtime; auto prefers Codex and falls back to the primary agent.",
    )
    s.add_argument("--ai-reviewer-model", help="Optional independent reviewer model override.")
    s.add_argument(
        "--ai-reviewer-reasoning",
        choices=["low", "medium", "high", "xhigh", "max", "ultra"],
        default="high",
        help="Codex reviewer reasoning effort (default: high).",
    )
    s.add_argument(
        "--ai-dangerous-skip-permissions", action="store_true",
        help="Use Claude dangerous-skip and Codex yolo mode for every Android AI role.",
    )
    s.add_argument(
        "--ai-rounds", type=int, default=2,
        help="Maximum supervisor and per-worker convergence rounds (default: 2).",
    )
    s.add_argument(
        "--ai-parallel", type=int, default=3,
        help="Maximum Android AI workers running concurrently (default: 3).",
    )
    s.set_defaults(func=_cmd_android_audit)

    s = sub.add_parser("install", help="Register the engine's MCP server with agents.")
    _add_engine_arg(s, with_both=True)
    s.add_argument("--agent", action="append", choices=["claude", "codex"], help="Repeatable; default both.")
    s.add_argument("--binary", help="Pin a default target binary into the registration.")
    s.set_defaults(func=_cmd_install)

    s = sub.add_parser("analyze", help="Raw headless analysis summary (no agent).")
    s.add_argument("binary")
    _add_engine_arg(s)
    s.add_argument("--decompile", action="store_true")
    s.add_argument("--max-functions", type=int, default=0)
    s.add_argument("--force", action="store_true")
    s.add_argument("--sandbox", action="store_true", help="Run the parse in a no-network bwrap sandbox.")
    s.add_argument("--no-timeout", action="store_true",
                   help="Let engine analysis finish naturally without a subprocess time limit.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_analyze)

    s = sub.add_parser("analyze-any",
                       help="Format-agnostic pipeline: detect → unpack → lift → analyze → optional agent loop.")
    s.add_argument("binary")
    s.add_argument("--recursive", action="store_true",
                   help="Recursively unpack containers before analysis (APK/IPA/firmware v1 cap)")
    s.add_argument("--engine", default=None,
                   help="Explicit RE engine override (ida, ghidra); default: FormatProfile hint.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_analyze_any)

    s = sub.add_parser("decompile", help="Decompile a single function (no agent).")
    s.add_argument("binary")
    s.add_argument("function")
    _add_engine_arg(s)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_decompile)

    s = sub.add_parser("update-ghidra", help="Check for / install the newest Ghidra release into vendor/.")
    s.add_argument("--check", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--prune", action="store_true")
    s.set_defaults(func=_cmd_update_ghidra)

    s = sub.add_parser("mcp-serve", help="Run the stdio MCP server for the selected engine.")
    _add_engine_arg(s)
    s.add_argument("--binary")
    s.set_defaults(func=_cmd_mcp_serve)

    s = sub.add_parser("web", help="Launch the web UI (browse runs, view code/docs/agent activity, start runs).")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--allow-remote", action="store_true",
                   help="Allow binding to non-loopback interfaces; requires an auth token.")
    s.add_argument("--auth-token", help="Bearer token; prefer ANGERONA_WEB_AUTH_TOKEN.")
    s.set_defaults(func=_cmd_web)

    s = sub.add_parser("guard-workspace",
                         help="Part 17: pre-commit guard — fail (exit 1) if workspaces/ "
                              "is tracked/staged (proprietary/malware code leak check).")
    s.add_argument("--home", help="Override $ANGERONA_HOME (state dir).")
    s.set_defaults(func=_cmd_guard_workspace)

    s = sub.add_parser("sota-analyze",
                       help="State-of-the-art analysis: triage + graph + signatures + sinks.")
    s.add_argument("binary")
    _add_engine_arg(s)
    s.add_argument("--max-functions", type=int, default=0)
    s.add_argument("--force", action="store_true")
    s.add_argument("--sandbox", action="store_true")
    s.add_argument("--no-timeout", action="store_true",
                   help="Let engine analysis finish naturally without a subprocess time limit.")
    s.add_argument("--signature-db", help="Path to a library signature DB JSON.")
    s.add_argument("--isa", help="Use a custom ISA processor (e.g. solana-bpf, evm) instead of IDA/Ghidra.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_sota_analyze)

    s = sub.add_parser("graph-query",
                       help="Query the cross-reference reasoning graph from a previous sota-analyze run.")
    s.add_argument("workspace")
    s.add_argument("query", choices=["callers", "callees", "paths", "sinks", "summary"])
    s.add_argument("--target")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_graph_query)

    s = sub.add_parser("checkpoint-list",
                       help="List checkpoints for a sota-analyze workspace.")
    s.add_argument("workspace")
    s.set_defaults(func=_cmd_checkpoint_list)

    s = sub.add_parser("checkpoint-revert",
                       help="Rollback mutations to a specific checkpoint.")
    s.add_argument("workspace")
    s.add_argument("checkpoint_id", type=int)
    s.set_defaults(func=_cmd_checkpoint_revert)

    s = sub.add_parser(
        "audit-status",
        help="Inspect durable whole-audit resume state and active-process lease.",
    )
    s.add_argument("workspace")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_audit_status)

    s = sub.add_parser(
        "audit-trace",
        help="Verify and inspect the correlated, tamper-evident audit event timeline.",
    )
    s.add_argument("workspace")
    s.add_argument("--since", type=int, default=0, help="Only events after this sequence.")
    s.add_argument("--limit", type=int, default=500, choices=range(1, 10001), metavar="1..10000")
    s.add_argument("--component")
    s.add_argument("--action")
    s.add_argument("--status")
    s.add_argument("--no-import-child", action="store_true")
    s.add_argument("--rebuild-mirror", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_audit_trace)

    s = sub.add_parser(
        "audit-pause",
        help="Cooperatively pause an audit after active workers reach committed safe points.",
    )
    s.add_argument("workspace")
    s.add_argument("--reason", default="")
    s.set_defaults(func=_cmd_audit_pause)

    s = sub.add_parser(
        "audit-instruct",
        help=(
            "Queue a hash-verified operator instruction for future workers or final "
            "consolidation without weakening fixed audit gates."
        ),
    )
    s.add_argument("workspace")
    s.add_argument("instruction", help="Bounded operator instruction (maximum 2000 characters).")
    s.add_argument(
        "--scope",
        choices=["all", "future-dispatches", "final-report"],
        default="all",
        help="Where the supervisor may apply the instruction.",
    )
    s.set_defaults(func=_cmd_audit_instruct)

    s = sub.add_parser(
        "audit-resume",
        help="Resume an interrupted or paused audit with its exact checkpointed configuration.",
    )
    s.add_argument("workspace")
    s.add_argument(
        "--binary",
        help="Override a relocated target path; its size and SHA-256 must match the snapshot.",
    )
    s.add_argument(
        "--anchor-idl",
        help="Relocated Anchor IDL; its immutable content identity must match the checkpoint.",
    )
    s.add_argument(
        "--similarity-corpus", action="append",
        help="Relocated identical corpus export; repeat for every checkpointed corpus.",
    )
    s.set_defaults(func=_cmd_audit_resume)

    s = sub.add_parser("sota-batch",
                       help="Headless full RE pipeline with automatic IDA-first engine routing.")
    s.add_argument("binary")
    _add_engine_arg(s)
    s.add_argument("--max-functions", type=int, default=0)
    s.add_argument("--force", action="store_true")
    s.add_argument("--sandbox", action="store_true")
    s.add_argument("--signature-db", help="Path to a library signature DB JSON.")
    s.add_argument("--type-library", help="Path to a type library JSON.")
    s.add_argument("--output-dir", help="Override output directory.")
    s.add_argument("--stages", help="Comma-separated stage list to run.")
    s.add_argument("--log-level", default="INFO")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_sota_batch)

    s = sub.add_parser(
        "full-re",
        help=(
            "Analyze one file end-to-end. IDA Pro is preferred automatically; "
            "unsupported targets fall back to Ghidra."
        ),
    )
    s.add_argument("binary")
    _add_engine_arg(s)
    s.add_argument("--max-functions", type=int, default=0)
    s.add_argument("--force", action="store_true")
    s.add_argument("--sandbox", action="store_true")
    s.add_argument("--signature-db", help="Path to a library signature DB JSON.")
    s.add_argument("--type-library", help="Path to a type library JSON.")
    s.add_argument("--output-dir", help="Override output directory.")
    s.add_argument("--stages", help="Comma-separated stage list to run.")
    s.add_argument("--log-level", default="INFO")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-ai", action="store_true",
                   help="Stop after deterministic RE artifacts; do not start AI workers.")
    s.add_argument("--agent", choices=["claude", "codex"], default="claude")
    s.add_argument("--objective", help="Custom research objective for AI workers.")
    s.add_argument("--resume-workspace",
                   help="Resume full-re from an existing workspace without re-running deterministic RE.")
    s.add_argument("--model", help="Override model for the subscription agent.")
    s.add_argument(
        "--anchor-idl",
        help="Anchor IDL JSON. Automatic discovery requires a binary-matching program id.",
    )
    s.add_argument(
        "--similarity-corpus", action="append",
        help="Trusted named code-export directory for similarity/symbol recovery; repeatable.",
    )
    s.add_argument("--rounds", type=int, default=2)
    s.add_argument("--parallel", type=int, default=3)
    s.add_argument("--idle-timeout", type=float, default=300.0)
    s.add_argument("--wall-timeout", type=float, default=1800.0)
    s.add_argument("--k-candidates", type=int, default=1)
    s.add_argument("--adversarial-review", action="store_true")
    s.add_argument("--topo-strategy", choices=["auto", "fixed"], default="auto")
    s.add_argument("--spawn-strategy", choices=["search", "llm"], default="search")
    s.add_argument("--search-k", type=int, default=4)
    s.add_argument("--cheap-agent", default=None)
    s.add_argument("--spawn-budget", type=int, default=12)
    s.add_argument("--complexity-tier", default="UNKNOWN",
                   choices=["UNKNOWN", "LOW", "MEDIUM", "HIGH"])
    s.add_argument("--no-strict-verify", action="store_true")
    _add_audit_budget_args(s)
    s.set_defaults(func=_cmd_full_re)

    s = sub.add_parser("backend-select",
                       help="Select the best execution backend for a binary.")
    s.add_argument("binary")
    s.set_defaults(func=_cmd_backend_select)

    s = sub.add_parser("enrich-function",
                       help="Run Appcall-style enrichment probe for a function in a sota workspace.")
    s.add_argument("workspace")
    s.add_argument("function")
    s.add_argument("--args", nargs="*", help="Positional arguments for the probe.")
    s.add_argument("--backend", help="Function-probe backend (unicorn, native, gdb, symbolic).")
    s.add_argument("--capture-range", action="append",
                   help="Memory range to capture as name:address:length (hex ok).")
    s.add_argument("--iterations", type=int, default=1, help="Max enrichment iterations.")
    s.add_argument("--apply", action="store_true", help="Write updated graph back to workspace.")
    s.add_argument("--symbolic", action="store_true", help="Force symbolic backend.")
    s.add_argument("--max-paths", type=int, default=0, help="Symbolic max paths.")
    s.add_argument("--max-steps", type=int, default=0, help="Symbolic max steps.")
    s.set_defaults(func=_cmd_enrich_function)

    s = sub.add_parser("symbolic-probe",
                       help="Run a symbolic/concolic probe for one function (requires angr; reports unavailable otherwise).")
    s.add_argument("binary")
    s.add_argument("function")
    s.add_argument("--address", help="Function hex address.")
    s.add_argument("--args", nargs="*", help="Positional arguments.")
    s.add_argument("--symbolic-arg", action="append", type=int,
                   help="Argument index to treat as symbolic.")
    s.add_argument("--max-paths", type=int, default=16, help="Max paths to explore.")
    s.add_argument("--max-steps", type=int, default=2000, help="Max steps per path.")
    s.add_argument("--target-addr", action="append",
                   help="Address we want to prove reachable (hex ok).")
    s.add_argument("--capture-range", action="append",
                   help="Memory range as name:address:length (hex ok).")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_symbolic_probe)

    s = sub.add_parser("pseudocode",
                       help="Emit structured decompiler pseudocode for all or one function.")
    s.add_argument("workspace")
    s.add_argument("--function", help="Limit to one function id/name/address.")
    s.add_argument("-o", "--output", help="Output JSON file.")
    s.add_argument("--structured", action="store_true",
                   help="Emit Phoenix-style structured (goto-free) pseudocode via CFG region analysis.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_pseudocode)

    s = sub.add_parser("function-summary",
                       help="Generate natural-language function summaries from the analysis graph.")
    s.add_argument("workspace")
    s.add_argument("--function", help="Limit to one function id/name/address.")
    s.add_argument("--top-n", type=int, help="Only summarize the first N functions by call count.")
    s.add_argument("-o", "--output", help="Output JSON file.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_function_summary)

    s = sub.add_parser("cfg-build",
                       help="Build function CFGs from an analysis graph workspace.")
    s.add_argument("workspace")
    s.add_argument("--function", help="Build only this function (name or address).")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_cfg_build)

    s = sub.add_parser("stack-frames",
                       help="Recover stack frames for functions in a workspace.")
    s.add_argument("workspace")
    s.add_argument("--function", help="Recover only this function (name or address).")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_stack_frames)

    s = sub.add_parser("gadget-find",
                       help="Find ROP/control-transfer gadgets in a binary.")
    s.add_argument("binary")
    s.add_argument("--max-ret-len", type=int, default=8, help="Max prefix bytes before ret.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_gadget_find)

    s = sub.add_parser("indirect-flow",
                       help="Heuristic indirect control-flow recovery (switch/jump tables) for a workspace.")
    s.add_argument("workspace")
    s.add_argument("--function", help="Limit recovery to this function.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_indirect_flow)

    s = sub.add_parser("compiler-detect",
                       help="Detect compiler / packer / protector and obfuscation indicators.")
    s.add_argument("binary")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_compiler_detect)

    s = sub.add_parser("custom-isa-list",
                       help="List registered custom ISA processors.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_custom_isa_list)

    s = sub.add_parser("analyze-custom",
                       help="Analyze a custom/VM bytecode sample with a registered ISA processor.")
    s.add_argument("binary")
    s.add_argument("--isa", required=True, help="Registered ISA name (e.g. solana-bpf, evm).")
    s.add_argument("--base-addr", type=lambda x: int(x, 0), default=0)
    s.add_argument("-o", "--output", help="Destination path for the graph JSON.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_analyze_custom)

    s = sub.add_parser("execution-status",
                       help="Check execution backend availability for a binary.")
    s.add_argument("binary")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_execution_status)

    s = sub.add_parser("qemu-plan",
                       help="Emit a shell-free QEMU Linux user-mode execution plan (does not run it).")
    s.add_argument("binary")
    s.add_argument("--arg", action="append", help="Target argument; repeatable.")
    s.add_argument("--architecture", help="Expected ELF architecture; mismatch is rejected.")
    s.add_argument("--sysroot", help="Guest library sysroot for QEMU -L.")
    s.add_argument("--cpu", help="QEMU CPU model.")
    s.add_argument("--strace", action="store_true", help="Enable QEMU user-mode syscall tracing.")
    s.set_defaults(func=_cmd_qemu_plan)

    s = sub.add_parser(
        "qemu-plugin-plan",
        help="Emit a shell-free full-system QEMU TCG instrumentation-plugin plan.",
    )
    s.add_argument("plugin", help="Compiled QEMU TCG plugin shared object.")
    s.add_argument("--architecture", help="QEMU guest architecture; defaults to the host.")
    s.add_argument("--plugin-arg", action="append", help="Plugin key=value argument; repeatable.")
    s.add_argument(
        "--qemu-arg", action="append",
        help="Raw QEMU argument; repeatable (use --qemu-arg=-kernel for leading dashes).",
    )
    s.set_defaults(func=_cmd_qemu_plugin_plan)

    s = sub.add_parser("bpftrace-plan",
                       help="Emit a shell-free bpftrace NDJSON execution plan (does not run it).")
    s.add_argument("script")
    s.add_argument("--dry-run", action="store_true", help="Ask bpftrace to print its compiled program.")
    s.add_argument("--sudo", action="store_true",
                   help="Prefix the plan with verified non-interactive sudo for kernel privileges.")
    s.set_defaults(func=_cmd_bpftrace_plan)

    s = sub.add_parser("radare2-mcp-plan",
                       help="Emit a readonly, sandbox-locked official radare2 MCP launch plan.")
    s.add_argument("allowed_root", help="Only files below this directory may be opened by r2mcp.")
    s.add_argument("--all-tools", action="store_true",
                   help="Expose all read-only tools instead of the minimal read-only set.")
    s.set_defaults(func=_cmd_radare2_mcp_plan)

    s = sub.add_parser("probe-run",
                       help="Run a single Appcall-style probe and capture a memory snapshot.")
    s.add_argument("binary")
    s.add_argument("function")
    s.add_argument("--backend", default="unicorn", help="Function-probe backend (unicorn, native, symbolic).")
    s.add_argument("--symbolic", action="store_true", help="Force symbolic backend.")
    s.add_argument("--args", nargs="*", help="Positional arguments.")
    s.add_argument("--address", help="Runtime function address (required for unresolved symbols).")
    s.add_argument("--isa", help="Architecture for raw code (for example x86_64 or arm64).")
    s.add_argument("--max-instructions", type=int, default=2_000)
    s.add_argument("--max-trace-events", type=int, default=16_384)
    s.add_argument("--capture-range", action="append",
                   help="Range as name:address:length (hex ok).")
    s.add_argument("--output", help="Write captured bytes to this file.")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_probe_run)

    s = sub.add_parser("enrich-workspace",
                       help="Run an enrichment probe and apply the snapshot to a workspace graph.")
    s.add_argument("workspace")
    s.add_argument("function")
    s.add_argument("--backend", help="Execution backend hint.")
    s.add_argument("--args", nargs="*", help="Positional arguments for the probe.")
    s.add_argument("--capture-range", action="append",
                   help="Range as name:address:length (hex ok).")
    s.add_argument("--iterations", type=int, default=1, help="Max enrichment iterations.")
    s.add_argument("--apply", action="store_true", help="Write updated graph back.")
    s.add_argument("--json", action="store_true")
    s.add_argument("--symbolic", action="store_true", help="Force symbolic backend.")
    s.add_argument("--max-paths", type=int, default=0, help="Symbolic max paths.")
    s.add_argument("--max-steps", type=int, default=0, help="Symbolic max steps.")
    s.set_defaults(func=_cmd_enrich_workspace)

    return p


def _cmd_web(ns) -> int:
    from .web.server import serve
    return serve(ns.host, ns.port, allow_remote=ns.allow_remote, auth_token=ns.auth_token)


# ------------------------------------------------------- workspace guard (Part 17)

def _cmd_guard_workspace(ns) -> int:
    """Pre-commit guard: refuse to let a decompiled binary be committed.

    Part 17 recommendation 5: ``workspaces/`` holds the full decompiled
    binary (code/, raw/, etc.). A committed workspace == committed
    proprietary/malware code. `.gitignore` excludes it, but a stray
    `git add -A` / force-add can still stage it. This command fails
    (exit 1) if `state_home` (the `workspaces/` root) is tracked or has
    staged content, so it can be wired as a pre-commit hook.
    """
    from .config import load_config
    home = getattr(ns, "home", None)
    if home:
        os.environ["ANGERONA_HOME"] = home
    cfg = load_config()
    # state_home() defaults to <repo>/workspaces (config.state_home) and the
    # decompiled run workspaces live under state_dir/"runs" (orchestrator,
    # workspace.RunWorkspace.create), so the guard root is state_dir itself —
    # NOT state_dir/"workspaces" (a path that never exists by default).
    ws_root = cfg.state_dir
    # resolve the git top-level by walking UP from the workspace root
    # (state_dir may be an external ANGERONA_HOME outside any repo).
    import subprocess
    git = subprocess.run(["git", "-C", str(ws_root), "rev-parse", "--show-toplevel"],
                        capture_output=True, text=True)
    if git.returncode != 0:
        print("not a git repo; nothing to guard", file=sys.stderr)
        return 0
    top = git.stdout.strip()
    rel = os.path.relpath(ws_root, top)
    # check for staged OR tracked files under the workspace root
    check = subprocess.run(
        ["git", "-C", top, "ls-files", "--error-unmatch", "--", rel],
        capture_output=True, text=True)
    staged = subprocess.run(
        ["git", "-C", top, "diff", "--cached", "--name-only", "--", rel],
        capture_output=True, text=True)
    bad = [l for l in (check.stdout + staged.stdout).splitlines() if l.strip()]
    if bad:
        print(f"GUARD FAILED: {len(bad)} workspace file(s) would be "
              f"committed (proprietary/malware code leak risk):", file=sys.stderr)
        for b in bad[:20]:
            print(f"  - {b}", file=sys.stderr)
        print("Fix: `git rm --cached -r --quiet workspaces/ && git commit --amend`",
              file=sys.stderr)
        return 1
    print(f"OK: no workspaces/ content staged under {ws_root}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    try:
        return ns.func(ns)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
