"""IDA MCP stdio proxy — prompt-injection wrapping + engine-agnostic tool parity.

The upstream ``idalib-mcp`` server does not mark its (attacker-controlled) tool
output as untrusted, and it does not expose our exploit-mitigation reader or the
disposable-container detonation tool. This thin stdio JSON-RPC proxy sits between
the MCP client (Claude Code / Codex) and the real ``idalib-mcp`` and:

* wraps every forwarded ``tools/call`` text result in the same ``⟦UNTRUSTED_DATA⟧``
  envelope the Ghidra server uses (prompt-injection defense parity), and
* injects two engine-agnostic tools — ``binary_security_properties`` and
  ``detonate_sample`` — handled locally (so IDA mode has the same safety tooling
  as Ghidra mode).

Everything else is forwarded verbatim. Responses are correlated by JSON-RPC id
so out-of-order / delayed replies (idalib auto-analysis can take a while) are
handled correctly.

Launched by the engine-aware MCP registration; reads ``ANGERONA_IDA_MCP_PYTHON``
(the venv python with ida-pro-mcp) and ``IDADIR`` from the environment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

from .server import _INTERESTING_IMPORTS, _safe_int, log, mark_untrusted  # noqa: F401
from .tool_output_governor import ToolOutputGovernor
from ..observability import child_observer_from_env, external_event_descriptor

_BINARY_PROP = {
    "name": "binary_security_properties",
    "description": (
        "Report the binary's exploit mitigations — PIE/ASLR, NX, stack canary, RELRO, "
        "Fortify, CET/IBT — parsed directly from the file (no shell). Use this to judge "
        "how exploitable a memory-safety bug really is (severity)."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."}},
        "required": ["binary"]},
}

_DETONATE = {
    "name": "detonate_sample",
    "description": (
        "DYNAMIC analysis: run the sample in a FRESH disposable Docker container (NO network, "
        "dropped caps, read-only root, memory/pid limits, hard timeout) under strace to observe "
        "runtime behaviour, then destroy the container. Use ONLY when static analysis is "
        "insufficient. Never runs on the host and never has network access."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."},
        "timeout_seconds": {"type": "integer", "description": "Max run time in the sandbox (1-120)."},
        "argv": {"type": "array", "items": {"type": "string"}, "description": "Arguments to pass to the sample."}},
        "required": ["binary"]},
}

_BINDIFF_MATCH = {
    "name": "bindiff_match",
    "description": (
        "Structurally compare the target against a reference corpus of known .BinExport files "
        "(known malware families / common libraries) via BinDiff. Returns ranked matches with an "
        "objective overall structural similarity — the binary-backed answer to 'what is this?'"),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."},
        "corpus_dir": {"type": "string", "description": "Directory (recursively scanned) of reference .BinExport files."},
        "similarity_threshold": {"type": "number", "description": "Minimum overall similarity to report a hit (0-1)."},
        "limit": {"type": "integer"}},
        "required": ["binary", "corpus_dir"]},
}

_VERIFY_UNDERSTANDING = {
    "name": "verify_understanding",
    "description": (
        "Verify an agent's reconstructed understanding against the original binary using BinDiff. "
        "Pass a recompiled/exported .BinExport of the agent's model; get an objective per-function "
        "(or whole-unit) structural similarity — the check an LLM reviewer cannot provide."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."},
        "recompiled_binexport": {"type": "string", "description": "Path to the .BinExport of the reconstructed/understood code."},
        "function_address": {"type": "string", "description": "Optional 0xADDRESS to verify one function; omit for whole unit."},
        "similarity_threshold": {"type": "number", "description": "Minimum similarity to count as verified (0-1)."}},
        "required": ["binary", "recompiled_binexport"]},
}

_VERIFY_RECONSTRUCTION = {
    "name": "verify_reconstruction",
    "description": (
        "Friction-free verification of an agent's reconstructed C/C++ source against the original "
        "binary. Compiles the source (gcc, sandboxed), exports via Ghidra/BinExport, and structurally "
        "diffs against the original — the agent need not recompile/re-export. Returns per-function (or "
        "whole-unit) verification: the strongest objective check that the understanding reproduces the "
        "original binary."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."},
        "c_source": {"type": "string", "description": "Path to the agent's reconstructed C/C++ source file."},
        "compiler": {"type": "string", "description": "Compiler to use (default: gcc)."},
        "extra_flags": {"type": "string", "description": "Extra compiler flags, space-separated (e.g. '-O2 -static')."},
        "function_address": {"type": "string", "description": "Optional 0xADDRESS to verify one function; omit for whole unit."},
        "similarity_threshold": {"type": "number", "description": "Minimum structural strength to count as verified (0-1)."}},
        "required": ["binary", "c_source"]},
}

_VERIFY_CLAIMS = {
    "name": "verify_claims",
    "description": (
        "Content-level 'reality anchor': verify that the strings/imports/symbols an RE agent "
        "CITES in its report actually EXIST in the binary. Checks the report against the binary's "
        "exported facts (strings.txt / imports.txt / exports.txt / symbols.txt). A cited fact absent "
        "from the binary is a hallucination -> verified=false. Catches the #1 RE hallucination."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."},
        "report": {"type": "string", "description": "The agent's markdown report to verify for cited claims."},
        "export_dir": {"type": "string", "description": "Optional dir holding exported facts; defaults to workspace code/ dir."}},
        "required": ["binary", "report"]},
}

_VERIFY_CAPABILITIES = {
    "name": "verify_capabilities",
    "description": (
        "Verify that CAPABILITIES an RE agent ASSERTS in its report (C2 beacon, AMSI bypass, "
        "persistence, exfiltration, injection, encryption) are backed by the binary's actual "
        "imports/xrefs. Capability keywords detected in the report (even prose) must be supported "
        "by at least one expected API import, else verified=false. Stops fluent prose describing "
        "behaviour with no corresponding imports."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string", "description": "Path to the target binary."},
        "report": {"type": "string", "description": "The agent's markdown report to verify for capability claims."},
        "export_dir": {"type": "string", "description": "Optional dir holding exported facts; defaults to workspace code/ dir."}},
        "required": ["binary", "report"]},
}

_LINUX_RUNTIME_STATUS = {
    "name": "linux_runtime_status",
    "description": "Report installed Linux tracing/emulation providers and truthful capabilities.",
    "inputSchema": {"type": "object", "properties": {}},
}

_QEMU_USER_PLAN = {
    "name": "qemu_user_plan",
    "description": (
        "Build a shell-free argv plan for QEMU Linux user-mode execution. Does not execute the "
        "target and explicitly reports that QEMU user mode is not a sandbox."),
    "inputSchema": {"type": "object", "properties": {
        "binary": {"type": "string"},
        "argv": {"type": "array", "items": {"type": "string"}},
        "architecture": {"type": "string"},
        "sysroot": {"type": "string"},
        "cpu": {"type": "string"},
        "syscall_trace": {"type": "boolean"}}, "required": ["binary"]},
}

_QEMU_TCG_PLUGIN_PLAN = {
    "name": "qemu_tcg_plugin_plan",
    "description": (
        "Build a shell-free full-system QEMU TCG instrumentation-plugin plan. "
        "Uses software translation and is not a sandbox."),
    "inputSchema": {"type": "object", "properties": {
        "plugin": {"type": "string"},
        "architecture": {"type": "string"},
        "plugin_arguments": {"type": "array", "items": {"type": "string"}},
        "qemu_arguments": {"type": "array", "items": {"type": "string"}},
    }, "required": ["plugin"]},
}

_BPFTRACE_PLAN = {
    "name": "bpftrace_plan",
    "description": "Build a shell-free bpftrace plan with newline-delimited JSON output.",
    "inputSchema": {"type": "object", "properties": {
        "script": {"type": "string"},
        "dry_run": {"type": "boolean"},
        "privileged": {"type": "boolean"}}, "required": ["script"]},
}

LOCAL_TOOLS = [_BINARY_PROP, _DETONATE, _BINDIFF_MATCH, _VERIFY_UNDERSTANDING,
               _VERIFY_RECONSTRUCTION, _VERIFY_CLAIMS, _VERIFY_CAPABILITIES,
               _LINUX_RUNTIME_STATUS, _QEMU_USER_PLAN, _QEMU_TCG_PLUGIN_PLAN,
               _BPFTRACE_PLAN]
LOCAL_TOOL_NAMES = {t["name"] for t in LOCAL_TOOLS}


def _local_tool_authorized(name: str) -> bool:
    return name != "detonate_sample" or os.environ.get("ANGERONA_MCP_ALLOW_WRITE") == "1"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _handle_local(name: str, args: dict) -> tuple[str, bool]:
    """Run a locally-provided tool. Returns (text, is_error)."""
    try:
        if name == "linux_runtime_status":
            from ..execution.providers import ProviderRegistry
            from .radare2_provider import Radare2McpProvider
            return json.dumps({
                "runtime": ProviderRegistry(include_unavailable=True).status(),
                "analysis_mcp": {"radare2": Radare2McpProvider().status()},
            }, indent=2), False
        if name == "qemu_tcg_plugin_plan":
            from ..execution.providers import QemuTcgPluginProvider
            plugin = args.get("plugin")
            if not plugin:
                return "ERROR: 'plugin' argument is required", True
            kwargs = {
                "architecture": args.get("architecture"),
                "plugin_arguments": args.get("plugin_arguments") or [],
            }
            if "qemu_arguments" in args:
                kwargs["qemu_arguments"] = args.get("qemu_arguments") or []
            plan = QemuTcgPluginProvider().plugin_plan(plugin, **kwargs)
            return json.dumps({
                "provider": plan.provider, "executable": plan.executable,
                "argv": list(plan.argv), "capabilities": plan.capabilities.__dict__,
                "metadata": plan.metadata,
            }, indent=2), False
        if name == "bpftrace_plan":
            from ..execution.providers import BpftraceProvider
            script = args.get("script")
            if not script:
                return "ERROR: 'script' argument is required", True
            plan = BpftraceProvider().script_plan(
                script,
                dry_run=bool(args.get("dry_run", False)),
                privileged=(bool(args["privileged"]) if "privileged" in args else None),
            )
            return json.dumps({
                "provider": plan.provider, "executable": plan.executable,
                "argv": list(plan.argv), "capabilities": plan.capabilities.__dict__,
                "metadata": plan.metadata,
            }, indent=2), False
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}", True
    binary = args.get("binary")
    if not binary:
        return "ERROR: 'binary' argument is required", True
    try:
        if name == "qemu_user_plan":
            from ..execution.providers import QemuUserProvider
            plan = QemuUserProvider().launch_plan(
                binary, argv=args.get("argv") or [], architecture=args.get("architecture"),
                sysroot=args.get("sysroot"), cpu=args.get("cpu"),
                syscall_trace=bool(args.get("syscall_trace", False)))
            return json.dumps({
                "provider": plan.provider, "executable": plan.executable,
                "argv": list(plan.argv), "capabilities": plan.capabilities.__dict__,
                "metadata": plan.metadata,
            }, indent=2), False
        if name == "binary_security_properties":
            from ..analysis.binprops import elf_security_properties
            return json.dumps(elf_security_properties(binary), indent=2), False
        if name == "detonate_sample":
            from ..analysis.detonate import detonate
            out = detonate(binary, timeout_seconds=_safe_int(args.get("timeout_seconds"), 20, 1, 120),
                           argv=args.get("argv") or [])
            return json.dumps(out, indent=2), False
        if name in ("bindiff_match", "verify_understanding", "verify_reconstruction",
                    "verify_claims", "verify_capabilities"):
            from ..analysis import bindiff as bd
            from ..analysis import verify as v
            from ..config import load_config
            from ..workspace import RunWorkspace
            cfg = load_config("ghidra")
            ok, msg = cfg.bindiff_ready()
            if not ok:
                return f"ERROR: BinDiff not ready: {msg}", True
            ws = RunWorkspace.create(cfg.state_dir / "runs" / "_bindiff", binary)
            if name == "bindiff_match":
                corpus_dir = args.get("corpus_dir")
                if not corpus_dir:
                    return "ERROR: 'corpus_dir' is required", True
                hits = bd.match_against_corpus(
                    cfg, ws, binary, corpus_dir,
                    similarity_threshold=float(args.get("similarity_threshold", 0.5)))
                limit = _safe_int(args.get("limit"), 20, 0, 500)
                return json.dumps({"binary": binary, "hits": [h.as_dict() for h in hits[:limit]],
                                   "hit_count": len(hits[:limit])}, indent=2), False
            if name == "verify_reconstruction":
                c_source = args.get("c_source")
                if not c_source:
                    return "ERROR: 'c_source' is required", True
                addr_raw = args.get("function_address")
                addr = (int(addr_raw, 16) if addr_raw and addr_raw.lower().startswith("0x")
                        else int(addr_raw)) if addr_raw else None
                result = bd.verify_reconstruction(
                    cfg, ws, binary, c_source,
                    compiler=args.get("compiler"), extra_flags=args.get("extra_flags"),
                    function_address=addr,
                    similarity_threshold=float(args.get("similarity_threshold", 0.7)))
                if isinstance(result, list):
                    payload = {"binary": binary, "c_source": c_source,
                               "verified_count": sum(1 for r in result if r.verified),
                               "total": len(result), "results": [r.as_dict() for r in result]}
                else:
                    payload = result.as_dict()
                return json.dumps(payload, indent=2), False
            if name == "verify_understanding":
                recompiled = args.get("recompiled_binexport")
                if not recompiled:
                    return "ERROR: 'recompiled_binexport' is required", True
                addr_raw = args.get("function_address")
                addr = (int(addr_raw, 16) if addr_raw and addr_raw.lower().startswith("0x")
                        else int(addr_raw)) if addr_raw else None
                result = bd.verify_understanding(
                    cfg, ws, binary, recompiled, function_address=addr,
                    similarity_threshold=float(args.get("similarity_threshold", 0.7)))
                if isinstance(result, list):
                    payload = {"binary": binary, "verified_count": sum(1 for r in result if r.verified),
                               "total": len(result), "results": [r.as_dict() for r in result]}
                else:
                    payload = result.as_dict()
                return json.dumps(payload, indent=2), False
        if name == "verify_claims":
            report = args.get("report")
            if not report:
                return "ERROR: 'report' is required", True
            export_dir = args.get("export_dir") or str(ws.code_dir)
            rep = v.verify_claims(report, export_dir, binary=binary)
            return json.dumps({"binary": binary, "verified": rep.verified, "status": rep.status,
                               "checked": rep.checked, "unsupported": rep.unsupported,
                               "detail": rep.detail}, indent=2), False
        if name == "verify_capabilities":
            report = args.get("report")
            if not report:
                return "ERROR: 'report' is required", True
            export_dir = args.get("export_dir") or str(ws.code_dir)
            rep = v.verify_capabilities(report, export_dir)
            return json.dumps({"binary": binary, "verified": rep.verified, "status": rep.status,
                               "checked": rep.checked, "unsupported": rep.unsupported,
                               "detail": rep.detail}, indent=2), False
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}", True
    return f"ERROR: unknown local tool: {name}", True


def _wrap_tool_result(
    result: dict,
    *,
    tool_name: str = "unknown",
    request_id: object | None = None,
    governor: ToolOutputGovernor | None = None,
) -> dict:
    """Wrap forwarded tools/call text as untrusted and preserve upstream errors.

    Some upstream MCP/IDA failures arrive as successful JSON-RPC replies whose
    text payload is a JSON object like {"error": "..."} instead of a proper
    ``isError=true`` tool result. If we leave those as success, workers can treat
    a broken live IDA session as usable evidence. Normalize that shape before
    wrapping the attacker/binary-controlled text.
    """
    active_governor = governor or ToolOutputGovernor.from_env()
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                text = item["text"]
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    parsed = None
                if (
                    isinstance(parsed, dict)
                    and parsed.get("error")
                    and parsed.get("success") is not True
                ):
                    result["isError"] = True
    canonical = json.dumps(
        result,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    decision = active_governor.process(
        tool_name,
        canonical,
        request_id=request_id,
        is_error=bool(result.get("isError")),
    )
    source_is_error = bool(result.get("isError"))
    if decision.offloaded or decision.reason == "persistence_failed":
        safe_text = decision.text
        safe_meta = {
            "angerona_tool_output_governed": True,
            "angerona_offloaded": decision.offloaded,
            "artifact_path": decision.artifact_path,
            "manifest_path": decision.manifest_path,
            "reason": decision.reason,
        }
    else:
        # No parallel raw channel is retained: structuredContent, _meta, binary
        # blocks, and extension fields are all represented inside this one
        # explicitly untrusted canonical JSON envelope.
        safe_text = canonical
        safe_meta = {
            "angerona_tool_output_governed": True,
            "encoding": "canonical-json",
            "reason": decision.reason,
        }
    result.clear()
    result.update({
        "content": [{"type": "text", "text": mark_untrusted(safe_text)}],
        "isError": source_is_error or decision.is_error,
        "_meta": safe_meta,
    })
    return result


def _wrap_jsonrpc_error(
    error: object,
    *,
    tool_name: str,
    request_id: object | None,
    governor: ToolOutputGovernor,
) -> dict:
    value = error if isinstance(error, dict) else {"message": str(error)}
    canonical = json.dumps(
        {"error": value}, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), default=str,
    )
    decision = governor.process(
        tool_name,
        canonical,
        request_id=request_id,
        is_error=True,
    )
    return {
        "code": value.get("code", -32603),
        "message": mark_untrusted(decision.text),
        "data": {
            "angerona_offloaded": decision.offloaded,
            "artifact_path": decision.artifact_path,
            "manifest_path": decision.manifest_path,
        },
    }


def _govern_forwarded_response(
    obj: dict,
    *,
    tool_name: str,
    request_id: object | None,
    governor: ToolOutputGovernor,
) -> dict:
    """Fail closed without killing the proxy reader on malformed child output."""

    try:
        if isinstance(obj.get("result"), dict):
            obj["result"] = _wrap_tool_result(
                obj["result"],
                tool_name=tool_name,
                request_id=request_id,
                governor=governor,
            )
        elif "error" in obj:
            obj["error"] = _wrap_jsonrpc_error(
                obj.get("error"),
                tool_name=tool_name,
                request_id=request_id,
                governor=governor,
            )
        return obj
    except Exception as exc:  # noqa: BLE001 - protocol boundary must survive bad data
        log(f"[ida-proxy] output governance failed: {type(exc).__name__}")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32603,
                "message": (
                    "Angerona could not safely preserve the complete IDA tool result; "
                    "retry with a narrower query."
                ),
            },
        }


def _target_path_from_args(args: dict) -> str | None:
    for key in ("input_path", "path", "binary", "file", "input_file", "idb_path"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _worker_workspace_from_env() -> Path:
    run_cwd = os.environ.get("ANGERONA_RUN_CWD")
    if run_cwd:
        cwd = Path(run_cwd).expanduser().resolve()
    else:
        cwd = Path.cwd().resolve()
    return cwd.parent if cwd.name == "code" else cwd


def _is_worker_staged_target(path: Path, target: Path) -> bool:
    """Return true for a proxy-created staged copy of the current target."""
    try:
        path = path.expanduser().resolve()
        workspace = _worker_workspace_from_env().resolve()
    except Exception:
        return False
    stage_root = workspace / "runtime" / "ida-input"
    allowed_names = {
        target.name,
        f"{target.name}.i64",
        f"{target.name}.idb",
        f"{target.name}.id0",
        f"{target.name}.id1",
        f"{target.name}.id2",
        f"{target.name}.nam",
        f"{target.name}.til",
    }
    return _is_relative_to(path, stage_root) and path.name in allowed_names


def _target_path_allowed(req_path: str, target: str) -> bool:
    try:
        requested = Path(req_path).expanduser().resolve()
        expected = Path(target).expanduser().resolve()
    except Exception:
        return req_path == target
    return requested == expected or _is_worker_staged_target(requested, expected)


def _validate_target_scope(tool_name: str, args: dict) -> tuple[str | None, bool]:
    required = os.environ.get("ANGERONA_REQUIRE_TARGET_BINARY") == "1"
    target = os.environ.get("ANGERONA_TARGET_BINARY")
    if not required or tool_name != "idb_open" or not target:
        return None, False
    requested = _target_path_from_args(args)
    if not requested:
        return (
            "ERROR: idb_open must include the current target path; refusing to open an implicit/stale database.",
            True,
        )
    try:
        req_path = str(Path(requested).expanduser().resolve())
    except Exception:
        req_path = requested
    if not _target_path_allowed(req_path, target):
        return (
            "ERROR: refusing idb_open for non-current target. "
            f"requested={req_path!r} expected={target!r}",
            True,
        )
    return None, False


def _stage_ida_target_for_worker(requested: str) -> str:
    """Stage the target and existing IDA sidecar DB files into writable worker state.

    Workers see the repository read-only. IDA/idapro may need to create or update
    loose database sidecars (.id0/.id1/.nam/.til) beside the input path, so opening
    ``samples/foo`` directly from a sandbox fails even though the file is readable.
    Keep target validation against the original path, then forward a per-worker
    copy to upstream idalib.
    """
    if os.environ.get("ANGERONA_AGENT_FS_SANDBOX_ACTIVE") != "1":
        return requested
    target = os.environ.get("ANGERONA_TARGET_BINARY")
    if not target:
        return requested
    try:
        original = Path(requested).expanduser().resolve()
        expected = Path(target).expanduser().resolve()
    except Exception:
        return requested
    if original == expected:
        copy_source = expected
    elif _is_worker_staged_target(original, expected):
        # Agents sometimes pass back the path returned by a previous idb_open.
        # Treat that as an alias for the original target and create a fresh
        # staged copy; the old staged DB may belong to a dead/retried MCP
        # process and can be locked or partially mutated.
        copy_source = expected
    else:
        return requested
    if not copy_source.exists():
        return requested

    stage_dir = _worker_workspace_from_env() / "runtime" / "ida-input" / str(os.getpid())
    stage_dir.mkdir(parents=True, exist_ok=True)
    staged = stage_dir / copy_source.name
    shutil.copy2(copy_source, staged)
    for ext in (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"):
        sidecar = Path(str(copy_source) + ext)
        if sidecar.exists():
            shutil.copy2(sidecar, stage_dir / (copy_source.name + ext))
    # Prefer a complete IDA database sidecar when present.  For SBF/eBPF inputs
    # the raw ELF import path can repeatedly create partial loose sidecars and
    # close the idalib connection; opening the already-created .i64/.idb avoids
    # re-importing the unsupported/fragile loader path while preserving target
    # validation against the original binary above.
    for db_ext in (".i64", ".idb"):
        db = stage_dir / (copy_source.name + db_ext)
        if db.exists():
            return str(db.resolve())
    return str(staged.resolve())


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _validate_ida_call_scope(tool_name: str, args: dict) -> tuple[str | None, bool]:
    """Prevent expensive broad IDA sweeps that should use exported artifacts."""
    if os.environ.get("ANGERONA_ALLOW_FULL_IDA_SWEEP") in {"1", "true", "yes", "on"}:
        return None, False
    if tool_name == "analyze_funcs":
        selectors = (
            args.get("functions") or args.get("addresses") or args.get("addrs")
            or args.get("names") or args.get("pattern") or args.get("function")
        )
        limit = _as_int(args.get("limit") or args.get("max_functions") or 0)
        if not selectors and (limit <= 0 or limit > 50):
            return (
                "ERROR: refusing broad analyze_funcs sweep. Use current-run exported "
                "artifacts (CALL_SUMMARY.json/functions.csv/analysis.json/security_slices.json) "
                "for broad counts, then call analyze_funcs only on a narrow function/address list "
                "(or set ANGERONA_ALLOW_FULL_IDA_SWEEP=1 explicitly).",
                True,
            )
    if tool_name == "decompile" and not (
        args.get("function") or args.get("address") or args.get("addr") or args.get("name") or args.get("ea")
    ):
        return "ERROR: decompile requires a specific function/address; broad decompile is already exported.", True
    return None, False


def _child_command() -> tuple[list[str], dict[str, str]]:
    # Test/override hook: a JSON list replaces the real idalib-mcp child (no idalib needed).
    override = os.environ.get("ANGERONA_IDA_MCP_CHILD_CMD")
    if override:
        try:
            cmd = json.loads(override)
            if isinstance(cmd, list) and cmd:
                return [str(x) for x in cmd], dict(os.environ)
        except Exception:  # noqa: BLE001
            pass
    py = os.environ.get("ANGERONA_IDA_MCP_PYTHON") or sys.executable
    max_workers = os.environ.get("IDA_MCP_MAX_WORKERS", "1")
    cmd = [py, "-m", "ida_pro_mcp.idalib_supervisor", "--stdio", "--max-workers", str(max_workers)]
    env = dict(os.environ)  # IDADIR / HOME / PATH propagate to the real server
    return cmd, env


class IdaMcpProxy:
    def __init__(self, child_cmd: list[str], child_env: dict[str, str]):
        self.child_cmd = child_cmd
        self.child_env = child_env
        self._out_lock = threading.Lock()
        self._pending: dict[Any, tuple[str, str | None]] = {}
        self._pending_lock = threading.Lock()
        self._ida_lock_handle = None
        self._ida_lock_guard = threading.Lock()
        self._opened_target_path: str | None = None
        self.tool_output_governor = ToolOutputGovernor.from_env()
        self.observability = child_observer_from_env("mcp.ida")
        self.proc: subprocess.Popen | None = None

    # ------------------------------------------------------------------ io

    def _emit(self, obj: dict) -> None:
        if self.observability is not None:
            result = obj.get("result") if isinstance(obj, dict) else None
            is_error = bool(
                "error" in obj
                or (isinstance(result, dict) and bool(result.get("isError")))
            )
            self.observability.emit(
                category="jsonrpc",
                action="response",
                status="error" if is_error else "ok",
                attributes={
                    "request_id": obj.get("id"),
                    "response": external_event_descriptor(obj),
                },
            )
        with self._out_lock:
            sys.stdout.write(json.dumps(obj) + "\n")
            sys.stdout.flush()

    def _to_child(self, line: str) -> None:
        assert self.proc is not None and self.proc.stdin is not None
        self.proc.stdin.write(line if line.endswith("\n") else line + "\n")
        self.proc.stdin.flush()

    # ------------------------------------------------------------- child->client

    def _pump_child(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = obj.get("id")
            tag = None
            tool_name = None
            if rid is not None:
                with self._pending_lock:
                    pending = self._pending.pop(rid, None)
                if pending is not None:
                    tag, tool_name = pending
            if tag == "tools_list" and isinstance(obj.get("result"), dict):
                tools = obj["result"].setdefault("tools", [])
                have = {t.get("name") for t in tools if isinstance(t, dict)}
                for t in LOCAL_TOOLS:
                    if t["name"] not in have:
                        tools.append(t)
            elif tag == "forward_call":
                obj = _govern_forwarded_response(
                    obj,
                    tool_name=tool_name or "unknown",
                    request_id=rid,
                    governor=self.tool_output_governor,
                )
            elif tag == "forward_call_locked":
                try:
                    obj = _govern_forwarded_response(
                        obj,
                        tool_name=tool_name or "unknown",
                        request_id=rid,
                        governor=self.tool_output_governor,
                    )
                finally:
                    self._release_ida_lock()
            self._emit(obj)

    # ------------------------------------------------------------- client->child

    def _handle_request(self, line: str, req: dict) -> None:
        method = req.get("method")
        rid = req.get("id")
        params = req.get("params") or {}
        if self.observability is not None:
            self.observability.emit(
                category="jsonrpc",
                action="request",
                status="running",
                attributes={
                    "method": str(method or "unknown"),
                    "request_id": rid,
                    "tool_name": str(params.get("name") or ""),
                    "request": external_event_descriptor(req),
                },
            )

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if name in LOCAL_TOOL_NAMES:
                if not _local_tool_authorized(str(name)):
                    text, is_error = (
                        "detonate_sample is disabled; set ANGERONA_MCP_ALLOW_WRITE=1 explicitly",
                        True,
                    )
                else:
                    text, is_error = _handle_local(name, arguments)
                decision = self.tool_output_governor.process(
                    str(name), text, request_id=rid, is_error=is_error,
                )
                self._emit({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": mark_untrusted(decision.text)}],
                    "isError": decision.is_error}})
                return
            text, is_error = _validate_target_scope(str(name or ""), arguments)
            if is_error:
                self._emit({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": mark_untrusted(text or "ERROR")}],
                    "isError": True}})
                return
            if name == "idb_open":
                requested = _target_path_from_args(arguments)
                if requested:
                    try:
                        requested = str(Path(requested).expanduser().resolve())
                    except Exception:
                        requested = str(requested)
                if requested:
                    self._opened_target_path = requested
                    staged = _stage_ida_target_for_worker(requested)
                    if staged != requested:
                        params = dict(params)
                        arguments = dict(arguments)
                        arguments["input_path"] = staged
                        params["arguments"] = arguments
                        req = dict(req)
                        req["params"] = params
                        line = json.dumps(req)
            text, is_error = _validate_ida_call_scope(str(name or ""), arguments)
            if is_error:
                self._emit({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": mark_untrusted(text or "ERROR")}],
                    "isError": True}})
                return
            lock_taken = self._acquire_ida_lock()
            if rid is not None:
                with self._pending_lock:
                    self._pending[rid] = (
                        "forward_call_locked" if lock_taken else "forward_call",
                        str(name or "unknown"),
                    )
            self._to_child(line)
            return

        if method == "tools/list" and rid is not None:
            with self._pending_lock:
                self._pending[rid] = ("tools_list", None)
            self._to_child(line)
            return

        # initialize / ping / resources/* / prompts/* / notifications -> forward verbatim
        self._to_child(line)

    def serve(self) -> int:
        started = time.monotonic_ns()
        if self.observability is not None:
            self.observability.emit(
                category="subprocess",
                action="ida_mcp_child_start",
                status="running",
                attributes={"executable": Path(self.child_cmd[0]).name if self.child_cmd else ""},
            )
        try:
            self.proc = subprocess.Popen(
                self.child_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=None, text=True, bufsize=1, env=self.child_env,
            )
        except Exception as exc:  # noqa: BLE001
            if self.observability is not None:
                self.observability.emit(
                    category="subprocess",
                    action="ida_mcp_child_end",
                    status="error",
                    duration_ms=round((time.monotonic_ns() - started) / 1_000_000, 3),
                    attributes={"exception": type(exc).__name__},
                )
            log(f"[ida-proxy] failed to launch idalib-mcp child: {exc}")
            return 1
        log(f"[ida-proxy] started; child={self.child_cmd[0]} max_workers="
            f"{self.child_env.get('IDA_MCP_MAX_WORKERS')}")
        reader = threading.Thread(target=self._pump_child, daemon=True)
        reader.start()
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._handle_request(line, req)
        finally:
            # Signal EOF to the child so it exits its own stdio loop, let it flush any
            # queued responses (idb_open can be slow), then reap.
            try:
                if self.proc and self.proc.stdin:
                    self.proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                if self.proc:
                    self.proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            reader.join(timeout=5)
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    self.proc.kill()
            self._release_ida_lock()
        if self.observability is not None:
            self.observability.emit(
                category="subprocess",
                action="ida_mcp_child_end",
                status="ok" if self.proc and self.proc.returncode == 0 else "error",
                duration_ms=round((time.monotonic_ns() - started) / 1_000_000, 3),
                attributes={"returncode": self.proc.returncode if self.proc else None},
            )
        return 0

    def _acquire_ida_lock(self) -> bool:
        lock_path = os.environ.get("ANGERONA_IDA_LOCK_FILE")
        if not lock_path or fcntl is None:
            return False
        Path(lock_path).parent.mkdir(parents=True, exist_ok=True)
        fh = open(lock_path, "a+")
        # Do NOT hold self._ida_lock_guard while blocked in flock: flock treats
        # separate opens of the same file in the same process as conflicting, so
        # a second in-flight forwarded call would block here while holding the
        # guard, and the reader thread's _release_ida_lock (which needs the guard
        # to unlock the first fd) would deadlock against us forever (flock has no
        # timeout). The guard only protects the handle assignment below.
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        with self._ida_lock_guard:
            self._ida_lock_handle = fh
        return True

    def _release_ida_lock(self) -> None:
        with self._ida_lock_guard:
            fh = self._ida_lock_handle
            self._ida_lock_handle = None
            if fh is None:
                return
            try:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            finally:
                fh.close()


def main(argv: list[str] | None = None) -> int:
    cmd, env = _child_command()
    return IdaMcpProxy(cmd, env).serve()


if __name__ == "__main__":
    raise SystemExit(main())
