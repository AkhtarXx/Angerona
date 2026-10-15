"""Web UI backend - a stdlib-only HTTP server exposing Angerona run state.

Lets you browse every analysis run transparently: list runs, open a run, see its
binary/code/docs/raw/workers tree, read any file (all_decompiled.c, progress.md,
consolidated_report.md, ...), tail a live agent stream, and start a new run from
the browser. No external dependencies — Python stdlib only.

Run:
    python -m src.web.server --host 127.0.0.1 --port 8765
    ./bin/angerona web
"""

from __future__ import annotations

import argparse
import collections
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from ..config import REPO_ROOT, load_config
from ..workspace import RunWorkspace  # noqa: F401  (re-exported for clarity)

WEB_DIR = Path(__file__).resolve().parent


def _request_token_valid(headers, token: str | None) -> bool:
    if not token:
        return True
    supplied = str(headers.get("Authorization") or "")
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()
    else:
        supplied = str(headers.get("X-Angerona-Token") or "").strip()
    return bool(supplied) and hmac.compare_digest(supplied, token)

# ---------------------------------------------------------------- run-state model

# Live runs: run_id -> {meta, events[], started, process, log_path}
_LIVE: dict[str, dict] = {}
_LIVE_LOCK = threading.Lock()

# Bounded ring of recent events kept in memory for a run (cap to avoid OOM).
_MAX_LIVE_EVENTS = 4000
_MAX_POST_BYTES = 64 * 1024
_MAX_FILE_DISPLAY_BYTES = 2_000_000
_MAX_FILE_PICKER_ENTRIES = 1000
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+__[A-Za-z0-9._-]+$")
_EVENT_KINDS = {"log", "error", "text", "tool_use", "tool_result", "result"}
_BINARY_EXTS = {
    "", ".bin", ".elf", ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".a",
    ".lib", ".ko", ".sys", ".apk", ".jar", ".class", ".wasm", ".idb", ".i64",
    ".raw", ".img", ".rom", ".fw",
}


def _state_dir() -> Path:
    return load_config().state_dir


def _runs_dir() -> Path:
    return _state_dir() / "runs"


def _run_root(run_id: str) -> Path | None:
    """Resolve a run id to a run root, rejecting encoded slashes/traversal."""
    if not _RUN_ID_RE.fullmatch(run_id or ""):
        return None
    runs = _runs_dir().resolve()
    root = (runs / run_id).resolve()
    # Older CLI versions stored runs under category directories. Preserve
    # read/resume access while new runs use the canonical flat directory.
    existing = [candidate for candidate in (
        runs / run_id, runs / "batch" / run_id, runs / "sota" / run_id,
    ) if candidate.is_dir()]
    if len(existing) > 1:
        return None
    if existing:
        root = existing[0].resolve()
    try:
        root.relative_to(runs)
    except ValueError:
        return None
    return root


def _safe_rel(p: Path, base: Path) -> str:
    try:
        return str(p.resolve().relative_to(base.resolve()))
    except ValueError:
        return p.name


def _list_runs() -> list[dict]:
    """All runs (live + on-disk), newest first, with a compact summary."""
    runs_dir = _runs_dir()
    out: list[dict] = []
    seen: set[str] = set()

    # Live runs first.
    with _LIVE_LOCK:
        for rid, info in list(_LIVE.items()):
            root = info.get("root")
            if root:
                seen.add(str(Path(root).name))
                out.append(_summarize_run(Path(root), live=info))
    if runs_dir.exists():
        candidates = list(runs_dir.iterdir())
        for category in ("batch", "sota"):
            legacy = runs_dir / category
            if legacy.is_dir() and not legacy.is_symlink():
                candidates.extend(legacy.iterdir())
        for d in sorted(candidates, reverse=True):
            if not d.is_dir() or d.is_symlink() or d.name in seen or not _RUN_ID_RE.fullmatch(d.name):
                continue
            if _run_root(d.name) != d.resolve():
                continue
            seen.add(d.name)
            out.append(_summarize_run(d, live=_LIVE.get(d.name)))
    return out


def _read_run_json(root: Path) -> dict:
    p = root / "run.json"
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_run_json(root: Path, meta: dict) -> None:
    (root / "run.json").write_text(json.dumps(meta, indent=2))


def _run_is_running(root: Path) -> bool:
    return _summarize_run(root, live=_LIVE.get(root.name))["status"] == "running"


def _clamped_int(value, default: int, lo: int, hi: int) -> int:
    return max(lo, min(int(value if value is not None else default), hi))


def _validated_similarity_paths(value) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("similarity_corpora must be a list of at most 32 paths")
    paths: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("every similarity corpus path must be a string")
        path = item.strip()
        if len(path) > 4096:
            raise ValueError("similarity corpus path exceeds 4096 characters")
        if path:
            paths.append(path)
    return paths


def _run_config_from_meta(meta: dict) -> dict:
    return {
        "binary": meta.get("binary") or "",
        "engine": meta.get("engine") or "ida",
        "agent": meta.get("agent") or "claude",
        "objective": meta.get("objective") or "",
        "model": meta.get("model") or "",
        "anchor_idl": meta.get("anchor_idl") or "",
        "similarity_corpora": list(meta.get("similarity_corpora") or []),
        "sandbox": bool(meta.get("sandbox")),
        "rounds": _clamped_int(meta.get("requested_rounds") or meta.get("total_rounds"), 2, 1, 5),
        "parallel": _clamped_int(meta.get("requested_parallel"), 3, 1, 8),
        "max_agent_calls": meta.get("max_agent_calls"),
        "audit_wall_timeout": meta.get("audit_wall_timeout"),
        "max_agent_tokens": meta.get("max_agent_tokens"),
        "max_agent_cost_usd": meta.get("max_agent_cost_usd"),
        "budget_verification_reserve_calls": meta.get(
            "budget_verification_reserve_calls"
        ),
    }


def _validated_run_config(body: dict, base: dict | None = None, *, allow_binary: bool = True) -> dict:
    cfg = dict(base or {})
    if allow_binary and "binary" in body:
        cfg["binary"] = (body.get("binary") or "").strip()
    if "engine" in body:
        cfg["engine"] = body.get("engine") or "ida"
    if "agent" in body:
        cfg["agent"] = body.get("agent") or "claude"
    if "objective" in body:
        cfg["objective"] = str(body.get("objective") or "")
    if "model" in body:
        cfg["model"] = str(body.get("model") or "").strip()
    if "anchor_idl" in body:
        cfg["anchor_idl"] = str(body.get("anchor_idl") or "").strip() or None
    if "similarity_corpora" in body:
        cfg["similarity_corpora"] = _validated_similarity_paths(
            body.get("similarity_corpora")
        )
    if "sandbox" in body:
        cfg["sandbox"] = bool(body.get("sandbox"))
    try:
        if "rounds" in body:
            cfg["rounds"] = _clamped_int(body.get("rounds"), 2, 1, 5)
        if "parallel" in body:
            cfg["parallel"] = _clamped_int(body.get("parallel"), 3, 1, 8)
        if "max_agent_calls" in body:
            cfg["max_agent_calls"] = _clamped_int(
                body.get("max_agent_calls"), 64, 1, 10_000
            )
        if "audit_wall_timeout" in body:
            cfg["audit_wall_timeout"] = max(
                0.0, min(604_800.0, float(body.get("audit_wall_timeout") or 0.0))
            )
        if "max_agent_tokens" in body:
            cfg["max_agent_tokens"] = _clamped_int(
                body.get("max_agent_tokens"), 0, 0, 10_000_000_000
            )
        if "max_agent_cost_usd" in body:
            cfg["max_agent_cost_usd"] = max(
                0.0, min(1_000_000.0, float(body.get("max_agent_cost_usd") or 0.0))
            )
        if "budget_verification_reserve_calls" in body:
            cfg["budget_verification_reserve_calls"] = _clamped_int(
                body.get("budget_verification_reserve_calls"), 4, 0, 9_999
            )
    except (TypeError, ValueError) as exc:
        raise ValueError("rounds, parallel, and audit budget limits must be numeric") from exc
    if not cfg.get("binary"):
        raise ValueError("binary required")
    if cfg.get("engine") not in {"ida", "ghidra"}:
        raise ValueError("engine must be ida or ghidra")
    if cfg.get("agent") not in {"claude", "codex"}:
        raise ValueError("agent must be claude or codex")
    return cfg


def edit_run(run_id: str, body: dict) -> dict:
    root = _run_root(run_id)
    if root is None:
        raise ValueError("invalid run id")
    if not root.exists():
        raise FileNotFoundError("run not found")
    if _run_is_running(root):
        raise RuntimeError("cannot edit a running run")

    meta = _read_run_json(root)
    if "binary" in body and (body.get("binary") or "").strip() != (meta.get("binary") or ""):
        raise ValueError("binary cannot be edited for an existing run; rerun or start a new run")
    cfg = _validated_run_config(body, _run_config_from_meta(meta), allow_binary=False)
    meta.update({
        "engine": cfg["engine"],
        "agent": cfg["agent"],
        "model": cfg.get("model") or "",
        "anchor_idl": cfg.get("anchor_idl") or "",
        "similarity_corpora": list(cfg.get("similarity_corpora") or []),
        "objective": cfg["objective"],
        "sandbox": bool(cfg["sandbox"]),
        "requested_rounds": cfg["rounds"],
        "requested_parallel": cfg["parallel"],
        "max_agent_calls": cfg.get("max_agent_calls"),
        "audit_wall_timeout": cfg.get("audit_wall_timeout"),
        "max_agent_tokens": cfg.get("max_agent_tokens"),
        "max_agent_cost_usd": cfg.get("max_agent_cost_usd"),
        "budget_verification_reserve_calls": cfg.get(
            "budget_verification_reserve_calls"
        ),
    })
    if "note" in body:
        meta["note"] = str(body.get("note") or "")
    _save_run_json(root, meta)
    return _run_detail(root)


def rerun_run(run_id: str, overrides: dict | None = None) -> dict:
    root = _run_root(run_id)
    if root is None:
        raise ValueError("invalid run id")
    if not root.exists():
        raise FileNotFoundError("run not found")
    meta = _read_run_json(root)
    cfg = _validated_run_config(overrides or {}, _run_config_from_meta(meta), allow_binary=True)
    for optional in ("model", "anchor_idl"):
        if not cfg.get(optional):
            cfg.pop(optional, None)
    if not cfg.get("similarity_corpora"):
        cfg.pop("similarity_corpora", None)
    cfg = {key: value for key, value in cfg.items() if value is not None}
    res = start_run(**cfg)
    res["source_run_id"] = run_id
    return res


def pause_run(run_id: str, reason: str = "") -> dict:
    from ..agents.audit_state import AuditStateStore

    root = _run_root(run_id)
    if root is None:
        raise ValueError("invalid run id")
    if not root.exists():
        raise FileNotFoundError("run not found")
    with AuditStateStore(root) as store:
        snapshot = store.load_latest()
        if snapshot is None:
            raise RuntimeError("run has no resumable audit state")
        if snapshot.payload.get("status") in {
            "completed", "budget_exhausted", "incomplete",
        }:
            raise RuntimeError(
                f"audit is already terminal ({snapshot.payload.get('status')})"
            )
        control = store.request_pause(reason or "web pause")
        active = store.lease_active()
    return {
        "run_id": run_id,
        "pause_requested": True,
        "draining": active,
        "control": str(control),
    }


def resume_run(
    run_id: str,
    binary_override: str | None = None,
    anchor_idl_override: str | None = None,
    similarity_corpora_override: list[str] | None = None,
) -> dict:
    from ..agents.audit_state import AuditLeaseError, AuditStateStore
    from ..agents.budget_harness import AuditBudgetPolicy
    from ..agents.orchestrator import Orchestrator
    from ..agents.run_contract import build_run_contract, validate_run_contract
    from ..analysis.similarity_corpus import resolve_similarity_corpora

    root = _run_root(run_id)
    if root is None:
        raise ValueError("invalid run id")
    if not root.exists():
        raise FileNotFoundError("run not found")
    store = AuditStateStore(root)
    try:
        snapshot = store.load_latest()
        if snapshot is None:
            raise RuntimeError("run has no resumable audit state")
        if snapshot.payload.get("status") in {
            "completed", "budget_exhausted", "incomplete",
        }:
            raise RuntimeError(
                f"audit is already terminal ({snapshot.payload.get('status')})"
            )
        store.acquire_lease()
        payload = snapshot.payload
        config = dict(payload.get("config") or {})
        binary = store.validate_identity(
            dict(payload.get("identity") or {}),
            binary_override=binary_override,
        )
        engine_config = load_config(str(config.get("engine") or "ida"))
        audit_budget_policy = AuditBudgetPolicy.from_env(
            os.environ,
            max_calls=int(config.get("max_agent_calls") or 0) or None,
            max_wall_seconds=(
                None if config.get("audit_wall_timeout") is None
                else float(config.get("audit_wall_timeout"))
            ),
            max_tokens=int(config.get("max_agent_tokens") or 0),
            max_cost_usd=float(config.get("max_agent_cost_usd") or 0.0),
            critical_reserve_calls=(
                None
                if config.get("budget_verification_reserve_calls") is None
                else int(config.get("budget_verification_reserve_calls"))
            ),
        )
        current_contract = build_run_contract(
            config=engine_config,
            binary=binary,
            model=config.get("model"),
            supervisor=str(config.get("supervisor") or "claude"),
            worker_analyst=str(config.get("worker_analyst") or "claude"),
            worker_reviewer=str(config.get("worker_reviewer") or "claude"),
            idle_timeout=float(config.get("idle_timeout") or 300.0),
            wall_timeout=(
                None if config.get("wall_timeout") is None
                else float(config.get("wall_timeout"))
            ),
            cheap_agent=str(config.get("cheap_agent") or "claude"),
            pinned_context_windows={
                str(key): int(value)
                for key, value in dict(config.get("context_windows") or {}).items()
            },
            audit_budget_policy=audit_budget_policy,
            anchor_idl=anchor_idl_override or config.get("anchor_idl"),
            similarity_corpus_resolution=resolve_similarity_corpora(
                similarity_corpora_override
                if similarity_corpora_override is not None
                else list(config.get("similarity_corpora") or [])
            ),
        )
        validate_run_contract(
            dict(payload.get("run_contract") or {}), current_contract
        )
    except Exception:
        store.close()
        raise

    ws = RunWorkspace.open(root, binary=binary)
    collector = _LiveCollector(run_id, root, root / "live.log")
    with _LIVE_LOCK:
        _LIVE[run_id] = {
            "id": run_id,
            "root": str(root),
            "started": ws.meta.get("started", ""),
            "engine": config.get("engine") or "ida",
            "agent": config.get("worker_analyst") or "claude",
            "binary": binary,
            "collector": collector,
            "events": collector.events,
            "next_seq": collector.next_seq,
            "process": None,
        }

    def _runner():
        try:
            orch = Orchestrator(engine_config)
            result = orch.swarm_run(
                binary,
                workspace=ws,
                pre_analyze=False,
                on_event=collector.on_event,
                objective=str(config.get("objective") or "") or None,
                supervisor=str(config.get("supervisor") or "claude"),
                worker_analyst=str(config.get("worker_analyst") or "claude"),
                worker_reviewer=str(config.get("worker_reviewer") or "claude"),
                model=config.get("model"),
                max_supervisor_rounds=int(config.get("max_supervisor_rounds") or 2),
                max_worker_rounds=int(config.get("max_worker_rounds") or 2),
                max_parallel=int(config.get("max_parallel") or 3),
                k_candidates=int(config.get("k_candidates") or 1),
                adversarial_review=bool(config.get("adversarial_review")),
                topo_strategy=str(config.get("topo_strategy") or "auto"),
                spawn_strategy=str(config.get("spawn_strategy") or "search"),
                search_k=int(config.get("search_k") or 4),
                cheap_agent=str(config.get("cheap_agent") or "claude"),
                spawn_budget=int(config.get("spawn_budget") or 12),
                complexity_tier=str(config.get("complexity_tier") or "UNKNOWN"),
                strict_verify=bool(config.get("strict_verify", True)),
                max_agent_calls=audit_budget_policy.max_calls,
                audit_wall_timeout=audit_budget_policy.max_wall_seconds,
                max_agent_tokens=audit_budget_policy.max_tokens,
                max_agent_cost_usd=audit_budget_policy.max_cost_usd,
                budget_verification_reserve_calls=(
                    audit_budget_policy.critical_reserve_calls
                ),
                anchor_idl=anchor_idl_override,
                similarity_corpora=similarity_corpora_override,
                audit_state_store=store,
            )
            collector.log(
                "done",
                f"resumed paused={result.paused} converged={result.converged} "
                f"workers={len(result.workers)} root={root}",
            )
        except Exception as exc:  # noqa: BLE001
            collector.log("error", f"{exc}\n{traceback.format_exc()}")
        finally:
            store.close()
            collector.close()
            with _LIVE_LOCK:
                info = _LIVE.get(run_id)
                if info:
                    info["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    info["collector"] = None
                    info["next_seq"] = collector.next_seq

    thread = threading.Thread(target=_runner, daemon=True, name=f"angerona-resume-{run_id}")
    with _LIVE_LOCK:
        _LIVE[run_id]["thread"] = thread
    try:
        thread.start()
    except Exception:
        store.close()
        with _LIVE_LOCK:
            _LIVE.pop(run_id, None)
        raise
    return {"run_id": run_id, "workspace": str(root), "status": "resuming"}


def delete_run(run_id: str) -> dict:
    root = _run_root(run_id)
    if root is None:
        raise ValueError("invalid run id")
    if not root.exists():
        raise FileNotFoundError("run not found")
    if _run_is_running(root):
        raise RuntimeError("cannot delete a running run")
    with _LIVE_LOCK:
        info = _LIVE.get(run_id)
        thread = info.get("thread") if info else None
        if info and (info.get("collector") or (thread and thread.is_alive())):
            raise RuntimeError("cannot delete a running run")
        _LIVE.pop(run_id, None)
    shutil.rmtree(root)
    return {"deleted": run_id}


def _read_json_file(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:  # noqa: BLE001
        return {}


def _file_picker_roots() -> list[dict]:
    roots = [
        ("Samples", REPO_ROOT / "samples"),
        ("Repository", REPO_ROOT),
        ("Home", Path.home()),
        ("Root", Path("/")),
        ("Temp", Path("/tmp")),
    ]
    out = []
    seen = set()
    for label, path in roots:
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.exists() or not resolved.is_dir():
            continue
        seen.add(resolved)
        out.append({"label": label, "path": str(resolved)})
    return out


def _file_picker_default_dir() -> Path:
    samples = REPO_ROOT / "samples"
    return samples if samples.exists() else REPO_ROOT


def _is_binary_candidate(path: Path) -> bool:
    return path.suffix.lower() in _BINARY_EXTS


def list_server_files(path_text: str = "") -> dict:
    raw = (path_text or "").strip()
    path = Path(raw).expanduser() if raw else _file_picker_default_dir()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path.absolute()
    if not resolved.exists():
        raise FileNotFoundError(f"path not found: {raw}")
    if resolved.is_file():
        resolved = resolved.parent
    if not resolved.is_dir():
        raise NotADirectoryError(str(resolved))

    entries = []
    try:
        children = sorted(
            resolved.iterdir(),
            key=lambda p: (not p.is_dir(), p.name.lower()),
        )
    except PermissionError as exc:
        raise PermissionError(f"permission denied: {resolved}") from exc
    except OSError as exc:
        raise OSError(f"cannot read directory: {resolved}: {exc}") from exc

    for child in children[:_MAX_FILE_PICKER_ENTRIES]:
        if child.name.startswith("."):
            continue
        try:
            st = child.stat()
            is_dir = child.is_dir()
            is_file = child.is_file()
        except OSError:
            continue
        entries.append({
            "name": child.name,
            "path": str(child),
            "type": "dir" if is_dir else "file",
            "size": 0 if is_dir else st.st_size,
            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            "selectable": bool(is_file),
            "candidate": bool(is_file and _is_binary_candidate(child)),
        })

    parent = str(resolved.parent) if resolved.parent != resolved else ""
    return {
        "path": str(resolved),
        "parent": parent,
        "entries": entries,
        "truncated": len(children) > _MAX_FILE_PICKER_ENTRIES,
        "roots": _file_picker_roots(),
    }


def _worker_dirs(root: Path) -> list[Path]:
    wdir = root / "workers"
    if not wdir.exists():
        return []
    return sorted([d for d in wdir.iterdir() if d.is_dir()])


def _event_preview(ev: dict | None) -> str:
    if not ev:
        return ""
    if ev.get("kind") == "log":
        return f"{ev.get('phase', '')}: {ev.get('text', '')}".strip(": ")
    if ev.get("kind") == "tool_use":
        return f"tool: {ev.get('name', '')}".strip()
    if ev.get("kind") == "text":
        return str(ev.get("text", ""))[:180]
    if ev.get("kind") == "error":
        return f"error: {ev.get('text', '')}"[:180]
    return str(ev.get("kind") or "") or json.dumps(ev)[:180]


def _events_after(events: list[dict], since: int) -> list[dict]:
    return [ev for ev in events if int(ev.get("seq") or 0) > since]


def _normalize_event(ev: dict, seq: int | None = None) -> dict:
    if not isinstance(ev, dict):
        ev = {"kind": "log", "text": str(ev)}
    kind = str(ev.get("kind") or "log")
    if kind not in _EVENT_KINDS:
        kind = "log"
    out = dict(ev)
    out["kind"] = kind
    if seq is not None:
        out["seq"] = int(out.get("seq") or seq)
    else:
        out["seq"] = int(out.get("seq") or 0)
    out["ts"] = str(out.get("ts") or "")
    if "phase" in out:
        out["phase"] = str(out.get("phase") or "")
    return out


def _read_live_log(root: Path) -> list[dict]:
    log = root / "live.log"
    events: list[dict] = []
    if not log.exists():
        return events
    try:
        with open(log, encoding="utf-8", errors="replace") as fh:
            recent = collections.deque(fh, maxlen=_MAX_LIVE_EVENTS)
        for i, line in enumerate(recent, 1):
            if line.strip():
                events.append(_normalize_event(json.loads(line), i))
    except Exception:  # noqa: BLE001
        pass
    return events


def _disk_run_active(root: Path, meta: dict) -> bool:
    if meta.get("finished"):
        return False
    log = root / "live.log"
    if log.exists():
        try:
            # Separate web processes cannot see the original in-memory collector.
            # Treat a recently-written live.log as active so forwarded dashboards show progress.
            return (time.time() - log.stat().st_mtime) < 300
        except OSError:
            pass

    # CLI-created runs may not have live.log. Use recent metadata/docs updates as a
    # fallback signal to avoid falsely showing unknown/inactive on alive runs.
    candidates = [
        root / "run.json",
        root / "docs" / "progress.md",
        root / "docs" / "findings.md",
        root / "docs" / "review.md",
        root / "raw" / "plan_1.json",
    ]
    latest = 0.0
    for path in candidates:
        try:
            latest = max(latest, path.stat().st_mtime)
        except OSError:
            continue
    if latest:
        return (time.time() - latest) < 300
    return False


def _infer_status(meta: dict, swarm: dict, live: dict | None = None, root: Path | None = None) -> str:
    """Infer run status while avoiding an explicit unknown state."""
    live_finished = bool(live and live.get("finished"))
    if live and not live_finished:
        return "running"
    if meta.get("status") == "paused":
        return "paused"
    if meta.get("error"):
        return "failed"
    if meta.get("finished"):
        converged = bool(meta.get("converged"))
        coverage = bool((swarm or {}).get("coverage_complete"))
        return "completed" if (converged and coverage) else "partial"
    # Explicit completion marker in memory (e.g. dead live collector with finished) takes
    # priority over disk activity heuristics that can remain fresh after shutdown.
    if not live_finished and root is not None and _disk_run_active(root, meta):
        return "running"
    if meta.get("rounds") or meta.get("total_rounds") or meta.get("swarm") or meta.get("coverage_complete") is not None:
        return "partial"
    if _read_live_log(root) if root else []:
        return "partial"
    return "partial"


def _live_snapshot(live: dict | None, root: Path | None = None) -> dict:
    if not live:
        events = _read_live_log(root) if root else []
        last = events[-1] if events else None
        return {
            "running": False,
            "event_count": int(last.get("seq") or len(events)) if last else 0,
            "last_event": last,
            "last_event_text": _event_preview(last),
        }
    collector = live.get("collector")
    events = collector.events if collector else live.get("events", [])
    last = events[-1] if events else None
    return {
        "running": not bool(live.get("finished")),
        "event_count": int(live.get("next_seq") or (int(last.get("seq") or 0) + 1 if last else 1)) - 1,
        "last_event": last,
        "last_event_text": _event_preview(last),
    }


def _summarize_run(root: Path, live: dict | None = None) -> dict:
    meta = _read_run_json(root)
    swarm = meta.get("swarm") or {}
    workers = swarm.get("workers") or []
    converged = bool(meta.get("converged"))
    coverage = swarm.get("coverage_complete")
    label = root.name
    live_state = _live_snapshot(live, root)
    status = _infer_status(meta, swarm, live, root)
    audit_status = ""
    if (root / "audit_state" / "audit-head.json").is_file():
        try:
            from ..agents.audit_state import AuditStateStore

            with AuditStateStore(root) as audit_store:
                audit_snapshot = audit_store.load_latest()
            audit_status = str(
                audit_snapshot.payload.get("status") if audit_snapshot else ""
            )
        except (OSError, RuntimeError, ValueError):
            # A corrupt state is not advertised as resumable; resume itself will
            # surface the integrity error with full detail.
            audit_status = "invalid"
    # binary name (last path component)
    binary = meta.get("binary") or ""
    bin_name = Path(binary).name if binary else (root.name.split("__", 1)[-1])
    return {
        "id": root.name,
        "label": label,
        "binary": binary,
        "binary_name": bin_name,
        "engine": meta.get("engine") or (live or {}).get("engine") or "",
        "agent": meta.get("agent") or (live or {}).get("agent") or "",
        "model": meta.get("model") or "",
        "anchor_idl": meta.get("anchor_idl") or "",
        "similarity_corpora": list(meta.get("similarity_corpora") or []),
        "anchor_instruction_count": int(meta.get("anchor_instruction_count") or 0),
        "reviewer": meta.get("reviewer", ""),
        "objective": meta.get("objective", ""),
        "sandbox": bool(meta.get("sandbox")),
        "started": meta.get("started", ""),
        "finished": meta.get("finished", ""),
        "status": status,
        "resumable": bool(meta.get("exact_resume_ready"))
        and (root / "audit_state" / "audit-head.json").is_file()
        and audit_status not in {
            "completed", "budget_exhausted", "incomplete", "invalid",
        },
        "converged": converged,
        "coverage_complete": coverage,
        "total_rounds": meta.get("total_rounds"),
        "requested_rounds": meta.get("requested_rounds"),
        "requested_parallel": meta.get("requested_parallel"),
        "worker_count": len(workers),
        "workers_converged": sum(1 for w in workers if w.get("converged")),
        "worker_summary": [
            {"id": w.get("id"), "title": w.get("title"), "converged": w.get("converged"),
             "rounds": w.get("rounds"), "workspace": str(Path(w.get("workspace", "")).name)
             if w.get("workspace") else ""}
            for w in workers
        ],
        "note": meta.get("note", ""),
        "live_event_count": live_state["event_count"],
        "last_event": live_state["last_event"],
        "last_event_text": live_state["last_event_text"],
    }


def _run_detail(root: Path) -> dict:
    summary = _summarize_run(root, live=_LIVE.get(root.name))
    meta = _read_run_json(root)
    swarm = meta.get("swarm") or {}
    swarm_workers = swarm.get("workers") or []
    workers_by_dir = {
        Path(w.get("workspace", "")).name: w for w in swarm_workers if w.get("workspace")
    }
    # file tree grouped by section
    tree = _build_tree(root)
    workers = []
    for wd in _worker_dirs(root):
        wmeta = _read_run_json(wd)
        spec = workers_by_dir.get(wd.name, {})
        workers.append({
            "id": spec.get("id") or wd.name,
            "title": spec.get("title") or Path(wmeta.get("binary", wd.name)).name,
            "workspace_name": wd.name,
            "workspace": spec.get("workspace", str(wd)),
            "converged": spec.get("converged", wmeta.get("converged")),
            "total_rounds": spec.get("rounds", wmeta.get("total_rounds")),
            "started": wmeta.get("started"),
            "finished": wmeta.get("finished"),
            "rounds": wmeta.get("rounds", []),
            "tree": _build_tree(wd),
            "root": _safe_rel(wd, root).replace(os.sep, "/"),
        })
    return {
        **summary,
        "swarm": swarm,
        "tree": tree,
        "workers": workers,
        "root": str(root.relative_to(_runs_dir())),
        "artifacts": _collect_artifacts(root),
        "export": _export_summary(root),
        "security": _security_summary(root),
    }


def _artifact_role(rel: str) -> str:
    if rel == "run.json":
        return "run metadata"
    if rel == "live.log":
        return "live agent stream"
    if rel.startswith("docs/"):
        return "agent report"
    if rel.startswith("code/decompiled/"):
        return "decompiled function"
    if rel.startswith("code/"):
        return "binary code export"
    if rel.startswith("raw/") and rel.endswith(".events.json"):
        return "agent event transcript"
    if rel.startswith("raw/"):
        return "raw agent transcript"
    if rel.startswith("workers/") and rel.endswith(".events.json"):
        return "worker event transcript"
    if rel.startswith("workers/") and "/raw/" in rel:
        return "worker raw transcript"
    if rel.startswith("workers/") and "/docs/" in rel:
        return "worker report"
    if rel.startswith("workers/"):
        return "worker workspace"
    return "run artifact"


def _collect_artifacts(root: Path, *, limit: int = 500) -> dict:
    files: list[dict] = []
    total_bytes = 0
    by_role: dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        rel = _safe_rel(p, root).replace(os.sep, "/")
        role = _artifact_role(rel)
        total_bytes += st.st_size
        by_role[role] = by_role.get(role, 0) + 1
        files.append({
            "path": rel,
            "name": p.name,
            "role": role,
            "size": st.st_size,
            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            "mtime_epoch": st.st_mtime,
        })
    files.sort(key=lambda x: x["mtime_epoch"], reverse=True)
    return {
        "total_files": len(files),
        "total_bytes": total_bytes,
        "by_role": by_role,
        "latest": files[:limit],
    }


def _export_summary(root: Path) -> dict:
    manifest = _read_json_file(root / "code" / "EXPORT_MANIFEST.json")
    if not manifest:
        return {}
    return {
        "metadata": manifest.get("metadata", {}),
        "counts": manifest.get("counts", {}),
        "file_count": len(manifest.get("files") or []),
        "binary": manifest.get("binary", ""),
    }


def _security_summary(root: Path) -> dict:
    props = _read_json_file(root / "code" / "security_properties.json")
    if not props:
        return {}
    return {
        "format": props.get("format"),
        "supported": props.get("supported"),
        "summary": props.get("exploit_mitigation_summary") or props.get("note", ""),
        "mitigations": props.get("mitigations", {}),
    }


def _build_tree(root: Path) -> dict:
    """A nested file/folder tree under a run root, with sizes (bounded depth)."""
    base = root.resolve()
    out: dict = {"name": root.name, "type": "dir", "children": []}

    def walk(d: Path, node: dict, depth: int):
        if depth > 6:
            return
        try:
            entries = sorted(d.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except OSError:
            return
        for p in entries:
            rel = _safe_rel(p, base)
            if p.is_dir():
                child = {"name": p.name, "type": "dir", "rel": rel, "children": []}
                node["children"].append(child)
                walk(p, child, depth + 1)
            else:
                try:
                    size = p.stat().st_size
                except OSError:
                    size = 0
                node["children"].append({
                    "name": p.name, "type": "file", "rel": rel, "size": size,
                    "ext": p.suffix.lower().lstrip("."),
                })

    walk(root, out, 0)
    return out


# ---------------------------------------------------------------- live-run capture

class _LiveCollector:
    """Captures orchestrator/worker events + stderr into a live run record."""

    def __init__(self, run_id: str, root: Path, log_path: Path):
        self.run_id = run_id
        self.root = root
        self.log_path = log_path
        self.events: list[dict] = []
        self.next_seq = 1
        self._lock = threading.Lock()
        self._f = open(log_path, "a", encoding="utf-8", buffering=1)

    def on_event(self, kind: str, data: dict) -> None:
        with self._lock:
            ev = {"seq": self.next_seq, "ts": time.strftime("%H:%M:%S"),
                  "kind": kind, **(data or {})}
            self.next_seq += 1
            self.events.append(ev)
            if len(self.events) > _MAX_LIVE_EVENTS:
                del self.events[:-_MAX_LIVE_EVENTS]
        try:
            self._f.write(json.dumps(ev) + "\n")
        except Exception:  # noqa: BLE001
            pass

    def log(self, phase: str, msg: str) -> None:
        with self._lock:
            ev = {"seq": self.next_seq, "ts": time.strftime("%H:%M:%S"),
                  "kind": "log", "phase": phase, "text": msg}
            self.next_seq += 1
            self.events.append(ev)
            if len(self.events) > _MAX_LIVE_EVENTS:
                del self.events[:-_MAX_LIVE_EVENTS]
        try:
            self._f.write(json.dumps(ev) + "\n")
        except Exception:  # noqa: BLE001
            pass

    def close(self):
        try:
            self._f.close()
        except Exception:  # noqa: BLE001
            pass


def _phase_collector(collector: _LiveCollector):
    """Return an on_event callback mirroring orchestrator._phase_printer, feeding the collector."""
    def on_event(kind: str, data: dict) -> None:
        collector.on_event(kind, data)
    return on_event


def start_run(binary: str, *, engine: str = "ida", agent: str = "claude", model: str = "",
              objective: str = "", sandbox: bool = False, rounds: int = 2,
              parallel: int = 3, max_agent_calls: int | None = None,
              audit_wall_timeout: float | None = None,
              max_agent_tokens: int | None = None,
              max_agent_cost_usd: float | None = None,
              budget_verification_reserve_calls: int | None = None,
              anchor_idl: str | None = None,
              similarity_corpora: list[str] | None = None) -> dict:
    """Launch a real analysis run in a background thread; return its run_id immediately."""
    from ..agents.orchestrator import Orchestrator

    binary_path = str(Path(binary).expanduser().resolve())
    if not Path(binary_path).exists():
        raise FileNotFoundError(f"binary not found: {binary}")
    cfg = load_config(engine)
    cfg.sandbox = bool(sandbox)
    ok, msg = cfg.ready()
    if not ok:
        raise RuntimeError(f"engine not ready: {msg}")

    orch = Orchestrator(cfg)
    # We need the run root before swarm_run creates it, so preflight to get binary abs.
    orch.preflight(binary_path)
    # Create the workspace up-front so we have a root + live.log path to capture into.
    runs_dir = cfg.state_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    ws = RunWorkspace.create(runs_dir, binary_path)
    run_id = ws.root.name
    live_log = ws.root / "live.log"
    ws.meta.update({
        "engine": engine,
        "agent": agent,
        "objective": objective or "",
        "model": model or "",
        "anchor_idl": anchor_idl or "",
        "similarity_corpora": list(similarity_corpora or []),
        "sandbox": bool(sandbox),
        "requested_rounds": rounds,
        "requested_parallel": parallel,
        "max_agent_calls": max_agent_calls,
        "audit_wall_timeout": audit_wall_timeout,
        "max_agent_tokens": max_agent_tokens,
        "max_agent_cost_usd": max_agent_cost_usd,
        "budget_verification_reserve_calls": budget_verification_reserve_calls,
    })
    ws._save_meta()

    collector = _LiveCollector(run_id, ws.root, live_log)
    with _LIVE_LOCK:
        _LIVE[run_id] = {
            "id": run_id, "root": str(ws.root), "started": ws.meta.get("started", ""),
            "engine": engine, "agent": agent, "binary": binary_path,
            "collector": collector, "events": collector.events, "next_seq": collector.next_seq,
            "process": None,
        }

    def _runner():
        try:
            collector.log("start", f"engine={engine} agent={agent} binary={binary_path}")
            from ..cli import pick_reviewer
            reviewer, note = pick_reviewer(agent, None, allow_shell=True)
            ws.meta["reviewer"] = reviewer
            ws._save_meta()
            if note:
                collector.log("reviewer", note)

            # Pass our pre-created workspace + live on_event into swarm_run so the run
            # writes into THIS dir (not a second freshly-created one) and every agent
            # event (tool_use / text / result) is teed into the collector for live streaming.
            res = orch.swarm_run(
                binary_path, objective=objective or None, supervisor=agent,
                worker_analyst=agent, worker_reviewer=reviewer, model=model or None,
                max_supervisor_rounds=rounds, max_worker_rounds=rounds,
                max_parallel=parallel, pre_analyze=True,
                workspace=ws, on_event=collector.on_event,
                max_agent_calls=max_agent_calls,
                audit_wall_timeout=audit_wall_timeout,
                max_agent_tokens=max_agent_tokens,
                max_agent_cost_usd=max_agent_cost_usd,
                budget_verification_reserve_calls=budget_verification_reserve_calls,
                anchor_idl=anchor_idl,
                similarity_corpora=similarity_corpora,
            )
            collector.log("done", f"converged={res.converged} workers={len(res.workers)} "
                                  f"root={res.workspace.root}")
        except Exception as exc:  # noqa: BLE001
            collector.log("error", f"{exc}\n{traceback.format_exc()}")
            ws.meta.update({
                "converged": False,
                "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(exc),
                "note": f"failed: {exc}",
                "total_rounds": ws.meta.get("total_rounds", 0),
            })
            ws._save_meta()
            ws.log("error", str(exc))
        finally:
            collector.close()
            with _LIVE_LOCK:
                info = _LIVE.get(run_id)
                if info:
                    info["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    info["collector"] = None
                    info["next_seq"] = collector.next_seq

    t = threading.Thread(target=_runner, daemon=True, name=f"angerona-run-{run_id}")
    with _LIVE_LOCK:
        if run_id in _LIVE:
            _LIVE[run_id]["thread"] = t
    t.start()
    return {"run_id": run_id, "root": str(ws.root), "live_log": str(live_log)}


def live_events(run_id: str, since: int = 0) -> dict:
    root = _run_root(run_id)
    if root is None:
        return {"run_id": run_id, "running": False, "events": [], "total": 0,
                "since": since, "error": "invalid run id"}
    with _LIVE_LOCK:
        info = _LIVE.get(run_id)
    if not info:
        # Run finished — replay from live.log on disk if present.
        events = _read_live_log(root)
        running = _disk_run_active(root, _read_run_json(root))
        total = int(events[-1].get("seq") or len(events)) if events else 0
        return {"run_id": run_id, "running": running, "events": _events_after(events, since),
                "total": total, "since": since}
    collector = info.get("collector")
    evs = collector.events if collector else info.get("events", [])
    total = (collector.next_seq - 1) if collector else int(info.get("next_seq") or 1) - 1
    running = not bool(info.get("finished"))
    return {"run_id": run_id, "running": running,
            "events": _events_after(evs, since),
            "total": total, "since": since}


def observability_events(
    run_id: str, since: int = 0, limit: int = 500, *, verify: bool = True
) -> dict:
    """Return the durable correlated timeline, not the lossy in-memory live feed."""

    from ..observability import ledger_for_workspace

    root = _run_root(run_id)
    if root is None:
        return {"error": "invalid run id"}
    if not root.is_dir() or not (root / "run.json").is_file():
        return {"error": "run not found"}
    ledger = ledger_for_workspace(root)
    imported = ledger.import_child_spools(root)
    result = {
        "run_id": run_id,
        "since": since,
        "events": ledger.events(since=since, limit=limit),
        "child_events_imported": imported,
    }
    if verify:
        result["verification"] = ledger.verify()
    return result


# ---------------------------------------------------------------- file serving

_TEXT_EXTS = {"md", "txt", "c", "h", "csv", "json", "log", "py", "java", "sh", "js", "css", "html", "yaml", "yml", "toml"}
_BINARY_NOTE = "(binary file — not displayed)"


def read_file_safe(run_id: str, rel_path: str) -> dict:
    """Read a file under a run root by relative path. Bounded size; text only."""
    root = _run_root(run_id)
    if root is None:
        return {"error": "invalid run id"}
    rel_path = (rel_path or "").strip().lstrip("/")
    if not rel_path:
        return {"error": "file path required"}
    # allow worker paths like "workers/<wdir>/rel"
    target = (root / rel_path).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {"error": "path escapes run root"}
    if not target.exists() or not target.is_file():
        return {"error": f"file not found: {rel_path}"}
    try:
        size = target.stat().st_size
    except OSError:
        size = 0
    ext = target.suffix.lower().lstrip(".")
    is_text = ext in _TEXT_EXTS or not ext
    if not is_text:
        return {"path": rel_path, "size": size, "is_text": False, "content": _BINARY_NOTE,
                "truncated": False, "full_path": str(target)}
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read(_MAX_FILE_DISPLAY_BYTES + 1)
    except Exception as exc:  # noqa: BLE001
        return {"path": rel_path, "size": size, "is_text": True, "content": f"(read error: {exc})"}
    truncated = len(raw) > _MAX_FILE_DISPLAY_BYTES
    try:
        mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(target.stat().st_mtime))
    except OSError:
        mtime = ""
    return {"path": rel_path, "size": size, "is_text": True,
            "content": raw[:_MAX_FILE_DISPLAY_BYTES], "truncated": truncated, "full_size": size,
            "mtime": mtime, "full_path": str(target)}


# ---------------------------------------------------------------- HTTP server

class Handler(BaseHTTPRequestHandler):
    server_version = "angerona-web/0.1"
    auth_token: str | None = None

    def log_message(self, fmt, *args):  # quieter logging
        sys.stderr.write("[web] %s - %s\n" % (self.address_string(), fmt % args))

    # ----- helpers
    def _json(self, obj, status=200):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorize_api(self, path: str) -> bool:
        if not path.startswith("/api/"):
            return True
        authority = str(self.headers.get("Host") or "").lower()
        host = urlparse("//" + authority).hostname
        if not self.auth_token and host not in {"localhost", "127.0.0.1", "::1"}:
            self._json({"error": "untrusted request host"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if parsed_origin.scheme not in {"http", "https"} or parsed_origin.netloc.lower() != authority:
                self._json({"error": "cross-origin API request denied"}, 403)
                return False
        if _request_token_valid(self.headers, self.auth_token):
            return True
        self.send_response(401)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("WWW-Authenticate", "Bearer")
        body = b'{"error":"authentication required"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _send_file(self, path: Path, content_type: str):
        if not path.exists() or not path.is_file():
            self.send_error(404, "not found")
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None, {"error": "invalid Content-Length"}, 400
        if length < 0:
            return None, {"error": "invalid Content-Length"}, 400
        if length > _MAX_POST_BYTES:
            return None, {"error": "request body too large"}, 413
        if length and self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            return None, {"error": "application/json required"}, 415
        try:
            body = json.loads(self.rfile.read(length) or "{}")
        except json.JSONDecodeError:
            return None, {"error": "invalid JSON"}, 400
        if not isinstance(body, dict):
            return None, {"error": "JSON body must be an object"}, 400
        return body, None, 200

    # ----- routing
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if not self._authorize_api(path):
            return

        if path == "/" or path == "/index.html":
            return self._send_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/api/runs":
            return self._json({"runs": _list_runs()})
        if path == "/api/engines":
            cfg_ida = load_config("ida")
            cfg_ghidra = load_config("ghidra")
            ida_ok, ida_msg = cfg_ida.ida_ready()
            gh_ok, gh_msg = cfg_ghidra.ghidra_ready()
            return self._json({"ida": {"ready": ida_ok, "message": ida_msg},
                               "ghidra": {"ready": gh_ok, "message": gh_msg}})
        if path == "/api/samples":
            sdir = REPO_ROOT / "samples"
            samples = []
            if sdir.exists():
                for p in sorted(sdir.iterdir()):
                    if p.is_file():
                        samples.append({"name": p.name, "path": str(p), "size": p.stat().st_size})
            return self._json({"samples": samples})
        if path == "/api/files":
            try:
                return self._json(list_server_files(qs.get("path", [""])[0]))
            except FileNotFoundError as exc:
                return self._json({"error": str(exc)}, 404)
            except PermissionError as exc:
                return self._json({"error": str(exc)}, 403)
            except OSError as exc:
                return self._json({"error": str(exc)}, 400)
        m = re.match(r"^/api/runs/([^/]+)$", path)
        if m:
            rid = unquote(m.group(1))
            root = _run_root(rid)
            if root is None:
                return self._json({"error": "invalid run id"}, 400)
            if not root.exists() and rid not in _LIVE:
                return self._json({"error": "run not found"}, 404)
            return self._json(_run_detail(root if root.exists() else Path(_LIVE[rid]["root"])))
        m = re.match(r"^/api/runs/([^/]+)/file$", path)
        if m:
            rid = unquote(m.group(1))
            if _run_root(rid) is None:
                return self._json({"error": "invalid run id"}, 400)
            rel = qs.get("path", [""])[0]
            return self._json(read_file_safe(rid, rel))
        m = re.match(r"^/api/runs/([^/]+)/live$", path)
        if m:
            rid = unquote(m.group(1))
            if _run_root(rid) is None:
                return self._json({"error": "invalid run id"}, 400)
            try:
                since = max(0, int(qs.get("since", ["0"])[0] or 0))
            except ValueError:
                since = 0
            return self._json(live_events(rid, since))
        m = re.match(r"^/api/runs/([^/]+)/trace$", path)
        if m:
            rid = unquote(m.group(1))
            if _run_root(rid) is None:
                return self._json({"error": "invalid run id"}, 400)
            try:
                since = max(0, int(qs.get("since", ["0"])[0] or 0))
                limit = _clamped_int(qs.get("limit", ["500"])[0], 500, 1, 5000)
                verify = qs.get("verify", ["1"])[0].lower() not in {"0", "false", "no"}
                return self._json(observability_events(rid, since, limit, verify=verify))
            except (OSError, ValueError, RuntimeError) as exc:
                return self._json({"error": str(exc)}, 400)
        # static assets under /static/
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            asset = (WEB_DIR / "static" / rel).resolve()
            try:
                asset.relative_to((WEB_DIR / "static").resolve())
            except ValueError:
                self.send_error(403)
                return
            ctype = "application/javascript" if asset.suffix == ".js" else "text/css"
            return self._send_file(asset, ctype + "; charset=utf-8")
        self.send_error(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self._authorize_api(parsed.path):
            return
        if parsed.path == "/api/runs/start":
            body, err, status = self._json_body()
            if err:
                return self._json(err, status)
            try:
                cfg = _validated_run_config(body, {
                    "binary": "",
                    "engine": "ida",
                    "agent": "claude",
                    "objective": "",
                    "sandbox": False,
                    "rounds": 2,
                    "parallel": 3,
                })
                res = start_run(**cfg)
                return self._json(res, 201)
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            except FileNotFoundError as exc:
                return self._json({"error": str(exc)}, 404)
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": str(exc)}, 500)
        m = re.match(r"^/api/runs/([^/]+)/pause$", parsed.path)
        if m:
            body, err, status = self._json_body()
            if err:
                return self._json(err, status)
            try:
                return self._json(
                    pause_run(unquote(m.group(1)), str(body.get("reason") or "")),
                    202,
                )
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            except FileNotFoundError as exc:
                return self._json({"error": str(exc)}, 404)
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, 409)
        m = re.match(r"^/api/runs/([^/]+)/resume$", parsed.path)
        if m:
            body, err, status = self._json_body()
            if err:
                return self._json(err, status)
            try:
                similarity_override = (
                    _validated_similarity_paths(body.get("similarity_corpora"))
                    if "similarity_corpora" in body else None
                )
                return self._json(
                    resume_run(
                        unquote(m.group(1)),
                        str(body.get("binary") or "") or None,
                        str(body.get("anchor_idl") or "") or None,
                        similarity_override,
                    ),
                    202,
                )
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            except FileNotFoundError as exc:
                return self._json({"error": str(exc)}, 404)
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, 409)
        m = re.match(r"^/api/runs/([^/]+)/edit$", parsed.path)
        if m:
            body, err, status = self._json_body()
            if err:
                return self._json(err, status)
            rid = unquote(m.group(1))
            try:
                return self._json(edit_run(rid, body))
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            except FileNotFoundError as exc:
                return self._json({"error": str(exc)}, 404)
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, 409)
        m = re.match(r"^/api/runs/([^/]+)/rerun$", parsed.path)
        if m:
            body, err, status = self._json_body()
            if err:
                return self._json(err, status)
            rid = unquote(m.group(1))
            try:
                return self._json(rerun_run(rid, body), 201)
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            except FileNotFoundError as exc:
                return self._json({"error": str(exc)}, 404)
            except RuntimeError as exc:
                return self._json({"error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": str(exc)}, 500)
        self.send_error(404, "not found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if not self._authorize_api(parsed.path):
            return
        m = re.match(r"^/api/runs/([^/]+)$", parsed.path)
        if not m:
            self.send_error(404, "not found")
            return
        rid = unquote(m.group(1))
        try:
            return self._json(delete_run(rid))
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        except FileNotFoundError as exc:
            return self._json({"error": str(exc)}, 404)
        except RuntimeError as exc:
            return self._json({"error": str(exc)}, 409)


def _is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_remote: bool = False,
    auth_token: str | None = None,
) -> int:
    if not allow_remote and not _is_loopback_host(host):
        print("[angerona-web] refusing remote bind without --allow-remote. "
              "Use SSH port forwarding: ssh -L 8765:127.0.0.1:8765 <host>",
              file=sys.stderr, flush=True)
        return 2
    token = auth_token or os.environ.get("ANGERONA_WEB_AUTH_TOKEN") or None
    if allow_remote and not _is_loopback_host(host) and not token:
        print("[angerona-web] refusing remote bind without an authentication token. "
              "Set ANGERONA_WEB_AUTH_TOKEN or pass --auth-token.",
              file=sys.stderr, flush=True)
        return 2
    # Ensure web static dir exists.
    (WEB_DIR / "static").mkdir(parents=True, exist_ok=True)
    request_handler = type("AuthenticatedHandler", (Handler,), {"auth_token": token})
    httpd = ThreadingHTTPServer((host, port), request_handler)
    print(f"[angerona-web] serving on http://{host}:{port}  (runs: {_runs_dir()})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[angerona-web] shutting down", flush=True)
    httpd.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Angerona web UI (stdlib HTTP server).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--allow-remote", action="store_true",
                   help="Allow a non-loopback bind; requires an authentication token.")
    p.add_argument("--auth-token", help="Bearer token; prefer ANGERONA_WEB_AUTH_TOKEN.")
    ns = p.parse_args(argv)
    return serve(ns.host, ns.port, allow_remote=ns.allow_remote, auth_token=ns.auth_token)


if __name__ == "__main__":
    raise SystemExit(main())
