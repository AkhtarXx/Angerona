"""Per-run workspace: persist EVERYTHING, end-to-end, nothing missed.

Layout for each analysis run::

    <state>/runs/<binary>_<ts>/
      code/                 agent's working dir (decompiled dumps, scratch scripts)
      docs/
        progress.md         append-only timeline of every step (round, phase, event)
        findings.md         living security findings (updated each round)
        review.md           independent-reviewer verdicts, per round
      raw/
        round_<n>_analyst.md / .events.json
        round_<n>_review.md  / .events.json
      run.json              machine-readable run metadata + status

Writes are append/replace on plain files so a human or a restarted agent can
recover state by reading a few files (a la thoth's readable loop-state files).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .observability import (
    ObservabilityLedger,
    content_descriptor,
    ledger_for_workspace,
    sanitize_attributes,
)


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:60] or "target"


def _run_label(binary: str) -> str:
    """Human-readable label for a target: family + short hash for hash-named samples,
    else the cleaned filename stem. e.g. 'WannaCry-ed01ebfbc9', 'crackme'."""
    p = Path(binary)
    stem = p.stem
    if re.fullmatch(r"[0-9a-fA-F]{32,}", stem):          # hash-named sample
        label = stem[:10]
        parent = p.parent.name
        if parent and not re.fullmatch(r"[0-9a-fA-F]{16,}", parent) \
                and parent.lower() not in ("extracted", "samples", "tmp", "malware", "quarantine"):
            label = f"{re.sub(r'[^A-Za-z0-9]+', '-', parent)}-{label}"
    else:
        label = re.sub(r"[^A-Za-z0-9._-]+", "-", stem)[:28]
    return label.strip("-_.") or "target"


def _run_dir_name(binary: str) -> str:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return f"{ts}__{_run_label(binary)}-{uuid.uuid4().hex[:8]}"


@dataclass
class RunWorkspace:
    root: Path
    binary: str
    meta: dict = field(default_factory=dict)
    _meta_lock: threading.RLock = field(
        default_factory=threading.RLock, repr=False, compare=False
    )
    _observability: ObservabilityLedger | None = field(
        default=None, repr=False, compare=False
    )

    # ---------------------------------------------------------------- creation

    @classmethod
    def create(cls, runs_dir: Path, binary: str) -> "RunWorkspace":
        root = Path(runs_dir) / _run_dir_name(binary)
        for sub in ("code", "docs", "raw"):
            (root / sub).mkdir(parents=True, exist_ok=False)
        ws = cls(root=root, binary=str(binary))
        (ws.docs_dir / "progress.md").write_text(
            f"# Progress — {Path(binary).name}\n\n"
            f"- Binary: `{binary}`\n- Started: {_now()}\n- Workspace: `{root}`\n\n"
            f"## Timeline\n\n")
        (ws.docs_dir / "findings.md").write_text(
            f"# Findings — {Path(binary).name}\n\n_(updated each analysis round)_\n\n")
        (ws.docs_dir / "review.md").write_text(
            f"# Independent reviews — {Path(binary).name}\n\n")
        ws.meta = {
            "binary": str(binary),
            "started": _now(),
            "root": str(root),
            "rounds": [],
            "converged": False,
            "status": "running",
            "observability_id": uuid.uuid4().hex,
            "trace_id": uuid.uuid4().hex,
        }
        ws._save_meta()
        ws.observability.emit(
            component="workspace",
            category="lifecycle",
            action="created",
            attributes={
                "root": str(root),
                "binary": content_descriptor(str(binary)),
                "initial_artifacts": [
                    "docs/progress.md",
                    "docs/findings.md",
                    "docs/review.md",
                    "run.json",
                ],
            },
        )
        return ws

    @classmethod
    def open(cls, root: str | Path, *, binary: str | None = None) -> "RunWorkspace":
        """Open an existing run without recreating or truncating any artifact."""

        workspace_root = Path(root).expanduser().resolve()
        meta_path = workspace_root / "run.json"
        if not workspace_root.is_dir() or not meta_path.is_file():
            raise FileNotFoundError(f"not an Angerona workspace: {workspace_root}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(meta, dict):
            raise ValueError("workspace run.json must contain an object")
        target = binary or str(meta.get("binary") or "")
        if not target:
            raise ValueError("workspace does not record its target binary")
        for required in ("code", "docs", "raw"):
            if not (workspace_root / required).is_dir():
                raise FileNotFoundError(f"workspace is missing {required}/")
        ws = cls(root=workspace_root, binary=str(target), meta=meta)
        metadata_changed = False
        if not re.fullmatch(r"[0-9a-f]{32}", str(ws.meta.get("observability_id") or "")):
            ws.meta["observability_id"] = uuid.uuid4().hex
            metadata_changed = True
        if not re.fullmatch(r"[0-9a-f]{32}", str(ws.meta.get("trace_id") or "")):
            ws.meta["trace_id"] = uuid.uuid4().hex
            metadata_changed = True
        if metadata_changed:
            ws._save_meta()
        ws.observability.emit(
            component="workspace",
            category="lifecycle",
            action="opened",
            attributes={"root": str(workspace_root), "status": ws.meta.get("status")},
        )
        return ws

    # ------------------------------------------------------------------ paths

    @property
    def code_dir(self) -> Path:
        return self.root / "code"

    @property
    def docs_dir(self) -> Path:
        return self.root / "docs"

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def graph_dir(self) -> Path:
        d = self.root / "graph"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def checkpoint_db_path(self) -> Path:
        return self.root / "checkpoints.db"

    @property
    def observability(self) -> ObservabilityLedger:
        if self._observability is None:
            self._observability = ledger_for_workspace(self.root)
        return self._observability

    # --------------------------------------------------------------- persist

    def log(self, phase: str, message: str) -> None:
        """Append a timestamped entry to docs/progress.md (nothing is missed)."""
        line = f"- **{_now()}** · `{phase}` — {message}\n"
        with open(self.docs_dir / "progress.md", "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self.observability.emit(
            component="workspace",
            category="log",
            action="progress_appended",
            attributes={"phase": phase, "message": content_descriptor(message)},
        )

    def trace(self, event: str, **fields) -> None:
        """Unified machine-readable run log: ONE line per event, every stage writes
        here so a post-mortem sees the FULL story — agent spawn/fail, engine output
        (functions count, which engine), binary found/missing, verify gate result,
        review verdict. Written to docs/run_log.md (append-only, never missed)."""
        safe_fields = sanitize_attributes(fields)
        assert isinstance(safe_fields, dict)
        parts = [f"[{_now()}] {event}"]
        for k, v in safe_fields.items():
            parts.append(f"{k}={v}")
        line = " ".join(parts) + "\n"
        with open(self.docs_dir / "run_log.md", "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self.observability.emit(
            component="workspace",
            category="legacy_trace",
            action=str(event),
            attributes=safe_fields,
        )

    def update_findings(self, text: str, round_no: int) -> None:
        (self.docs_dir / "findings.md").write_text(
            f"# Findings — {Path(self.binary).name}\n\n"
            f"_Last updated: {_now()} (analysis round {round_no})_\n\n{text}\n")
        self.observability.emit(
            component="workspace",
            category="artifact",
            action="findings_replaced",
            attributes={"round": round_no, "content": content_descriptor(text)},
        )

    def append_review(self, round_no: int, verdict: str, text: str) -> None:
        with open(self.docs_dir / "review.md", "a", encoding="utf-8") as f:
            f.write(f"\n## Round {round_no} — verdict: {verdict}  ({_now()})\n\n{text}\n")
            f.flush()
            os.fsync(f.fileno())
        self.observability.emit(
            component="workspace",
            category="artifact",
            action="review_appended",
            attributes={
                "round": round_no,
                "verdict": verdict,
                "content": content_descriptor(text),
            },
        )

    def save_raw(self, name: str, text: str) -> Path:
        p = self.raw_dir / name
        p.write_text(text)
        self.observability.emit(
            component="workspace",
            category="artifact",
            action="raw_saved",
            attributes={"path": f"raw/{name}", "content": content_descriptor(text)},
        )
        return p

    def save_events(self, name: str, events: list) -> Path:
        p = self.raw_dir / name
        payload = json.dumps(events, indent=2)
        p.write_text(payload)
        self.observability.emit(
            component="workspace",
            category="artifact",
            action="events_saved",
            attributes={
                "path": f"raw/{name}",
                "event_count": len(events),
                "content": content_descriptor(payload),
            },
        )
        return p

    def record_round(self, entry: dict) -> None:
        with self._meta_lock:
            self.meta.setdefault("rounds", []).append(entry)
            self._save_meta()
        self.observability.emit(
            component="workspace",
            category="state",
            action="round_recorded",
            attributes={"round": sanitize_attributes(entry)},
        )

    def update_progress(self, key: str, payload: dict) -> None:
        """Atomically publish non-terminal progress without clobbering run state."""

        if not key or key in {"status", "converged", "finished"}:
            raise ValueError("progress key must be non-terminal")
        safe_payload = sanitize_attributes(payload)
        if not isinstance(safe_payload, dict):
            raise ValueError("progress payload must be an object")
        with self._meta_lock:
            self.meta[key] = safe_payload
            self._save_meta()
        self.observability.emit(
            component="workspace",
            category="progress",
            action="progress_updated",
            attributes={"key": key, "progress": safe_payload},
        )

    def finish(
        self,
        *,
        converged: bool,
        rounds: int,
        note: str = "",
        status: str = "completed",
        persist: bool = True,
    ) -> None:
        # Terminal persistence is the final fail-closed boundary.  A caller that
        # forgets to provide an incomplete status must never publish a failed run
        # as completed, while a converged run may not carry a contradictory
        # terminal status.
        if status == "completed" and not converged:
            status = "incomplete"
        if converged and status != "completed":
            raise ValueError("a converged workspace must use completed status")
        with self._meta_lock:
            self.meta.update({"converged": converged, "total_rounds": rounds,
                              "finished": _now(), "note": note, "status": status})
            if persist:
                self._save_meta()
        self.log("done", f"converged={converged} after {rounds} round(s). {note}")
        self.observability.emit(
            component="workspace",
            category="lifecycle",
            action="finished",
            status=status,
            attributes={"converged": converged, "rounds": rounds, "note": note},
        )

    def pause(self, *, phase: str, note: str = "") -> None:
        with self._meta_lock:
            self.meta.update({
                "status": "paused",
                "paused": _now(),
                "pause_phase": phase,
                "note": note,
            })
            self._save_meta()
        self.log("paused", f"phase={phase}. {note}")
        self.observability.emit(
            component="workspace",
            category="lifecycle",
            action="paused",
            status="paused",
            attributes={"phase": phase, "note": note},
        )

    def mark_finalizing(self, *, note: str = "") -> None:
        with self._meta_lock:
            self.meta.update({"status": "finalizing", "note": note})
            self._save_meta()
        self.log("finalizing", note or "supervisor complete; finishing deterministic reports")
        self.observability.emit(
            component="workspace",
            category="lifecycle",
            action="finalizing",
            status="running",
            attributes={"note": note},
        )

    def resume(self, *, generation: int | None = None) -> None:
        with self._meta_lock:
            self.meta.update({
                "status": "running",
                "resumed": _now(),
                "resume_generation": generation,
            })
            self.meta.pop("finished", None)
            self._save_meta()
        self.log("resume", f"generation={generation or 'new'}")
        self.observability.emit(
            component="workspace",
            category="lifecycle",
            action="resumed",
            status="running",
            attributes={"generation": generation},
        )

    def _save_meta(self) -> None:
        with self._meta_lock:
            target = self.root / "run.json"
            before = content_descriptor(target.read_bytes()) if target.exists() else None
            tmp = self.root / f".run.json.{uuid.uuid4().hex}.tmp"
            try:
                with tmp.open("w", encoding="utf-8") as handle:
                    json.dump(self.meta, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, target)
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                descriptor = os.open(self.root, flags)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass
            after = content_descriptor(target.read_bytes())
            self.observability.emit(
                component="workspace",
                category="state",
                action="run_metadata_replaced",
                attributes={"path": "run.json", "before": before, "after": after},
            )
