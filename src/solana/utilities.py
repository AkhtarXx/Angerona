"""Optional Solana utility evidence collectors.

These tools are deliberately treated as utility evidence, not analysis engines:
they may strengthen or cross-check IDA/Ghidra/Binja output, but they never drive
engine selection and they are never mandatory for a Solana scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from ..observability import (
    capture_tree,
    content_descriptor,
    ledger_for_workspace,
    resolve_workspace_root,
)


UTILITY_POLICY = (
    "Optional utilities only. They may add local disassembly/version/context "
    "evidence, but do not decide engine routing and do not promote findings to "
    "CONFIRMED without the normal verified-worker/evidence gates. solana-cli "
    "network/program lookups are not run implicitly."
)


def collect_solana_utility_evidence(
    binary: str | Path,
    output_dir: str | Path,
    *,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run safe local utility probes for a Solana SBF binary.

    Missing tools are recorded as unavailable. Command stdout/stderr are written
    to files to avoid large in-memory captures.
    """

    binary_path = Path(binary).expanduser().resolve()
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    utilities: dict[str, dict[str, Any]] = {}
    utilities["llvm-objdump"] = _run_if_available(
        name="llvm-objdump",
        binaries=("llvm-objdump",),
        args=lambda exe: [exe, "-d", "--no-show-raw-insn", str(binary_path)],
        out_dir=out_dir,
        timeout=timeout,
        purpose="lightweight ELF/SBF disassembly cross-check",
    )
    utilities["radare2"] = _run_if_available(
        name="radare2",
        binaries=("r2", "radare2"),
        args=lambda exe: [
            exe,
            "-q",
            "-e",
            "scr.color=false",
            "-e",
            "io.cache=true",
            "-c",
            "aaa",
            "-c",
            "iIj",
            "-c",
            "aflj",
            "-c",
            "isj",
            "-c",
            "izj",
            "-c",
            "q",
            str(binary_path),
        ],
        out_dir=out_dir,
        timeout=timeout,
        purpose="secondary function/string/symbol discovery cross-check",
    )
    utilities["anchor-cli"] = _run_if_available(
        name="anchor-cli",
        binaries=("anchor",),
        args=lambda exe: [exe, "--version"],
        out_dir=out_dir,
        timeout=min(timeout, 10),
        purpose="Anchor framework version/context only; project IDL parsing is opt-in",
    )
    utilities["solana-cli"] = _run_if_available(
        name="solana-cli",
        binaries=("solana",),
        args=lambda exe: [exe, "--version"],
        out_dir=out_dir,
        timeout=min(timeout, 10),
        purpose="Solana CLI version/context only; no implicit network lookup",
    )

    manifest = {
        "schema_version": 1,
        "model": "solana_utility_evidence",
        "binary": str(binary_path),
        "policy": UTILITY_POLICY,
        "utilities": utilities,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _run_if_available(
    *,
    name: str,
    binaries: tuple[str, ...],
    args,
    out_dir: Path,
    timeout: int,
    purpose: str,
) -> dict[str, Any]:
    for binary in binaries:
        exe = shutil.which(binary)
        if exe:
            return _run_to_files(
                name=name,
                command=args(exe),
                out_dir=out_dir,
                timeout=timeout,
                purpose=purpose,
            )
    return {
        "available": False,
        "tool": name,
        "purpose": purpose,
        "reason": f"{'/'.join(binaries)} not found on PATH",
    }


def _run_to_files(
    *,
    name: str,
    command: list[str],
    out_dir: Path,
    timeout: int,
    purpose: str,
) -> dict[str, Any]:
    stdout_path = out_dir / f"{name}.stdout.txt"
    stderr_path = out_dir / f"{name}.stderr.txt"
    started = time.monotonic()
    timed_out = False
    root = resolve_workspace_root(out_dir)
    observed = (root / "run.json").is_file() and all(
        (root / part).is_dir() for part in ("code", "docs", "raw")
    )
    ledger = ledger_for_workspace(root) if observed else None
    span = (
        ledger.start_span(
            component="solana_utility",
            category="subprocess",
            action="run_to_files",
            attributes={
                "tool": name,
                "command": content_descriptor(str(command)),
                "purpose": content_descriptor(purpose),
                "timeout": timeout,
            },
        )
        if ledger is not None
        else None
    )
    before = capture_tree(root) if ledger is not None else {}
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            proc = subprocess.Popen(
                command,
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                cwd=str(out_dir),
            )
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    returncode = proc.wait(timeout=3)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    returncode = -signal.SIGKILL
    except BaseException as exc:
        if span is not None:
            span.finish(status="error", attributes={"exception": type(exc).__name__})
        raise

    seconds = round(time.monotonic() - started, 3)
    if span is not None and ledger is not None:
        changes = ledger.record_tree_delta(
            before, capture_tree(root), component="solana_utility", parent_span_id=span.span_id
        )
        span.finish(
            status="ok" if returncode == 0 else "error",
            attributes={
                "returncode": returncode,
                "timed_out": timed_out,
                "stdout": _file_descriptor(stdout_path),
                "stderr": _file_descriptor(stderr_path),
                "filesystem_changes": changes,
            },
        )
    return {
        "available": True,
        "tool": name,
        "purpose": purpose,
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "seconds": seconds,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_bytes": _safe_size(stdout_path),
        "stderr_bytes": _safe_size(stderr_path),
        "stdout_tail": _tail_text(stdout_path),
        "stderr_tail": _tail_text(stderr_path),
    }


def _file_descriptor(path: Path) -> dict[str, object]:
    """Stream a captured output file into a content descriptor without loading it all.

    Mirrors the bytes descriptor shape from observability.content_descriptor but
    reads in bounded chunks so verbose tool output never materializes in memory.
    """
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
    except OSError:
        return {"present": False, "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    return {"present": True, "bytes": total, "sha256": digest.hexdigest()}


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _tail_text(path: Path, limit: int = 4000) -> str:
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            if size > limit:
                handle.seek(size - limit)
            data = handle.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")
