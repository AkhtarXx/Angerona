"""Deterministic binary -> code export.

Saves EVERYTHING Ghidra recovers from a binary into a plain-file tree so nothing
is lost and it does not depend on the agent remembering to write files:

    code/analysis.json            full structured analysis (metadata, functions, ...)
    code/all_decompiled.c         every decompiled function, concatenated
    code/decompiled/<fn>_<addr>.c one file per decompiled function
    code/strings.txt              defined strings (addr + value)
    code/imports.txt              imported/external symbols
    code/exports.txt              exported symbols / entry points
    code/symbols.txt              program symbols
    code/functions.csv            function index (name, entry, size, signature)
    code/security_properties.json exploit mitigations (ELF)
    code/anchor_instructions.json safe Anchor IDL -> logical instruction map
    code/anchor_instructions.md   compact instruction index for agents/humans
    code/EXPORT_MANIFEST.json     summary of what was written
    code/injection_scan.json      prompt-injection scan of recovered strings (Crawford defense)
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import uuid
import fcntl
from pathlib import Path
from typing import Any

from .evidence_ledger import LEDGER_FILENAME, write_export_evidence_ledger
from .scan_injection import scan_strings_file


_AUTO_ANCHOR_RESOLUTION = object()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_export_tree(root: Path) -> None:
    """Make every staged file and directory durable before promotion."""

    directories: list[Path] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        for name in [*dirnames, *filenames]:
            candidate = current_path / name
            if candidate.is_symlink():
                raise RuntimeError(f"export staging tree contains a symlink: {candidate}")
        for name in filenames:
            path = current_path / name
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise RuntimeError(
                        f"export staging artifact is not a regular file: {path}"
                    )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        _fsync_directory(directory)


def _remove_export_tree(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"unsafe export transaction tree: {path}")
    shutil.rmtree(path)


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name)[:60] or "fn"


def _call_summary(functions: list[dict]) -> dict:
    """Authoritative call-count artifact derived directly from engine JSON."""
    rows = []
    for f in functions:
        callers = [str(x) for x in (f.get("callers") or [])]
        callees = [str(x) for x in (f.get("callees") or [])]
        rows.append({
            "name": str(f.get("name", "")),
            "entry": str(f.get("entry", "")),
            "caller_count": len(callers),
            "callee_count": len(callees),
            "callers": callers,
            "callees": callees,
        })
    return {
        "model": "authoritative_engine_call_summary",
        "function_count": len(functions),
        "functions_with_calls": sum(1 for row in rows if row["callee_count"] > 0),
        "total_call_edges": sum(row["callee_count"] for row in rows),
        "functions": rows,
    }


def _export_analysis_into(engine, binary: str, dest: str | Path, *,
                          decompile: bool = True, max_functions: int = 0,
                          analysis_data: dict | None = None,
                          producer: str = "engine_export",
                          anchor_idl: str | Path | None = None,
                          anchor_idl_resolution: dict[str, Any] | None | object = _AUTO_ANCHOR_RESOLUTION) -> dict:
    """Analyze ``binary`` and dump the full binary->code output under ``dest``."""
    dest = Path(dest)
    (dest / "decompiled").mkdir(parents=True, exist_ok=True)
    from .anchor_idl import (
        resolve_anchor_idl,
        validate_anchor_resolution_binary,
        write_anchor_instruction_map,
    )
    resolved_anchor_idl = (
        resolve_anchor_idl(binary, anchor_idl)
        if anchor_idl_resolution is _AUTO_ANCHOR_RESOLUTION
        else anchor_idl_resolution
    )
    validate_anchor_resolution_binary(binary, resolved_anchor_idl)

    if analysis_data is None:
        try:
            data = engine.analyze(binary, decompile=decompile, max_functions=max_functions)
        except Exception as exc:  # noqa: BLE001
            # Stage A hardening: a crashed engine must NOT leave a fake-ok manifest.
            # Write an explicit error status so the agent never trusts a partial tree.
            (dest / "EXPORT_MANIFEST.json").write_text(json.dumps({
                "binary": str(binary), "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }, indent=2))
            raise
    else:
        data = analysis_data

    # The engine may run for minutes. Revalidate before writing even the first
    # artifact so a replaced source cannot leave a stale-but-plausible export.
    validate_anchor_resolution_binary(binary, resolved_anchor_idl)
    (dest / "analysis.json").write_text(json.dumps(data, indent=2))

    from .binprops import elf_security_properties
    (dest / "security_properties.json").write_text(
        json.dumps(elf_security_properties(binary), indent=2))

    funcs = data.get("functions", [])
    combined: list[str] = []
    decompiled = 0
    for f in funcs:
        c = f.get("decompiled")
        if not c:
            continue
        header = (f"// {f.get('signature', '')}  @ {f.get('entry')}\n"
                  f"// callers={f.get('callers')} callees={f.get('callees')}\n\n")
        block = header + c
        name = str(f.get("name", "fn"))
        entry = str(f.get("entry", ""))
        addr = entry.lower().removeprefix("0x")
        # Don't duplicate the address: FUN_/LAB_/SUB_ names already contain it.
        if name.startswith(("FUN_", "thunk_FUN_", "LAB_", "SUB_")) or (addr and addr in name.lower()):
            fname = f"{_safe(name)}.c"
        else:
            fname = f"{_safe(name)}_{entry}.c"
        (dest / "decompiled" / fname).write_text(block)
        combined.append(block)
        decompiled += 1
    (dest / "all_decompiled.c").write_text("\n\n".join(combined))

    (dest / "strings.txt").write_text(
        "\n".join(f"{s.get('address')}\t{s.get('value')}" for s in data.get("strings", [])))
    (dest / "imports.txt").write_text(
        "\n".join(f"{i.get('library', '')}\t{i.get('name')}" for i in data.get("imports", [])))
    (dest / "exports.txt").write_text(
        "\n".join(f"{e.get('address')}\t{e.get('name')}" for e in data.get("exports", [])))
    (dest / "symbols.txt").write_text(
        "\n".join(f"{s.get('address')}\t{s.get('type')}\t{s.get('name')}" for s in data.get("symbols", [])))

    def _csv_row(f: dict) -> str:
        sig = str(f.get("signature", "")).replace('"', "'")
        return f'{f.get("name")},{f.get("entry")},{f.get("size")},"{sig}"'
    (dest / "functions.csv").write_text(
        "name,entry,size,signature\n" + "\n".join(_csv_row(f) for f in funcs))
    (dest / "CALL_SUMMARY.json").write_text(json.dumps(_call_summary(funcs), indent=2))

    # Anchor IDLs provide the program's logical instruction surface, but only if
    # they can be associated safely. The mapper preserves dispatcher/handler
    # uncertainty instead of pretending every discriminator match is a handler.
    validate_anchor_resolution_binary(binary, resolved_anchor_idl)
    anchor_report = write_anchor_instruction_map(dest, data, resolved_anchor_idl)

    # P0-3: scan recovered strings for prompt-injection (Crawford defense).
    # SECURITY BOUNDARY — a failed scan must NOT be reported as "clean"
    # (that is the "gate that can never fail" trap). On exception, mark the
    # report FAILED so the orchestrator treats it as UNTRUSTED, never clean.
    try:
        inj = scan_strings_file(dest).as_dict()
        inj["status"] = "ok"
        (dest / "injection_scan.json").write_text(json.dumps(inj, indent=2))
    except Exception as exc:  # noqa: BLE001
        inj = {"status": "failed", "error": f"{type(exc).__name__}: {exc}",
               "scanned": 0, "high": 0, "medium": 0, "hits": []}
        (dest / "injection_scan.json").write_text(json.dumps(inj, indent=2))

    md = data.get("metadata", {})
    # Stage A hardening: explicit status so the agent can reject partial/empty trees.
    # 'failed' is set when the engine crashed (see early except above).
    # 'partial' warns when fewer functions were decompiled than exist (e.g. IDA's
    # silent 600-cap on max_functions<=0) so coverage loss is NEVER silent.
    total_funcs = len(funcs)
    status = (
        "empty" if total_funcs == 0
        else "ok" if decompiled == total_funcs
        else "partial"
    )
    if status == "partial":
        md_note = (
            f"decompiled {decompiled}/{total_funcs} functions — decompilation coverage "
            "is limited; assembly/function metadata remains available"
        )
    else:
        md_note = ""
    manifest = {
        "binary": str(binary),
        "status": status,
        "effective_max_functions": max_functions if max_functions > 0 else "all",
        "metadata": md,
        "counts": {
            "functions": total_funcs,
            "decompiled_functions": decompiled,
            "strings": len(data.get("strings", [])),
            "imports": len(data.get("imports", [])),
            "exports": len(data.get("exports", [])),
            "symbols": len(data.get("symbols", [])),
            "anchor_instructions": anchor_report.get("summary", {}).get("instructions", 0),
            "anchor_handler_mapped": anchor_report.get("summary", {}).get("handler_mapped", 0),
        },
        "anchor": {
            "status": anchor_report.get("status"),
            "idl": anchor_report.get("idl", {}),
            "summary": anchor_report.get("summary", {}),
        },
        "files": sorted(
            str(p.relative_to(dest))
            for p in dest.rglob("*")
            if p.is_file() and p.name != LEDGER_FILENAME
        ),
        "note": md_note,
    }
    # Atomic write: temp file + rename so a crashed run never leaves a half-written
    # manifest the agent would trust as complete (R3 hardening).
    _manifest_atomic(dest / "EXPORT_MANIFEST.json", manifest)
    engine_name = str(md.get("engine") or md.get("tool") or md.get("producer") or producer)
    write_export_evidence_ledger(
        dest=dest,
        binary=binary,
        producer=producer,
        engine=engine_name,
        analysis=data,
        manifest=manifest,
    )
    return manifest


def export_analysis(engine, binary: str, dest: str | Path, *,
                    decompile: bool = True, max_functions: int = 0,
                    analysis_data: dict | None = None,
                    producer: str = "engine_export",
                    anchor_idl: str | Path | None = None,
                    anchor_idl_resolution: dict[str, Any] | None | object = _AUTO_ANCHOR_RESOLUTION) -> dict:
    """Build, validate, and recoverably promote one complete export transaction."""

    from .audit_readiness import validate_audit_readiness, write_audit_readiness

    destination = Path(dest).absolute()
    for component in (destination, *destination.parents):
        if component.exists() and component.is_symlink():
            raise RuntimeError(
                f"export destination contains a symlink component: {component}"
            )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise RuntimeError(f"export destination symlink refused: {destination}")
    backup = destination.parent / f".{destination.name}.export-backup"
    lock_path = destination.parent / f".{destination.name}.export.lock"
    staging: Path | None = None
    lock_fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    if not os.path.isfile(lock_path) or not os.path.samestat(
        os.fstat(lock_fd), os.stat(lock_path, follow_symlinks=False)
    ):
        os.close(lock_fd)
        raise RuntimeError("export transaction lock is not a stable regular file")
    with os.fdopen(lock_fd, "a+b") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        if not destination.exists() and backup.is_dir() and not backup.is_symlink():
            os.replace(backup, destination)
            _fsync_directory(destination.parent)
        if backup.exists():
            if backup.is_symlink() or not backup.is_dir():
                raise RuntimeError(f"unsafe export transaction backup: {backup}")
            if not destination.is_dir() or destination.is_symlink():
                raise RuntimeError("export transaction has no safe committed destination")
            try:
                validate_audit_readiness(destination)
            except Exception:
                _remove_export_tree(destination)
                os.replace(backup, destination)
                _fsync_directory(destination.parent)
            else:
                _remove_export_tree(backup)
                _fsync_directory(destination.parent)
        for orphan in destination.parent.glob(f".{destination.name}.export-*-*"):
            if orphan == backup:
                continue
            _remove_export_tree(orphan)
        _fsync_directory(destination.parent)
        previous_moved = False
        promoted = False
        committed = False
        try:
            staging = Path(tempfile.mkdtemp(
                prefix=f".{destination.name}.export-{uuid.uuid4().hex[:12]}-",
                dir=destination.parent,
            ))
            manifest = _export_analysis_into(
                engine,
                binary,
                staging,
                decompile=decompile,
                max_functions=max_functions,
                analysis_data=analysis_data,
                producer=producer,
                anchor_idl=anchor_idl,
                anchor_idl_resolution=anchor_idl_resolution,
            )
            write_audit_readiness(staging, binary=binary)
            _fsync_export_tree(staging)
            if destination.exists():
                if destination.is_symlink() or not destination.is_dir():
                    raise RuntimeError(f"unsafe export destination: {destination}")
                os.replace(destination, backup)
                previous_moved = True
                _fsync_directory(destination.parent)
            try:
                os.replace(staging, destination)
                staging = None
                promoted = True
            except Exception:
                if not destination.exists() and backup.is_dir():
                    os.replace(backup, destination)
                    previous_moved = False
                    _fsync_directory(destination.parent)
                raise
            _fsync_directory(destination.parent)
            committed = True
            if backup.exists():
                try:
                    _remove_export_tree(backup)
                    _fsync_directory(destination.parent)
                except OSError:
                    # The new tree is already beyond the durability barrier.
                    # Recovery validates it and reclaims this backup next time.
                    pass
            return manifest
        except Exception:
            if not committed:
                rollback_error: Exception | None = None
                aborted: Path | None = None
                try:
                    if promoted and destination.exists():
                        aborted = destination.parent / (
                            f".{destination.name}.export-aborted-{uuid.uuid4().hex}"
                        )
                        os.replace(destination, aborted)
                        staging = aborted
                        promoted = False
                    if previous_moved and backup.is_dir() and not backup.is_symlink():
                        os.replace(backup, destination)
                        previous_moved = False
                    _fsync_directory(destination.parent)
                except Exception as exc:  # noqa: BLE001
                    rollback_error = exc
                if rollback_error is not None:
                    raise RuntimeError(
                        f"export failed and rollback was incomplete: {rollback_error}"
                    ) from rollback_error
            raise
        finally:
            if staging is not None and staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging, ignore_errors=True)


def _manifest_atomic(path: Path, manifest: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2))
    tmp.replace(path)
