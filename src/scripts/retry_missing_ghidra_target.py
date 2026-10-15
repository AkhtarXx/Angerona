from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from src.config import load_config
from src.engines.ghidra import GhidraEngine
from src.analysis.evidence_signing import sign_document
from src.analysis.native_ownership_manifest import (
    bind_native_output_directory,
    native_routing_context,
    native_routing_targets,
    publish_native_lane_receipt,
)


SCHEMA = "angerona/isolated-ghidra-retry/v1"


def _sha_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--lane-epoch-id", required=True)
    parser.add_argument("--result-root", required=True)
    args = parser.parse_args()
    supplied_target = Path(args.target).expanduser().absolute()
    if supplied_target.is_symlink() or not supplied_target.is_file():
        raise SystemExit("Ghidra retry target must be a non-symlink regular file")
    target = supplied_target.resolve(strict=True)
    audit_root = Path(args.audit_root).resolve()
    target_sha = _sha_path(target)
    if target_sha != args.expected_sha256.lower():
        raise SystemExit(f"target hash mismatch: {target_sha}")
    _routing, selected, policy_events, routing_binding = native_routing_context(
        args.ownership_manifest, args.native_universe,
    )
    app_targets, _excluded, hold_targets = native_routing_targets(selected, policy_events)
    if hold_targets:
        raise SystemExit(f"native ownership HOLD prevents Ghidra retry: {sorted(hold_targets)}")
    if target_sha not in app_targets:
        raise SystemExit("Ghidra retry target is not in exact signed app-owned queue")
    selected_row = next(row for row in selected if row["target_sha256"] == target_sha)

    retry_root = bind_native_output_directory(
        audit_root / "ghidra-isolated-retry" / target_sha,
        lane="native-ghidra-isolated-retry", lane_epoch_id=args.lane_epoch_id,
        routing_binding=routing_binding,
    )
    lock = (retry_root / ".retry.lock").open("a+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("isolated Ghidra retry is already running") from exc

    attempts_root = retry_root / "attempts"
    attempts_root.mkdir(parents=True, exist_ok=True)
    attempt_numbers = []
    for candidate in attempts_root.glob("attempt-*"):
        try:
            attempt_numbers.append(int(candidate.name.removeprefix("attempt-")))
        except ValueError:
            continue
    attempt_id = max(attempt_numbers, default=0) + 1
    attempt_root = attempts_root / f"attempt-{attempt_id:04d}"
    attempt_root.mkdir(parents=False, exist_ok=False)
    (attempt_root / "home").mkdir()
    os.environ.setdefault("ANGERONA_GHIDRA_MAX_CPU", "1")
    os.environ.setdefault("ANGERONA_ANALYSIS_TIMEOUT", "5400")
    os.environ.setdefault("GHIDRA_HEADLESS_MAXMEM", "2G")
    java_options = os.environ.get("GHIDRA_HEADLESS_JAVA_OPTIONS", "").strip()
    if "-XX:ActiveProcessorCount=" not in java_options:
        java_options = f"{java_options} -XX:ActiveProcessorCount=1".strip()
    if "-Duser.home=" not in java_options:
        java_options = f"{java_options} -Duser.home={attempt_root / 'home'}".strip()
    os.environ["GHIDRA_HEADLESS_JAVA_OPTIONS"] = java_options

    base = load_config("ghidra")
    isolated = dataclasses.replace(
        base,
        state_dir=attempt_root / "state",
        projects_dir=attempt_root / "projects",
        cache_dir=attempt_root / "cache",
    )
    isolated.state_dir.mkdir(parents=True, exist_ok=True)
    isolated.projects_dir.mkdir(parents=True, exist_ok=True)
    isolated.cache_dir.mkdir(parents=True, exist_ok=True)
    engine = GhidraEngine(isolated)
    launch_token = selected_row.get("native_launch_authority_token")
    engine.configure_native_authority(selected_row, launch_token)
    started = datetime.now(timezone.utc).isoformat()
    data = (
        engine.analyze_restricted_meta(target, native_authority_token=launch_token)
        if selected_row.get("analysis_scope") == "selective_ranges"
        else engine.analyze(
            target, decompile=False, force=True, timeout=None,
            native_authority_token=launch_token,
        )
    )
    cache_path = Path(str(data.get("_cache") or "")).resolve()
    if not cache_path.is_file():
        raise RuntimeError("Ghidra returned no durable analysis cache")
    analysis_bytes = cache_path.read_bytes()
    analysis = json.loads(analysis_bytes)
    recorded_sha = str((analysis.get("metadata") or {}).get("sha256") or "").lower()
    if recorded_sha != target_sha:
        raise RuntimeError(f"Ghidra analysis hash mismatch: {recorded_sha}")
    expected_mode = (
        "restricted_meta" if selected_row.get("analysis_scope") == "selective_ranges" else "meta"
    )
    if not analysis.get("export_complete") or analysis.get("mode") != expected_mode:
        raise RuntimeError("Ghidra meta export is not complete")
    functions = analysis.get("functions")
    if not isinstance(functions, list) or not functions:
        raise RuntimeError("Ghidra meta export contains no functions")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    result_root = bind_native_output_directory(
        args.result_root, lane="native-ghidra-isolated-retry-results",
        lane_epoch_id=args.lane_epoch_id, routing_binding=routing_binding,
    )
    final = result_root / f"{stamp}__libhermes-{target_sha[:8]}"
    staging = result_root / f".{final.name}.{os.getpid()}.tmp"
    if staging.exists():
        shutil.rmtree(staging)
    (staging / "code").mkdir(parents=True)
    (staging / "raw").mkdir(parents=True)
    _atomic(staging / "code" / "analysis.json", analysis_bytes)
    headless_log = cache_path.parent / "headless.log"
    if headless_log.is_file():
        shutil.copyfile(headless_log, staging / "raw" / "headless.log")
    receipt = {
        "schema": SCHEMA,
        "target_path": str(target),
        "target_sha256": target_sha,
        "target_bytes": target.stat().st_size,
        "attempt_id": attempt_id,
        "attempt_root": str(attempt_root),
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "ghidra_status": engine.status(),
        "heap_cap": os.environ.get("GHIDRA_HEADLESS_MAXMEM") or "2G-launcher-default",
        "ghidra_max_cpu": os.environ.get("ANGERONA_GHIDRA_MAX_CPU") or "unbounded",
        "analysis_sha256": hashlib.sha256(analysis_bytes).hexdigest(),
        "functions": len(functions),
        "published_analysis": str(final / "code" / "analysis.json"),
        "native_routing": routing_binding,
    }
    receipt = sign_document(receipt)
    if receipt.get("trust") != "operator_signed":
        raise RuntimeError("Ghidra retry receipt requires operator signing")
    _atomic(staging / "RETRY_RECEIPT.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
    result_root.mkdir(parents=True, exist_ok=True)
    os.replace(staging, final)
    _atomic(retry_root / "LATEST_SUCCESS.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
    publish_native_lane_receipt(
        retry_root / "NATIVE_GHIDRA_RETRY_LANE_COMPLETION_RECEIPT.json",
        lane="native-ghidra-isolated-retry", lane_epoch_id=args.lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets={target_sha}, excluded_targets=_excluded,
        hold_targets=hold_targets, semantic_complete=True,
        input_bindings=[{"path": str(target), "sha256": target_sha}],
        counts={"attempt_id": attempt_id, "functions": len(functions)},
    )
    print(json.dumps({"event": "isolated-ghidra-retry-complete", **receipt}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
