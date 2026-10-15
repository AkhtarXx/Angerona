"""Run real JADX and seal its result without treating exit zero as coverage."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path

from ..analysis.jadx_bridge import analyze_apk


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--memory-mb", type=int, default=2048)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    jadx_output = output / "jadx-output"
    result = analyze_apk(
        args.apk,
        timeout=args.timeout,
        memory_limit_mb=args.memory_mb,
        keep_output=jadx_output,
    )
    row = asdict(result)
    row["schema"] = "angerona/jadx-attempt/v2"
    if jadx_output.is_dir():
        source_rows = []
        for path in sorted(jadx_output.rglob("*.java")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            source_rows.append({
                "path": path.relative_to(jadx_output).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": digest,
            })
        row["source_artifacts"] = source_rows
        row["source_artifact_count"] = len(source_rows)
    else:
        row["source_artifacts"] = []
        row["source_artifact_count"] = 0
    canonical = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    row["attempt_sha256"] = hashlib.sha256(canonical).hexdigest()
    _atomic(output / "JADX_RESULT.json", json.dumps(row, indent=2, sort_keys=True).encode() + b"\n")
    print(json.dumps({
        "status": row["status"],
        "classes_count": row["classes_count"],
        "source_artifact_count": row["source_artifact_count"],
        "errors": len(row["errors"]),
        "attempt_sha256": row["attempt_sha256"],
    }, sort_keys=True))
    return 0 if row["status"] == "success" and row["source_artifact_count"] > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
