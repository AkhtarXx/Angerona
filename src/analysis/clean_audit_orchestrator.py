"""Checkpointed executor for a previously signed clean-audit routing plan."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any

from .audit_lineage import load_audit_epoch, open_verified_artifact
from .clean_audit_routing import EXECUTION_SCHEMA, verify_clean_apk_routing_plan
from .evidence_signing import sign_document, verify_document
from .schema_validation import require_int_field


CHECKPOINT_SCHEMA = "angerona/clean-audit-lane-checkpoint/v2"
LEGACY_CHECKPOINT_SCHEMA = "angerona/clean-audit-lane-checkpoint/v1"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = path.parent.lstat()
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError(f"immutable audit artifact parent is unsafe: {path.parent}")
    archive_metadata = path.parent.parent.lstat()
    if stat.S_ISLNK(archive_metadata.st_mode) or not stat.S_ISDIR(archive_metadata.st_mode):
        raise ValueError(f"immutable checkpoint archive root is unsafe: {path.parent.parent}")
    if os.path.lexists(path):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"immutable audit artifact path is unsafe: {path}")
        if path.read_bytes() == payload:
            return
        raise FileExistsError(f"refusing to replace immutable audit artifact: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or path.read_bytes() != payload
            ):
                raise FileExistsError(f"refusing to replace immutable audit artifact: {path}")
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load_execution_spec(
    plan: dict[str, Any], supplied: str | Path | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    if supplied is not None:
        supplied_path = Path(supplied).resolve(strict=True)
        supplied_payload = supplied_path.read_bytes()
        descriptor = {"path": str(supplied_path), "sha256": _sha(supplied_payload)}
    else:
        descriptor = plan.get("execution_spec")
    if not descriptor:
        raise ValueError("signed plan has no execution specification")
    execution_descriptor = descriptor
    roots = [Path(root).resolve(strict=True) for root in plan["trusted_roots"]]
    _, payload = open_verified_artifact(descriptor, roots)
    spec = json.loads(payload)
    if spec.get("schema") != EXECUTION_SCHEMA or not verify_document(spec, require_signature=True):
        raise ValueError("execution specification is unsigned or unknown")
    if (
        spec.get("source_plan_id") != plan.get("plan_id")
        or spec.get("routing_set_id") != plan.get("routing_set_id")
        or spec.get("audit_epoch") != plan.get("audit_epoch")
    ):
        raise ValueError("detached execution specification lineage mismatch")
    for artifact_descriptor in [
        *(spec.get("code_artifacts") or []),
        *(spec.get("argument_artifacts") or []),
        *[
            descriptor
            for row in (spec.get("lanes") or {}).values()
            for descriptor in (row.get("tool_artifacts") or {}).values()
        ],
    ]:
        open_verified_artifact(artifact_descriptor, roots)
    if spec.get("audit_epoch"):
        epoch_path, epoch_payload = open_verified_artifact(spec["audit_epoch"], roots)
        epoch = load_audit_epoch(epoch_path)
        if (
            spec["audit_epoch"].get("epoch_id") != epoch.get("epoch_id")
            or spec["audit_epoch"].get("sha256") != _sha(epoch_payload)
        ):
            raise ValueError("execution specification epoch binding mismatch")
    return spec, execution_descriptor


def _checkpoint_dir(plan: dict[str, Any], lane: str) -> Path:
    if lane not in (plan.get("lanes") or {}) or Path(lane).name != lane:
        raise ValueError("checkpoint lane is not an exact signed-plan lane")
    return Path(plan["output_root"]).resolve() / "orchestrator-checkpoints" / lane


def _verified_checkpoints(plan: dict[str, Any], lane: str) -> list[dict[str, Any]]:
    directory = _checkpoint_dir(plan, lane)
    if not os.path.lexists(directory):
        return []
    directory_metadata = directory.lstat()
    if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode):
        raise ValueError(f"lane checkpoint archive is not a non-symlink directory: {directory}")
    output_root = Path(plan["output_root"]).resolve(strict=True)
    resolved_directory = directory.resolve(strict=True)
    if output_root not in resolved_directory.parents:
        raise ValueError("lane checkpoint archive escapes the signed audit output")
    archive_root = output_root / "orchestrator-checkpoints"
    archive_metadata = archive_root.lstat()
    if stat.S_ISLNK(archive_metadata.st_mode) or not stat.S_ISDIR(archive_metadata.st_mode):
        raise ValueError("checkpoint archive root is not a non-symlink directory")
    rows_by_sequence: dict[int, dict[str, Any]] = {}
    archive_entries = list(directory.iterdir())
    if any(path.suffix != ".json" for path in archive_entries):
        raise ValueError("lane checkpoint archive contains a non-checkpoint entry")
    for path in archive_entries:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or path.resolve(strict=True).parent != resolved_directory
        ):
            raise ValueError(f"lane checkpoint is not a confined regular file: {path}")
        payload = path.read_bytes()
        if path.name != f"{_sha(payload)}.json":
            raise ValueError(f"lane checkpoint is not content addressed: {path}")
        row = json.loads(payload)
        if row.get("schema") == LEGACY_CHECKPOINT_SCHEMA:
            raise ValueError(
                "legacy attempt-ordered lane checkpoints require an explicit signed migration; "
                "mixed or implicit acceptance is forbidden"
            )
        if (
            row.get("schema") != CHECKPOINT_SCHEMA
            or row.get("plan_id") != plan.get("plan_id")
            or row.get("routing_set_id") != plan.get("routing_set_id")
            or row.get("lane") != lane
            or row.get("audit_epoch") != plan.get("audit_epoch")
            or not verify_document(row, require_signature=True)
        ):
            raise ValueError(f"invalid lane checkpoint: {path}")
        sequence = row.get("transition_sequence")
        attempt = row.get("attempt")
        if (
            not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1
            or not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1
            or row.get("status") not in {"RUNNING", "COMPLETE", "FAILED"}
        ):
            raise ValueError(f"lane checkpoint has invalid transition metadata: {path}")
        if sequence in rows_by_sequence:
            raise ValueError(f"lane checkpoint archive has a duplicate transition sequence: {sequence}")
        row["_checkpoint_path"] = str(path)
        row["_checkpoint_sha256"] = _sha(payload)
        rows_by_sequence[sequence] = row
    if not rows_by_sequence:
        return []
    expected_sequences = set(range(1, len(rows_by_sequence) + 1))
    if set(rows_by_sequence) != expected_sequences:
        raise ValueError("lane checkpoint archive has an orphan or non-contiguous transition")
    rows = [rows_by_sequence[sequence] for sequence in sorted(rows_by_sequence)]
    for index, row in enumerate(rows):
        parent_sha = row.get("immediate_parent_checkpoint_sha256")
        parent_path = row.get("immediate_parent_checkpoint_path")
        if index == 0:
            if parent_sha != "" or parent_path != "" or row.get("status") != "RUNNING" or row["attempt"] != 1:
                raise ValueError("lane checkpoint genesis transition is invalid")
            continue
        parent = rows[index - 1]
        if (
            parent_sha != parent["_checkpoint_sha256"]
            or parent_path != parent["_checkpoint_path"]
        ):
            raise ValueError("lane checkpoint immediate-parent binding is invalid")
        parent_status = parent["status"]
        status = row["status"]
        if parent_status == "COMPLETE":
            raise ValueError("lane checkpoint archive extends a terminal COMPLETE transition")
        if status == "RUNNING":
            if row["attempt"] != parent["attempt"] + 1:
                raise ValueError("lane RUNNING retry does not increment semantic attempt exactly once")
        elif parent_status != "RUNNING" or row["attempt"] != parent["attempt"]:
            raise ValueError("lane terminal transition is not the matching RUNNING attempt")
        if status in {"COMPLETE", "FAILED"} and row.get("running_checkpoint_sha256") != parent["_checkpoint_sha256"]:
            raise ValueError("lane terminal transition is not bound to its RUNNING checkpoint")
    return rows


def _write_checkpoint(
    plan: dict[str, Any], lane: str, body: dict[str, Any],
    *, parent: dict[str, Any] | None,
) -> dict[str, Any]:
    sequence = 1 if parent is None else int(parent["transition_sequence"]) + 1
    document = sign_document({
        "schema": CHECKPOINT_SCHEMA, "plan_id": plan["plan_id"],
        "routing_set_id": plan["routing_set_id"], "lane": lane,
        "audit_epoch": plan.get("audit_epoch"),
        "transition_sequence": sequence,
        "immediate_parent_checkpoint_sha256": (
            "" if parent is None else parent["_checkpoint_sha256"]
        ),
        "immediate_parent_checkpoint_path": (
            "" if parent is None else parent["_checkpoint_path"]
        ),
        **body,
    })
    if not verify_document(document, require_signature=True):
        raise ValueError("lane checkpoint signing failed")
    payload = json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
    path = _checkpoint_dir(plan, lane) / f"{_sha(payload)}.json"
    _atomic(path, payload)
    return {**document, "checkpoint_path": str(path), "checkpoint_sha256": _sha(payload)}


def lane_status(plan_path: str | Path) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    result = {}
    for lane in plan.get("lanes") or {}:
        rows = _verified_checkpoints(plan, lane)
        result[lane] = rows[-1] if rows else None
    return result


def run_clean_audit_lane(
    plan_path: str | Path, lane: str, *, resume: bool = False,
    execution_spec: str | Path | None = None,
) -> dict[str, Any]:
    plan = verify_clean_apk_routing_plan(plan_path)
    if not plan.get("conservation_complete"):
        raise ValueError("no lane may start before signed routing conservation")
    lane_plan = (plan.get("lanes") or {}).get(lane)
    if not isinstance(lane_plan, dict):
        raise ValueError("lane is not present in the signed plan")
    if lane_plan.get("externally_managed"):
        raise ValueError("external native lane cannot be launched by this orchestrator")
    spec, spec_descriptor = _load_execution_spec(plan, execution_spec)
    command = (spec.get("lanes") or {}).get(lane)
    if not isinstance(command, dict) or not isinstance(command.get("argv"), list) or not command["argv"]:
        raise ValueError("lane has no signed argv specification")
    if not all(isinstance(value, str) and value for value in command["argv"]):
        raise ValueError("lane argv is invalid")
    cwd = Path(str(command.get("cwd") or "")).resolve(strict=True)
    roots = [Path(root).resolve(strict=True) for root in plan["trusted_roots"]]
    if not any(cwd == root or root in cwd.parents for root in roots):
        raise ValueError("lane working directory escapes trusted roots")
    argv_executable = command["argv"][0]
    resolved_executable = (
        argv_executable if Path(argv_executable).is_absolute() else shutil.which(argv_executable)
    )
    if not resolved_executable:
        raise ValueError("lane argv executable is unavailable")
    executable = Path(resolved_executable).resolve(strict=True)
    executable_descriptor = command.get("executable")
    opened, _ = open_verified_artifact(executable_descriptor, roots)
    if opened != executable:
        raise ValueError("lane argv executable differs from signed executable")

    lock_path = Path(plan["output_root"]) / "orchestrator-locks" / f"{lane}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        prior = _verified_checkpoints(plan, lane)
        if prior and prior[-1].get("status") == "COMPLETE":
            return {**prior[-1], "cache_hit": True}
        if prior and prior[-1].get("status") == "RUNNING" and not resume:
            raise ValueError("lane has a durable RUNNING checkpoint; explicit --resume required")
        for dependency in lane_plan.get("depends_on") or []:
            if dependency == "native_external":
                if not plan.get("external_native_routing"):
                    raise ValueError("signed external native routing is absent")
                continue
            dependency_rows = _verified_checkpoints(plan, dependency)
            if not dependency_rows or dependency_rows[-1].get("status") != "COMPLETE":
                raise ValueError(f"lane dependency is not complete: {dependency}")
        expected_schema = lane_plan.get("completion_schema")
        if not expected_schema or command.get("completion_schema") != expected_schema:
            raise ValueError("lane completion schema differs from the signed routing contract")
        if lane == "cross_layer_merge":
            coverage_path = Path(plan["coverage_accounting"]["path"])
            coverage = json.loads(coverage_path.read_bytes())
            if coverage.get("disposition_counts", {}).get("HOLD"):
                raise ValueError("cross-layer merge is blocked by HOLD artifacts")

        attempt = 1 + max([
            require_int_field(
                row, "attempt", context="prior lane checkpoint", minimum=1,
            ) for row in prior
        ] or [0])
        running = _write_checkpoint(plan, lane, {
            "attempt": attempt, "status": "RUNNING", "argv": command["argv"],
            "cwd": str(cwd), "execution_spec": spec_descriptor,
        }, parent=prior[-1] if prior else None)
        environment = os.environ.copy()
        reserved_environment = {
            "ANGERONA_PLAN_ID": plan["plan_id"],
            "ANGERONA_ROUTING_SET_ID": plan["routing_set_id"],
            "ANGERONA_LANE": lane,
            "ANGERONA_EXECUTION_SPEC_DESCRIPTOR_JSON": json.dumps(spec_descriptor, sort_keys=True, separators=(",", ":")),
            "ANGERONA_AUDIT_EPOCH_DESCRIPTOR_JSON": json.dumps(
                spec.get("audit_epoch") or plan.get("audit_epoch"), sort_keys=True, separators=(",", ":")
            ),
        }
        for key, value in (command.get("environment") or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("signed lane environment is invalid")
            if key in reserved_environment or key == "ANGERONA_PARENT_RECEIPTS_JSON":
                raise ValueError("signed lane environment attempts to override lineage")
            environment[key] = value
        parent_receipts = {}
        for dependency in lane_plan.get("depends_on") or []:
            if dependency == "native_external":
                parent_receipts[dependency] = plan["external_native_routing"]
                continue
            parent = _verified_checkpoints(plan, dependency)[-1]
            parent_receipts[dependency] = parent["completion_receipt"]
        environment.update(reserved_environment)
        environment["ANGERONA_PARENT_RECEIPTS_JSON"] = json.dumps(parent_receipts, sort_keys=True, separators=(",", ":"))
        completed = subprocess.run(command["argv"], cwd=cwd, env=environment, check=False)
        receipt_descriptor = None
        error = None
        if completed.returncode == 0:
            receipt = Path(str(command.get("completion_receipt") or ""))
            if not receipt.is_absolute():
                receipt = Path(plan["output_root"]) / receipt
            receipt = receipt.resolve(strict=True)
            if not (receipt == Path(plan["output_root"]).resolve() or Path(plan["output_root"]).resolve() in receipt.parents):
                raise ValueError("lane completion receipt escapes audit output")
            receipt_payload = receipt.read_bytes()
            receipt_document = json.loads(receipt_payload)
            if not verify_document(receipt_document, require_signature=True):
                raise ValueError("lane completion receipt is unsigned")
            if receipt_document.get("schema") != expected_schema:
                raise ValueError("lane completion receipt schema mismatch")
            if (
                receipt_document.get("plan_id") != plan["plan_id"]
                or receipt_document.get("routing_set_id") != plan["routing_set_id"]
                or receipt_document.get("lane") != lane
                or receipt_document.get("parent_receipts") != parent_receipts
                or receipt_document.get("ownership_policy") != plan.get("ownership_policy")
                or receipt_document.get("audit_epoch") != (spec.get("audit_epoch") or plan.get("audit_epoch"))
                or receipt_document.get("execution_spec") != spec_descriptor
            ):
                raise ValueError("lane completion receipt lineage mismatch")
            receipt_descriptor = {"path": str(receipt), "sha256": _sha(receipt_payload)}
        else:
            error = f"subprocess-exit-{completed.returncode}"
        return _write_checkpoint(plan, lane, {
            "attempt": attempt, "status": "COMPLETE" if completed.returncode == 0 else "FAILED",
            "returncode": completed.returncode, "running_checkpoint_sha256": running["checkpoint_sha256"],
            "completion_receipt": receipt_descriptor, "execution_spec": spec_descriptor, "error": error,
        }, parent={
            **running,
            "_checkpoint_path": running["checkpoint_path"],
            "_checkpoint_sha256": running["checkpoint_sha256"],
        })
