"""Signed APK-native target universe and controller conservation helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any
import zipfile

from .apk_content_manifest import (
    SCHEMA as APK_MANIFEST_SCHEMA,
    apk_content_manifest_sha256,
)
from .evidence_signing import sign_document, verify_document
from .schema_validation import require_int_field, require_list_field


NATIVE_TARGET_UNIVERSE_SCHEMA = "angerona/native-target-universe/v1"
ROOT_CONSERVATION_SCHEMA = "angerona/native-reconstruction-root-conservation/v1"
SCOPED_OPERATION_SCHEMA = "angerona/native-reconstruction-scoped-operation/v1"


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        payload = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def _require_regular_contained(path: Path, root: Path, label: str) -> None:
    root_resolved = root.resolve()
    try:
        path.parent.resolve().relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"{label} parent escapes receipt history root") from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink regular file")
    try:
        path.resolve(strict=True).relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} resolves outside receipt history root") from exc


def _safe_history_path(parent: Path, relative: str, history_root: Path) -> Path:
    if not relative:
        raise ValueError("receipt predecessor path is empty")
    candidate = parent / relative
    try:
        candidate.parent.resolve().relative_to(history_root.resolve())
    except ValueError as exc:
        raise ValueError("receipt predecessor path escapes history root") from exc
    return candidate


def _verify_full_history(
    *, latest_path: Path, history_root: Path, chain_identity: dict[str, Any],
) -> tuple[dict[str, Any], str, Path]:
    """Verify every signed archive hop from latest through genesis."""
    _require_regular_contained(latest_path, latest_path.parent, "controller latest pointer")
    latest_bytes = latest_path.read_bytes()
    try:
        current = json.loads(latest_bytes)
    except (ValueError, TypeError) as exc:
        raise ValueError("existing controller receipt is unreadable") from exc
    sequence = require_int_field(
        current, "sequence", context="controller receipt", minimum=1, maximum=1_000_000,
    )
    current_bytes = latest_bytes
    latest_sha = hashlib.sha256(latest_bytes).hexdigest()
    latest_archive = history_root / f"{sequence:08d}-{latest_sha}.json"
    for expected_sequence in range(sequence, 0, -1):
        if require_int_field(
            current, "sequence", context="controller receipt history",
            minimum=1, maximum=1_000_000,
        ) != expected_sequence:
            raise ValueError("controller receipt history sequence discontinuity")
        if current.get("chain_identity") != chain_identity:
            raise ValueError("controller receipt history chain identity mismatch")
        scope_identity = current.get("scope_identity")
        if not isinstance(scope_identity, dict):
            raise ValueError("controller receipt history lacks scope identity")
        if current.get("scope_identity_sha256") != hashlib.sha256(_canonical(scope_identity)).hexdigest():
            raise ValueError("controller receipt history scope identity mismatch")
        if not verify_document(current, require_signature=True):
            raise ValueError("controller receipt history signature verification failed")
        current_sha = hashlib.sha256(current_bytes).hexdigest()
        archive_path = history_root / f"{expected_sequence:08d}-{current_sha}.json"
        _require_regular_contained(archive_path, history_root, "controller receipt archive")
        if archive_path.read_bytes() != current_bytes:
            raise ValueError("controller receipt history archive bytes mismatch")
        previous_sha = str(current.get("previous_receipt_sha256") or "")
        previous_relative = str(current.get("previous_receipt_path") or "")
        if expected_sequence == 1:
            if previous_sha or previous_relative:
                raise ValueError("controller receipt genesis has a predecessor")
            break
        if len(previous_sha) != 64 or not previous_relative:
            raise ValueError("controller receipt predecessor binding is incomplete")
        previous_path = _safe_history_path(
            latest_path.parent, previous_relative, history_root,
        )
        expected_name = f"{expected_sequence - 1:08d}-{previous_sha}.json"
        if previous_path.parent.resolve() != history_root.resolve() or previous_path.name != expected_name:
            raise ValueError("controller receipt predecessor path is non-canonical")
        _require_regular_contained(previous_path, history_root, "controller predecessor archive")
        current_bytes = previous_path.read_bytes()
        if hashlib.sha256(current_bytes).hexdigest() != previous_sha:
            raise ValueError("controller receipt predecessor hash mismatch")
        try:
            current = json.loads(current_bytes)
        except (ValueError, TypeError) as exc:
            raise ValueError("controller predecessor receipt is unreadable") from exc
    return json.loads(latest_bytes), latest_sha, latest_archive


def _write_immutable(path: Path, payload: bytes, history_root: Path) -> None:
    """Publish immutable bytes without ever replacing an existing archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.resolve().relative_to(history_root.resolve())
    except ValueError as exc:
        raise ValueError("immutable receipt archive escapes history root") from exc
    if os.path.lexists(path):
        _require_regular_contained(path, history_root, "immutable receipt archive collision")
        if path.read_bytes() != payload:
            raise ValueError(f"immutable receipt archive collision: {path}")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            _require_regular_contained(path, history_root, "immutable receipt archive race")
            if path.read_bytes() != payload:
                raise ValueError(f"immutable receipt archive race: {path}")
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _publish_controller_receipt(
    *, output_path: Path, body: dict[str, Any], receipt_kind: str,
    scope_identity: dict[str, Any],
) -> dict[str, Any]:
    """Append one signed receipt to an immutable, verified hash chain."""
    output_path = output_path.expanduser().absolute()
    history_root = output_path.parent / "controller-receipt-history" / receipt_kind
    chain_identity = {
        "receipt_kind": receipt_kind,
        "target_universe_sha256": body.get("target_universe_sha256"),
    }
    scope_identity_sha = hashlib.sha256(_canonical(scope_identity)).hexdigest()
    previous_sha = ""
    previous_path = ""
    previous_sequence = 0
    if os.path.lexists(output_path):
        previous, previous_sha, archive = _verify_full_history(
            latest_path=output_path, history_root=history_root,
            chain_identity=chain_identity,
        )
        previous_sequence = int(previous["sequence"])
        previous_path = archive.relative_to(output_path.parent).as_posix()
    chained_body = {
        **body,
        "chain_identity": chain_identity,
        "scope_identity": scope_identity,
        "scope_identity_sha256": scope_identity_sha,
        "sequence": previous_sequence + 1,
        "previous_receipt_sha256": previous_sha,
        "previous_receipt_path": previous_path,
    }
    receipt = sign_document(chained_body)
    if receipt.get("trust") != "operator_signed" or not verify_document(receipt, require_signature=True):
        raise ValueError("controller receipt signing verification failed")
    payload = _json_bytes(receipt)
    receipt_sha = hashlib.sha256(payload).hexdigest()
    archive_path = history_root / f"{previous_sequence + 1:08d}-{receipt_sha}.json"
    _write_immutable(archive_path, payload, history_root)
    _atomic_json(output_path, receipt)
    _require_regular_contained(output_path, output_path.parent, "controller latest pointer")
    latest_bytes = output_path.read_bytes()
    if (
        latest_bytes != payload
        or hashlib.sha256(latest_bytes).hexdigest() != receipt_sha
        or archive_path.read_bytes() != latest_bytes
    ):
        raise ValueError("controller latest pointer/archive publication mismatch")
    return receipt


def _authenticated_apk_manifest(manifest_path: Path, apk_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != APK_MANIFEST_SCHEMA:
        raise ValueError("APK content manifest schema mismatch")
    if manifest.get("manifest_sha256") != apk_content_manifest_sha256(manifest):
        raise ValueError("APK content manifest payload hash mismatch")
    if manifest.get("apk_sha256") != _sha256_path(apk_path):
        raise ValueError("APK content manifest target hash mismatch")
    if require_int_field(
        manifest, "apk_bytes", context="APK content manifest", minimum=0,
    ) != apk_path.stat().st_size:
        raise ValueError("APK content manifest size mismatch")
    if not manifest.get("archive_byte_partition_complete") or manifest.get("unaccounted_entries"):
        raise ValueError("APK content manifest archive accounting is incomplete")
    return manifest


def _file_index(root: Path) -> dict[str, list[Path]]:
    result: dict[str, list[Path]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result.setdefault(_sha256_path(path), []).append(path.resolve())
    return result


def _analysis_index(root: Path) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(root.glob("ghidra-results/*/*/code/analysis.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        target_sha = str((document.get("metadata") or {}).get("sha256") or "").lower()
        if len(target_sha) != 64:
            continue
        result.setdefault(target_sha, []).append({
            "path": str(path.resolve()),
            "sha256": _sha256_path(path),
            "schema": document.get("schema"),
            "mode": document.get("mode"),
            "function_count": len(document.get("functions") or []),
        })
    return result


def build_native_target_universe(
    *, apk_manifest_path: Path, apk_path: Path, targets_root: Path,
    audit_root: Path, output_path: Path,
) -> dict[str, Any]:
    """Authenticate APK bytes and publish an immutable signed ELF universe."""
    apk_manifest_path = apk_manifest_path.resolve()
    apk_path = apk_path.resolve()
    targets_root = targets_root.resolve()
    audit_root = audit_root.resolve()
    output_path = output_path.resolve()
    if output_path.exists():
        raise ValueError("native target universe output already exists")
    manifest = _authenticated_apk_manifest(apk_manifest_path, apk_path)
    manifest_rows = require_list_field(
        manifest, "entries", context="APK content manifest",
    )
    if len(manifest_rows) != require_int_field(
        manifest, "entry_count", context="APK content manifest", minimum=0,
    ):
        raise ValueError("APK content manifest entry count mismatch")

    native_entries: list[dict[str, Any]] = []
    raw_apk = apk_path.read_bytes()
    with zipfile.ZipFile(apk_path) as archive:
        infos = archive.infolist()
        if len(infos) != len(manifest_rows):
            raise ValueError("APK ZIP/member universe count mismatch")
        if hashlib.sha256(raw_apk[int(archive.start_dir):]).hexdigest() != manifest.get("zip_structure_sha256"):
            raise ValueError("APK ZIP structure hash mismatch")
        for index, (info, row) in enumerate(zip(infos, manifest_rows, strict=True)):
            if not isinstance(row, dict):
                raise ValueError(f"invalid APK manifest row: {index}")
            if row.get("central_directory_index") != index or row.get("name") != info.filename:
                raise ValueError(f"APK central-directory identity mismatch: {index}")
            if require_int_field(
                row, "content_bytes", context=f"APK entry {index}", minimum=0,
            ) != info.file_size or row.get("crc32") != f"{info.CRC:08x}":
                raise ValueError(f"APK member metadata mismatch: {info.filename}")
            if info.is_dir() or bool(info.flag_bits & 1):
                continue
            digest = hashlib.sha256()
            prefix = b""
            observed = 0
            with archive.open(info) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    if len(prefix) < 4:
                        prefix += chunk[:4 - len(prefix)]
                    digest.update(chunk)
                    observed += len(chunk)
            content_sha = digest.hexdigest()
            if observed != info.file_size or content_sha != row.get("content_sha256"):
                raise ValueError(f"APK member content mismatch: {info.filename}")
            if prefix != b"\x7fELF":
                continue
            parts = Path(info.filename).parts
            abi = parts[1] if len(parts) >= 3 and parts[0] == "lib" else "unknown"
            native_entries.append({
                "entry_id": row.get("entry_id"),
                "central_directory_index": index,
                "apk_path": info.filename,
                "abi": abi,
                "bytes": observed,
                "sha256": content_sha,
                "crc32": f"{info.CRC:08x}",
            })

    extracted = _file_index(targets_root)
    analyses = _analysis_index(audit_root)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in native_entries:
        grouped.setdefault(row["sha256"], []).append(row)
    targets: list[dict[str, Any]] = []
    for target_sha, entry_rows in sorted(grouped.items()):
        entry_rows = sorted(entry_rows, key=lambda row: (row["central_directory_index"], row["apk_path"]))
        extracted_paths = sorted(str(path) for path in extracted.get(target_sha, []))
        analysis_candidates = sorted(analyses.get(target_sha, []), key=lambda row: (row["sha256"], row["path"]))
        distinct_analysis_hashes = {row["sha256"] for row in analysis_candidates}
        analysis_ready = len(distinct_analysis_hashes) == 1 and bool(analysis_candidates)
        selected_analysis = analysis_candidates[0] if analysis_ready else None
        targets.append({
            "member_id": hashlib.sha256(_canonical({"apk_sha256": manifest["apk_sha256"], "target_sha256": target_sha})).hexdigest(),
            "target_sha256": target_sha,
            "apk_path": entry_rows[0]["apk_path"],
            "aliases": [row["apk_path"] for row in entry_rows[1:]],
            "entry_ids": [row["entry_id"] for row in entry_rows],
            "abis": sorted({row["abi"] for row in entry_rows}),
            "bytes": entry_rows[0]["bytes"],
            "entry_bytes": [
                {"apk_path": row["apk_path"], "bytes": row["bytes"]}
                for row in entry_rows
            ],
            "grouped_bytes": sum(int(row["bytes"]) for row in entry_rows),
            "extraction_disposition": "ready" if extracted_paths else "missing",
            "extracted_target_path": extracted_paths[0] if extracted_paths else None,
            "extracted_target_aliases": extracted_paths[1:],
            "analysis_disposition": "ready" if analysis_ready else ("missing" if not analysis_candidates else "ambiguous"),
            "analysis_path": selected_analysis["path"] if selected_analysis else None,
            "analysis_sha256": selected_analysis["sha256"] if selected_analysis else None,
            "analysis_candidates": analysis_candidates,
        })
    native_entry_hash = hashlib.sha256(_canonical(native_entries)).hexdigest()
    target_hash = hashlib.sha256(_canonical(targets)).hexdigest()
    document = sign_document({
        "schema": NATIVE_TARGET_UNIVERSE_SCHEMA,
        "apk_path": str(apk_path),
        "apk_sha256": manifest["apk_sha256"],
        "apk_content_manifest_path": str(apk_manifest_path),
        "apk_content_manifest_sha256": _sha256_path(apk_manifest_path),
        "apk_content_manifest_payload_sha256": manifest["manifest_sha256"],
        "targets_root": str(targets_root),
        "audit_root": str(audit_root),
        "native_entry_count": len(native_entries),
        "native_entry_universe_sha256": native_entry_hash,
        "native_entries": native_entries,
        "target_count": len(targets),
        "target_universe_sha256": target_hash,
        "targets": targets,
    })
    if document.get("trust") != "operator_signed":
        raise ValueError("native target universe requires an operator signing key")
    _atomic_json(output_path, document)
    return document


def _signed_directory(value: Any, label: str) -> Path:
    supplied = Path(str(value or "")).expanduser()
    if not supplied.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        metadata = supplied.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink directory")
    return supplied.resolve(strict=True)


def _signed_regular_path(
    value: Any, *, allowed_root: Path, label: str, expected_sha256: str,
) -> Path:
    supplied = Path(str(value or "")).expanduser()
    if not supplied.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    try:
        metadata = supplied.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is missing or unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink regular file")
    resolved = supplied.resolve(strict=True)
    try:
        resolved.relative_to(allowed_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} escapes its signed allowed root") from exc
    if len(str(expected_sha256 or "")) != 64 or _sha256_path(resolved) != expected_sha256:
        raise ValueError(f"{label} hash mismatch")
    return resolved


def load_native_target_universe(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Verify the signed immutable universe and all selected local inputs."""
    path = path.resolve()
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != NATIVE_TARGET_UNIVERSE_SCHEMA:
        raise ValueError("native target universe schema mismatch")
    if not verify_document(document, require_signature=True) or document.get("trust") != "operator_signed":
        raise ValueError("native target universe signature verification failed")
    native_entries = require_list_field(
        document, "native_entries", context="native target universe",
    )
    targets = require_list_field(document, "targets", context="native target universe")
    if len(native_entries) != document.get("native_entry_count"):
        raise ValueError("native entry universe count mismatch")
    if hashlib.sha256(_canonical(native_entries)).hexdigest() != document.get("native_entry_universe_sha256"):
        raise ValueError("native entry universe hash mismatch")

    # Do not reduce the signed native-entry array to a set before proving its
    # order. Reconstruct the exact sequence from the authenticated APK content
    # manifest and the ZIP central directory, including stable entry ids.
    targets_root = _signed_directory(document.get("targets_root"), "signed targets root")
    audit_root = _signed_directory(document.get("audit_root"), "signed audit root")
    apk_supplied = Path(str(document.get("apk_path") or "")).expanduser()
    apk_root = _signed_directory(apk_supplied.parent, "signed APK parent")
    apk_path = _signed_regular_path(
        apk_supplied, allowed_root=apk_root, label="signed APK",
        expected_sha256=str(document.get("apk_sha256") or ""),
    )
    manifest_supplied = Path(str(document.get("apk_content_manifest_path") or "")).expanduser()
    manifest_path = _signed_regular_path(
        manifest_supplied, allowed_root=audit_root, label="signed APK content manifest",
        expected_sha256=str(document.get("apk_content_manifest_sha256") or ""),
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read authenticated APK content manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != APK_MANIFEST_SCHEMA:
        raise ValueError("authenticated APK content manifest schema mismatch")
    if manifest.get("manifest_sha256") != document.get("apk_content_manifest_payload_sha256"):
        raise ValueError("authenticated APK content manifest payload hash mismatch")
    if manifest.get("apk_sha256") != document.get("apk_sha256"):
        raise ValueError("authenticated APK content manifest APK hash mismatch")
    manifest_rows = manifest.get("entries")
    if not isinstance(manifest_rows, list):
        raise ValueError("authenticated APK content manifest entries must be a list")

    expected_native_entries: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            zip_rows = archive.infolist()
            if len(zip_rows) != len(manifest_rows):
                raise ValueError(
                    "APK central-directory count does not match authenticated content manifest"
                )
            for index, (info, manifest_row) in enumerate(
                zip(zip_rows, manifest_rows, strict=True)
            ):
                if not isinstance(manifest_row, dict):
                    raise ValueError(f"APK content manifest row {index} is not an object")
                expected_crc32 = f"{info.CRC & 0xffffffff:08x}"
                if (
                    manifest_row.get("central_directory_index") != index
                    or manifest_row.get("name") != info.filename
                    or manifest_row.get("content_bytes") != info.file_size
                    or manifest_row.get("crc32") != expected_crc32
                ):
                    raise ValueError(
                        f"APK content manifest row {index} does not match ZIP central directory"
                    )
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    raise ValueError(f"encrypted APK member is not admissible: {info.filename}")
                content = archive.read(info)
                content_sha256 = hashlib.sha256(content).hexdigest()
                if manifest_row.get("content_sha256") != content_sha256:
                    raise ValueError(f"APK member hash mismatch at central-directory row {index}")
                if not content.startswith(b"\x7fELF"):
                    continue
                parts = Path(info.filename).parts
                abi = parts[1] if len(parts) >= 3 and parts[0] == "lib" else "unknown"
                expected_native_entries.append({
                    "entry_id": manifest_row.get("entry_id"),
                    "central_directory_index": index,
                    "apk_path": info.filename,
                    "abi": abi,
                    "bytes": len(content),
                    "sha256": content_sha256,
                    "crc32": expected_crc32,
                })
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ValueError(f"cannot verify authenticated APK ZIP evidence: {exc}") from exc
    if native_entries != expected_native_entries:
        raise ValueError("native entries do not exactly match authenticated APK ZIP order")

    if len(targets) != document.get("target_count"):
        raise ValueError("native target universe count mismatch")
    if hashlib.sha256(_canonical(targets)).hexdigest() != document.get("target_universe_sha256"):
        raise ValueError("native target universe hash mismatch")
    grouped_entries: dict[str, list[dict[str, Any]]] = {}
    seen_entry_ids: set[str] = set()
    seen_indexes: set[int] = set()
    for row in native_entries:
        if not isinstance(row, dict):
            raise ValueError("native entry universe row is not an object")
        entry_id = str(row.get("entry_id") or "")
        target_sha = str(row.get("sha256") or "").lower()
        apk_member = str(row.get("apk_path") or "")
        abi = str(row.get("abi") or "")
        try:
            central_index = int(row.get("central_directory_index"))
            entry_size = int(row.get("bytes"))
        except (TypeError, ValueError) as exc:
            raise ValueError("native entry identity/size is invalid") from exc
        if (
            len(entry_id) != 64 or entry_id in seen_entry_ids
            or central_index < 0 or central_index in seen_indexes
            or len(target_sha) != 64 or not apk_member or not abi or entry_size < 0
        ):
            raise ValueError("native entry identity is duplicate or incomplete")
        seen_entry_ids.add(entry_id)
        seen_indexes.add(central_index)
        grouped_entries.setdefault(target_sha, []).append(row)
    expected_target_structure: list[dict[str, Any]] = []
    for target_sha, entry_rows in sorted(grouped_entries.items()):
        entry_rows = sorted(
            entry_rows,
            key=lambda row: (int(row["central_directory_index"]), str(row["apk_path"])),
        )
        expected_target_structure.append({
            "member_id": hashlib.sha256(_canonical({
                "apk_sha256": document.get("apk_sha256"),
                "target_sha256": target_sha,
            })).hexdigest(),
            "target_sha256": target_sha,
            "apk_path": str(entry_rows[0]["apk_path"]),
            "aliases": [str(row["apk_path"]) for row in entry_rows[1:]],
            "entry_ids": [str(row["entry_id"]) for row in entry_rows],
            "abis": sorted({str(row["abi"]) for row in entry_rows}),
            "bytes": int(entry_rows[0]["bytes"]),
            "entry_bytes": [
                {"apk_path": str(row["apk_path"]), "bytes": int(row["bytes"])}
                for row in entry_rows
            ],
            "grouped_bytes": sum(int(row["bytes"]) for row in entry_rows),
        })
    structural_fields = tuple(expected_target_structure[0].keys()) if expected_target_structure else ()
    actual_target_structure = [
        {field: row.get(field) for field in structural_fields}
        for row in targets if isinstance(row, dict)
    ]
    if actual_target_structure != expected_target_structure:
        raise ValueError("native target rows do not canonically conserve native APK entries")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in targets:
        if not isinstance(row, dict):
            raise ValueError("native target universe row is not an object")
        target_sha = str(row.get("target_sha256") or "").lower()
        if len(target_sha) != 64 or target_sha in seen:
            raise ValueError("duplicate or invalid native target SHA")
        seen.add(target_sha)
        target_value = row.get("extracted_target_path")
        analysis_value = row.get("analysis_path")
        target = _signed_regular_path(
            target_value, allowed_root=targets_root,
            label=f"native extracted target {target_sha}", expected_sha256=target_sha,
        ) if target_value else None
        analysis = _signed_regular_path(
            analysis_value, allowed_root=audit_root,
            label=f"native analysis {target_sha}",
            expected_sha256=str(row.get("analysis_sha256") or ""),
        ) if analysis_value else None
        if analysis is not None:
            analysis_doc = json.loads(analysis.read_text(encoding="utf-8"))
            if str((analysis_doc.get("metadata") or {}).get("sha256") or "").lower() != target_sha:
                raise ValueError(f"native analysis target binding mismatch: {target_sha}")
        alias_paths = []
        for value in row.get("extracted_target_aliases") or []:
            alias = _signed_regular_path(
                value, allowed_root=targets_root,
                label=f"native extracted target alias {target_sha}",
                expected_sha256=target_sha,
            )
            alias_paths.append(alias)
        for candidate in row.get("analysis_candidates") or []:
            if not isinstance(candidate, dict):
                raise ValueError(f"native analysis candidate is invalid: {target_sha}")
            _signed_regular_path(
                candidate.get("path"), allowed_root=audit_root,
                label=f"native analysis candidate {target_sha}",
                expected_sha256=str(candidate.get("sha256") or ""),
            )
        records.append({
            "target_sha256": target_sha,
            "target": target,
            "aliases": [target, *alias_paths] if target else [],
            "analysis": analysis,
            "analysis_sha256": row.get("analysis_sha256") or "",
            "function_count": 0,
            "universe_member": row,
        })
    return document, records


def preflight_operator_signing() -> str:
    probe = sign_document({"schema": "angerona/operator-signing-preflight/v1"})
    if (
        probe.get("trust") != "operator_signed"
        or not verify_document(probe, require_signature=True)
    ):
        raise ValueError("operator signing capability is required before reconstruction")
    return str(probe.get("signature_key_id") or "")


def write_scoped_operation_receipt(
    *, output_path: Path, universe_path: Path, universe: dict[str, Any],
    selected_target_sha256: list[str], terminal_events: list[dict[str, Any]],
    audit_epoch_id: str, target_selector: str | None, max_targets: int,
) -> dict[str, Any]:
    event_by_target = {
        str(event.get("target_sha256") or ""): event for event in terminal_events
    }
    rows = []
    for target_sha in selected_target_sha256:
        event = event_by_target.get(target_sha) or {}
        result = event.get("result") or {}
        selected_work_succeeded = bool(
            event
            and event.get("state") not in {"interrupted-or-failed", "missing-semantic-analysis"}
            and require_int_field(
                result, "failed", context=f"native result {target_sha}", minimum=0,
            ) == 0
            and require_int_field(
                result, "scheduled", context=f"native result {target_sha}", minimum=0,
            ) == require_int_field(
                result, "terminal", context=f"native result {target_sha}", minimum=0,
            )
        )
        rows.append({
            "target_sha256": target_sha,
            "state": event.get("state") if event else "missing-terminal-event",
            "selected_work_succeeded": selected_work_succeeded,
            "receipt_sha256": result.get("receipt_sha256"),
            "quality_ledger_sha256": result.get("quality_ledger_sha256"),
        })
    selected_conserved = len(rows) == len(selected_target_sha256) and all(
        row["state"] != "missing-terminal-event" for row in rows
    )
    operation_succeeded = selected_conserved and all(
        row["selected_work_succeeded"] for row in rows
    )
    body = {
        "schema": SCOPED_OPERATION_SCHEMA,
        "audit_epoch_id": audit_epoch_id,
        "universe_path": str(universe_path.resolve()),
        "universe_file_sha256": _sha256_path(universe_path.resolve()),
        "universe_payload_sha256": universe.get("payload_sha256"),
        "target_universe_sha256": universe.get("target_universe_sha256"),
        "target_selector": target_selector,
        "max_targets": max_targets,
        "selected_target_count": len(selected_target_sha256),
        "selected_target_sha256": selected_target_sha256,
        "rows": rows,
        "selected_scope_conserved": selected_conserved,
        "operation_succeeded": operation_succeeded,
        "global_conservation_claimed": False,
        "global_controller_complete": False,
    }
    return _publish_controller_receipt(
        output_path=output_path, body=body, receipt_kind="scoped",
        scope_identity={
            "audit_epoch_id": audit_epoch_id,
            "target_selector": target_selector,
            "max_targets": max_targets,
            "selected_target_sha256": selected_target_sha256,
        },
    )


def write_root_conservation_receipt(
    *, output_path: Path, universe_path: Path, universe: dict[str, Any],
    terminal_events: list[dict[str, Any]], audit_epoch_id: str,
) -> dict[str, Any]:
    expected = [str(row.get("target_sha256") or "") for row in require_list_field(
        universe, "targets", context="native target universe",
    )]
    event_by_target: dict[str, list[dict[str, Any]]] = {}
    for event in terminal_events:
        event_by_target.setdefault(str(event.get("target_sha256") or ""), []).append(event)
    rows = []
    for target_sha in expected:
        events = event_by_target.get(target_sha, [])
        event = events[0] if len(events) == 1 else {}
        rows.append({
            "target_sha256": target_sha,
            "event_count": len(events),
            "state": event.get("state") if event else "missing-terminal-event",
            "receipt_sha256": (event.get("result") or {}).get("receipt_sha256") if event else None,
            "quality_ledger_sha256": (event.get("result") or {}).get("quality_ledger_sha256") if event else None,
        })
    conserved = len(rows) == len(expected) and all(row["event_count"] == 1 for row in rows)
    controller_complete = conserved and all(row["state"] == "target-semantic-complete" for row in rows)
    body = {
        "schema": ROOT_CONSERVATION_SCHEMA,
        "audit_epoch_id": audit_epoch_id,
        "universe_path": str(universe_path.resolve()),
        "universe_file_sha256": _sha256_path(universe_path.resolve()),
        "universe_payload_sha256": universe.get("payload_sha256"),
        "target_universe_sha256": universe.get("target_universe_sha256"),
        "expected_target_count": len(expected),
        "terminal_event_count": len(terminal_events),
        "rows": rows,
        "universe_conserved": conserved,
        "controller_complete": controller_complete,
    }
    return _publish_controller_receipt(
        output_path=output_path, body=body, receipt_kind="root",
        scope_identity={
            "audit_epoch_id": audit_epoch_id,
            "target_universe_sha256": universe.get("target_universe_sha256"),
            "expected_target_sha256": expected,
        },
    )


def _verified_ownership_receipt_binding(
    ownership_path: Path, ownership: dict[str, Any], universe: dict[str, Any],
) -> dict[str, Any]:
    """Bind an already policy-validated ownership manifest into a controller receipt."""
    from .evidence_signing import verify_document

    supplied = ownership_path.expanduser().absolute()
    metadata = supplied.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("native ownership manifest must be a non-symlink regular file")
    disk = json.loads(supplied.read_text(encoding="utf-8"))
    if disk != ownership or not verify_document(disk, require_signature=True):
        raise ValueError("native ownership manifest changed or is not operator-signed")
    if disk.get("target_universe_sha256") != universe.get("target_universe_sha256"):
        raise ValueError("native ownership manifest/universe mismatch")
    return {
        "ownership_manifest_path": str(supplied.resolve(strict=True)),
        "ownership_manifest_file_sha256": _sha256_path(supplied),
        "ownership_manifest_payload_sha256": disk.get("payload_sha256"),
        "ownership_policy_sha256": disk.get("policy_sha256"),
        "ownership_rows_sha256": disk.get("rows_sha256"),
        "app_owned_queue_sha256": disk.get("app_owned_queue_sha256"),
        "app_owned_queue_count": disk.get("app_owned_queue_count"),
    }


def write_ownership_root_conservation_receipt(
    *, output_path: Path, universe_path: Path, universe: dict[str, Any],
    ownership_path: Path, ownership: dict[str, Any],
    terminal_events: list[dict[str, Any]], audit_epoch_id: str,
) -> dict[str, Any]:
    binding = _verified_ownership_receipt_binding(ownership_path, ownership, universe)
    expected = [str(row.get("target_sha256") or "") for row in require_list_field(
        universe, "targets", context="native target universe",
    )]
    event_by_target: dict[str, list[dict[str, Any]]] = {}
    for event in terminal_events:
        event_by_target.setdefault(str(event.get("target_sha256") or ""), []).append(event)
    rows = []
    for target_sha in expected:
        events = event_by_target.get(target_sha, [])
        event = events[0] if len(events) == 1 else {}
        result = event.get("result") or {}
        rows.append({
            "target_sha256": target_sha,
            "event_count": len(events),
            "state": event.get("state") if event else "missing-terminal-event",
            "ownership_disposition": event.get("ownership_disposition"),
            "ownership_row_sha256": event.get("ownership_row_sha256"),
            "receipt_sha256": result.get("receipt_sha256"),
            "quality_ledger_sha256": result.get("quality_ledger_sha256"),
        })
    conserved = len(rows) == len(expected) and all(row["event_count"] == 1 for row in rows)
    accepted = {"target-semantic-complete", "ownership-excluded-third-party"}
    controller_complete = conserved and all(row["state"] in accepted for row in rows)
    body = {
        "schema": ROOT_CONSERVATION_SCHEMA,
        "audit_epoch_id": audit_epoch_id,
        "universe_path": str(universe_path.resolve()),
        "universe_file_sha256": _sha256_path(universe_path.resolve()),
        "universe_payload_sha256": universe.get("payload_sha256"),
        "target_universe_sha256": universe.get("target_universe_sha256"),
        **binding,
        "expected_target_count": len(expected),
        "terminal_event_count": len(terminal_events),
        "rows": rows,
        "accepted_terminal_states": sorted(accepted),
        "universe_conserved": conserved,
        "controller_complete": controller_complete,
    }
    return _publish_controller_receipt(
        output_path=output_path, body=body, receipt_kind="root",
        scope_identity={
            "audit_epoch_id": audit_epoch_id,
            "target_universe_sha256": universe.get("target_universe_sha256"),
            "ownership_manifest_payload_sha256": ownership.get("payload_sha256"),
            "expected_target_sha256": expected,
        },
    )


def write_ownership_scoped_operation_receipt(
    *, output_path: Path, universe_path: Path, universe: dict[str, Any],
    ownership_path: Path, ownership: dict[str, Any],
    selected_target_sha256: list[str], terminal_events: list[dict[str, Any]],
    audit_epoch_id: str, target_selector: str | None, max_targets: int,
) -> dict[str, Any]:
    binding = _verified_ownership_receipt_binding(ownership_path, ownership, universe)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in terminal_events:
        grouped.setdefault(str(event.get("target_sha256") or ""), []).append(event)
    rows = []
    for target_sha in selected_target_sha256:
        events = grouped.get(target_sha, [])
        event = events[0] if len(events) == 1 else {}
        result = event.get("result") or {}
        state = event.get("state") if event else "missing-terminal-event"
        selected_work_succeeded = bool(
            len(events) == 1
            and (
                state in {"target-semantic-complete", "ownership-excluded-third-party"}
                or (
                    state not in {
                        "ownership-hold", "interrupted-or-failed", "missing-semantic-analysis",
                    }
                    and require_int_field(
                        result, "failed", context=f"native result {target_sha}", minimum=0,
                    ) == 0
                    and require_int_field(
                        result, "scheduled", context=f"native result {target_sha}", minimum=0,
                    ) == require_int_field(
                        result, "terminal", context=f"native result {target_sha}", minimum=0,
                    )
                )
            )
        )
        rows.append({
            "target_sha256": target_sha,
            "event_count": len(events),
            "state": state,
            "ownership_disposition": event.get("ownership_disposition"),
            "ownership_row_sha256": event.get("ownership_row_sha256"),
            "selected_work_succeeded": selected_work_succeeded,
            "receipt_sha256": result.get("receipt_sha256"),
            "quality_ledger_sha256": result.get("quality_ledger_sha256"),
        })
    selected_conserved = len(rows) == len(selected_target_sha256) and all(
        row["event_count"] == 1 for row in rows
    )
    operation_succeeded = selected_conserved and all(
        row["selected_work_succeeded"] for row in rows
    )
    body = {
        "schema": SCOPED_OPERATION_SCHEMA,
        "audit_epoch_id": audit_epoch_id,
        "universe_path": str(universe_path.resolve()),
        "universe_file_sha256": _sha256_path(universe_path.resolve()),
        "universe_payload_sha256": universe.get("payload_sha256"),
        "target_universe_sha256": universe.get("target_universe_sha256"),
        **binding,
        "target_selector": target_selector,
        "max_targets": max_targets,
        "selected_target_count": len(selected_target_sha256),
        "selected_target_sha256": selected_target_sha256,
        "rows": rows,
        "selected_scope_conserved": selected_conserved,
        "operation_succeeded": operation_succeeded,
        "global_conservation_claimed": False,
        "global_controller_complete": False,
    }
    return _publish_controller_receipt(
        output_path=output_path, body=body, receipt_kind="scoped",
        scope_identity={
            "audit_epoch_id": audit_epoch_id,
            "ownership_manifest_payload_sha256": ownership.get("payload_sha256"),
            "target_selector": target_selector,
            "max_targets": max_targets,
            "selected_target_sha256": selected_target_sha256,
        },
    )
