"""Trusted, immutable corpus inputs for binary-similarity analysis.

Similarity corpora affect recovered names and therefore model-visible evidence.  This
module treats them as versioned audit inputs: only explicit paths (or the dedicated
environment variable) are accepted, relevant files are content-addressed, and each run
uses a read-only snapshot rather than mutable source directories.
"""

from __future__ import annotations

import hashlib
import csv
import io
import json
import os
import shutil
import stat
import re
import math
import threading
import tempfile
from pathlib import Path
from typing import Any, Iterable


class SimilarityCorpusError(ValueError):
    """A similarity corpus is missing, unsafe, incompatible, or malformed."""


MAX_CORPORA = 32
MAX_FILES = 100_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BODY_FILE_BYTES = 512 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_JSON_STRING = 4096
_ROOT_FILES = ("functions.csv", "EXPORT_MANIFEST.json", "analysis.json")
_SUBDIR_SUFFIXES = {"asm": ".asm", "decompiled": ".c"}
_CSV_LIMIT_LOCK = threading.Lock()


def _open_beneath(root: Path, relative: str):
    """Open one regular file beneath root without following any path symlink."""

    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SimilarityCorpusError(f"invalid corpus relative path: {relative!r}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=current)
        mode = os.fstat(file_fd).st_mode
        if not stat.S_ISREG(mode):
            os.close(file_fd)
            raise SimilarityCorpusError(f"corpus entry is not a regular file: {relative}")
        return os.fdopen(file_fd, "rb")
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise SimilarityCorpusError(f"cannot safely open corpus entry {relative}: {exc}") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _bounded_identity(root: Path, relative: str, limit: int) -> tuple[int, str]:
    data = _bounded_read(root, relative, limit)
    return len(data), hashlib.sha256(data).hexdigest()


def _bounded_read(
    root: Path, relative: str, limit: int, *, missing_ok: bool = False,
) -> bytes | None:
    """Read one stable regular file, bounded and symlink-safe, exactly once."""

    try:
        handle_context = _open_beneath(root, relative)
    except FileNotFoundError as exc:
        if missing_ok:
            return None
        raise SimilarityCorpusError(f"corpus entry disappeared: {relative}") from exc
    with handle_context as handle:
        initial = os.fstat(handle.fileno())
        if initial.st_size > limit:
            raise SimilarityCorpusError(f"similarity corpus file exceeds {limit} bytes: {relative}")
        expected = int(initial.st_size)
        chunks: list[bytes] = []
        total = 0
        while total <= expected:
            chunk = handle.read(min(1024 * 1024, expected - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > expected:
                raise SimilarityCorpusError(f"corpus file changed while hashing: {relative}")
            chunks.append(chunk)
        final = os.fstat(handle.fileno())
        if total != expected or final.st_size != initial.st_size:
            raise SimilarityCorpusError(f"corpus file changed while hashing: {relative}")
    return b"".join(chunks)


def _configured_paths(values: Iterable[str | Path] | None) -> list[Path]:
    if values is None:
        raw = os.environ.get("ANGERONA_SIMILARITY_CORPUS", "")
        values = [item for item in raw.split(os.pathsep) if item.strip()]
    elif isinstance(values, (str, Path)):
        values = [values]
    paths = [Path(value).expanduser() for value in values if str(value).strip()]
    if len(paths) > MAX_CORPORA:
        raise SimilarityCorpusError(f"at most {MAX_CORPORA} similarity corpora are allowed")
    return paths


def _selected_files(root: Path) -> list[Path]:
    selected = [root / name for name in _ROOT_FILES if (root / name).is_file()]
    asm_path = root / "asm"
    if asm_path.is_symlink():
        raise SimilarityCorpusError(f"similarity corpus symlink refused: {asm_path}")
    if asm_path.is_file():
        selected.append(asm_path)
    for dirname, suffix in _SUBDIR_SUFFIXES.items():
        directory = root / dirname
        if directory.is_symlink():
            raise SimilarityCorpusError(f"similarity corpus symlink refused: {directory}")
        if directory.is_dir():
            selected.extend(sorted(p for p in directory.glob(f"*{suffix}") if p.is_file()))
    return sorted(set(selected), key=lambda p: p.relative_to(root).as_posix())


def _arch_from_manifest(
    root: Path, verified_files: dict[str, bytes] | None = None,
) -> str | None:
    for relative in ("EXPORT_MANIFEST.json", "analysis.json"):
        candidate = root / relative
        if verified_files is not None:
            raw = verified_files.get(relative)
            if raw is None:
                continue
        else:
            try:
                raw = _bounded_read(
                    root, relative, MAX_FILE_BYTES, missing_ok=True
                )
            except SimilarityCorpusError:
                raise
            if raw is None:
                continue
        value = _load_bounded_json_bytes(raw, candidate)
        metadata = value.get("metadata") if isinstance(value, dict) else None
        if not isinstance(metadata, dict):
            if isinstance(value, dict) and "metadata" in value:
                raise SimilarityCorpusError(f"metadata must be an object: {candidate}")
            metadata = value if isinstance(value, dict) else {}
        for key in ("language_id", "architecture", "arch", "processor"):
            raw = metadata.get(key)
            if isinstance(raw, str) and raw.strip():
                if len(raw) > 256 or any(ord(char) < 32 for char in raw):
                    raise SimilarityCorpusError(f"invalid architecture metadata: {candidate}")
                canonical = _canonical_arch(raw.strip())
                return canonical or (
                    "unknown:" + hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()[:16]
                )
            if raw is not None:
                raise SimilarityCorpusError(f"architecture metadata must be a string: {candidate}")
    return None


def _load_bounded_json_bytes(raw: bytes, path: Path) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def parse_int(raw: str) -> int:
        if len(raw.lstrip("-")) > 128:
            raise ValueError("JSON integer exceeds 128 digits")
        return int(raw)

    def parse_float(raw: str) -> float:
        if len(raw) > 128:
            raise ValueError("JSON float literal is too long")
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return value

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs_hook,
            parse_int=parse_int,
            parse_float=parse_float,
            parse_constant=lambda raw: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {raw}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SimilarityCorpusError(f"invalid corpus JSON {path}: {exc}") from exc
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise SimilarityCorpusError(f"corpus JSON resource limits exceeded: {path}")
        if isinstance(current, str) and len(current) > MAX_JSON_STRING:
            raise SimilarityCorpusError(f"corpus JSON string exceeds limit: {path}")
        if isinstance(current, dict):
            for key, item in current.items():
                if len(key) > MAX_JSON_STRING:
                    raise SimilarityCorpusError(f"corpus JSON key exceeds limit: {path}")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def _canonical_arch(value: str | None) -> str | None:
    if not value:
        return None
    text = value.lower().replace("-", "_")
    if text.startswith("unknown:"):
        return None
    ghidra = re.fullmatch(r"x86:(?:le|be):(16|32|64)(?::[a-z0-9_.]+)*", text)
    if ghidra:
        return "x86_64" if ghidra.group(1) == "64" else "x86"
    if re.fullmatch(r"(?:aarch64|arm64)(?::[a-z0-9_.]+)*", text):
        return "arm64"
    if re.fullmatch(r"arm(?::[a-z0-9_.]+)*", text):
        return "arm"
    if text in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    if text in {"x86", "i386", "i686"}:
        return "x86"
    if re.fullmatch(r"riscv(?:32|64)?(?::[a-z0-9_.]+)*", text):
        return "riscv"
    if re.fullmatch(r"mips(?:32|64)?(?::[a-z0-9_.]+)*", text):
        return "mips"
    if re.fullmatch(r"(?:bpf|sbf|solana)(?::[a-z0-9_.]+)*", text):
        return "bpf"
    return None


def _validate_functions_csv(raw: bytes | None) -> None:
    if raw is None:
        return
    with _CSV_LIMIT_LOCK:
        previous_limit = csv.field_size_limit()
        try:
            csv.field_size_limit(4096)
            text = raw.decode("utf-8", errors="strict")
            with io.StringIO(text, newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames or not {"name", "entry"}.issubset(reader.fieldnames):
                    raise SimilarityCorpusError("functions.csv must contain name and entry columns")
                entries: dict[str, str] = {}
                for row_number, row in enumerate(reader, start=2):
                    if row_number > MAX_FILES + 1:
                        raise SimilarityCorpusError("functions.csv exceeds the function row limit")
                    name = row.get("name")
                    entry = row.get("entry")
                    if not isinstance(name, str) or not isinstance(entry, str):
                        raise SimilarityCorpusError(f"functions.csv row {row_number} is malformed")
                    if len(name) > 256 or len(entry) > 128:
                        raise SimilarityCorpusError(
                            f"functions.csv row {row_number} exceeds field length limits"
                        )
                    normalized_entry = entry.strip().lower()
                    prior = entries.get(normalized_entry)
                    if prior is not None and prior != name.strip():
                        raise SimilarityCorpusError(
                            f"functions.csv has conflicting names for entry {entry!r}"
                        )
                    entries[normalized_entry] = name.strip()
        except (csv.Error, UnicodeError) as exc:
            raise SimilarityCorpusError(f"invalid functions.csv: {exc}") from exc
        finally:
            csv.field_size_limit(previous_limit)


def resolve_similarity_corpora(
    values: Iterable[str | Path] | None,
) -> list[dict[str, Any]]:
    """Validate and content-identify explicitly configured export directories."""

    records: list[dict[str, Any]] = []
    seen_sources: set[Path] = set()
    seen_digests: set[str] = set()
    aggregate_bytes = 0
    aggregate_functions = 0
    for requested in _configured_paths(values):
        absolute_requested = requested.absolute()
        for component in (absolute_requested, *absolute_requested.parents):
            if component.exists() and component.is_symlink():
                raise SimilarityCorpusError(
                    f"similarity corpus path contains a symlink component: {component}"
                )
        try:
            root = requested.resolve(strict=True)
        except OSError as exc:
            raise SimilarityCorpusError(f"similarity corpus not found: {requested}") from exc
        if not root.is_dir():
            raise SimilarityCorpusError(f"similarity corpus must be an export directory: {root}")
        if root in seen_sources:
            continue
        seen_sources.add(root)
        files = _selected_files(root)
        function_files = {
            path for path in files
            if path.parent.name in {"asm", "decompiled"}
        }
        aggregate_functions += len(function_files)
        if aggregate_functions > 50_000:
            raise SimilarityCorpusError("similarity corpora exceed 50000 function files")
        if not files or not any(p.parent.name in {"asm", "decompiled"} or p.name == "asm" for p in files):
            raise SimilarityCorpusError(
                f"similarity corpus has no asm/decompiled function bodies: {root}"
            )
        if len(files) > MAX_FILES:
            raise SimilarityCorpusError(f"similarity corpus exceeds {MAX_FILES} files: {root}")
        entries: list[dict[str, Any]] = []
        verified_metadata: dict[str, bytes] = {}
        tree = hashlib.sha256()
        total = 0
        for path in files:
            if path.is_symlink() or stat.S_ISLNK(path.lstat().st_mode):
                raise SimilarityCorpusError(f"similarity corpus symlink refused: {path}")
            relative = path.relative_to(root).as_posix()
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError) as exc:
                raise SimilarityCorpusError(
                    f"similarity corpus path escapes its root: {relative}"
                ) from exc
            file_limit = MAX_BODY_FILE_BYTES if path in function_files else MAX_FILE_BYTES
            data = _bounded_read(root, relative, file_limit)
            size = len(data)
            file_sha = hashlib.sha256(data).hexdigest()
            if relative in _ROOT_FILES:
                verified_metadata[relative] = data
            total += size
            aggregate_bytes += size
            if total > MAX_TOTAL_BYTES or aggregate_bytes > MAX_TOTAL_BYTES:
                raise SimilarityCorpusError(
                    f"similarity corpora exceed {MAX_TOTAL_BYTES} aggregate bytes"
                )
            entries.append({"path": relative, "size": size, "sha256": file_sha})
            tree.update(relative.encode("utf-8"))
            tree.update(b"\0")
            tree.update(bytes.fromhex(file_sha))
        tree_sha = tree.hexdigest()
        _validate_functions_csv(verified_metadata.get("functions.csv"))
        if tree_sha in seen_digests:
            continue
        seen_digests.add(tree_sha)
        records.append({
            "source_path": str(root),
            "path": str(root),
            "tree_sha256": tree_sha,
            "file_count": len(entries),
            "total_bytes": total,
            "architecture": _arch_from_manifest(root, verified_metadata),
            "files": entries,
        })
    return records


def materialize_similarity_corpora(
    resolutions: list[dict[str, Any]], destination: str | Path
) -> list[dict[str, Any]]:
    """Copy verified corpus inputs into content-addressed, read-only snapshots."""

    base = Path(destination).absolute()
    for component in (base, *base.parents):
        if component.exists() and component.is_symlink():
            raise SimilarityCorpusError(
                f"similarity snapshot destination contains a symlink: {component}"
            )
    base.mkdir(parents=True, exist_ok=True)
    if base.resolve(strict=True) != base:
        raise SimilarityCorpusError("similarity snapshot destination is not path-stable")

    def cleanup_staging(path: Path) -> None:
        if not path.exists() or path.is_symlink():
            return
        for item in path.rglob("*"):
            try:
                os.chmod(item, 0o700 if item.is_dir() else 0o600)
            except OSError:
                pass
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        shutil.rmtree(path, ignore_errors=True)

    def verified_copy(source_root: Path, entry: dict[str, Any], destination_file: Path) -> None:
        relative = str(entry["path"])
        expected_size = int(entry["size"])
        expected_sha = str(entry["sha256"])
        digest = hashlib.sha256()
        with _open_beneath(source_root, relative) as source_handle:
            initial = os.fstat(source_handle.fileno())
            if initial.st_size != expected_size:
                raise SimilarityCorpusError(f"corpus source changed before snapshot: {relative}")
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            total = 0
            with destination_file.open("xb") as output:
                while total <= expected_size:
                    chunk = source_handle.read(
                        min(1024 * 1024, expected_size - total + 1)
                    )
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected_size:
                        raise SimilarityCorpusError(
                            f"corpus source grew during snapshot: {relative}"
                        )
                    output.write(chunk)
                    digest.update(chunk)
            final = os.fstat(source_handle.fileno())
            if (
                total != expected_size
                or final.st_size != expected_size
                or digest.hexdigest() != expected_sha
            ):
                raise SimilarityCorpusError(
                    f"corpus source identity changed during snapshot: {relative}"
                )

    materialized: list[dict[str, Any]] = []
    for record in resolutions:
        source = Path(str(record["path"])).resolve(strict=True)
        target = base / str(record["tree_sha256"])
        if target.is_symlink():
            raise SimilarityCorpusError("similarity corpus snapshot symlink refused")
        if not target.exists():
            staging = Path(tempfile.mkdtemp(
                prefix=f".tmp-{str(record['tree_sha256'])[:16]}-", dir=base
            ))
            try:
                for entry in record["files"]:
                    verified_copy(source, entry, staging / str(entry["path"]))
                staged_resolution = resolve_similarity_corpora([staging])
                if (
                    len(staged_resolution) != 1
                    or staged_resolution[0]["tree_sha256"] != record["tree_sha256"]
                ):
                    raise SimilarityCorpusError(
                        "staged similarity corpus snapshot verification failed"
                    )
                for file_path in (p for p in staging.rglob("*") if p.is_file()):
                    os.chmod(file_path, 0o444)
                for directory in sorted(
                    (p for p in staging.rglob("*") if p.is_dir()), reverse=True
                ):
                    os.chmod(directory, 0o555)
                os.chmod(staging, 0o555)
                try:
                    staging.rename(target)
                except OSError:
                    if not target.is_dir():
                        raise
                    cleanup_staging(staging)
            except Exception:
                cleanup_staging(staging)
                raise
        verified = resolve_similarity_corpora([target])
        if len(verified) != 1 or verified[0]["tree_sha256"] != record["tree_sha256"]:
            raise SimilarityCorpusError("immutable similarity corpus snapshot verification failed")
        materialized.append({**record, "path": str(target), "snapshot": True})
    return materialized


def similarity_corpus_contract(resolutions: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a path-independent exact-resume contract."""

    return {
        "configured": bool(resolutions),
        "corpora": [
            {
                "tree_sha256": item["tree_sha256"],
                "file_count": item["file_count"],
                "total_bytes": item["total_bytes"],
                "architecture": item.get("architecture"),
                "files": item["files"],
            }
            for item in resolutions
        ],
    }


def similarity_corpus_summary(contract: dict[str, Any]) -> dict[str, Any]:
    """Compact model-safe view; omits untrusted filenames and source paths."""

    corpora = contract.get("corpora") if isinstance(contract, dict) else None
    if not isinstance(corpora, list):
        corpora = []
    return {
        "configured": bool(contract.get("configured")) if isinstance(contract, dict) else False,
        "corpora": [
            {
                "tree_sha256": str(item.get("tree_sha256") or ""),
                "file_count": int(item.get("file_count") or 0),
                "total_bytes": int(item.get("total_bytes") or 0),
                "architecture": str(item.get("architecture") or "unknown"),
            }
            for item in corpora
            if isinstance(item, dict)
        ],
    }


def validate_similarity_architecture(
    target_code_dir: str | Path, resolutions: list[dict[str, Any]]
) -> dict[str, Any]:
    """Reject known cross-architecture comparisons; preserve unknowns as caveats."""

    target_raw = _arch_from_manifest(Path(target_code_dir))
    target = _canonical_arch(target_raw)
    unknown: list[str] = []
    for item in resolutions:
        corpus_raw = item.get("architecture")
        corpus = _canonical_arch(corpus_raw)
        if target and corpus and target != corpus:
            raise SimilarityCorpusError(
                f"similarity corpus architecture mismatch: target={target_raw!r}, "
                f"corpus={corpus_raw!r} ({item['tree_sha256'][:16]})"
            )
        if not target or not corpus:
            unknown.append(str(item["tree_sha256"]))
    return {
        "target_architecture": target_raw,
        "canonical_target_architecture": target,
        "compatible": True,
        "unknown_architecture_corpora": unknown,
    }
