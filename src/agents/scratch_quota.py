"""Hard-bounded K-candidate scratch runtime and artifact transfer.

The provider executes in a private, size-limited tmpfs.  The immutable candidate
seed is copied into that tmpfs and only the configured reconstruction subtree is
streamed back to the host through a bounded pipe after the provider exits.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
import re
import resource
import signal
import socket
import stat
import struct
import subprocess
import tarfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

try:
    from .network_guard import (
        NETWORK_GATEWAY_ENV,
        NETWORK_POLICY_EXIT,
        CandidateLoopbackProxy,
        NetworkPolicyError,
    )
except ImportError:  # executed as the sandbox runner by absolute script path
    from network_guard import (
        NETWORK_GATEWAY_ENV, NETWORK_POLICY_EXIT,
        CandidateLoopbackProxy, NetworkPolicyError,
    )


SCRATCH_QUOTA_POLICY_VERSION = 7
SCRATCH_QUOTA_EXIT = 73
DEFAULT_SCRATCH_WRITE_BYTES = 128 * 1024 * 1024
DEFAULT_SCRATCH_WRITE_FILES = 2048
DEFAULT_SCRATCH_WRITE_DIRECTORIES = 512
DEFAULT_PROCESS_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
# Modern provider runtimes size worker pools from host CPU count. Keep a hard,
# checkpointed ceiling while leaving room for the trusted runner/proxy and a
# high-core Tokio/Node provider tree.
DEFAULT_PROCESS_TASKS = 256
DEFAULT_PROCESS_OPEN_FILES = 256
RECONSTRUCTION_MAX_FILES = 512
RECONSTRUCTION_MAX_DIRECTORIES = 512
RECONSTRUCTION_MAX_BYTES = 32 * 1024 * 1024
RECOVERY_STATE_MAX_FILES = DEFAULT_SCRATCH_WRITE_FILES
RECOVERY_STATE_MAX_DIRECTORIES = DEFAULT_SCRATCH_WRITE_DIRECTORIES
RECOVERY_STATE_MAX_BYTES = DEFAULT_SCRATCH_WRITE_BYTES
SEED_MAX_FILES = 4096
SEED_MAX_DIRECTORIES = 1024
SEED_MAX_BYTES = 512 * 1024 * 1024
EXPORT_STREAM_MAX_BYTES = RECOVERY_STATE_MAX_BYTES + 4 * 1024 * 1024
EXPORT_MAGIC = b"ANGERONA_SCRATCH_EXPORT_V1\x00"
RECOVERY_DELTA_MANIFEST = ".angerona-recovery-delta-v1.json"
SCOPE_MAX_BYTES = 64 * 1024
AUTH_SEED_MAX_BYTES = 1024 * 1024
_CLAUDE_SAFE_SETTING_KEYS = frozenset({"effortLevel", "model"})
_CLAUDE_ALLOWED_ENV_KEYS = frozenset({
    "API_TIMEOUT_MS",
    "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY",
    "DISABLE_COST_WARNINGS",
})
_CLAUDE_SAFE_STATE_KEYS = frozenset({
    "hasCompletedOnboarding", "installMethod", "lastOnboardingVersion",
    "migrationVersion",
})


class ScratchQuotaError(RuntimeError):
    """The scratch boundary or bounded transfer was violated."""


@dataclass(frozen=True)
class TreeUsage:
    files: int
    directories: int
    bytes: int
    allocated_bytes: int
    manifest_sha256: str


def _write_private_file(destination: Path, payload: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_auth_seed_fd(descriptor: int) -> bytes:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= AUTH_SEED_MAX_BYTES:
        raise ScratchQuotaError("candidate auth seed is unsafe or oversized")
    chunks: list[bytes] = []
    remaining = AUTH_SEED_MAX_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    if (
        len(payload) != info.st_size
        or after.st_size != info.st_size
        or after.st_mtime_ns != info.st_mtime_ns
        or after.st_ctime_ns != info.st_ctime_ns
    ):
        raise ScratchQuotaError("candidate auth seed changed during copy")
    return payload


def _sanitized_claude_settings(payload: bytes, gateway_url: str | None) -> bytes:
    try:
        source = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScratchQuotaError("candidate Claude settings seed is malformed") from exc
    if not isinstance(source, dict):
        raise ScratchQuotaError("candidate Claude settings root is invalid")
    settings = {
        key: source[key]
        for key in _CLAUDE_SAFE_SETTING_KEYS
        if key in source and isinstance(source[key], (str, int, float, bool))
    }
    raw_env = source.get("env")
    clean_env: dict[str, str] = {}
    if raw_env is not None and not isinstance(raw_env, dict):
        raise ScratchQuotaError("candidate Claude settings env is invalid")
    for key, value in (raw_env or {}).items():
        if (
            isinstance(key, str)
            and isinstance(value, str)
            and (key.startswith("ANTHROPIC_") or key in _CLAUDE_ALLOWED_ENV_KEYS)
        ):
            clean_env[key] = value
    if gateway_url:
        clean_env["ANTHROPIC_BASE_URL"] = gateway_url
    clean_env.update({
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    })
    settings["env"] = clean_env
    return json.dumps(
        settings, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sanitized_claude_state(payload: bytes) -> bytes:
    try:
        source = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScratchQuotaError("candidate Claude state seed is malformed") from exc
    if not isinstance(source, dict):
        raise ScratchQuotaError("candidate Claude state root is invalid")
    clean = {
        key: source[key]
        for key in _CLAUDE_SAFE_STATE_KEYS
        if key in source and isinstance(source[key], (str, int, bool))
    }
    return json.dumps(
        clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _prepare_runtime_auth(workspace: Path, seed_specs: list[str]) -> None:
    """Copy runner-only inherited auth/config FDs into candidate-local tmpfs."""

    destinations = {
        "claude-credentials": "runtime/home/.claude/.credentials.json",
        "home-credentials": "runtime/home/.credentials.json",
        "codex-auth": "runtime/home/.codex/auth.json",
        "claude-settings": "runtime/home/.claude/settings.json",
        "claude-state": "runtime/home/.claude.json",
    }
    parsed: dict[str, int] = {}
    for spec in seed_specs:
        name, separator, raw_fd = spec.rpartition(":")
        try:
            descriptor = int(raw_fd)
        except ValueError as exc:
            raise ScratchQuotaError("candidate auth seed descriptor is malformed") from exc
        if (
            separator != ":"
            or name not in destinations
            or name in parsed
            or descriptor < 3
            or descriptor in parsed.values()
        ):
            raise ScratchQuotaError("candidate auth seed descriptor set is invalid")
        parsed[name] = descriptor
    try:
        for name, descriptor in parsed.items():
            payload = _read_auth_seed_fd(descriptor)
            if name == "claude-settings":
                payload = _sanitized_claude_settings(
                    payload, os.environ.get(NETWORK_GATEWAY_ENV)
                )
            elif name == "claude-state":
                payload = _sanitized_claude_state(payload)
            _write_private_file(workspace / destinations[name], payload)
    finally:
        for descriptor in parsed.values():
            try:
                os.close(descriptor)
            except OSError:
                pass


def scratch_quota_contract() -> dict[str, int]:
    """Return every live scratch-policy input persisted for exact resume."""

    return {
        "policy_version": SCRATCH_QUOTA_POLICY_VERSION,
        "write_bytes": DEFAULT_SCRATCH_WRITE_BYTES,
        "write_files": DEFAULT_SCRATCH_WRITE_FILES,
        "write_directories": DEFAULT_SCRATCH_WRITE_DIRECTORIES,
        "process_memory_bytes": DEFAULT_PROCESS_MEMORY_BYTES,
        "process_tasks": DEFAULT_PROCESS_TASKS,
        "process_open_files": DEFAULT_PROCESS_OPEN_FILES,
        "seed_max_files": SEED_MAX_FILES,
        "seed_max_directories": SEED_MAX_DIRECTORIES,
        "seed_max_bytes": SEED_MAX_BYTES,
        "reconstruction_max_files": RECONSTRUCTION_MAX_FILES,
        "reconstruction_max_directories": RECONSTRUCTION_MAX_DIRECTORIES,
        "reconstruction_max_bytes": RECONSTRUCTION_MAX_BYTES,
    }


def _manifest_record(
    manifest: "hashlib._Hash", kind: bytes, relative: PurePosixPath, size: int = 0,
    digest: bytes = b"",
) -> None:
    encoded = relative.as_posix().encode("utf-8", errors="surrogatepass")
    manifest.update(kind)
    manifest.update(struct.pack("!Q", len(encoded)))
    manifest.update(encoded)
    manifest.update(struct.pack("!Q", size))
    manifest.update(digest)


def _validated_relative(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        not value
        or not relative.parts  # "." (and any path that normalizes to it)
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or len(value.encode("utf-8")) > 4096
        or any(len(part.encode("utf-8")) > 255 for part in relative.parts)
    ):
        raise ScratchQuotaError("candidate reconstruction authority is invalid")
    return relative


def reconstruction_authority(cwd: str | Path | int) -> str:
    """Read the trusted pre-dispatch reconstruction path from RUN_SCOPE.json."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd = (
        os.dup(cwd)
        if isinstance(cwd, int)
        else os.open(
            Path(cwd).expanduser().absolute(),
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
    )
    try:
        descriptor = os.open("RUN_SCOPE.json", flags, dir_fd=root_fd)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= SCOPE_MAX_BYTES:
                raise ScratchQuotaError("candidate RUN_SCOPE.json is unsafe or unbounded")
            chunks: list[bytes] = []
            remaining = SCOPE_MAX_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > SCOPE_MAX_BYTES:
                raise ScratchQuotaError("candidate RUN_SCOPE.json exceeds bounds")
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScratchQuotaError("candidate RUN_SCOPE.json is malformed") from exc
    value = payload.get("candidate_reconstruction_relative")
    if not isinstance(value, str):
        raise ScratchQuotaError("candidate reconstruction authority is missing")
    return _validated_relative(value).as_posix()


def _is_excluded_seed_path(
    relative: PurePosixPath,
    excluded: frozenset[PurePosixPath],
) -> bool:
    return any(
        relative == blocked or blocked in relative.parents
        for blocked in excluded
    )


def bounded_tree_usage(
    root: str | Path,
    *,
    excluded_paths: tuple[str, ...] = (),
) -> TreeUsage:
    """Measure and content-bind a regular-file tree without following links."""

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    root_fd = os.open(Path(root).expanduser().absolute(), flags)
    counters = {"files": 0, "directories": 0, "bytes": 0, "allocated": 0}
    manifest = hashlib.sha256()
    excluded = frozenset(_validated_relative(path) for path in excluded_paths)

    def visit(directory_fd: int, relative: PurePosixPath) -> None:
        counters["directories"] += 1
        if counters["directories"] > SEED_MAX_DIRECTORIES:
            raise ScratchQuotaError("candidate seed exceeds directory bounds")
        _manifest_record(manifest, b"D", relative)
        names: list[str] = []
        remaining = (
            SEED_MAX_FILES + SEED_MAX_DIRECTORIES
            - counters["files"] - counters["directories"]
        )
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > remaining:
                    raise ScratchQuotaError("candidate seed exceeds entry bounds")
        for name in sorted(names):
            child_relative = relative / name
            if _is_excluded_seed_path(child_relative, excluded):
                continue
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                        raise ScratchQuotaError("candidate seed changed during measurement")
                    visit(child, child_relative)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise ScratchQuotaError("candidate seed contains an unsafe entry")
            counters["files"] += 1
            counters["bytes"] += int(before.st_size)
            counters["allocated"] += ((int(before.st_size) + 4095) // 4096) * 4096
            if counters["files"] > SEED_MAX_FILES:
                raise ScratchQuotaError("candidate seed exceeds file bounds")
            if counters["bytes"] > SEED_MAX_BYTES:
                raise ScratchQuotaError("candidate seed exceeds byte bounds")
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            file_digest = hashlib.sha256()
            read_bytes = 0
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise ScratchQuotaError("candidate seed changed during measurement")
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    file_digest.update(chunk)
                after = os.fstat(descriptor)
                if (
                    read_bytes != opened.st_size
                    or after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or after.st_ctime_ns != opened.st_ctime_ns
                ):
                    raise ScratchQuotaError("candidate seed changed during measurement")
            finally:
                os.close(descriptor)
            _manifest_record(
                manifest, b"F", child_relative, read_bytes, file_digest.digest()
            )

    try:
        visit(root_fd, PurePosixPath("."))
    finally:
        os.close(root_fd)
    return TreeUsage(
        files=counters["files"],
        directories=counters["directories"],
        bytes=counters["bytes"],
        allocated_bytes=counters["allocated"],
        manifest_sha256=manifest.hexdigest(),
    )


def _copy_seed(
    source: Path,
    destination: Path,
    *,
    excluded_paths: tuple[str, ...] = (),
) -> TreeUsage:
    source_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    source_fd = os.open(source, source_flags)
    destination_fd = os.open(destination, source_flags)
    counters = {"files": 0, "directories": 0, "bytes": 0, "allocated": 0}
    manifest = hashlib.sha256()
    excluded = frozenset(_validated_relative(path) for path in excluded_paths)

    def copy_directory(src_fd: int, dst_fd: int, relative: PurePosixPath) -> None:
        counters["directories"] += 1
        if counters["directories"] > SEED_MAX_DIRECTORIES:
            raise ScratchQuotaError("candidate seed exceeds directory bounds")
        _manifest_record(manifest, b"D", relative)
        names: list[str] = []
        with os.scandir(src_fd) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) + counters["files"] + counters["directories"] > (
                    SEED_MAX_FILES + SEED_MAX_DIRECTORIES
                ):
                    raise ScratchQuotaError("candidate seed exceeds entry bounds")
        for name in sorted(names):
            child_relative = relative / name
            if _is_excluded_seed_path(child_relative, excluded):
                continue
            before = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child_src = os.open(name, source_flags, dir_fd=src_fd)
                try:
                    try:
                        os.mkdir(name, mode=0o700, dir_fd=dst_fd)
                    except FileExistsError:
                        pass
                    child_dst = os.open(name, source_flags, dir_fd=dst_fd)
                    try:
                        copy_directory(child_src, child_dst, child_relative)
                    finally:
                        os.close(child_dst)
                finally:
                    os.close(child_src)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise ScratchQuotaError("candidate seed contains an unsafe entry")
            counters["files"] += 1
            if counters["files"] > SEED_MAX_FILES:
                raise ScratchQuotaError("candidate seed exceeds file bounds")
            source_file = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=src_fd,
            )
            destination_file = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=dst_fd,
            )
            copied = 0
            file_digest = hashlib.sha256()
            try:
                opened = os.fstat(source_file)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise ScratchQuotaError("candidate seed changed during copy")
                while True:
                    chunk = os.read(source_file, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    file_digest.update(chunk)
                    counters["bytes"] += len(chunk)
                    if counters["bytes"] > SEED_MAX_BYTES:
                        raise ScratchQuotaError("candidate seed exceeds byte bounds")
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(destination_file, view):]
                after = os.fstat(source_file)
                if (
                    copied != opened.st_size
                    or after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or after.st_ctime_ns != opened.st_ctime_ns
                ):
                    raise ScratchQuotaError("candidate seed changed during copy")
            finally:
                os.close(destination_file)
                os.close(source_file)
            counters["allocated"] += ((copied + 4095) // 4096) * 4096
            _manifest_record(
                manifest, b"F", child_relative, copied, file_digest.digest()
            )

    try:
        copy_directory(source_fd, destination_fd, PurePosixPath("."))
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    return TreeUsage(
        files=counters["files"], directories=counters["directories"],
        bytes=counters["bytes"], allocated_bytes=counters["allocated"],
        manifest_sha256=manifest.hexdigest(),
    )


def _live_usage(root: Path, *, max_files: int, max_directories: int) -> TreeUsage:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, flags)
    root_device = os.fstat(root_fd).st_dev
    counters = {"files": 0, "directories": 0, "bytes": 0, "allocated": 0}

    def visit(directory_fd: int) -> None:
        counters["directories"] += 1
        if counters["directories"] > max_directories:
            raise ScratchQuotaError("candidate scratch inode quota exceeded")
        names: list[str] = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) + counters["files"] + counters["directories"] > (
                    max_files + max_directories
                ):
                    raise ScratchQuotaError("candidate scratch inode quota exceeded")
        for name in names:
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if info.st_dev != root_device:
                continue
            if stat.S_ISDIR(info.st_mode):
                try:
                    child = os.open(name, flags, dir_fd=directory_fd)
                except (FileNotFoundError, NotADirectoryError):
                    continue
                try:
                    visit(child)
                finally:
                    os.close(child)
            else:
                counters["files"] += 1
                if counters["files"] > max_files:
                    raise ScratchQuotaError("candidate scratch inode quota exceeded")
                if stat.S_ISREG(info.st_mode):
                    counters["bytes"] += int(info.st_size)
                    counters["allocated"] += int(info.st_blocks) * 512

    try:
        visit(root_fd)
    finally:
        os.close(root_fd)
    return TreeUsage(
        files=counters["files"], directories=counters["directories"],
        bytes=counters["bytes"], allocated_bytes=counters["allocated"],
        manifest_sha256="",
    )


def _build_reconstruction_archive(workspace: Path, relative: str) -> bytes:
    authority = _validated_relative(relative)
    root = workspace.joinpath(*authority.parts)
    buffer = io.BytesIO()
    try:
        root_info = os.stat(root, follow_symlinks=False)
    except FileNotFoundError:
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT):
            pass
        return buffer.getvalue()
    if not stat.S_ISDIR(root_info.st_mode):
        raise ScratchQuotaError("reconstruction root is unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, flags)
    counters = {"files": 0, "directories": 1, "bytes": 0}
    try:
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
            def add_directory(directory_fd: int, prefix: PurePosixPath) -> None:
                names: list[str] = []
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        names.append(entry.name)
                        if len(names) + counters["files"] + counters["directories"] > (
                            RECONSTRUCTION_MAX_FILES + RECONSTRUCTION_MAX_DIRECTORIES
                        ):
                            raise ScratchQuotaError("reconstruction exceeds entry bounds")
                for name in sorted(names):
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    path = prefix / name
                    if stat.S_ISDIR(info.st_mode):
                        counters["directories"] += 1
                        if counters["directories"] > RECONSTRUCTION_MAX_DIRECTORIES:
                            raise ScratchQuotaError("reconstruction exceeds directory bounds")
                        member = tarfile.TarInfo(path.as_posix())
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o700
                        archive.addfile(member)
                        child = os.open(name, flags, dir_fd=directory_fd)
                        try:
                            add_directory(child, path)
                        finally:
                            os.close(child)
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        raise ScratchQuotaError("reconstruction contains an unsafe entry")
                    counters["files"] += 1
                    counters["bytes"] += int(info.st_size)
                    if counters["files"] > RECONSTRUCTION_MAX_FILES:
                        raise ScratchQuotaError("reconstruction exceeds file bounds")
                    if counters["bytes"] > RECONSTRUCTION_MAX_BYTES:
                        raise ScratchQuotaError("reconstruction exceeds byte bounds")
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(descriptor)
                        if not stat.S_ISREG(opened.st_mode):
                            raise ScratchQuotaError("reconstruction changed during export")
                        member = tarfile.TarInfo(path.as_posix())
                        member.size = int(opened.st_size)
                        member.mode = 0o600
                        with os.fdopen(os.dup(descriptor), "rb") as source:
                            archive.addfile(member, source)
                        after = os.fstat(descriptor)
                        if (
                            after.st_size != opened.st_size
                            or after.st_mtime_ns != opened.st_mtime_ns
                            or after.st_ctime_ns != opened.st_ctime_ns
                        ):
                            raise ScratchQuotaError("reconstruction changed during export")
                    finally:
                        os.close(descriptor)

            add_directory(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    payload = buffer.getvalue()
    if len(payload) > EXPORT_STREAM_MAX_BYTES:
        raise ScratchQuotaError("reconstruction transfer exceeds stream bounds")
    return payload


def _recovery_state_excluded(relative: PurePosixPath) -> bool:
    parts = relative.parts
    if not parts:
        return False
    if parts[0] == "runtime":
        return True
    if parts[0] == "input" or (
        len(parts) >= 2 and parts[0] == "code" and parts[1] == "input"
    ):
        return True
    if any(part.startswith(".angerona-recovery-instructions-") for part in parts):
        return True
    if relative.as_posix() == RECOVERY_DELTA_MANIFEST:
        return True
    if parts[-1] in {
        ".mcp.json", "AGENTS.md", "AGENTS.override.md",
        "CLAUDE.md", "CLAUDE.local.md",
    }:
        return True
    if any(part in {".claude", ".codex"} for part in parts):
        return True
    if len(parts) >= 2 and parts[0] == "raw" and parts[1] in {
        "agent_retries", "context_history",
    }:
        return True
    return False


def _recovery_symlink_logical_target(
    relative: PurePosixPath,
    target: str,
) -> PurePosixPath:
    target_path = PurePosixPath(target)
    if target_path.is_absolute() or not target_path.parts:
        raise ScratchQuotaError("candidate recovery symlink target is unsafe")
    parts = list(relative.parent.parts)
    for component in target_path.parts:
        if component in {"", "."}:
            continue
        if component == "..":
            if not parts:
                raise ScratchQuotaError(
                    "candidate recovery symlink escapes the workspace"
                )
            parts.pop()
            continue
        parts.append(component)
    logical = PurePosixPath(*parts)
    if not logical.parts or _recovery_state_excluded(logical):
        raise ScratchQuotaError("candidate recovery symlink target is protected")
    return logical


def _recovery_tree_state(
    root: Path,
) -> tuple[
    dict[str, tuple[int, str, int]],
    dict[str, str],
    dict[str, int],
]:
    files: dict[str, tuple[int, str, int]] = {}
    symlinks: dict[str, str] = {}
    directories: dict[str, int] = {}
    total_bytes = 0
    root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(root, root_flags)
    try:
        def visit(directory_fd: int, prefix: PurePosixPath) -> None:
            nonlocal total_bytes
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                relative = prefix / name
                if _recovery_state_excluded(relative):
                    continue
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    directories[relative.as_posix()] = stat.S_IMODE(info.st_mode) & 0o777
                    if len(directories) > (
                        SEED_MAX_DIRECTORIES + RECOVERY_STATE_MAX_DIRECTORIES
                    ):
                        raise ScratchQuotaError(
                            "candidate recovery state exceeds directory bounds"
                        )
                    child = os.open(name, root_flags, dir_fd=directory_fd)
                    try:
                        visit(child, relative)
                    finally:
                        os.close(child)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(name, dir_fd=directory_fd)
                    _recovery_symlink_logical_target(relative, target)
                    symlinks[relative.as_posix()] = target
                    if len(files) + len(symlinks) > (
                        SEED_MAX_FILES + RECOVERY_STATE_MAX_FILES
                    ):
                        raise ScratchQuotaError(
                            "candidate recovery state exceeds file bounds"
                        )
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise ScratchQuotaError(
                        "candidate recovery state contains an unsafe entry"
                    )
                if len(files) >= SEED_MAX_FILES + RECOVERY_STATE_MAX_FILES:
                    raise ScratchQuotaError(
                        "candidate recovery state exceeds file bounds"
                    )
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(descriptor)
                    digest = hashlib.sha256()
                    remaining = int(opened.st_size)
                    total_bytes += remaining
                    if total_bytes > SEED_MAX_BYTES + RECOVERY_STATE_MAX_BYTES:
                        raise ScratchQuotaError(
                            "candidate recovery state exceeds byte bounds"
                        )
                    while remaining:
                        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ScratchQuotaError(
                                "candidate recovery state file ended early"
                            )
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if os.read(descriptor, 1):
                        raise ScratchQuotaError(
                            "candidate recovery state file grew during capture"
                        )
                    final = os.fstat(descriptor)
                    if (
                        final.st_size != opened.st_size
                        or final.st_mtime_ns != opened.st_mtime_ns
                        or final.st_ctime_ns != opened.st_ctime_ns
                    ):
                        raise ScratchQuotaError(
                            "candidate recovery state changed during capture"
                        )
                    files[relative.as_posix()] = (
                        int(opened.st_size),
                        digest.hexdigest(),
                        stat.S_IMODE(opened.st_mode) & 0o777,
                    )
                finally:
                    os.close(descriptor)

        visit(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    return files, symlinks, directories


def _build_recovery_delta(
    workspace: Path,
    baseline: tuple[
        dict[str, tuple[int, str, int]],
        dict[str, str],
        dict[str, int],
    ],
) -> bytes:
    baseline_files, baseline_symlinks, baseline_directories = baseline
    current_files, current_symlinks, current_directories = _recovery_tree_state(workspace)
    current_types = {
        **{path: "file" for path in current_files},
        **{path: "symlink" for path in current_symlinks},
        **{path: "directory" for path in current_directories},
    }
    baseline_types = {
        **{path: "file" for path in baseline_files},
        **{path: "symlink" for path in baseline_symlinks},
        **{path: "directory" for path in baseline_directories},
    }
    type_conflicts = sorted(
        path
        for path, expected_type in baseline_types.items()
        if path in current_types and current_types[path] != expected_type
    )
    if type_conflicts:
        raise ScratchQuotaError(
            "candidate recovery state replaced immutable seed entry type"
        )
    changed = sorted(
        path for path in current_files
        if path not in baseline_files
        and path not in baseline_symlinks
        and path not in baseline_directories
    )
    changed_symlinks = sorted(
        path for path in current_symlinks
        if path not in baseline_files
        and path not in baseline_symlinks
        and path not in baseline_directories
    )
    created_directories = {
        path: mode for path, mode in current_directories.items()
        if path not in baseline_directories
        and path not in baseline_files
        and path not in baseline_symlinks
    }
    if (
        len(changed) + len(changed_symlinks) > RECOVERY_STATE_MAX_FILES
        or len(created_directories) > RECOVERY_STATE_MAX_DIRECTORIES
        or sum(current_files[path][0] for path in changed) > RECOVERY_STATE_MAX_BYTES
    ):
        raise ScratchQuotaError("candidate recovery delta exceeds bounds")
    manifest = json.dumps(
        {
            "version": 1,
            "changed": {
                path: {
                    "kind": "file",
                    "size": current_files[path][0],
                    "sha256": current_files[path][1],
                    "mode": current_files[path][2],
                }
                for path in changed
            },
            "symlinks": {
                path: {"kind": "symlink", "target": current_symlinks[path]}
                for path in changed_symlinks
            },
            "directories": created_directories,
            "deleted": [],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        metadata = tarfile.TarInfo(RECOVERY_DELTA_MANIFEST)
        metadata.size = len(manifest)
        metadata.mode = 0o600
        archive.addfile(metadata, io.BytesIO(manifest))
        for relative_text in changed:
            relative = _validated_relative(relative_text)
            path = workspace.joinpath(*relative.parts)
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            try:
                info = os.fstat(descriptor)
                expected_size, expected_sha256, expected_mode = current_files[
                    relative_text
                ]
                if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
                    raise ScratchQuotaError(
                        "candidate recovery delta changed during export"
                    )
                member = tarfile.TarInfo(relative.as_posix())
                member.size = expected_size
                member.mode = expected_mode
                with os.fdopen(os.dup(descriptor), "rb") as source:
                    archive.addfile(member, source)
                os.lseek(descriptor, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != expected_sha256:
                    raise ScratchQuotaError(
                        "candidate recovery delta digest changed during export"
                    )
            finally:
                os.close(descriptor)
    payload = buffer.getvalue()
    if len(payload) > EXPORT_STREAM_MAX_BYTES:
        raise ScratchQuotaError("candidate recovery delta exceeds stream bounds")
    return payload


def _remove_tree_at(parent_fd: int, name: str, *, missing_ok: bool, budget: list[int]) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    budget[0] -= 1
    if budget[0] < 0:
        raise ScratchQuotaError("artifact cleanup exceeds entry bounds")
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        with os.scandir(directory_fd) as iterator:
            names = [entry.name for entry in iterator]
        for child in names:
            _remove_tree_at(directory_fd, child, missing_ok=False, budget=budget)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _open_relative_directory(root_fd: int, parts: tuple[str, ...], *, create: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.dup(root_fd)
    try:
        for component in parts:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            next_fd = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _install_archive(cwd: Path | int, relative: str, payload: bytes) -> None:
    authority = _validated_relative(relative)
    root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.dup(cwd) if isinstance(cwd, int) else os.open(cwd, root_flags)
    parent_fd = -1
    staging_fd = -1
    staging_name = f".{authority.parts[-1]}.scratch-{uuid.uuid4().hex}.tmp"
    backup_name = f".{authority.parts[-1]}.previous-{uuid.uuid4().hex}.tmp"
    target_name = authority.parts[-1]
    had_target = False
    committed = False
    try:
        parent_fd = _open_relative_directory(
            root_fd, tuple(authority.parts[:-1]), create=True
        )
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        staging_fd = os.open(staging_name, root_flags, dir_fd=parent_fd)
        counters = {"files": 0, "directories": 1, "bytes": 0}
        seen: set[str] = set()
        directory_paths: set[str] = {""}
        validated_members: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive:
                path = _validated_relative(member.name)
                normalized = path.as_posix()
                if normalized in seen:
                    raise ScratchQuotaError("artifact stream contains duplicate paths")
                seen.add(normalized)
                if not member.isdir() and (not member.isreg() or member.size < 0):
                    raise ScratchQuotaError("artifact stream contains an unsafe entry")
                for index in range(1, len(path.parts) + (1 if member.isdir() else 0)):
                    directory_paths.add(PurePosixPath(*path.parts[:index]).as_posix())
                    if len(directory_paths) > RECONSTRUCTION_MAX_DIRECTORIES:
                        raise ScratchQuotaError("artifact stream exceeds directory bounds")
                if member.isreg():
                    counters["files"] += 1
                    counters["bytes"] += int(member.size)
                    if counters["files"] > RECONSTRUCTION_MAX_FILES:
                        raise ScratchQuotaError("artifact stream exceeds file bounds")
                    if counters["bytes"] > RECONSTRUCTION_MAX_BYTES:
                        raise ScratchQuotaError("artifact stream exceeds byte bounds")
                validated_members.append((member, path))
                if len(validated_members) > (
                    RECONSTRUCTION_MAX_FILES + RECONSTRUCTION_MAX_DIRECTORIES
                ):
                    raise ScratchQuotaError("artifact stream exceeds entry bounds")

            counters["directories"] = len(directory_paths)
            for member, path in validated_members:
                parent = _open_relative_directory(
                    staging_fd, tuple(path.parts[:-1]), create=True
                )
                try:
                    if member.isdir():
                        try:
                            os.mkdir(path.parts[-1], mode=0o700, dir_fd=parent)
                        except FileExistsError:
                            existing = os.stat(
                                path.parts[-1], dir_fd=parent, follow_symlinks=False
                            )
                            if not stat.S_ISDIR(existing.st_mode):
                                raise ScratchQuotaError("artifact path type conflict")
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise ScratchQuotaError("artifact stream file body is missing")
                    destination = os.open(
                        path.parts[-1],
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=parent,
                    )
                    remaining = int(member.size)
                    try:
                        while remaining:
                            chunk = source.read(min(remaining, 1024 * 1024))
                            if not chunk:
                                raise ScratchQuotaError("artifact stream ended early")
                            remaining -= len(chunk)
                            view = memoryview(chunk)
                            while view:
                                view = view[os.write(destination, view):]
                    finally:
                        os.close(destination)
                        source.close()
                finally:
                    os.close(parent)
        try:
            target = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target = None
        had_target = target is not None
        if had_target:
            if not stat.S_ISDIR(target.st_mode):
                raise ScratchQuotaError("host reconstruction target is unsafe")
            os.rename(
                target_name, backup_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
            )
        try:
            os.rename(
                staging_name, target_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
            )
            committed = True
        except Exception:
            if had_target:
                os.rename(
                    backup_name, target_name,
                    src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                )
            raise
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if parent_fd >= 0:
            budget = [SEED_MAX_FILES + SEED_MAX_DIRECTORIES + 16]
            _remove_tree_at(parent_fd, staging_name, missing_ok=True, budget=budget)
            if committed and had_target:
                budget = [SEED_MAX_FILES + SEED_MAX_DIRECTORIES + 16]
                _remove_tree_at(parent_fd, backup_name, missing_ok=True, budget=budget)
            os.close(parent_fd)
        os.close(root_fd)


def _read_export_frame(read_chunk) -> bytes:
    def read_exact(size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = read_chunk(min(remaining, 1024 * 1024))
            if not chunk:
                raise ScratchQuotaError("candidate artifact stream ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    if read_exact(len(EXPORT_MAGIC)) != EXPORT_MAGIC:
        raise ScratchQuotaError("candidate artifact stream magic is invalid")
    length = struct.unpack("!Q", read_exact(8))[0]
    expected_digest = read_exact(32)
    if length > EXPORT_STREAM_MAX_BYTES:
        raise ScratchQuotaError("candidate artifact stream exceeds bounds")
    payload = read_exact(int(length))
    if hashlib.sha256(payload).digest() != expected_digest:
        raise ScratchQuotaError("candidate artifact stream digest is invalid")
    if read_chunk(1):
        raise ScratchQuotaError("candidate artifact stream has trailing data")
    return payload


def read_export(read_fd: int) -> bytes:
    """Read and validate one bounded scratch-export frame from a descriptor."""

    try:
        return _read_export_frame(lambda size: os.read(read_fd, size))
    finally:
        os.close(read_fd)


def read_export_socket(
    connection: socket.socket, *, timeout: float | None = 2.0
) -> bytes:
    """Read one frame with a deadline so a provider cannot pin the importer."""

    connection.settimeout(timeout)
    return _read_export_frame(connection.recv)


def install_export(cwd: str | Path | int, relative: str, payload: bytes) -> None:
    """Atomically install a previously validated reconstruction archive."""

    root = cwd if isinstance(cwd, int) else Path(cwd).expanduser().absolute()
    _install_archive(root, relative, payload)


def _install_recovery_delta(workspace: Path, payload: bytes) -> None:
    if len(payload) > EXPORT_STREAM_MAX_BYTES:
        raise ScratchQuotaError("candidate recovery delta exceeds stream bounds")
    bodies: dict[str, bytes] = {}
    manifest: dict[str, object] | None = None
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive:
            relative = _validated_relative(member.name)
            normalized = relative.as_posix()
            if normalized in seen or not member.isreg() or member.size < 0:
                raise ScratchQuotaError("candidate recovery delta is malformed")
            seen.add(normalized)
            source = archive.extractfile(member)
            if source is None:
                raise ScratchQuotaError("candidate recovery delta body is missing")
            body = source.read(member.size + 1)
            source.close()
            if len(body) != member.size:
                raise ScratchQuotaError("candidate recovery delta body size mismatch")
            if normalized == RECOVERY_DELTA_MANIFEST:
                try:
                    decoded = json.loads(body)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ScratchQuotaError(
                        "candidate recovery delta manifest is invalid"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise ScratchQuotaError(
                        "candidate recovery delta manifest is invalid"
                    )
                manifest = decoded
            else:
                if _recovery_state_excluded(relative):
                    raise ScratchQuotaError(
                        "candidate recovery delta targets protected state"
                    )
                bodies[normalized] = body
    if manifest is None or manifest.get("version") != 1:
        raise ScratchQuotaError("candidate recovery delta manifest is missing")
    changed = manifest.get("changed")
    symlinks = manifest.get("symlinks")
    directories = manifest.get("directories")
    deleted = manifest.get("deleted")
    if (
        not isinstance(changed, dict)
        or not isinstance(symlinks, dict)
        or not isinstance(directories, dict)
        or not isinstance(deleted, list)
        or set(changed) != set(bodies)
        or len(changed) + len(symlinks) > RECOVERY_STATE_MAX_FILES
        or len(directories) > RECOVERY_STATE_MAX_DIRECTORIES
        or len(deleted) > RECOVERY_STATE_MAX_FILES + RECOVERY_STATE_MAX_DIRECTORIES
        or sum(len(body) for body in bodies.values()) > RECOVERY_STATE_MAX_BYTES
    ):
        raise ScratchQuotaError("candidate recovery delta manifest is inconsistent")
    validated_deleted: list[PurePosixPath] = []
    for value in deleted:
        if not isinstance(value, str):
            raise ScratchQuotaError("candidate recovery deletion path is invalid")
        relative = _validated_relative(value)
        if _recovery_state_excluded(relative):
            raise ScratchQuotaError("candidate recovery deletion targets protected state")
        validated_deleted.append(relative)
    for path, record in changed.items():
        if not isinstance(path, str) or not isinstance(record, dict):
            raise ScratchQuotaError("candidate recovery file record is invalid")
        body = bodies[path]
        if (
            record.get("kind") != "file"
            or
            record.get("size") != len(body)
            or not isinstance(record.get("sha256"), str)
            or hashlib.sha256(body).hexdigest() != record.get("sha256")
            or not isinstance(record.get("mode"), int)
            or isinstance(record.get("mode"), bool)
            or not 0 <= int(record["mode"]) <= 0o777
        ):
            raise ScratchQuotaError("candidate recovery file digest is invalid")
    validated_symlinks: dict[PurePosixPath, str] = {}
    for path, record in symlinks.items():
        if not isinstance(path, str) or not isinstance(record, dict):
            raise ScratchQuotaError("candidate recovery symlink record is invalid")
        relative = _validated_relative(path)
        target = record.get("target")
        if not isinstance(target, str) or record.get("kind") != "symlink":
            raise ScratchQuotaError("candidate recovery symlink record is invalid")
        if _recovery_state_excluded(relative):
            raise ScratchQuotaError("candidate recovery symlink target is unsafe")
        _recovery_symlink_logical_target(relative, target)
        validated_symlinks[relative] = target
    validated_directories: dict[PurePosixPath, int] = {}
    for path, mode in directories.items():
        if (
            not isinstance(path, str)
            or not isinstance(mode, int)
            or isinstance(mode, bool)
            or not 0 <= mode <= 0o777
        ):
            raise ScratchQuotaError("candidate recovery directory record is invalid")
        relative = _validated_relative(path)
        if _recovery_state_excluded(relative):
            raise ScratchQuotaError("candidate recovery directory targets protected state")
        validated_directories[relative] = mode

    root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(workspace, root_flags)
    try:
        budget = [
            SEED_MAX_FILES + SEED_MAX_DIRECTORIES
            + RECOVERY_STATE_MAX_FILES + RECOVERY_STATE_MAX_DIRECTORIES + 32
        ]
        for relative in sorted(
            validated_deleted,
            key=lambda value: (-len(value.parts), value.as_posix()),
        ):
            try:
                parent = _open_relative_directory(
                    root_fd, tuple(relative.parts[:-1]), create=False
                )
            except FileNotFoundError:
                continue
            try:
                _remove_tree_at(
                    parent,
                    relative.parts[-1],
                    missing_ok=True,
                    budget=budget,
                )
            finally:
                os.close(parent)
        for relative, mode in sorted(
            validated_directories.items(),
            key=lambda item: (len(item[0].parts), item[0].as_posix()),
        ):
            parent = _open_relative_directory(
                root_fd, tuple(relative.parts[:-1]), create=True
            )
            try:
                try:
                    os.mkdir(relative.parts[-1], mode=0o700, dir_fd=parent)
                except FileExistsError:
                    info = os.stat(
                        relative.parts[-1], dir_fd=parent, follow_symlinks=False
                    )
                    if not stat.S_ISDIR(info.st_mode):
                        raise ScratchQuotaError(
                            "candidate recovery directory conflicts with seed state"
                        )
            finally:
                os.close(parent)
        for path in sorted(bodies):
            relative = _validated_relative(path)
            parent = _open_relative_directory(
                root_fd, tuple(relative.parts[:-1]), create=True
            )
            target = relative.parts[-1]
            temporary = f".{target}.recovery-{uuid.uuid4().hex}.tmp"
            try:
                _remove_tree_at(
                    parent,
                    target,
                    missing_ok=True,
                    budget=budget,
                )
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent,
                )
                try:
                    os.fchmod(descriptor, int(changed[path]["mode"]))
                    view = memoryview(bodies[path])
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise ScratchQuotaError(
                                "candidate recovery write made no progress"
                            )
                        view = view[written:]
                finally:
                    os.close(descriptor)
                os.rename(
                    temporary,
                    target,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                )
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
                os.close(parent)
        for relative, target_value in sorted(
            validated_symlinks.items(), key=lambda item: item[0].as_posix()
        ):
            parent = _open_relative_directory(
                root_fd, tuple(relative.parts[:-1]), create=True
            )
            try:
                _remove_tree_at(
                    parent,
                    relative.parts[-1],
                    missing_ok=True,
                    budget=budget,
                )
                os.symlink(
                    target_value,
                    relative.parts[-1],
                    dir_fd=parent,
                )
            finally:
                os.close(parent)
        for relative, mode in sorted(
            validated_directories.items(),
            key=lambda item: (-len(item[0].parts), item[0].as_posix()),
        ):
            parent = _open_relative_directory(
                root_fd, tuple(relative.parts[:-1]), create=False
            )
            try:
                os.chmod(
                    relative.parts[-1],
                    mode,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
            finally:
                os.close(parent)
    finally:
        os.close(root_fd)


def receive_export(read_fd: int, cwd: str | Path, relative: str) -> None:
    """Receive one bounded frame and atomically install it."""

    install_export(cwd, relative, read_export(read_fd))


def _install_storage_seccomp() -> None:
    """Deny anonymous file stores that escape the bounded scratch tmpfs."""

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "cannot enable no-new-privileges")
    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    class ScmpArgCmp(ctypes.Structure):
        _fields_ = [
            ("arg", ctypes.c_uint),
            ("op", ctypes.c_int),
            ("datum_a", ctypes.c_uint64),
            ("datum_b", ctypes.c_uint64),
        ]

    seccomp.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
        ctypes.POINTER(ScmpArgCmp),
    ]
    seccomp.seccomp_rule_add_array.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise ScratchQuotaError("cannot allocate candidate seccomp policy")
    try:
        def deny_syscall(name: bytes, error_number: int = errno.ENOSPC) -> None:
            syscall_number = seccomp.seccomp_syscall_resolve_name(name)
            if syscall_number < 0:
                return
            action = 0x00050000 | error_number  # SCMP_ACT_ERRNO(error_number)
            if seccomp.seccomp_rule_add(context, action, syscall_number, 0) != 0:
                raise ScratchQuotaError("cannot construct candidate seccomp policy")

        def deny_argument_equal(
            name: bytes, argument: int, value: int,
            error_number: int = errno.ENOTSUP,
        ) -> None:
            syscall_number = seccomp.seccomp_syscall_resolve_name(name)
            if syscall_number < 0:
                return
            comparison = ScmpArgCmp(argument, 4, value, value)  # SCMP_CMP_EQ
            action = 0x00050000 | error_number
            if seccomp.seccomp_rule_add_array(
                context, action, syscall_number, 1, ctypes.byref(comparison)
            ) != 0:
                raise ScratchQuotaError("cannot protect candidate quota runner")

        for name in (b"memfd_create", b"memfd_secret", b"shmget"):
            deny_syscall(name)
        for name in (
            b"unshare", b"setns", b"mount", b"umount2", b"pivot_root",
            b"fsopen", b"fsconfig", b"fsmount", b"move_mount", b"open_tree",
            b"mount_setattr", b"sendmsg", b"sendmmsg", b"io_uring_setup",
            b"io_uring_register", b"io_setup", b"io_submit",
            b"landlock_create_ruleset", b"landlock_add_rule",
            b"landlock_restrict_self",
        ):
            deny_syscall(name, errno.ENOTSUP)
        # clone3 passes flags through a pointed-to structure, which classic seccomp
        # cannot inspect. ENOSYS makes libc/runtime implementations fall back to
        # legacy clone, whose namespace flags are filtered below.
        deny_syscall(b"clone3", errno.ENOSYS)
        deny_syscall(b"pidfd_getfd", errno.ENOTSUP)
        deny_argument_equal(b"ptrace", 1, 1)
        deny_argument_equal(b"process_vm_readv", 0, 1)
        deny_argument_equal(b"process_vm_writev", 0, 1)
        deny_argument_equal(b"kcmp", 0, 1)
        deny_argument_equal(b"kcmp", 1, 1)
        # The trusted quota runner owns the inherited AF_UNIX broker channels.
        # The provider gets only AF_INET/AF_INET6 access to its private-namespace
        # loopback proxy and cannot open host service or kernel control sockets.
        for family in (
            socket.AF_UNIX,
            getattr(socket, "AF_NETLINK", 16),
            getattr(socket, "AF_PACKET", 17),
            getattr(socket, "AF_VSOCK", 40),
            getattr(socket, "AF_XDP", 44),
        ):
            deny_argument_equal(b"socket", 0, int(family), errno.EACCES)
        clone_number = seccomp.seccomp_syscall_resolve_name(b"clone")
        if clone_number >= 0:
            namespace_flags = (
                0x00000080,  # CLONE_NEWTIME
                0x00020000,  # CLONE_NEWNS
                0x02000000,  # CLONE_NEWCGROUP
                0x04000000,  # CLONE_NEWUTS
                0x08000000,  # CLONE_NEWIPC
                0x10000000,  # CLONE_NEWUSER
                0x20000000,  # CLONE_NEWPID
                0x40000000,  # CLONE_NEWNET
            )
            for flag in namespace_flags:
                comparison = ScmpArgCmp(0, 7, flag, flag)  # SCMP_CMP_MASKED_EQ
                action = 0x00050000 | errno.ENOTSUP
                if seccomp.seccomp_rule_add_array(
                    context, action, clone_number, 1, ctypes.byref(comparison)
                ) != 0:
                    raise ScratchQuotaError("cannot constrain candidate clone flags")
        if seccomp.seccomp_load(context) != 0:
            raise ScratchQuotaError("cannot activate candidate seccomp policy")
    finally:
        seccomp.seccomp_release(context)


def _enforce_hidden_inode_quota(
    max_handles: int,
    scratch_device: int,
    inspection_denials: dict[tuple[int, str], int],
) -> None:
    """Account tmpfs files hidden from tree walks by unlink-while-open."""

    hidden_objects: set[tuple[int, int]] = set()
    denied_this_scan: set[tuple[int, str]] = set()

    def process_starttime(process_entry: Path) -> str | None:
        try:
            raw = (process_entry / "stat").read_text(encoding="ascii")
            fields = raw[raw.rfind(")") + 2:].split()
            if fields[0] in {"Z", "X"}:
                return None
            return fields[19]
        except (FileNotFoundError, ProcessLookupError, IndexError, UnicodeError):
            return None

    def record(link: Path, process_entry: Path, starttime: str) -> None:
        for attempt in range(2):
            try:
                target = os.readlink(link)
                if not target.endswith(" (deleted)") or not (
                    target.startswith("/tmp/") or target.startswith("/dev/shm/")
                ):
                    return
                info = os.stat(link)
                break
            except (FileNotFoundError, ProcessLookupError):
                return
            except PermissionError:
                if process_starttime(process_entry) != starttime:
                    return
                if attempt == 0:
                    time.sleep(0)
                    continue
                denied_this_scan.add((int(process_entry.name), starttime))
                return
        if info.st_dev == scratch_device:
            hidden_objects.add((info.st_dev, info.st_ino))
            if len(hidden_objects) > max_handles:
                raise ScratchQuotaError("candidate hidden inode quota exceeded")

    for process_entry in Path("/proc").iterdir():
        if not process_entry.name.isdigit() or int(process_entry.name) == os.getpid():
            continue
        starttime = process_starttime(process_entry)
        if starttime is None:
            continue
        try:
            descriptors = list((process_entry / "fd").iterdir())
        except (FileNotFoundError, PermissionError):
            continue
        if len(descriptors) > DEFAULT_PROCESS_OPEN_FILES:
            raise ScratchQuotaError("candidate process descriptor quota exceeded")
        for descriptor in descriptors:
            record(descriptor, process_entry, starttime)
        for attempt in range(2):
            try:
                mappings = list((process_entry / "map_files").iterdir())
                break
            except (FileNotFoundError, ProcessLookupError):
                mappings = []
                break
            except PermissionError:
                if process_starttime(process_entry) != starttime:
                    mappings = []
                    break
                if attempt == 0:
                    time.sleep(0)
                    continue
                denied_this_scan.add((int(process_entry.name), starttime))
                mappings = []
                break
        for mapping in mappings:
            record(mapping, process_entry, starttime)
        record(process_entry / "cwd", process_entry, starttime)
    for identity in list(inspection_denials):
        if identity not in denied_this_scan:
            inspection_denials.pop(identity, None)
    for identity in denied_this_scan:
        inspection_denials[identity] = inspection_denials.get(identity, 0) + 1
        if inspection_denials[identity] >= 3:
            raise ScratchQuotaError("candidate hidden inode state is not inspectable")


def _run_provider_isolated(args: argparse.Namespace, command: list[str]) -> int:
    workspace = Path(args.workspace)
    source = Path(args.input_root)
    instruction_masks = tuple(
        _validated_relative(value).as_posix()
        for value in (args.instruction_mask_relative or [])
    )
    if len(set(instruction_masks)) != len(instruction_masks):
        raise ScratchQuotaError("candidate instruction masks contain duplicates")
    baseline = _copy_seed(
        source,
        workspace,
        excluded_paths=instruction_masks,
    )
    if (
        baseline.files != args.seed_files
        or baseline.directories != args.seed_directories
        or baseline.bytes != args.seed_bytes
        or baseline.manifest_sha256 != args.seed_manifest_sha256
    ):
        raise ScratchQuotaError("candidate seed identity changed before execution")

    # Every failed export is cumulative relative to the immutable host seed.
    # A later recovery therefore retains unchanged progress from every earlier
    # failed attempt instead of replacing delta1 with delta2.
    recovery_baseline = _recovery_tree_state(workspace)
    recovery_seed_fd = int(args.recovery_seed_fd)
    recovery_seed_size = int(args.recovery_seed_size)
    recovery_seed_sha256 = str(args.recovery_seed_sha256 or "")
    if recovery_seed_fd < 0:
        if recovery_seed_size != 0 or recovery_seed_sha256:
            raise ScratchQuotaError("candidate recovery seed metadata is incomplete")
    else:
        import fcntl

        if (
            recovery_seed_fd < 3
            or recovery_seed_size < 0
            or recovery_seed_size > EXPORT_STREAM_MAX_BYTES
            or not re.fullmatch(r"[0-9a-f]{64}", recovery_seed_sha256)
        ):
            raise ScratchQuotaError("candidate recovery seed metadata is invalid")
        seed_info = os.fstat(recovery_seed_fd)
        required_seals = (
            getattr(fcntl, "F_SEAL_SEAL", 0x0001)
            | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
            | getattr(fcntl, "F_SEAL_GROW", 0x0004)
            | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        )
        if (
            not stat.S_ISREG(seed_info.st_mode)
            or seed_info.st_size != recovery_seed_size
            or fcntl.fcntl(
                recovery_seed_fd, getattr(fcntl, "F_GET_SEALS", 1034)
            ) & required_seals
            != required_seals
        ):
            raise ScratchQuotaError("candidate recovery seed is not immutable")
        chunks: list[bytes] = []
        remaining = recovery_seed_size
        offset = 0
        while remaining:
            chunk = os.pread(recovery_seed_fd, min(remaining, 1024 * 1024), offset)
            if not chunk:
                raise ScratchQuotaError("candidate recovery seed ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
            offset += len(chunk)
        recovery_payload = b"".join(chunks)
        if hashlib.sha256(recovery_payload).hexdigest() != recovery_seed_sha256:
            raise ScratchQuotaError("candidate recovery seed digest mismatch")
        _install_recovery_delta(workspace, recovery_payload)

    _prepare_runtime_auth(workspace, args.auth_seed)

    scratch_baseline = _live_usage(
        Path("/tmp"),
        max_files=SEED_MAX_FILES + args.write_files + 256,
        max_directories=SEED_MAX_DIRECTORIES + args.write_directories + 256,
    )
    scratch_device = os.stat("/tmp", follow_symlinks=False).st_dev
    # /run is also a writable tmpfs in the K-candidate isolation path (see
    # _workspace_sandbox_command in runtime.py, which now bounds it with
    # --size).  Baseline it too so the monitor can detect a candidate that
    # fills /run to escape the /tmp quota.  (ELITE-2 verdict round-3 fix.)
    run_baseline = _live_usage(
        Path("/run"),
        max_files=SEED_MAX_FILES + args.write_files + 256,
        max_directories=SEED_MAX_DIRECTORIES + args.write_directories + 256,
    ) if os.path.isdir("/run") else None
    quota_hit = threading.Event()
    quota_failure: list[str] = []
    inspection_denials: dict[tuple[int, str], int] = {}
    stop_monitor = threading.Event()
    def preexec() -> None:
        file_size_limit = args.seed_bytes + args.write_bytes
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_limit, file_size_limit))
        open_file_limit = min(
            DEFAULT_PROCESS_OPEN_FILES, max(64, args.write_files + 32)
        )
        resource.setrlimit(resource.RLIMIT_NOFILE, (open_file_limit, open_file_limit))
        _install_storage_seccomp()

    child_env = dict(os.environ)
    child_env.pop("ANGERONA_SCRATCH_EXPORT_FD", None)
    child_env.pop(NETWORK_GATEWAY_ENV, None)
    try:
        trusted_input_fds = tuple(
            int(value) for value in str(args.trusted_input_fds or "").split(",")
            if value
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ScratchQuotaError("trusted candidate inputs are malformed") from exc
    if len(set(trusted_input_fds)) != len(trusted_input_fds) or any(
        descriptor < 3 for descriptor in trusted_input_fds
    ):
        raise ScratchQuotaError("trusted candidate inputs are invalid")
    if trusted_input_fds:
        import fcntl

        required_seals = (
            getattr(fcntl, "F_SEAL_SEAL", 0x0001)
            | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
            | getattr(fcntl, "F_SEAL_GROW", 0x0004)
            | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        )
        for descriptor in trusted_input_fds:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or fcntl.fcntl(
                    descriptor, getattr(fcntl, "F_GET_SEALS", 1034)
                ) & required_seals
                != required_seals
            ):
                raise ScratchQuotaError("trusted candidate input is not immutable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise ScratchQuotaError("cannot protect candidate quota runner process")
    export_channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    export_channel.connect(args.export_socket)
    try:
        child = subprocess.Popen(
            command,
            cwd=args.cwd,
            env=child_env,
            stdin=None,
            stdout=None,
            stderr=None,
            close_fds=True,
            pass_fds=trusted_input_fds,
            start_new_session=True,
            preexec_fn=preexec,
        )
    except Exception:
        export_channel.close()
        raise
    def monitor() -> None:
        while not stop_monitor.wait(0.05):
            try:
                scratch_usage = _live_usage(
                    Path("/tmp"),
                    max_files=scratch_baseline.files + args.write_files,
                    max_directories=scratch_baseline.directories + args.write_directories,
                )
                if (
                    scratch_usage.bytes > scratch_baseline.bytes + args.write_bytes
                ):
                    raise ScratchQuotaError("candidate scratch byte quota exceeded")
                # Also bound /run so a candidate cannot fill it to escape the
                # /tmp quota.  (ELITE-2 verdict round-3 fix.)
                if run_baseline is not None:
                    run_usage = _live_usage(
                        Path("/run"),
                        max_files=run_baseline.files + args.write_files,
                        max_directories=run_baseline.directories + args.write_directories,
                    )
                    if (
                        run_usage.bytes > run_baseline.bytes + args.write_bytes
                    ):
                        raise ScratchQuotaError("candidate /run byte quota exceeded")
                _enforce_hidden_inode_quota(
                    args.write_files, scratch_device, inspection_denials
                )
            except (OSError, ScratchQuotaError) as exc:
                quota_failure.append(f"{type(exc).__name__}: {exc}")
                quota_hit.set()
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    returncode = child.wait()
    stop_monitor.set()
    monitor_thread.join(timeout=2)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    # The provider may daemonize into a new session to escape its process group.
    # The quota runner is PID 1 in a private PID namespace; kill every remaining
    # namespace process before emitting the authoritative final artifact frame.
    for process_entry in Path("/proc").iterdir():
        if not process_entry.name.isdigit():
            continue
        process_id = int(process_entry.name)
        if process_id == os.getpid():
            continue
        try:
            os.kill(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        scratch_usage = _live_usage(
            Path("/tmp"),
            max_files=scratch_baseline.files + args.write_files,
            max_directories=scratch_baseline.directories + args.write_directories,
        )
        if (
            scratch_usage.bytes > scratch_baseline.bytes + args.write_bytes
        ):
            quota_hit.set()
    except (OSError, ScratchQuotaError):
        quota_hit.set()
    if quota_hit.is_set():
        if quota_failure:
            try:
                os.write(
                    2,
                    ("[angerona] scratch monitor rejected candidate: "
                     + quota_failure[-1] + "\n").encode(),
                )
            except OSError:
                pass
        export_channel.close()
        return SCRATCH_QUOTA_EXIT
    payload = (
        _build_reconstruction_archive(Path(args.cwd), args.reconstruction)
        if returncode == 0
        else _build_recovery_delta(workspace, recovery_baseline)
    )
    frame = (
        EXPORT_MAGIC
        + struct.pack("!Q", len(payload))
        + hashlib.sha256(payload).digest()
        + payload
    )
    with export_channel:
        export_channel.sendall(frame)
        export_channel.shutdown(socket.SHUT_WR)
    return returncode if returncode >= 0 else 128 + abs(returncode)


def _run_provider(args: argparse.Namespace, command: list[str]) -> int:
    try:
        network_fds = tuple(int(value) for value in args.network_fds.split(","))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ScratchQuotaError("candidate network channels are malformed") from exc
    try:
        proxy = CandidateLoopbackProxy(network_fds)
        with proxy:
            returncode = _run_provider_isolated(args, command)
        if proxy.violations:
            try:
                os.write(
                    2,
                    (
                        "[angerona] candidate local network proxy rejected "
                        f"{proxy.violations} request(s)\n"
                    ).encode(),
                )
            except OSError:
                pass
            return NETWORK_POLICY_EXIT
        return returncode
    except NetworkPolicyError as exc:
        raise ScratchQuotaError("candidate network proxy could not start") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--reconstruction", required=True)
    parser.add_argument("--export-socket", required=True)
    parser.add_argument("--seed-files", required=True, type=int)
    parser.add_argument("--seed-directories", required=True, type=int)
    parser.add_argument("--seed-bytes", required=True, type=int)
    parser.add_argument("--seed-manifest-sha256", required=True)
    parser.add_argument("--write-bytes", required=True, type=int)
    parser.add_argument("--write-files", required=True, type=int)
    parser.add_argument("--write-directories", required=True, type=int)
    parser.add_argument("--network-fds", required=True)
    parser.add_argument("--trusted-input-fds", default="")
    parser.add_argument("--recovery-seed-fd", default=-1, type=int)
    parser.add_argument("--recovery-seed-size", default=0, type=int)
    parser.add_argument("--recovery-seed-sha256", default="")
    parser.add_argument("--instruction-mask-relative", action="append", default=[])
    parser.add_argument("--auth-seed", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise ScratchQuotaError("candidate provider command is missing")
    try:
        return _run_provider(args, command)
    except (OSError, subprocess.SubprocessError, ScratchQuotaError, tarfile.TarError) as exc:
        try:
            os.write(2, f"[angerona] scratch quota failure: {type(exc).__name__}: {exc}\n".encode())
        except OSError:
            pass
        return SCRATCH_QUOTA_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
