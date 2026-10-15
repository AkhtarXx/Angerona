"""Content-addressed target snapshots shared by every audit backend."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


class TargetSnapshotError(RuntimeError):
    """The target could not be captured as one stable immutable audit input."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stable_identity(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise TargetSnapshotError(f"audit target is not a regular file: {path}")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while size <= initial.st_size:
                chunk = handle.read(min(1024 * 1024, initial.st_size - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > initial.st_size:
                    raise TargetSnapshotError("audit target grew while being captured")
                digest.update(chunk)
        final = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size != initial.st_size or any(
            getattr(initial, field) != getattr(final, field) for field in stable_fields
        ):
            raise TargetSnapshotError("audit target changed while being captured")
        return {"size": size, "sha256": digest.hexdigest()}
    except OSError as exc:
        raise TargetSnapshotError(f"cannot read audit target {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def materialize_audit_target_snapshot(
    binary: str | Path,
    snapshot_dir: str | Path,
    *,
    target_suffix: str = ".bin",
) -> tuple[Path, dict[str, Any]]:
    """Copy exactly one opened target into a durable, read-only digest path.

    The analysis engine only receives the returned path. Replacing the caller's
    original path after this point cannot change the bytes being audited.
    """

    if (
        not target_suffix.startswith(".")
        or len(target_suffix) > 16
        or not target_suffix[1:].isalnum()
    ):
        raise TargetSnapshotError(f"invalid target snapshot suffix: {target_suffix!r}")
    source = Path(binary).expanduser().absolute()
    directory = Path(snapshot_dir).expanduser().absolute()
    for component in (directory, *directory.parents):
        if component.exists() and component.is_symlink():
            raise TargetSnapshotError(
                f"target snapshot directory contains a symlink: {component}"
            )
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise TargetSnapshotError(f"unsafe target snapshot directory: {directory}")

    # A previous successful capture seals this directory. Temporarily make it
    # writable only while holding the workspace's single-audit lease.
    os.chmod(directory, 0o700)
    temporary: Path | None = None
    source_fd: int | None = None
    try:
        for orphan in directory.glob(".target-*.tmp"):
            if orphan.is_symlink() or not orphan.is_file():
                raise TargetSnapshotError(f"unsafe orphan target snapshot: {orphan}")
            orphan.unlink()

        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        initial = os.fstat(source_fd)
        if not stat.S_ISREG(initial.st_mode):
            raise TargetSnapshotError(f"audit target is not a regular file: {source}")
        digest = hashlib.sha256()
        size = 0
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=directory,
            prefix=".target-",
            suffix=".tmp",
            delete=False,
        ) as writer:
            temporary = Path(writer.name)
            with os.fdopen(source_fd, "rb", closefd=False) as reader:
                while size <= initial.st_size:
                    chunk = reader.read(min(1024 * 1024, initial.st_size - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > initial.st_size:
                        raise TargetSnapshotError("audit target grew while being captured")
                    writer.write(chunk)
                    digest.update(chunk)
            final = os.fstat(source_fd)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if size != initial.st_size or any(
                getattr(initial, field) != getattr(final, field) for field in stable_fields
            ):
                raise TargetSnapshotError("audit target changed while being captured")
            writer.flush()
            os.fsync(writer.fileno())

        identity = {"size": size, "sha256": digest.hexdigest()}
        target = directory / f"{identity['sha256']}{target_suffix.lower()}"
        if target.exists():
            if target.is_symlink() or _stable_identity(target) != identity:
                raise TargetSnapshotError("existing target snapshot failed verification")
            temporary.unlink()
            temporary = None
        else:
            os.chmod(temporary, 0o444)
            os.replace(temporary, target)
            temporary = None
        _fsync_directory(directory)
        os.chmod(directory, 0o555)
        _fsync_directory(directory.parent)
        return target, identity
    except TargetSnapshotError:
        raise
    except OSError as exc:
        raise TargetSnapshotError(f"cannot materialize audit target snapshot: {exc}") from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            os.chmod(directory, 0o555)
        except OSError:
            pass
