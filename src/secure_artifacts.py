"""Confined, atomic artifact storage rooted in one trusted workspace directory."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator


def _audit_workspace(root: Path) -> bool:
    return (root / "run.json").is_file() and all(
        (root / name).is_dir() for name in ("code", "docs", "raw")
    )


class SecureArtifactStore:
    """Write files without following attacker-controlled descendant symlinks."""

    def __init__(self, workspace_root: str | Path, relative_dir: str) -> None:
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        relative = PurePosixPath(relative_dir)
        if relative.is_absolute() or not relative.parts or any(
            part in ("", ".", "..") for part in relative.parts
        ):
            raise ValueError("artifact directory must be a non-traversing relative path")
        self.relative_dir = relative
        self.path = self.workspace_root.joinpath(*relative.parts)
        self._dir_fd: int | None = None
        self._open_confined_directory()

    def _open_confined_directory(self) -> None:
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        current_fd = os.open(self.workspace_root, directory_flags)
        try:
            for component in self.relative_dir.parts:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(
                    component,
                    directory_flags | nofollow,
                    dir_fd=current_fd,
                )
                info = os.fstat(next_fd)
                if not stat.S_ISDIR(info.st_mode):
                    os.close(next_fd)
                    raise OSError(f"artifact component is not a directory: {component}")
                try:
                    os.fchmod(next_fd, 0o700)
                except OSError:
                    pass
                os.close(current_fd)
                current_fd = next_fd
            self._dir_fd = current_fd
            current_fd = -1
        finally:
            if current_fd >= 0:
                os.close(current_fd)

    @property
    def dir_fd(self) -> int:
        if self._dir_fd is None:
            raise OSError("artifact store is closed")
        return self._dir_fd

    @staticmethod
    def _validate_filename(filename: str) -> None:
        if not filename or filename in (".", "..") or "/" in filename or "\\" in filename:
            raise ValueError("artifact filename must be one plain path component")

    def file_path(self, filename: str) -> Path:
        self._validate_filename(filename)
        return self.path / filename

    def _observe_mutation(self, action: str, filename: str, data: bytes) -> None:
        # Child observability writes are the telemetry transport itself. Logging
        # those writes would recurse and would incorrectly promote child claims.
        if self.relative_dir.as_posix() == "raw/observability":
            return
        if not _audit_workspace(self.workspace_root):
            return
        from .observability import content_descriptor, ledger_for_workspace

        ledger_for_workspace(self.workspace_root).emit(
            component="artifact_store",
            category="filesystem",
            action=action,
            attributes={
                "path": (self.relative_dir / filename).as_posix(),
                "content": content_descriptor(data),
            },
        )

    def list_names(self) -> list[str]:
        """List plain child names through the already-confined directory handle."""

        return sorted(str(name) for name in os.listdir(self.dir_fd))

    def read_bytes(self, filename: str) -> bytes:
        self._validate_filename(filename)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(filename, flags, dir_fd=self.dir_fd)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("artifact is not a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        finally:
            os.close(descriptor)

    def matches(self, filename: str, data: bytes) -> bool:
        try:
            existing = self.read_bytes(filename)
        except FileNotFoundError:
            return False
        return hashlib.sha256(existing).digest() == hashlib.sha256(data).digest() and existing == data

    def write_bytes_atomic(self, filename: str, data: bytes) -> bool:
        """Install bytes once; return False when identical content already exists."""

        self._validate_filename(filename)
        if self.matches(filename, data):
            return False
        temporary = f".{filename}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=self.dir_fd)
        try:
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.link(
                    temporary,
                    filename,
                    src_dir_fd=self.dir_fd,
                    dst_dir_fd=self.dir_fd,
                    follow_symlinks=False,
                )
                created = True
            except FileExistsError:
                if not self.matches(filename, data):
                    raise OSError(errno.EEXIST, "artifact name exists with different content")
                created = False
            os.fsync(self.dir_fd)
            if created:
                self._observe_mutation("created", filename, data)
            return created
        finally:
            try:
                os.unlink(temporary, dir_fd=self.dir_fd)
            except FileNotFoundError:
                pass

    def replace_bytes_atomic(self, filename: str, data: bytes) -> None:
        """Durably replace one fixed-name metadata file without following links."""

        self._validate_filename(filename)
        temporary = f".{filename}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=self.dir_fd)
        try:
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(
                temporary,
                filename,
                src_dir_fd=self.dir_fd,
                dst_dir_fd=self.dir_fd,
            )
            os.fsync(self.dir_fd)
            self._observe_mutation("replaced", filename, data)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.dir_fd)
            except FileNotFoundError:
                pass

    @contextmanager
    def exclusive_lock(self) -> Iterator[None]:
        """Serialize quota checks and writes across MCP server processes."""

        filename = ".artifact-store.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(filename, flags, 0o600, dir_fd=self.dir_fd)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("artifact-store lock is not a regular file")
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except ImportError:
                pass
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            os.close(descriptor)

    def write_text_atomic(self, filename: str, text: str) -> bool:
        return self.write_bytes_atomic(filename, text.encode("utf-8", errors="surrogatepass"))

    def append_line(self, filename: str, line: str) -> None:
        self._validate_filename(filename)
        payload = (line.rstrip("\n") + "\n").encode("utf-8", errors="backslashreplace")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(filename, flags, 0o600, dir_fd=self.dir_fd)
        try:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except (ImportError, OSError):
                pass
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._observe_mutation("appended", filename, payload)

    def regular_file_bytes(self, *, suffixes: tuple[str, ...] = ()) -> int:
        total = 0
        for name in os.listdir(self.dir_fd):
            if suffixes and not name.endswith(suffixes):
                continue
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(name, flags, dir_fd=self.dir_fd)
            except OSError:
                continue
            try:
                info = os.fstat(descriptor)
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
            finally:
                os.close(descriptor)
        return total

    def regular_file_count(self) -> int:
        total = 0
        for name in os.listdir(self.dir_fd):
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(name, flags, dir_fd=self.dir_fd)
            except OSError:
                continue
            try:
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    total += 1
            finally:
                os.close(descriptor)
        return total

    def regular_file_size(self, filename: str) -> int | None:
        self._validate_filename(filename)
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(filename, flags, dir_fd=self.dir_fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("artifact is not a regular file")
            return info.st_size
        finally:
            os.close(descriptor)

    def close(self) -> None:
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None

    def __enter__(self) -> "SecureArtifactStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass
