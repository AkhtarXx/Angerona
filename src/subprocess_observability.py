"""Observed host subprocess boundary used outside the model-provider runtime."""

from __future__ import annotations

import ctypes
import hashlib
import os
import signal
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .observability import (
    ObservabilityError,
    capture_tree,
    content_descriptor,
    current_span_id,
    ledger_for_workspace,
    resolve_workspace_root,
)


def bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    """Read a hostile/untrusted environment integer with explicit bounds."""
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def atomic_publish_directory(staging: Path, destination: Path) -> None:
    """Publish a complete evidence tree with no absent-destination window."""
    staging = staging.resolve()
    destination = destination.absolute()
    if staging.parent != destination.parent:
        raise OSError("atomic evidence publish requires a shared parent directory")
    if not staging.is_dir() or staging.is_symlink():
        raise OSError("staged evidence tree must be a real directory")
    if destination.is_symlink():
        raise OSError("refusing to replace symlinked evidence destination")
    if not destination.exists():
        os.replace(staging, destination)
    else:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError("atomic directory exchange is unavailable on this host")
        renameat2.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        rc = renameat2(
            -100, os.fsencode(staging), -100, os.fsencode(destination), 2,
        )
        if rc != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), str(destination))
        # After the exchange, staging names the superseded generation.
        shutil.rmtree(staging, ignore_errors=True)
    directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def persist_bounded_log(source: Path, destination: Path, *, limit: int = 4 * 1024**2) -> dict[str, object]:
    """Persist a bounded diagnostic tail with an integrity digest and 0600 mode."""
    if limit <= 0:
        raise ValueError("log limit must be positive")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        size = source.stat().st_size
        with source.open("rb") as stream:
            if size > limit:
                stream.seek(size - limit)
            data = stream.read(limit)
    except OSError:
        return {"path": "", "sha256": "", "bytes": 0, "truncated": False}
    temporary = destination.with_suffix(destination.suffix + f".{os.getpid()}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "path": str(destination.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "truncated": size > len(data),
    }


@dataclass(frozen=True)
class ProgressRunResult:
    """Result from a subprocess whose durable output is its progress signal."""

    args: Sequence[str | os.PathLike[str]]
    returncode: int
    progress_bytes: int
    progress_items: int
    progress_events: int
    cpu_ticks: int
    peak_rss_bytes: int
    peak_processes: int
    elapsed_seconds: float


class ProgressTimeoutExpired(subprocess.TimeoutExpired):
    """Raised after a progress-aware subprocess becomes idle or hits its ceiling."""

    def __init__(
        self,
        cmd: object,
        timeout: float,
        *,
        reason: str,
        progress_bytes: int,
        progress_items: int,
        progress_events: int,
        cpu_ticks: int,
        elapsed_seconds: float,
    ) -> None:
        super().__init__(cmd, timeout)
        self.reason = reason
        self.progress_bytes = progress_bytes
        self.progress_items = progress_items
        self.progress_events = progress_events
        self.cpu_ticks = cpu_ticks
        self.elapsed_seconds = elapsed_seconds


def _terminate_process_group(process: subprocess.Popen[Any]) -> int:
    """Terminate the exact progress-run process group and reap its leader."""

    if os.name != "posix":
        # Native Windows has no killpg. This is a bounded child-process cleanup;
        # Linux remains required for process-group resource/isolation guarantees.
        if process.poll() is None:
            process.terminate()
        try:
            return int(process.wait(timeout=5))
        except subprocess.TimeoutExpired:
            process.kill()
            return int(process.wait(timeout=5))

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return int(process.wait(timeout=5))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            return int(process.wait(timeout=5))
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"subprocess group leader {process.pid} could not be reaped after SIGKILL"
            ) from exc


def _managed_run(*popenargs: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run`` semantics with an owned, bounded process group.

    Python's stock ``run(timeout=...)`` kills only the immediate child.  Tools
    such as JADX, Apktool and IDA launch JVM/native descendants, so a timed-out
    parent can otherwise leave the expensive analysis running in the
    background.  This helper owns a new session, terminates the whole group and
    always drains/reaps the leader before returning or re-raising.
    """

    input_data = kwargs.pop("input", None)
    capture_output = bool(kwargs.pop("capture_output", False))
    timeout = kwargs.pop("timeout", None)
    check = bool(kwargs.pop("check", False))
    if input_data is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used")
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout/stderr and capture_output may not both be used")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    # Callers cannot place a monitored command into somebody else's group.
    kwargs["start_new_session"] = True
    process = subprocess.Popen(*popenargs, **kwargs)
    try:
        stdout, stderr = process.communicate(input_data, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        stdout, stderr = process.communicate(timeout=5)
        exc.stdout = stdout
        exc.stderr = stderr
        raise exc
    except BaseException:
        # Cancellation (including a test deadline or KeyboardInterrupt) must not
        # abandon a JVM/native child while the parent unwinds.
        if process.poll() is None:
            if os.name == "posix":
                _terminate_process_group(process)
            else:
                process.kill()
                process.wait(timeout=5)
        raise
    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


def _progress_measure(path: Path) -> tuple[int, int, int]:
    """Return monotonic-enough bytes/item/mtime activity for a file or tree."""

    try:
        if path.is_file():
            stat = path.stat()
            return stat.st_size, 1, stat.st_mtime_ns
        if not path.is_dir():
            return 0, 0, 0
    except OSError:
        return 0, 0, 0
    total_bytes = 0
    total_items = 0
    newest_mtime_ns = 0
    try:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    stat = (Path(root) / name).stat()
                except OSError:
                    continue
                total_bytes += stat.st_size
                total_items += 1
                newest_mtime_ns = max(newest_mtime_ns, stat.st_mtime_ns)
    except OSError:
        pass
    return total_bytes, total_items, newest_mtime_ns


def _effective_free_reserve(path: Path, requested: int) -> int:
    """Scale an otherwise impossible reserve on deliberately small filesystems."""

    usage = shutil.disk_usage(path if path.exists() else path.parent)
    if requested > usage.total // 2:
        return min(requested, max(256 * 1024 * 1024, usage.total // 10))
    return requested


def _process_group_cpu_ticks(process_group: int) -> int:
    """Best-effort Linux CPU progress for quiet compute-heavy tool trees."""

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return 0
    total = 0
    try:
        entries = proc_root.iterdir()
    except OSError:
        return 0
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            if len(fields) > 12 and int(fields[2]) == process_group:
                total += int(fields[11]) + int(fields[12])
        except (OSError, ValueError):
            continue
    return total


def _process_group_usage(process_group: int) -> tuple[int, int, int]:
    """Return CPU ticks, resident bytes and process count for one owned group."""

    if os.name != "posix":
        return 0, 0, 0
    ticks = rss_bytes = processes = 0
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        return 0, 0, 0
    page_size = os.sysconf("SC_PAGE_SIZE")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            if len(fields) > 21 and int(fields[2]) == process_group:
                processes += 1
                ticks += int(fields[11]) + int(fields[12])
                rss_bytes += max(0, int(fields[21])) * page_size
        except (OSError, ValueError):
            continue
    return ticks, rss_bytes, processes


def observed_progress_run(
    args: Sequence[str | os.PathLike[str]],
    *,
    progress_path: str | os.PathLike[str],
    idle_timeout: float,
    wall_timeout: float,
    poll_interval: float = 0.25,
    observation_workspace: str | os.PathLike[str] | None = None,
    max_rss_bytes: int | None = None,
    max_processes: int | None = None,
    resource_paths: Sequence[str | os.PathLike[str]] = (),
    max_output_bytes: int | None = None,
    max_output_items: int | None = None,
    min_free_bytes: int | None = None,
    cpu_is_progress: bool = True,
    **popen_kwargs: Any,
) -> ProgressRunResult:
    """Run while output grows; stop only on inactivity or an absolute ceiling.

    ``progress_path`` must be the file receiving the tool's durable output.  A
    growing file resets the idle deadline, which avoids killing large analyses
    merely because their total runtime exceeds a fixed wall-clock timeout.

    ``cpu_is_progress`` (default True) treats a monotonically increasing CPU-tick
    counter as forward progress, which keeps the idle watchdog from killing quiet
    compute-heavy tools (objdump, jadx) that never print progress.  Callers whose
    tool emits an explicit progress heartbeat (e.g. IDA's ``ANGERONA_IDA_PROGRESS``
    on stderr) must pass ``cpu_is_progress=False``: a decompiler stuck mid-pass
    spins the CPU at 100% without ever growing its output, and counting those ticks
    as progress would make the idle timeout unreachable for exactly the pathological
    case it exists to bound.
    """

    if idle_timeout <= 0 or wall_timeout <= 0:
        raise ValueError("progress timeouts must be positive")
    if wall_timeout < idle_timeout:
        raise ValueError("wall_timeout must be greater than or equal to idle_timeout")
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")

    progress = Path(progress_path)
    workspace = _workspace_from_call(
        args,
        cwd=popen_kwargs.get("cwd"),
        env=popen_kwargs.get("env"),
        explicit=observation_workspace,
    )
    ledger = ledger_for_workspace(workspace) if workspace is not None else None
    span = (
        ledger.start_span(
            component="host_subprocess",
            category="subprocess",
            action="progress_run",
            parent_span_id=current_span_id(),
            attributes={
                "command": content_descriptor(str(args)),
                "executable": Path(os.fspath(args[0])).name if args else "",
                "cwd": str(popen_kwargs.get("cwd") or Path.cwd()),
                "idle_timeout_seconds": idle_timeout,
                "wall_timeout_seconds": wall_timeout,
                "progress_path": str(progress),
            },
        )
        if ledger is not None
        else None
    )
    try:
        before = capture_tree(workspace) if workspace is not None else {}
    except (OSError, ObservabilityError) as observation_exc:
        # capture_tree is a DEBUG-ONLY filesystem change-diff for the observability
        # ledger; a large workspace (e.g. accumulated worker dirs) exceeding the
        # tree-file limit must NOT kill the subprocess/disassembly it wraps. Degrade
        # to "no before snapshot" and continue. Opt back into hard-fail with
        # ANGERONA_OBSERVABILITY_TREE_STRICT=1 for debugging.
        if os.environ.get("ANGERONA_OBSERVABILITY_TREE_STRICT") == "1":
            if span is not None:
                span.finish(
                    status="error",
                    attributes={
                        "observation_stage": "initial_tree_capture",
                        "exception": type(observation_exc).__name__,
                    },
                )
            raise
        before = {}
        workspace = None  # disable the after-diff too; no baseline to diff against

    started = time.monotonic()
    last_progress = started
    progress_bytes, progress_items, progress_mtime_ns = _progress_measure(progress)
    progress_events = 0
    last_ledger_progress = started
    process: subprocess.Popen[Any] | None = None
    cpu_ticks = 0
    peak_rss_bytes = 0
    peak_processes = 0
    resource_roots = [Path(item) for item in resource_paths]
    last_resource_check = 0.0
    popen_kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(args, **popen_kwargs)
        cpu_ticks, peak_rss_bytes, peak_processes = _process_group_usage(process.pid)
        while True:
            returncode = process.poll()
            now = time.monotonic()
            current_bytes, current_items, current_mtime_ns = _progress_measure(progress)
            current_cpu_ticks, current_rss_bytes, current_processes = _process_group_usage(
                process.pid
            )
            peak_rss_bytes = max(peak_rss_bytes, current_rss_bytes)
            peak_processes = max(peak_processes, current_processes)
            activity = (
                current_bytes != progress_bytes
                or current_items != progress_items
                or current_mtime_ns > progress_mtime_ns
                or (cpu_is_progress and current_cpu_ticks > cpu_ticks)
            )
            if activity:
                progress_bytes = current_bytes
                progress_items = current_items
                progress_mtime_ns = current_mtime_ns
                cpu_ticks = current_cpu_ticks
                progress_events += 1
                last_progress = now
                if span is not None and now - last_ledger_progress >= 30.0:
                    span.event(
                        "progress",
                        attributes={
                            "progress_bytes": progress_bytes,
                            "progress_items": progress_items,
                            "progress_events": progress_events,
                            "cpu_ticks": cpu_ticks,
                            "elapsed_seconds": round(now - started, 3),
                        },
                    )
                    last_ledger_progress = now
            resource_reason = ""
            if max_rss_bytes is not None and current_rss_bytes > max_rss_bytes:
                resource_reason = "rss-limit"
            elif max_processes is not None and current_processes > max_processes:
                resource_reason = "process-limit"
            if not resource_reason and resource_roots and now - last_resource_check >= 5.0:
                output_bytes = sum(_progress_measure(item)[0] for item in resource_roots)
                output_items = sum(_progress_measure(item)[1] for item in resource_roots)
                if max_output_bytes is not None and output_bytes > max_output_bytes:
                    resource_reason = "output-bytes-limit"
                elif max_output_items is not None and output_items > max_output_items:
                    resource_reason = "output-items-limit"
                elif min_free_bytes is not None:
                    free_checks = [
                        (
                            shutil.disk_usage(item if item.exists() else item.parent).free,
                            _effective_free_reserve(item, min_free_bytes),
                        )
                        for item in resource_roots
                    ]
                    if any(free < reserve for free, reserve in free_checks):
                        resource_reason = "free-space-reserve"
                last_resource_check = now
            if resource_reason:
                _terminate_process_group(process)
                raise ProgressTimeoutExpired(
                    args,
                    now - started,
                    reason=resource_reason,
                    progress_bytes=progress_bytes,
                    progress_items=progress_items,
                    progress_events=progress_events,
                    cpu_ticks=cpu_ticks,
                    elapsed_seconds=now - started,
                )

            # A fast child may create its entire output and exit between two
            # polls. Final resource accounting must therefore precede the
            # successful-exit break; otherwise quotas are trivially bypassed.
            if returncode is not None:
                if resource_roots:
                    output_bytes = sum(
                        _progress_measure(item)[0] for item in resource_roots
                    )
                    output_items = sum(
                        _progress_measure(item)[1] for item in resource_roots
                    )
                    if max_output_bytes is not None and output_bytes > max_output_bytes:
                        raise ProgressTimeoutExpired(
                            args, now - started, reason="output-bytes-limit",
                            progress_bytes=current_bytes,
                            progress_items=current_items,
                            progress_events=progress_events,
                            cpu_ticks=current_cpu_ticks,
                            elapsed_seconds=now - started,
                        )
                    if max_output_items is not None and output_items > max_output_items:
                        raise ProgressTimeoutExpired(
                            args, now - started, reason="output-items-limit",
                            progress_bytes=current_bytes,
                            progress_items=current_items,
                            progress_events=progress_events,
                            cpu_ticks=current_cpu_ticks,
                            elapsed_seconds=now - started,
                        )
                    if min_free_bytes is not None:
                        free_checks = [
                            (
                                shutil.disk_usage(item if item.exists() else item.parent).free,
                                _effective_free_reserve(item, min_free_bytes),
                            )
                            for item in resource_roots
                        ]
                        if any(free < reserve for free, reserve in free_checks):
                            raise ProgressTimeoutExpired(
                                args, now - started, reason="free-space-reserve",
                                progress_bytes=current_bytes,
                                progress_items=current_items,
                                progress_events=progress_events,
                                cpu_ticks=current_cpu_ticks,
                                elapsed_seconds=now - started,
                            )
                break

            elapsed = now - started
            idle = now - last_progress
            reason = ""
            deadline = wall_timeout
            if elapsed >= wall_timeout:
                reason = "wall-timeout"
            elif idle >= idle_timeout:
                reason = "idle-timeout"
                deadline = idle_timeout
            if reason:
                _terminate_process_group(process)
                raise ProgressTimeoutExpired(
                    args,
                    deadline,
                    reason=reason,
                    progress_bytes=progress_bytes,
                    progress_items=progress_items,
                    progress_events=progress_events,
                    cpu_ticks=cpu_ticks,
                    elapsed_seconds=elapsed,
                )
            time.sleep(min(poll_interval, idle_timeout - idle, wall_timeout - elapsed))
    except BaseException as exc:
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
        attributes: dict[str, object] = {
            "exception": type(exc).__name__,
            "timeout_reason": getattr(exc, "reason", ""),
            "progress_bytes": getattr(exc, "progress_bytes", progress_bytes),
            "progress_items": getattr(exc, "progress_items", progress_items),
            "progress_events": getattr(exc, "progress_events", progress_events),
            "cpu_ticks": cpu_ticks,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_processes": peak_processes,
            "elapsed_seconds": round(
                float(getattr(exc, "elapsed_seconds", time.monotonic() - started)), 3
            ),
        }
        if ledger is not None and span is not None and workspace is not None:
            try:
                attributes["filesystem_changes"] = ledger.record_tree_delta(
                    before,
                    capture_tree(workspace),
                    component="host_subprocess",
                    parent_span_id=span.span_id,
                )
            except (OSError, ObservabilityError) as observation_exc:
                attributes["final_observation_error"] = type(observation_exc).__name__
            span.finish(status="error", attributes=attributes)
        raise

    elapsed_seconds = round(time.monotonic() - started, 3)
    result = ProgressRunResult(
        args=args,
        returncode=int(returncode),
        progress_bytes=progress_bytes,
        progress_items=progress_items,
        progress_events=progress_events,
        cpu_ticks=cpu_ticks,
        peak_rss_bytes=peak_rss_bytes,
        peak_processes=peak_processes,
        elapsed_seconds=elapsed_seconds,
    )
    if ledger is not None and span is not None and workspace is not None:
        changes = None
        try:
            after = capture_tree(workspace)
            changes = ledger.record_tree_delta(
                before,
                after,
                component="host_subprocess",
                parent_span_id=span.span_id,
            )
        except (OSError, ObservabilityError) as observation_exc:
            # Same non-fatal observability policy as the before-capture above.
            changes = None
        span.finish(
            status="ok" if result.returncode == 0 else "error",
            attributes={
                "returncode": result.returncode,
                "progress_bytes": result.progress_bytes,
                "progress_items": result.progress_items,
                "progress_events": result.progress_events,
                "cpu_ticks": cpu_ticks,
                "peak_rss_bytes": peak_rss_bytes,
                "peak_processes": peak_processes,
                "elapsed_seconds": result.elapsed_seconds,
                "filesystem_changes": changes,
            },
        )
    return result


def _workspace_from_call(
    command: object,
    *,
    cwd: str | os.PathLike[str] | None,
    env: Mapping[str, str] | None,
    explicit: str | os.PathLike[str] | None,
) -> Path | None:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    source = env or os.environ
    configured = str(source.get("ANGERONA_AGENT_WORKSPACE_ROOT") or "").strip()
    if configured:
        candidates.append(Path(configured))
    if cwd is not None:
        candidates.append(Path(cwd))
    values = command if isinstance(command, Sequence) and not isinstance(command, str) else [command]
    for value in values:
        if not isinstance(value, (str, os.PathLike)):
            continue
        text = os.fspath(value)
        if "=" in text and text.startswith("-"):
            text = text.split("=", 1)[1]
        if text:
            candidates.append(Path(text))
    for candidate in candidates:
        try:
            root = resolve_workspace_root(candidate)
        except (OSError, ValueError):
            continue
        if (root / "run.json").is_file() and all(
            (root / name).is_dir() for name in ("code", "docs", "raw")
        ):
            return root
    return None


def observed_run(*popenargs: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    """Drop-in ``subprocess.run`` with durable audit correlation when in a run."""

    explicit = kwargs.pop("observation_workspace", None)
    command = kwargs.get("args") if "args" in kwargs else (popenargs[0] if popenargs else None)
    workspace = _workspace_from_call(
        command,
        cwd=kwargs.get("cwd"),
        env=kwargs.get("env"),
        explicit=explicit,
    )
    if workspace is None:
        return _managed_run(*popenargs, **kwargs)

    ledger = ledger_for_workspace(workspace)
    span = ledger.start_span(
        component="host_subprocess",
        category="subprocess",
        action="run",
        parent_span_id=current_span_id(),
        attributes={
            "command": content_descriptor(str(command)),
            "executable": (
                Path(os.fspath(command[0])).name
                if isinstance(command, Sequence)
                and not isinstance(command, str)
                and command
                else ""
            ),
            "cwd": str(kwargs.get("cwd") or Path.cwd()),
            "timeout": kwargs.get("timeout"),
            "stdin": content_descriptor(kwargs.get("input")),
        },
    )
    try:
        before = capture_tree(workspace)
    except BaseException as exc:
        span.finish(
            status="error",
            attributes={"observation_stage": "initial_tree_capture", "exception": type(exc).__name__},
        )
        raise
    try:
        result = _managed_run(*popenargs, **kwargs)
    except BaseException as exc:
        attributes: dict[str, object] = {
            "exception": type(exc).__name__,
            "stdout": content_descriptor(getattr(exc, "stdout", None)),
            "stderr": content_descriptor(getattr(exc, "stderr", None)),
        }
        try:
            attributes["filesystem_changes"] = ledger.record_tree_delta(
                before,
                capture_tree(workspace),
                component="host_subprocess",
                parent_span_id=span.span_id,
            )
        except (OSError, ObservabilityError) as observation_exc:
            attributes["final_observation_error"] = type(observation_exc).__name__
        span.finish(status="error", attributes=attributes)
        raise
    changes = None
    try:
        changes = ledger.record_tree_delta(
            before,
            capture_tree(workspace),
            component="host_subprocess",
            parent_span_id=span.span_id,
        )
    except (OSError, ObservabilityError) as observation_exc:
        # Same non-fatal observability policy as the failure path and
        # observed_progress_run: an observation error must not turn a successful
        # subprocess into a crash.
        changes = None
    span.finish(
        status="ok" if int(result.returncode) == 0 else "error",
        attributes={
            "returncode": int(result.returncode),
            "stdout": content_descriptor(result.stdout),
            "stderr": content_descriptor(result.stderr),
            "filesystem_changes": changes,
        },
    )
    return result
