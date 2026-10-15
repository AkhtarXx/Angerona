"""IDA Pro headless engine (idalib).

The IDA counterpart of :mod:`src.engines.ghidra`. It drives ``scripts/ida_dump.py``
under a Python that has the ``idapro`` (idalib) module, producing the SAME
structured JSON as the Ghidra engine, with identical on-disk caching and
single-function decompilation. This keeps the whole pipeline (export, overview,
non-agent CLI) engine-agnostic.

Licensing note: idalib validates the IDA license the first time a database is
opened. This engine does not embed, generate, or bypass any license — point it
at a properly licensed IDA install (``IDA_INSTALL_DIR`` / vendored ``vendor/ida*``)
and activate idalib once (``py-activate-idalib.py`` or the ``IDADIR`` env var,
which the engine sets automatically).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import hashlib
from contextlib import contextmanager
from pathlib import Path

from ..subprocess_observability import (
    ProgressTimeoutExpired,
    bounded_env_int,
    observed_progress_run,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

from ..config import Config, load_config
from ..analysis.native_range_authority import validate_launch_authority
from .ghidra import EngineError, RunResult, _binary_key

_IDA_CACHE_SCHEMA = 2


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _timeout_text(value: str | bytes | None) -> str:
    """Normalize TimeoutExpired output, which stays bytes even with text=True."""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


class IdaEngine:
    def __init__(self, config: Config | None = None):
        self.config = config or load_config("ida")
        self._native_authority: dict | None = None
        self._native_launch_authority_token: str | None = None

    def configure_native_authority(self, authority: dict, authority_token: str) -> None:
        if self._native_authority is not None:
            raise EngineError("IDA native launch authority is already configured")
        try:
            validate_launch_authority(authority, authority_token)
        except ValueError as exc:
            raise EngineError(str(exc)) from exc
        self._native_authority = authority
        self._native_launch_authority_token = authority_token

    def _require_native_token(self, token: str | None) -> None:
        if self._native_authority is None:
            if token is not None:
                raise EngineError("IDA native token supplied without configured authority")
            return
        if token != self._native_launch_authority_token:
            raise EngineError("IDA native launch authority token mismatch")

    def _producer_contract(self, *, tag: str) -> tuple[str, dict]:
        components = []
        # Include the idat/Solana route producers (the idat binary, the idat dump
        # script, and the Solana loader) alongside the idalib route so a change
        # to either producer invalidates cached evidence for the route that
        # consumes it.
        solana_loader = (
            self.config.ida_install / "loaders" / "solana_sbf.py"
            if self.config.ida_install else None
        )
        for path in (
            self._dump_script,
            self._idat_dump_script,
            self.config.ida_mcp_python,
            self.config.libidalib,
            self.config.idat,
            solana_loader,
        ):
            if path is None:
                continue
            resolved = Path(path).resolve()
            try:
                stat = resolved.stat()
                digest = _sha256_file(resolved)
            except OSError:
                stat = None
                digest = ""
            components.append({
                "path": str(resolved),
                "bytes": stat.st_size if stat is not None else 0,
                "sha256": digest,
            })
        contract = {
            "schema": _IDA_CACHE_SCHEMA,
            "engine": "ida-pro-idalib",
            "tag": tag,
            "components": components,
            "semantic_policy": {
                "all_functions": tag.endswith("_all"),
                "max_decompiled_chars": os.environ.get(
                    "ANGERONA_IDA_MAX_DECOMPILED_CHARS", "60000"
                ),
                "max_disasm": os.environ.get("ANGERONA_IDA_MAX_DISASM", "6000"),
                "max_refs": os.environ.get("ANGERONA_IDA_MAX_REFS", "200"),
            },
        }
        encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest(), contract

    def producer_contract_sha256(
        self, *, decompile: bool = False, max_functions: int = 0
    ) -> str:
        """Return the current producer identity used to validate durable evidence."""

        tag = (
            f"full_{max_functions if max_functions > 0 else 'all'}"
            if decompile else "meta"
        )
        digest, _contract = self._producer_contract(tag=tag)
        return digest

    # ------------------------------------------------------------------ status

    def status(self) -> dict:
        ok, msg = self.config.ida_ready()
        return {
            "ready": ok,
            "message": msg,
            "engine": "ida",
            "ida_install": str(self.config.ida_install) if self.config.ida_install else None,
            "idalib": str(self.config.libidalib) if self.config.libidalib else None,
            "ida_mcp_python": str(self.config.ida_mcp_python) if self.config.ida_mcp_python else None,
            "idalib_activated": self.config.ida_activated(),
            "scripts_dir": str(self.config.scripts_dir),
            "state_dir": str(self.config.state_dir),
            "note": ("idalib resolves the install via IDADIR (auto-set by this engine at "
                     "launch). A valid IDA Pro license is required the first time a database "
                     "is opened; this tool neither ships nor bypasses any license."),
        }

    def _require_ready(self) -> None:
        ok, msg = self.config.ida_ready()
        if not ok:
            raise EngineError(msg)

    # ---------------------------------------------------------------- internals

    @property
    def _dump_script(self) -> Path:
        return self.config.scripts_dir / "ida_dump.py"

    @property
    def _idat_dump_script(self) -> Path:
        return self.config.scripts_dir / "ida_idat_dump.py"

    def _ida_site_packages(self) -> list[Path]:
        if not self.config.ida_mcp_python:
            return []
        # ``venv/bin/python`` can be a symlink to a shared interpreter.  Use the
        # configured path itself so packages installed into the venv (notably
        # rust_demangler for the Solana processor) stay visible to IDAPython.
        venv = self.config.ida_mcp_python.parent.parent
        return sorted((venv / "lib").glob("python*/site-packages"))

    def _idat_env(self, out_json: Path, mode: str, max_functions: int, func: str | None = None) -> dict[str, str]:
        env = self.config.ida_env()
        env["TVHEADLESS"] = "1"
        env["ANGERONA_IDA_LOCK_FILE"] = str(self._ida_lock_path())
        env["ANGERONA_IDA_IDAT_OUT"] = str(out_json)
        env["ANGERONA_IDA_IDAT_MODE"] = mode
        env["ANGERONA_IDA_IDAT_MAX_FUNCTIONS"] = str(max_functions)
        env["ANGERONA_IDA_IDAT_PROCESSOR"] = "EBPF"
        if func:
            env["ANGERONA_IDA_IDAT_FUNCTION"] = func

        pythonpath: list[str] = []
        if self.config.ida_install:
            pythonpath.append(str(self.config.ida_install / "procs"))
        pythonpath.extend(str(path) for path in self._ida_site_packages())
        if env.get("PYTHONPATH"):
            pythonpath.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(pythonpath)
        return env

    def _ida_lock_path(self) -> Path:
        lock_dir = self.config.state_dir / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        return lock_dir / "ida.lock"

    @contextmanager
    def _ida_host_lock(self, *, timeout: float | None = None):
        """Serialize host IDA/idalib entrypoints across parallel agents."""
        lock_path = self._ida_lock_path()
        with lock_path.open("a+") as fh:
            if fcntl is not None:
                started = time.monotonic()
                while True:
                    try:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if timeout is not None and time.monotonic() - started >= timeout:
                            raise EngineError(
                                f"timed out after {timeout:.1f}s waiting for the IDA host lock"
                            )
                        time.sleep(0.5)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _run_dump(
        self,
        args: list[str],
        timeout: int | float | None,
        ro_binds: list[Path] | None = None,
        deadline_monotonic: float | None = None,
    ) -> RunResult:
        assert self.config.ida_mcp_python is not None
        cmd = [str(self.config.ida_mcp_python), str(self._dump_script), *args]
        if self.config.sandbox:
            from ..analysis import sandbox
            from ..config import REPO_ROOT
            if not sandbox.available():
                raise EngineError(
                    "sandbox requested (ANGERONA_SANDBOX=1) but 'bwrap' is not installed. "
                    "Install bubblewrap (`sudo apt-get install -y bubblewrap`) or disable sandbox."
                )
            ro: list[Path] = [REPO_ROOT]
            if self.config.ida_install:
                ro.append(self.config.ida_install)
            if self.config.ida_mcp_python:
                ro.append(self.config.ida_mcp_python.resolve().parent.parent)  # the venv
            ro += list(ro_binds or [])
            cmd = sandbox.wrap(cmd, writable_dirs=[self.config.state_dir], readonly_binds=ro)
        start = time.monotonic()
        output_path = Path(args[1]).resolve()
        stdout_path = output_path.with_suffix(output_path.suffix + ".stdout.partial")
        stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.partial")
        requested = float(timeout or 0)
        idle_timeout = max(900.0, requested) if requested else 900.0
        # ida_dump.py's per-function soft-cancel watchdog fires at 900s, and the
        # ANGERONA_IDA_PROGRESS heartbeat is emitted once every 25 functions.  A
        # slow-but-interruptible function soft-cancelled at 900s needs a short grace
        # window to emit its next heartbeat before the output-only idle watchdog
        # (cpu_is_progress=False below) hard-kills the process.  Without this grace,
        # the idle watchdog could SIGKILL a process that was about to recover.
        idle_timeout += 300.0
        try:
            wall_timeout = float(os.environ.get("ANGERONA_IDA_WALL_TIMEOUT_SECONDS", "86400"))
        except ValueError:
            wall_timeout = 86_400.0
        wall_timeout = max(idle_timeout, min(wall_timeout, 172_800.0))
        if deadline_monotonic is not None:
            remaining = max(0.001, deadline_monotonic - time.monotonic())
            wall_timeout = min(wall_timeout, remaining)
            idle_timeout = min(idle_timeout, wall_timeout)
        try:
            env = self.config.ida_env()
            env["ANGERONA_IDA_LOCK_FILE"] = str(self._ida_lock_path())
            with self._ida_host_lock(timeout=wall_timeout):
                with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                    proc = observed_progress_run(
                        cmd,
                        progress_path=stderr_path,
                        idle_timeout=idle_timeout,
                        wall_timeout=wall_timeout,
                        poll_interval=1.0,
                        cpu_is_progress=False,
                        stdout=stdout,
                        stderr=stderr,
                        stdin=subprocess.DEVNULL,
                        env=env,
                        max_rss_bytes=bounded_env_int(
                            "ANGERONA_IDA_MAX_RSS_MB", 8192,
                            minimum=1024, maximum=32768,
                        ) * 1024 * 1024,
                        max_processes=bounded_env_int(
                            "ANGERONA_IDA_MAX_PROCESSES", 128,
                            minimum=8, maximum=1024,
                        ),
                        resource_paths=[output_path, stdout_path, stderr_path],
                        max_output_bytes=bounded_env_int(
                            "ANGERONA_IDA_MAX_OUTPUT_GIB", 8,
                            minimum=1, maximum=128,
                        ) * 1024**3,
                        min_free_bytes=bounded_env_int(
                            "ANGERONA_ANDROID_MIN_FREE_GIB", 8,
                            minimum=1, maximum=128,
                        ) * 1024**3,
                    )
        except ProgressTimeoutExpired as exc:
            stdout_text = stdout_path.read_text(errors="replace")[-2000:] if stdout_path.exists() else ""
            stderr_text = stderr_path.read_text(errors="replace")[-2000:] if stderr_path.exists() else ""
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
            return RunResult(
                False,
                stdout_text,
                stderr_text + (
                    f"\n[{exc.reason} after {exc.elapsed_seconds:.1f}s; "
                    f"progress_bytes={exc.progress_bytes}; cpu_ticks={exc.cpu_ticks}]"
                ),
                124,
                time.monotonic() - start,
            )
        stdout_text = stdout_path.read_text(errors="replace")[-2000:] if stdout_path.exists() else ""
        stderr_text = stderr_path.read_text(errors="replace")[-2000:] if stderr_path.exists() else ""
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        return RunResult(
            proc.returncode == 0,
            stdout_text,
            stderr_text,
            proc.returncode,
            time.monotonic() - start,
        )

    def _run_idat_dump(
        self,
        binary: Path,
        out_json: Path,
        log_file: Path,
        *,
        mode: str,
        max_functions: int,
        timeout: int | float | None,
        func: str | None = None,
        deadline_monotonic: float | None = None,
    ) -> RunResult:
        if self.config.idat is None:
            raise EngineError("IDA idat executable not found; cannot run Solana custom loader")
        loader = self.config.ida_install / "loaders" / "solana_sbf.py" if self.config.ida_install else None
        if loader is None or not loader.is_file():
            raise EngineError("IDA Solana loader missing: expected loaders/solana_sbf.py")

        db_dir = Path(tempfile.mkdtemp(prefix=f"{out_json.stem}-idat-", dir=out_json.parent))
        db_path = db_dir / "analysis.i64"
        cmd = [
            str(self.config.idat),
            f"-L{log_file}",
            "-A",
            "-TSolana SBF/eBPF ELF",
            f"-S{self._idat_dump_script}",
            f"-o{db_path}",
            str(binary),
        ]
        start = time.monotonic()
        requested = float(timeout or 0)
        idle_timeout = max(900.0, requested) if requested else 900.0
        try:
            wall_timeout = float(os.environ.get("ANGERONA_IDA_WALL_TIMEOUT_SECONDS", "86400"))
        except ValueError:
            wall_timeout = 86_400.0
        wall_timeout = max(idle_timeout, min(wall_timeout, 172_800.0))
        if deadline_monotonic is not None:
            remaining = max(0.001, deadline_monotonic - time.monotonic())
            wall_timeout = min(wall_timeout, remaining)
            idle_timeout = min(idle_timeout, wall_timeout)
        stdout_path = out_json.with_suffix(out_json.suffix + ".idat.stdout.partial")
        stderr_path = out_json.with_suffix(out_json.suffix + ".idat.stderr.partial")
        try:
            try:
                with self._ida_host_lock(timeout=wall_timeout):
                    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                        proc = observed_progress_run(
                            cmd,
                            progress_path=log_file,
                            idle_timeout=idle_timeout,
                            wall_timeout=wall_timeout,
                            poll_interval=1.0,
                            stdout=stdout,
                            stderr=stderr,
                            stdin=subprocess.DEVNULL,
                            env=self._idat_env(out_json, mode, max_functions, func),
                            max_rss_bytes=bounded_env_int(
                                "ANGERONA_IDA_MAX_RSS_MB", 8192,
                                minimum=1024, maximum=32768,
                            ) * 1024 * 1024,
                            max_processes=bounded_env_int(
                                "ANGERONA_IDA_MAX_PROCESSES", 128,
                                minimum=8, maximum=1024,
                            ),
                            resource_paths=[db_dir, out_json, log_file],
                            max_output_bytes=bounded_env_int(
                                "ANGERONA_IDA_MAX_OUTPUT_GIB", 8,
                                minimum=1, maximum=128,
                            ) * 1024**3,
                            min_free_bytes=bounded_env_int(
                                "ANGERONA_ANDROID_MIN_FREE_GIB", 8,
                                minimum=1, maximum=128,
                            ) * 1024**3,
                        )
            except ProgressTimeoutExpired as exc:
                timed_out = RunResult(
                    False,
                    stdout_path.read_text(errors="replace")[-2000:]
                    if stdout_path.exists() else "",
                    (
                        stderr_path.read_text(errors="replace")[-2000:]
                        if stderr_path.exists() else ""
                    ) + (
                        f"\n[{exc.reason} after {exc.elapsed_seconds:.1f}s; "
                        f"progress_bytes={exc.progress_bytes}; cpu_ticks={exc.cpu_ticks}]"
                    ),
                    124,
                    time.monotonic() - start,
                )
                stdout_path.unlink(missing_ok=True)
                stderr_path.unlink(missing_ok=True)
                return timed_out
        finally:
            shutil.rmtree(db_dir, ignore_errors=True)
        stdout_text = stdout_path.read_text(errors="replace")[-2000:] if stdout_path.exists() else ""
        stderr_text = stderr_path.read_text(errors="replace")[-2000:] if stderr_path.exists() else ""
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        ok = proc.returncode == 0 or out_json.exists()
        return RunResult(ok, stdout_text, stderr_text, proc.returncode, time.monotonic() - start)

    def _cache_dir_for(self, key: str) -> Path:
        d = self.config.cache_dir / key
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _staged_input(self, binary: Path, cache_dir: Path) -> Path:
        """Create an isolated writable input for one idalib invocation.

        idalib can leave an ``.i64`` beside the sample even when the caller asks
        not to save. Reusing that directory made later force-runs fail with
        ``open_database rc=4``. A unique staging directory also prevents two
        callers from racing over the same database files.
        """
        staging_root = cache_dir / "input"
        staging_root.mkdir(parents=True, exist_ok=True)
        dest_dir = Path(tempfile.mkdtemp(prefix=f"{binary.name}-", dir=staging_root))
        dest = dest_dir / binary.name
        try:
            shutil.copy2(binary, dest)
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise EngineError(f"failed to stage sample for idalib: {exc}")
        return dest

    # ------------------------------------------------------------------- analyze

    def analyze(
        self,
        binary: str | Path,
        *,
        decompile: bool = False,
        max_functions: int = 0,
        force: bool = False,
        timeout: int | None = None,
        deadline_monotonic: float | None = None,
        allowed_ranges: list[dict] | None = None,
        range_authority_sha256: str | None = None,
        native_authority_token: str | None = None,
    ) -> dict:
        """Open + auto-analyze a binary with idalib, returning the structured JSON dump.

        Cached on disk (engine-namespaced) keyed by content hash. ``decompile=True``
        also embeds decompiled C for functions (bounded by ``max_functions``).
        """
        self._require_ready()
        self._require_native_token(native_authority_token)
        binary = Path(binary).expanduser().resolve()
        if not binary.exists():
            raise EngineError(f"binary not found: {binary}")

        restricted = allowed_ranges is not None or range_authority_sha256 is not None
        if restricted and self._native_authority is None:
            raise EngineError("IDA restricted analysis requires configured centralized authority")
        if self._native_authority is not None:
            expected_restricted = self._native_authority.get("analysis_scope") == "selective_ranges"
            if restricted != expected_restricted:
                raise EngineError("generic IDA analyze cannot bypass configured native authority")
            if restricted and (
                allowed_ranges != self._native_authority.get("allowed_executable_ranges")
                or range_authority_sha256 != self._native_authority.get("range_authority_sha256")
            ):
                raise EngineError("IDA restricted parameters differ from signed authority")
        if restricted:
            if (
                not allowed_ranges or not range_authority_sha256
                or len(range_authority_sha256) != 64
            ):
                raise EngineError("IDA restricted mode requires signed allowed ranges")
            normalized_ranges = sorted(
                (int(row["address"]), int(row["size"])) for row in allowed_ranges
                if isinstance(row, dict) and int(row.get("size") or 0) > 0
            )
            if len(normalized_ranges) != len(allowed_ranges):
                raise EngineError("IDA restricted range queue is malformed")
        else:
            normalized_ranges = []
        key = _binary_key(binary)
        if restricted:
            key = f"{key}__restricted_{range_authority_sha256}"
        cache_dir = self._cache_dir_for(key)
        tag = (
            f"full_{max_functions if max_functions > 0 else 'all'}"
            if decompile else "meta"
        )
        if restricted:
            tag = f"restricted_{range_authority_sha256}"
        cache_file = cache_dir / f"analysis_ida_{tag}.json"
        receipt_file = cache_file.with_suffix(cache_file.suffix + ".receipt.json")
        target_sha256 = _sha256_file(binary)
        target_size = binary.stat().st_size
        producer_contract_sha256, producer_contract = self._producer_contract(tag=tag)

        if cache_file.exists() and receipt_file.exists() and not force:
            try:
                receipt = json.loads(receipt_file.read_text())
                evidence_sha256 = _sha256_file(cache_file)
                data = json.loads(cache_file.read_text())
                metadata_sha256 = str(data.get("metadata", {}).get("sha256") or "").lower()
                valid_receipt = bool(
                    receipt.get("schema_version") == _IDA_CACHE_SCHEMA
                    and receipt.get("status") == "complete"
                    and receipt.get("target_sha256") == target_sha256
                    and receipt.get("target_bytes") == target_size
                    and receipt.get("producer_contract_sha256")
                    == producer_contract_sha256
                    and receipt.get("evidence_sha256") == evidence_sha256
                    and receipt.get("evidence_bytes") == cache_file.stat().st_size
                    and metadata_sha256 == target_sha256
                    and receipt.get("native_launch_authority_token") == native_authority_token
                    and receipt.get("partition_sha256") == (
                        self._native_authority or {}
                    ).get("partition_sha256")
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                valid_receipt = False
                data = {}
            if valid_receipt:
                data["_cache"] = str(cache_file)
                data["_cache_receipt"] = str(receipt_file)
                data["_producer_contract_sha256"] = producer_contract_sha256
                data["_cached"] = True
                return data

        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            raise EngineError("aggregate pre-AI deadline exhausted before IDA launch")

        mode_args = ["full", str(max_functions)] if decompile else ["meta"]
        if restricted:
            range_spec = ",".join(
                f"0x{start:x}:{size}" for start, size in normalized_ranges
            )
            mode_args = [
                "restricted", range_spec, str(range_authority_sha256),
                str(native_authority_token),
            ]
        staged = self._staged_input(binary, cache_dir)
        if decompile and max_functions <= 0 and not restricted:
            # Honor "0 = ALL" like the Ghidra engine (no silent truncation).
            mode_args = ["full", "0"]
        args = [str(staged), str(cache_file), *mode_args]
        # Never accept a stale cache artifact as the result of a failed rerun.
        cache_file.unlink(missing_ok=True)
        receipt_file.unlink(missing_ok=True)
        process_timeout = (
            None if timeout == 0
            else timeout if timeout is not None
            else self.config.analysis_timeout + 300
        )
        use_solana_idat = False
        try:
            from src.solana.adapters import is_solana_elf

            use_solana_idat = is_solana_elf(binary)
        except Exception:
            use_solana_idat = False

        if use_solana_idat:
            shutil.rmtree(staged.parent, ignore_errors=True)
            log_file = cache_dir / "ida_solana_idat.log"
            result = self._run_idat_dump(
                binary,
                cache_file,
                log_file,
                mode=mode_args[0],
                max_functions=int(mode_args[1]) if len(mode_args) > 1 else 0,
                timeout=process_timeout,
                deadline_monotonic=deadline_monotonic,
            )
            if not cache_file.exists():
                raise EngineError(
                    f"IDA Solana analysis failed (rc={result.returncode}, output_exists=False).\n"
                    f"log tail:\n{log_file.read_text(errors='ignore')[-2000:] if log_file.exists() else ''}\n"
                    f"stderr tail:\n{result.stderr[-2000:]}"
                )
            data = json.loads(cache_file.read_text())
            if str(data.get("metadata", {}).get("sha256") or "").lower() != target_sha256:
                cache_file.unlink(missing_ok=True)
                raise EngineError("IDA output input SHA-256 does not match the analyzed binary")
            _atomic_json(receipt_file, {
                "schema_version": _IDA_CACHE_SCHEMA,
                "status": "complete",
                "target_sha256": target_sha256,
                "target_bytes": target_size,
                "producer_contract_sha256": producer_contract_sha256,
                "producer_contract": producer_contract,
                "evidence_sha256": _sha256_file(cache_file),
                "evidence_bytes": cache_file.stat().st_size,
            })
            sandbox_note = "SANDBOXED via bwrap (no network, read-only host)" if self.config.sandbox else "not sandboxed"
            (cache_dir / "ida_headless.log").write_text(
                f"# isolation: {sandbox_note}\n"
                f"# route: idat Solana custom loader\n"
                f"# idat_rc: {result.returncode}\n"
                f"# idat_log: {log_file}\n\n"
                f"=== STDOUT ===\n{result.stdout}\n\n=== STDERR ===\n{result.stderr}\n\n"
                f"=== IDA LOG TAIL ===\n{log_file.read_text(errors='ignore')[-6000:] if log_file.exists() else ''}"
            )
            data["_cache"] = str(cache_file)
            data["_cache_receipt"] = str(receipt_file)
            data["_producer_contract_sha256"] = producer_contract_sha256
            data["_cached"] = False
            data["_seconds"] = round(result.seconds, 1)
            data["_route"] = "ida-idat-solana-loader"
            data["_idat_returncode"] = result.returncode
            return data

        try:
            result = self._run_dump(
                args, process_timeout, deadline_monotonic=deadline_monotonic
            )
        finally:
            shutil.rmtree(staged.parent, ignore_errors=True)
        if not result.ok or not cache_file.exists():
            raise EngineError(
                f"IDA analysis failed (rc={result.returncode}, output_exists={cache_file.exists()}).\n"
                f"IDA user state: {self.config.ida_env().get('IDAUSR', '<unset>')}\n"
                f"stdout tail:\n{result.stdout[-2000:]}\n"
                f"stderr tail:\n{result.stderr[-2000:]}"
            )
        data = json.loads(cache_file.read_text())
        if str(data.get("metadata", {}).get("sha256") or "").lower() != target_sha256:
            cache_file.unlink(missing_ok=True)
            raise EngineError("IDA output input SHA-256 does not match the analyzed binary")
        if restricted and (
            data.get("analysis_scope") != "selective_ranges"
            or data.get("range_authority_sha256") != range_authority_sha256
            or data.get("native_launch_authority_token") != native_authority_token
        ):
            cache_file.unlink(missing_ok=True)
            raise EngineError("IDA restricted output range authority mismatch")
        _atomic_json(receipt_file, {
            "schema_version": _IDA_CACHE_SCHEMA,
            "status": "complete",
            "target_sha256": target_sha256,
            "target_bytes": target_size,
            "producer_contract_sha256": producer_contract_sha256,
            "producer_contract": producer_contract,
            "evidence_sha256": _sha256_file(cache_file),
            "evidence_bytes": cache_file.stat().st_size,
            "native_launch_authority_token": native_authority_token,
            "partition_sha256": (self._native_authority or {}).get("partition_sha256"),
        })
        sandbox_note = "SANDBOXED via bwrap (no network, read-only host)" if self.config.sandbox else "not sandboxed"
        (cache_dir / "ida_headless.log").write_text(
            f"# isolation: {sandbox_note}\n$ {self.config.ida_mcp_python} {self._dump_script} {' '.join(args)}\n\n"
            f"=== STDOUT ===\n{result.stdout}\n\n=== STDERR ===\n{result.stderr}"
        )
        data["_cache"] = str(cache_file)
        data["_cache_receipt"] = str(receipt_file)
        data["_producer_contract_sha256"] = producer_contract_sha256
        data["_cached"] = False
        data["_seconds"] = round(result.seconds, 1)
        return data

    def decompile_function(
        self, binary: str | Path, name_or_addr: str, *, timeout: int = 300,
        native_authority_token: str | None = None,
    ) -> dict:
        """Decompile + disassemble a single function via idalib."""
        self._require_ready()
        self._require_native_token(native_authority_token)
        if self._native_authority is not None:
            raise EngineError("generic IDA decompile is forbidden under native authority")
        binary = Path(binary).expanduser().resolve()
        if not binary.exists():
            raise EngineError(f"binary not found: {binary}")
        key = _binary_key(binary)
        cache_dir = self._cache_dir_for(key)
        staged = self._staged_input(binary, cache_dir)
        safe = "".join(c if c.isalnum() else "_" for c in name_or_addr)[:80]
        out_json = cache_dir / f"ida_func_{safe}.json"
        args = [str(staged), str(out_json), "function", name_or_addr]
        # Never accept a stale artifact as the result of a failed rerun.
        out_json.unlink(missing_ok=True)
        try:
            result = self._run_dump(args, timeout)
        finally:
            shutil.rmtree(staged.parent, ignore_errors=True)
        if not result.ok or not out_json.exists():
            raise EngineError(
                f"IDA decompile failed (rc={result.returncode}, output_exists={out_json.exists()}).\n"
                f"stderr tail:\n{result.stderr[-1500:]}"
            )
        return json.loads(out_json.read_text())

    # ------------------------------------------------------- cached query helpers

    def load_meta(self, binary: str | Path, *, native_authority_token: str | None = None) -> dict:
        """Return the cached meta analysis, running it if needed."""
        self._require_native_token(native_authority_token)
        binary = Path(binary).expanduser().resolve()
        cache_dir = self._cache_dir_for(_binary_key(binary))
        meta = cache_dir / "analysis_ida_meta.json"
        if meta.exists():
            return json.loads(meta.read_text())
        return self.analyze(binary, native_authority_token=native_authority_token)
