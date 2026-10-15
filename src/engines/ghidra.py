"""Ghidra headless engine.

Wraps ``analyzeHeadless`` + the REDump.java GhidraScript to produce structured
JSON analysis of a binary, with on-disk caching and fast single-function
decompilation against an already-analyzed project.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..subprocess_observability import observed_run

from ..config import Config, load_config
from ..analysis.evidence_signing import sign_document, verify_document
from ..analysis.native_range_authority import validate_launch_authority


def _is_ebpf_binary(binary: Path) -> bool:
    """Detect a generic eBPF or Solana SBF ELF.

    A language is pinned explicitly so extension selection remains deterministic
    in headless mode.
    """
    try:
        with binary.open("rb") as fh:
            magic = fh.read(4)
            if magic != b"\x7fELF":
                return False
            # e_machine is a 2-byte little-endian field at offset 18
            fh.seek(18)
            machine = int.from_bytes(fh.read(2), "little")
            return machine in {0x00F7, 0x0107}
    except (OSError, ValueError):
        return False


class EngineError(RuntimeError):
    pass


@dataclass
class RunResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    seconds: float


@dataclass(frozen=True)
class FunctionEvidence:
    result: dict
    raw_canonical_bytes: bytes
    raw_result_sha256: str
    attempt_receipt: dict


def _binary_key(path: Path) -> str:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    # Cache identity is security authority for downstream evidence reuse. A
    # truncated digest is not an acceptable object identity.
    return f"{path.name}_{h.hexdigest()}_{size}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


_REDUMP_SCHEMA = "angerona/1"


def _dump_is_complete(data: object, expected_mode: str, target_sha256: str) -> bool:
    """Return True only for a complete, untruncated REDump JSON document.

    REDump.java hand-serializes a single JSON document to the cache file
    in-place and non-atomically; a kill mid-write can leave a truncated file
    that either fails to parse or parses as a valid JSON prefix. Require the
    dump's own schema/mode markers plus a metadata sha256 that matches the
    target binary before trusting it as a cached result.
    """
    if not isinstance(data, dict):
        return False
    if data.get("schema") != _REDUMP_SCHEMA:
        return False
    if data.get("mode") != expected_mode:
        return False
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        return False
    return str(metadata.get("sha256") or "").lower() == target_sha256


_OWNER_RE = re.compile(r'<STATE\s+NAME="OWNER"[^>]*VALUE="([^"]*)"')


def _project_owner(projects_dir: Path, project_name: str) -> str | None:
    properties = projects_dir / f"{project_name}.rep" / "project.prp"
    try:
        match = _OWNER_RE.search(properties.read_text(errors="replace"))
    except OSError:
        return None
    return match.group(1) if match else None


def _project_name_for(projects_dir: Path, key: str) -> str:
    """Select a reusable Ghidra project owned by the current OS user."""
    # The cache key deliberately includes the original filename, but Ghidra
    # project names reject characters that are valid in filenames (for
    # example the '+' characters in libc++_shared.so).  Keep the full digest
    # identity while normalizing only the project namespace.
    key = re.sub(r"[^A-Za-z0-9_.-]+", "_", key).strip("._-") or "binary"
    base = projects_dir / f"{key}.gpr"
    if not base.exists():
        return key
    user = getpass.getuser()
    if _project_owner(projects_dir, key) == user:
        return key

    safe_user = re.sub(r"[^A-Za-z0-9_.-]+", "_", user).strip("._-") or "user"
    candidate = f"{key}__owner_{safe_user}"
    candidate_path = projects_dir / f"{candidate}.gpr"
    if not candidate_path.exists() or _project_owner(projects_dir, candidate) == user:
        return candidate
    raise EngineError(
        f"no writable Ghidra project namespace for {key}: both the base project "
        f"and {candidate} are owned by another user"
    )


class GhidraEngine:
    def __init__(self, config: Config | None = None):
        self.config = config or load_config()
        self._restricted_range_authority: dict | None = None
        self._restricted_address_bias = 0
        self._native_launch_authority_token: str | None = None
        self._restricted_project: tuple[str, Path] | None = None

    def configure_native_authority(self, authority: dict, authority_token: str) -> None:
        if self._native_launch_authority_token is not None:
            raise EngineError("Ghidra native launch authority is already configured")
        try:
            validate_launch_authority(authority, authority_token)
        except ValueError as exc:
            raise EngineError(str(exc)) from exc
        self._native_launch_authority_token = authority_token
        if authority.get("analysis_scope") == "selective_ranges":
            self._configure_restricted_ranges(authority)

    def configure_restricted_ranges(self, authority: dict, authority_token: str | None = None) -> None:
        """Pin a signed, target-specific selective-analysis authority before launch."""
        if authority_token is None:
            raise EngineError("Ghidra restricted mode requires a centralized launch authority token")
        self.configure_native_authority(authority, authority_token)

    def _configure_restricted_ranges(self, authority: dict) -> None:
        if self._restricted_range_authority is not None:
            raise EngineError("Ghidra restricted range authority is already configured")
        if authority.get("analysis_scope") != "selective_ranges":
            raise EngineError("Ghidra restricted mode requires selective_ranges scope")
        ranges = authority.get("allowed_executable_ranges")
        if not isinstance(ranges, list) or not ranges or not authority.get("range_authority_sha256"):
            raise EngineError("Ghidra restricted mode lacks signed allowed ranges")
        normalized = sorted(
            (int(row["address"]), int(row["size"])) for row in ranges
            if isinstance(row, dict) and int(row.get("size") or 0) > 0
        )
        if len(normalized) != len(ranges):
            raise EngineError("Ghidra restricted range authority is malformed")
        self._restricted_range_authority = {**authority, "_normalized_ranges": normalized}

    def _require_native_token(self, token: str | None) -> None:
        if self._native_launch_authority_token is None:
            if token is not None:
                raise EngineError("native authority token supplied without configured authority")
            return
        if token != self._native_launch_authority_token:
            raise EngineError("native Ghidra launch authority token mismatch")

    def _project_identity(self, project_name: str) -> dict:
        paths = [
            self.config.projects_dir / f"{project_name}.gpr",
            self.config.projects_dir / f"{project_name}.rep" / "project.prp",
        ]
        rows = []
        for path in paths:
            metadata = path.lstat()
            if path.is_symlink() or not path.is_file():
                raise EngineError("Ghidra project identity member is not a regular file")
            rows.append({"path": str(path), "sha256": _sha256_file(path), "bytes": metadata.st_size})
        return {"project_name": project_name, "members": rows}

    def _project_receipt_body(self, binary: Path, project_name: str) -> dict:
        if self._restricted_range_authority is None or self._native_launch_authority_token is None:
            raise EngineError("restricted Ghidra project receipt lacks native authority")
        exporter = self.config.scripts_dir / "REDump.java"
        headless = Path(str(self.config.analyze_headless))
        return {
            "schema": "angerona/ghidra-native-project-receipt/v1",
            "target_path": str(binary),
            "target_sha256": _sha256_file(binary),
            "target_bytes": binary.stat().st_size,
            "range_authority_sha256": self._restricted_range_authority["range_authority_sha256"],
            "native_launch_authority_token": self._native_launch_authority_token,
            "partition_sha256": self._restricted_range_authority.get("partition_sha256"),
            "partition_counts": self._restricted_range_authority.get("partition_counts"),
            "project_identity": self._project_identity(project_name),
            "exporter_path": str(exporter),
            "exporter_sha256": _sha256_file(exporter),
            "analyze_headless_path": str(headless),
            "analyze_headless_sha256": _sha256_file(headless),
            "ghidra_install": str(self.config.ghidra_install),
            "java_home": self.config.java_home,
        }

    def _write_project_receipt(self, binary: Path, project_name: str, cache_dir: Path) -> dict:
        receipt = sign_document(self._project_receipt_body(binary, project_name))
        if receipt.get("trust") != "operator_signed":
            raise EngineError("Ghidra native project receipt requires operator signing")
        path = cache_dir / "GHIDRA_NATIVE_PROJECT_RECEIPT.json"
        payload = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        with temporary.open("xb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return receipt

    def _verify_project_receipt(self, binary: Path, project_name: str, cache_dir: Path) -> dict:
        path = cache_dir / "GHIDRA_NATIVE_PROJECT_RECEIPT.json"
        if path.is_symlink() or not path.is_file():
            raise EngineError("Ghidra native project receipt is missing")
        receipt = json.loads(path.read_text())
        if not verify_document(receipt, require_signature=True):
            raise EngineError("Ghidra native project receipt signature is invalid")
        body = self._project_receipt_body(binary, project_name)
        for key, value in body.items():
            if receipt.get(key) != value:
                raise EngineError(f"Ghidra native project receipt mismatch: {key}")
        return receipt

    def _restricted_spec(self) -> tuple[str, str]:
        authority = self._restricted_range_authority
        if authority is None:
            raise EngineError("Ghidra restricted range authority is not configured")
        spec = ",".join(f"0x{start:x}:{size}" for start, size in authority["_normalized_ranges"])
        return spec, str(authority["range_authority_sha256"])

    def _restricted_entry_allowed(self, entry: str) -> bool:
        try:
            address = int(str(entry), 16)
        except ValueError:
            return False
        return bool(self._restricted_range_authority and any(
            start <= address < start + size
            or start + self._restricted_address_bias <= address < start + self._restricted_address_bias + size
            for start, size in self._restricted_range_authority["_normalized_ranges"]
        ))

    # ------------------------------------------------------------------ status

    def status(self) -> dict:
        ok, msg = self.config.ghidra_ready()
        return {
            "ready": ok,
            "message": msg,
            "ghidra_install": str(self.config.ghidra_install) if self.config.ghidra_install else None,
            "java_home": self.config.java_home,
            "scripts_dir": str(self.config.scripts_dir),
            "state_dir": str(self.config.state_dir),
        }

    def _require_ready(self) -> None:
        ok, msg = self.config.ghidra_ready()
        if not ok:
            raise EngineError(msg)

    # ---------------------------------------------------------------- internals

    def _run_headless(
        self,
        args: list[str],
        timeout: int | float | None,
        ro_binds: list[Path] | None = None,
    ) -> RunResult:
        assert self.config.analyze_headless is not None
        cmd = [str(self.config.analyze_headless), *args]
        if self.config.sandbox:
            from ..analysis import sandbox
            from ..config import REPO_ROOT
            if not sandbox.available():
                raise EngineError(
                    "sandbox requested (ANGERONA_SANDBOX=1) but 'bwrap' is not installed. "
                    "Install bubblewrap (`sudo apt-get install -y bubblewrap`) or disable sandbox."
                )
            ro: list[Path] = [REPO_ROOT]
            if self.config.ghidra_install:
                ro.append(self.config.ghidra_install)
            if self.config.java_home:
                ro.append(Path(self.config.java_home))
            ro += list(ro_binds or [])
            cmd = sandbox.wrap(cmd, writable_dirs=[self.config.state_dir], readonly_binds=ro)
        start = time.monotonic()
        try:
            proc = observed_run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self.config.subprocess_env(),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return RunResult(False, exc.stdout or "", (exc.stderr or "") + f"\n[timeout after {timeout}s]", 124, time.monotonic() - start)
        return RunResult(proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode, time.monotonic() - start)

    def _cache_dir_for(self, key: str) -> Path:
        d = self.config.cache_dir / key
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ------------------------------------------------------------------- analyze

    def analyze(
        self,
        binary: str | Path,
        *,
        decompile: bool = False,
        max_functions: int = 0,
        force: bool = False,
        timeout: int | None = None,
        native_authority_token: str | None = None,
    ) -> dict:
        """Import + analyze a binary, returning the structured JSON dump.

        Results are cached on disk keyed by content hash. ``decompile=True``
        also embeds decompiled C for functions (bounded by ``max_functions``).
        """
        self._require_ready()
        self._require_native_token(native_authority_token)
        if self._restricted_range_authority is not None:
            raise EngineError("generic Ghidra analyze is forbidden under selective native authority")
        binary = Path(binary).expanduser().resolve()
        if not binary.exists():
            raise EngineError(f"binary not found: {binary}")

        processor = None
        if _is_ebpf_binary(binary):
            processor = "eBPF:LE:64:default"
            try:
                from ..solana.adapters import ghidra_solana_language

                processor = ghidra_solana_language(self.config) or processor
            except Exception:
                pass
        processor_tag = processor.split(":", 1)[0] if processor else None

        key = _binary_key(binary)
        cache_dir = self._cache_dir_for(key)
        tag = (
            f"full_{max_functions if max_functions > 0 else 'all'}"
            if decompile else "meta"
        )
        if processor_tag:
            tag = f"{tag}_{processor_tag}"
        cache_file = cache_dir / f"analysis_{tag}.json"

        if cache_file.exists() and not force:
            # The cache file is written in-place by REDump.java, not atomically:
            # a killed run can leave a truncated document that json.loads either
            # rejects or (worse) accepts as a valid JSON prefix. Re-read
            # defensively and re-verify the dump's completeness markers before
            # serving it as a cached result.
            try:
                data = json.loads(cache_file.read_text())
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                data = {}
            if _dump_is_complete(data, "full" if decompile else "meta", _sha256_file(binary)):
                data["_cache"] = str(cache_file)
                data["_cached"] = True
                return data

        project_key = f"{key}__{processor_tag}" if processor_tag else key
        project_name = _project_name_for(self.config.projects_dir, project_key)
        out_json = cache_dir / f"analysis_{tag}.json"
        mode_args = [tag] if not decompile else ["full", str(max_functions)]
        project_exists = (self.config.projects_dir / f"{project_name}.gpr").exists()

        args: list[str] = [str(self.config.projects_dir), project_name]
        if project_exists:
            args += ["-process", binary.name, "-noanalysis"]
        else:
            args += ["-import", str(binary)]
        # Pin the strongest installed Solana/eBPF language explicitly. Processor
        # identity is also part of the project/cache key above, so installing an
        # extension can never silently reuse an older generic-eBPF project.
        if processor:
            args += ["-processor", processor]
        max_cpu_raw = self.config.subprocess_env().get("ANGERONA_GHIDRA_MAX_CPU", "").strip()
        if max_cpu_raw:
            try:
                max_cpu = int(max_cpu_raw)
            except ValueError as exc:
                raise EngineError("ANGERONA_GHIDRA_MAX_CPU must be an integer >= 1") from exc
            if max_cpu < 1:
                raise EngineError("ANGERONA_GHIDRA_MAX_CPU must be an integer >= 1")
            args += ["-max-cpu", str(max_cpu)]
        args += [
            "-scriptPath", str(self.config.scripts_dir),
            "-postScript", "REDump.java", str(out_json), *mode_args,
        ]
        if timeout != 0:
            args += ["-analysisTimeoutPerFile", str(self.config.analysis_timeout)]

        # A forced rerun must never mistake a stale prior artifact for fresh
        # output after an engine crash or timeout.
        out_json.unlink(missing_ok=True)
        process_timeout = (
            None if timeout == 0
            else timeout if timeout is not None
            else self.config.analysis_timeout + 300
        )
        result = self._run_headless(args, process_timeout, ro_binds=[binary])
        if not result.ok or not out_json.exists():
            raise EngineError(
                f"analysis produced no output (rc={result.returncode}).\n"
                f"stdout tail:\n{result.stdout[-2000:]}\n"
                f"stderr tail:\n{result.stderr[-2000:]}"
            )
        data = json.loads(out_json.read_text())
        sandbox_note = "SANDBOXED via bwrap (no network, read-only host)" if self.config.sandbox else "not sandboxed"
        (cache_dir / "headless.log").write_text(
            f"# isolation: {sandbox_note}\n$ analyzeHeadless {' '.join(args)}\n\n=== STDOUT ===\n{result.stdout}\n\n=== STDERR ===\n{result.stderr}"
        )
        data["_cache"] = str(cache_file)
        data["_cached"] = False
        data["_seconds"] = round(result.seconds, 1)
        return data

    def _ensure_analyzed(self, binary: Path) -> tuple[str, Path]:
        key = _binary_key(binary)
        if self._restricted_range_authority is not None:
            if self._restricted_project is not None:
                project_name, cache_dir = self._restricted_project
                try:
                    self._verify_project_receipt(binary, project_name, cache_dir)
                    return project_name, cache_dir
                except EngineError:
                    self._restricted_project = None
            spec, authority_sha = self._restricted_spec()
            restricted_key = f"{key}__restricted_{authority_sha}"
            project_name = _project_name_for(self.config.projects_dir, restricted_key)
            cache_dir = self._cache_dir_for(restricted_key)
            project_file = self.config.projects_dir / f"{project_name}.gpr"
            if project_file.exists():
                try:
                    self._verify_project_receipt(binary, project_name, cache_dir)
                except EngineError:
                    fresh_key = f"{restricted_key}__fresh_{uuid.uuid4().hex[:12]}"
                    project_name = _project_name_for(self.config.projects_dir, fresh_key)
                    cache_dir = self._cache_dir_for(fresh_key)
                    project_file = self.config.projects_dir / f"{project_name}.gpr"
            if not project_file.exists():
                out_json = cache_dir / "analysis_restricted_meta.json"
                out_json.unlink(missing_ok=True)
                args = [
                    str(self.config.projects_dir), project_name,
                    "-import", str(binary), "-noanalysis",
                    "-scriptPath", str(self.config.scripts_dir),
                    "-postScript", "REDump.java", str(out_json),
                    "restricted_meta", spec, authority_sha,
                ]
                result = self._run_headless(
                    args, self.config.analysis_timeout + 300, ro_binds=[binary],
                )
                if not result.ok or not out_json.is_file():
                    raise EngineError(
                        f"restricted Ghidra import failed (rc={result.returncode}): "
                        f"{result.stderr[-1500:]}"
                    )
                data = json.loads(out_json.read_text())
                if (
                    data.get("mode") != "restricted_meta"
                    or data.get("range_authority_sha256") != authority_sha
                    or str((data.get("metadata") or {}).get("sha256") or "").lower()
                    != _sha256_file(binary)
                ):
                    raise EngineError("restricted Ghidra project receipt mismatch")
                self._write_project_receipt(binary, project_name, cache_dir)
            metadata_path = cache_dir / "analysis_restricted_meta.json"
            if not metadata_path.is_file():
                raise EngineError("restricted Ghidra project lacks its authority-bound metadata")
            restricted_metadata = json.loads(metadata_path.read_text())
            self._verify_project_receipt(binary, project_name, cache_dir)
            self._restricted_address_bias = int(
                str((restricted_metadata.get("metadata") or {}).get("image_base") or "0"), 16,
            )
            self._restricted_project = (project_name, cache_dir)
            return project_name, cache_dir
        project_name = _project_name_for(self.config.projects_dir, key)
        if not (self.config.projects_dir / f"{project_name}.gpr").exists():
            # A cache created on another host/user does not prove this user's
            # project exists; force a fresh engine run to create it.
            self.analyze(
                binary, force=True,
                native_authority_token=self._native_launch_authority_token,
            )
        return project_name, self._cache_dir_for(key)

    def analyze_restricted_meta(self, binary: str | Path, *, native_authority_token: str | None = None) -> dict:
        if self._restricted_range_authority is None:
            raise EngineError("restricted metadata requires configured range authority")
        self._require_native_token(native_authority_token)
        binary_path = Path(binary).expanduser().resolve()
        _project, cache_dir = self._ensure_analyzed(binary_path)
        output = cache_dir / "analysis_restricted_meta.json"
        data = json.loads(output.read_text())
        if data.get("range_authority_sha256") != self._restricted_range_authority.get(
            "range_authority_sha256"
        ):
            raise EngineError("restricted metadata range authority mismatch")
        data["_cache"] = str(output)
        data["_cached"] = True
        return data

    def decompile_function_evidence(
        self, binary: str | Path, name_or_addr: str, *, timeout: int = 180,
        native_authority_token: str | None = None,
    ) -> FunctionEvidence:
        """Return fresh raw function evidence and a launch-bound attempt receipt."""
        self._require_ready()
        self._require_native_token(native_authority_token)
        binary = Path(binary).expanduser().resolve()
        if not binary.exists():
            raise EngineError(f"binary not found: {binary}")
        project_name, cache_dir = self._ensure_analyzed(binary)
        project_receipt = (
            self._verify_project_receipt(binary, project_name, cache_dir)
            if self._restricted_range_authority is not None else None
        )
        restricted_args: list[str] = []
        restricted_authority = None
        if self._restricted_range_authority is not None:
            if not self._restricted_entry_allowed(name_or_addr):
                raise EngineError("requested Ghidra entry is outside signed allowed ranges")
            spec, restricted_authority = self._restricted_spec()
            restricted_args = ["restricted", spec, restricted_authority]

        safe = "".join(c if c.isalnum() else "_" for c in name_or_addr)[:80]
        attempt_id = uuid.uuid4().hex
        attempt_dir = cache_dir / "function-attempts" / safe
        attempt_dir.mkdir(parents=True, exist_ok=True)
        out_json = attempt_dir / f"{attempt_id}.json"
        if out_json.exists():
            raise EngineError(f"fresh attempt output already exists: {out_json}")
        target_sha = _sha256_file(binary)
        exporter_path = self.config.scripts_dir / "REDump.java"
        exporter_sha = _sha256_file(exporter_path)
        analyze_headless = Path(str(self.config.analyze_headless))
        ghidra_identity = {
            "status": self.status(),
            "analyze_headless": str(analyze_headless),
            "analyze_headless_sha256": _sha256_file(analyze_headless),
            "ghidra_install": str(self.config.ghidra_install) if self.config.ghidra_install else None,
            "java_home": self.config.java_home,
        }
        started_ns = time.time_ns()
        args = [
            str(self.config.projects_dir), project_name,
            "-process", binary.name, "-noanalysis",
            "-scriptPath", str(self.config.scripts_dir),
            "-postScript", "REDump.java", str(out_json), "function", name_or_addr,
            *restricted_args,
        ]
        result = self._run_headless(args, timeout, ro_binds=[binary])
        finished_ns = time.time_ns()
        if not result.ok or not out_json.exists():
            raise EngineError(
                f"decompile produced no output (rc={result.returncode}).\n"
                f"stdout tail:\n{result.stdout[-1500:]}\n"
                f"stderr tail:\n{result.stderr[-1500:]}"
            )
        raw_result = json.loads(out_json.read_text())
        if not isinstance(raw_result, dict):
            raise EngineError("function output is not a JSON object")
        if self._restricted_range_authority is not None:
            project_receipt = self._verify_project_receipt(binary, project_name, cache_dir)
        raw = (json.dumps(raw_result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        raw_sha = hashlib.sha256(raw).hexdigest()
        receipt_body = {
            "schema": "angerona/ghidra-function-attempt/v1",
            "attempt_id": attempt_id,
            "target_sha256": target_sha,
            "requested_entry": str(name_or_addr).lower(),
            "returned_entry": str(raw_result.get("entry") or "").lower(),
            "project_name": project_name,
            "project_key": _binary_key(binary),
            "project_receipt_path": (
                str(cache_dir / "GHIDRA_NATIVE_PROJECT_RECEIPT.json")
                if project_receipt is not None else None
            ),
            "project_receipt_sha256": (
                _sha256_file(cache_dir / "GHIDRA_NATIVE_PROJECT_RECEIPT.json")
                if project_receipt is not None else None
            ),
            "project_receipt_payload_sha256": (project_receipt or {}).get("payload_sha256"),
            "native_launch_authority_token": self._native_launch_authority_token,
            "range_authority_sha256": restricted_authority,
            "analysis_scope": (
                "selective_ranges" if restricted_authority else "whole_target"
            ),
            "exporter_schema": _REDUMP_SCHEMA,
            "exporter_path": str(exporter_path),
            "exporter_sha256": exporter_sha,
            "ghidra_identity": ghidra_identity,
            "started_at_unix_ns": started_ns,
            "finished_at_unix_ns": finished_ns,
            "returncode": result.returncode,
            "output_path": str(out_json),
            "raw_result_sha256": raw_sha,
            "raw_result_bytes": len(raw),
        }
        receipt_sha = hashlib.sha256(
            (json.dumps(receipt_body, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        return FunctionEvidence(
            result=raw_result,
            raw_canonical_bytes=raw,
            raw_result_sha256=raw_sha,
            attempt_receipt={**receipt_body, "receipt_sha256": receipt_sha},
        )

    def decompile_function(
        self, binary: str | Path, name_or_addr: str, *, timeout: int = 180,
        native_authority_token: str | None = None,
    ) -> dict:
        """Backward-compatible dict-only wrapper around fresh function evidence."""
        return self.decompile_function_evidence(
            binary, name_or_addr, timeout=timeout,
            native_authority_token=native_authority_token,
        ).result

    # ------------------------------------------------------- cached query helpers

    def load_meta(self, binary: str | Path, *, native_authority_token: str | None = None) -> dict:
        self._require_native_token(native_authority_token)
        if self._restricted_range_authority is not None:
            return self.analyze_restricted_meta(
                binary, native_authority_token=native_authority_token,
            )
        """Return the cached meta analysis, running it if needed."""
        binary = Path(binary).expanduser().resolve()
        cache_dir = self._cache_dir_for(_binary_key(binary))
        meta = cache_dir / "analysis_meta.json"
        if meta.exists():
            try:
                data = json.loads(meta.read_text())
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                data = {}
            if _dump_is_complete(data, "meta", _sha256_file(binary)):
                return data
        return self.analyze(
            binary, native_authority_token=native_authority_token,
        )
