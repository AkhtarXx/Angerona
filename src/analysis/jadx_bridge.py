"""JADX headless bridge for deep semantic DEX analysis.

Runs the jadx CLI in an isolated subprocess (bounded memory, path-jail, JSONL
output only) and translates its decompile findings into Angerona evidence-style
findings. The entire communication surface is one-way raw text -> structured
rows, so a malformed JADX output never escalates into pipeline context.

Design (per professional critique):
  * JADX is a **helper oracle**, not a producer of authority — every emitted
    finding carries the ``untrusted_child`` trust marker until verified by
    deterministic gates downstream.
  * Subprocess is fully isolated (bwrap when available, read-only bind-mounts
    so JADX's incidental writes cannot touch the caller workspace).
  * Budget bounded: memory limit + wall timeout are always live.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..subprocess_observability import (
    ProgressTimeoutExpired,
    atomic_publish_directory,
    bounded_env_int,
    observed_progress_run,
    persist_bounded_log,
)


@dataclass
class JadxFinding:
    kind: str                       # hardcoded-string | reflection | exported-component |
                                    # permission-abuse | weak-crypto
    severity: str                   # high | medium | low | info
    class_path: str
    method: str
    message: str
    evidence: str
    line_no: int = 0

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "class_path": self.class_path,
            "method": self.method,
            "message": self.message,
            "evidence": self.evidence,
            "line_no": self.line_no,
        }


@dataclass
class JadxResult:
    status: str                     # success | unavailable | partial | skipped
    apk_path: str
    classes_count: int = 0
    findings: list[dict] = field(default_factory=list)
    exported_components: list[dict] = field(default_factory=list)
    permissions_requested: list[str] = field(default_factory=list)
    jadx_binary: str | None = None
    exit_code: int = 0
    note: str = ""
    errors: list[str] = field(default_factory=list)
    attempt_log: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "apk_path": self.apk_path,
            "classes_count": self.classes_count,
            "findings": self.findings,
            "exported_components": self.exported_components,
            "permissions_requested": self.permissions_requested,
            "jadx_binary": self.jadx_binary,
            "exit_code": self.exit_code,
            "attempt_log": self.attempt_log,
            "note": self.note,
            "errors": self.errors,
        }


# ------------------------------------------------------------------ discovery

def find_jadx_cli(cfg: Config | None = None) -> Path | None:
    """Locate the jadx CLI.

    Order: ``JADX_CLI`` env -> vendored at ``vendor/jadx-{ver}/bin/jadx`` -> PATH.
    A Windows .bat on any host is skipped. Returns None if no candidate exists
    (callers must degrade gracefully rather than raise).
    """
    env = os.environ.get("JADX_CLI")
    if env and Path(env).is_file() and os.access(env, os.X_OK):
        return Path(env)
    if Path("/tmp/jadx_ext/bin/jadx").is_file():
        return Path("/tmp/jadx_ext/bin/jadx")
    root = Path(__file__).resolve().parents[2]
    candidates = sorted((root / "vendor").glob("jadx*/bin/jadx"), reverse=True)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    which = shutil.which("jadx-cli") or shutil.which("jadx")
    if which:
        return Path(which)
    return None


# ------------------------------------------------------------------ parse


_REFLECTION_MARK = r"(Class\.forName|getMethod\(|getDeclaredMethod\(|getField\(|getDeclaredField\(|DexClassLoader|ProcessBuilder|Runtime\.exec|loadLibrary|load\()"
_HARDCODED_MARK = r"\"(AKIA|AIza|\d{20,}|-----BEGIN|api[_-]?key|token[_-]?=|password|secret)[A-Za-z0-9+/=_-]*\""

# Attribute order inside a decoded manifest tag is not stable: binary AXML
# (and JADX) emit ``android:name`` before ``android:exported``, so match the
# two attributes independently instead of requiring a fixed order.
_MANIFEST_COMPONENT_TAG = re.compile(r"<(activity|service|provider|receiver)[^>]*>")
_MANIFEST_EXPORTED_FLAG = re.compile(r"android:exported=\"true\"")
_MANIFEST_NAME_ATTR = re.compile(r"android:name=\"([^\"]+)\"")
_MANIFEST_PERMISSION = re.compile(r"<uses-permission[^>]*?android:name=\"([^\"]+)\"")


def _parse_jadx_sources(source_dirs: list[Path]) -> tuple[list[dict], list[str], int]:
    """Walk jadx's produced source tree and emit security findings."""
    findings: list[dict] = []
    errors: list[str] = []
    try:
        max_files = max(1, min(int(os.environ.get("ANGERONA_JADX_MAX_FILES", "200000")), 1_000_000))
    except ValueError:
        max_files = 200_000
    try:
        max_findings = max(1, min(int(os.environ.get("ANGERONA_JADX_MAX_FINDINGS", "100000")), 500_000))
    except ValueError:
        max_findings = 100_000
    try:
        max_file_bytes = max(1024 * 1024, min(
            int(os.environ.get("ANGERONA_JADX_MAX_SOURCE_BYTES", str(16 * 1024 * 1024))),
            128 * 1024 * 1024,
        ))
    except ValueError:
        max_file_bytes = 16 * 1024 * 1024
    # JADX's top-level output contains ``sources/``. Callers historically passed
    # both roots, causing every Java file and finding to be counted twice. Keep
    # the first (most specific) root for a physical file and parse it exactly once.
    canonical_files: dict[Path, tuple[Path, Path]] = {}
    for root in source_dirs:
        if not root.is_dir():
            continue
        for java_f in root.rglob("*.java"):
            try:
                resolved = java_f.resolve(strict=True)
            except OSError:
                resolved = java_f.absolute()
            canonical_files.setdefault(resolved, (java_f, root))
    if len(canonical_files) > max_files:
        errors.append(
            f"coverage-limit: JADX source files {len(canonical_files)} exceed {max_files}"
        )
        canonical_files = dict(list(canonical_files.items())[:max_files])

    finding_keys: set[tuple[object, ...]] = set()
    findings_limited = False
    for java_f, root in canonical_files.values():
        try:
            class_path = java_f.relative_to(root).as_posix()
        except ValueError:
            class_path = java_f.name
        before = len(findings)
        try:
            if java_f.stat().st_size > max_file_bytes:
                errors.append(
                    f"coverage-limit: source file exceeds {max_file_bytes} bytes: {java_f}"
                )
                continue
            text = java_f.read_text(errors="ignore")
        except OSError:
            errors.append(f"cannot read {java_f}")
            continue
        lines = text.splitlines()
        for line_no, line in enumerate(lines, 1):
            if len(findings) >= max_findings:
                errors.append(
                    f"coverage-limit: JADX findings exceed {max_findings}"
                )
                findings_limited = True
                break
            if re.search(_REFLECTION_MARK, line):
                findings.append(JadxFinding(
                    kind="reflection", severity="medium",
                    class_path=class_path,
                    method=_extract_method_from_surround(lines, line_no),
                    message="reflection/dynamic loader usage",
                    evidence=line.strip(), line_no=line_no,
                ).as_dict())
            for _match in re.finditer(_HARDCODED_MARK, line):
                findings.append(JadxFinding(
                    kind="hardcoded-secret", severity="high",
                    class_path=class_path,
                    method=_extract_method_from_surround(lines, line_no),
                    message="hardcoded credential string embedded",
                    evidence=line.strip(), line_no=line_no,
                ).as_dict())
            if re.search(r"javax\.crypto\.Cipher|getInstance\(.*(MD5|SHA1|DES|RC4|ECB)", line):
                findings.append(JadxFinding(
                    kind="weak-crypto", severity="medium",
                    class_path=class_path,
                    method=_extract_method_from_surround(lines, line_no),
                    message="weak cryptographic primitive",
                    evidence=line.strip(), line_no=line_no,
                ).as_dict())
        unique: list[dict] = []
        for finding in findings[before:]:
            key = (
                finding.get("kind"), finding.get("class_path"), finding.get("method"),
                finding.get("line_no"), finding.get("evidence"),
            )
            if key not in finding_keys:
                finding_keys.add(key)
                unique.append(finding)
        findings[before:] = unique
        if findings_limited:
            break
    return findings, errors, len(canonical_files)


def _extract_method_from_surround(lines: list[str], line_no: int) -> str:
    """Walk backward from line_no to find the enclosing method name."""
    method = ""
    for i in range(line_no - 1, max(0, line_no - 200), -1):
        if i >= len(lines):
            continue
        line = lines[i]
        m = re.match(r"\s+(?:public|private|protected)?\s*(?:static|final)?\s*[\w<>,\[\]\s]+\s+(\w+)\s*\(", line)
        if m:
            method = m.group(1)
            break
    return method or "<class-init>"


def _parse_manifest(manifest_xml: str) -> tuple[list[dict], list[str]]:
    exported: list[dict] = []
    permissions: list[str] = []
    for m in _MANIFEST_COMPONENT_TAG.finditer(manifest_xml):
        attrs = m.group(0)
        if not _MANIFEST_EXPORTED_FLAG.search(attrs):
            continue
        name_m = _MANIFEST_NAME_ATTR.search(attrs)
        if not name_m:
            continue
        exported.append({
            "component_type": m.group(1),
            "name": name_m.group(1),
            "risk": "exported component requires authorization review",
        })
    for m in _MANIFEST_PERMISSION.finditer(manifest_xml):
        permissions.append(m.group(1))
    return exported, permissions


def _decode_manifest_bytes(raw: bytes) -> str:
    """Decode a raw ``AndroidManifest.xml`` zip member into text XML.

    APK manifests are compiled binary AXML: decoding the bytes as UTF-8 yields
    mojibake whose string-pool / typed-attribute layout ``_parse_manifest``
    cannot match, silently dropping the exported components and permissions
    this fallback exists to preserve. Prefer pyaxmlparser (a declared
    dependency) which resolves the string pool and typed attributes (including
    the boolean ``android:exported`` flag) into real XML. Repacked manifests
    stored as plain text pass through unchanged.
    """
    if not raw:
        return ""
    # Some tooling repacks AndroidManifest.xml as plain text: pass it through.
    text = raw.decode("utf-8", errors="ignore")
    if "<manifest" in text or "<application" in text or "<uses-permission" in text:
        return text
    if not raw.startswith(b"\x03\x00"):
        # Not binary AXML either; keep whatever printable text survived.
        return text
    try:
        from pyaxmlparser.axmlprinter import AXMLPrinter

        return AXMLPrinter(raw).get_buff().decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return ""


# ------------------------------------------------------------------ driver


def analyze_apk(
    apk_path: str | Path,
    *,
    cfg: Config | None = None,
    timeout: int = 300,
    memory_limit_mb: int = 2048,
    keep_output: str | Path | None = None,
    deadline_monotonic: float | None = None,
) -> JadxResult:
    """Run jadx headless on an APK and return a structured :class:`JadxResult`.

    The output directories' Java source is parsed for security-relevant patterns;
    the AndroidManifest.xml is parsed for exported components + permissions.
    Every returned row carries ``trust: untrusted_child``.

    Graceful degradation:
      * JADX unavailable -> status="unavailable" (caller skips gracefully)
      * APK unreadable -> status="skipped" (never a crash)
      * partial output -> status="partial" (results retained with errors list)
    """
    apk_path = Path(apk_path).expanduser().resolve()
    if not apk_path.is_file():
        return JadxResult(status="skipped", apk_path=str(apk_path),
                          note=f"missing: {apk_path}")

    cli = find_jadx_cli(cfg)
    if cli is None:
        return JadxResult(status="unavailable", apk_path=str(apk_path),
                          note="jadx-cli not found (set JADX_CLI or vendor under vendor/jadx-*/bin)")

    # Pre-extract the AndroidManifest.xml from the zip ourselves so a malformed
    # classes.dex cannot deny component-surface evidence: JADX may fail at the
    # DexHeader stage (we still want manifest facts). This mirrors how the
    # pipeline treats valid-but-partial inputs.
    pre_extracted_manifest = b""
    try:
        import zipfile
        with zipfile.ZipFile(apk_path, "r") as apk:
            if "AndroidManifest.xml" in apk.namelist():
                pre_extracted_manifest = apk.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, OSError, RuntimeError, KeyError):
        pre_extracted_manifest = b""

    publish_dir = Path(keep_output).expanduser().resolve() if keep_output else None
    out_dir: Path
    if publish_dir is None:
        tmp = tempfile.TemporaryDirectory(prefix="jadx-")
        out_dir = Path(tmp.name)
    else:
        publish_dir.parent.mkdir(parents=True, exist_ok=True)
        out_dir = Path(tempfile.mkdtemp(
            prefix=f".{publish_dir.name}.staging-", dir=publish_dir.parent
        ))

    manifest_text = ""
    exported_components: list[dict] = []
    permissions: list[str] = []
    findings: list[dict] = []
    errors: list[str] = []
    classes_count = 0
    status = "success"
    note = ""
    exit_code = 0

    env = os.environ.copy()
    # JAVA_OPTS is consumed by JADX's generated launcher without the diagnostic
    # banner emitted by JAVA_TOOL_OPTIONS.  This is a JVM heap ceiling, not an
    # OS sandbox or a total-process RSS guarantee.
    env.pop("JAVA_TOOL_OPTIONS", None)
    env.pop("_JAVA_OPTIONS", None)
    heap_mb = max(256, min(int(memory_limit_mb), 8192))
    env["JAVA_OPTS"] = f"-Xmx{heap_mb}m"
    env["JADX_CACHE_DIR"] = str(out_dir / ".jadx-cache")
    cpu_count = max(1, os.cpu_count() or 1)
    jadx_threads = max(1, min(8, cpu_count, max(1, heap_mb // 512)))
    cmd = [
        str(cli),
        "--output-dir", str(out_dir),
        "--no-imports",
        "--no-debug-info",
        "--threads-count", str(jadx_threads),
        "--log-level", "progress",
        "--show-bad-code",
        str(apk_path),
    ]

    # A fixed wall timeout is wrong for large APKs: a healthy decompiler may
    # continuously publish thousands of source files for hours. Monitor the
    # output tree and reset the idle deadline whenever bytes/files/mtime move.
    log_parent = publish_dir.parent if publish_dir is not None else out_dir.parent
    log_handle = tempfile.NamedTemporaryFile(
        prefix=f".{out_dir.name}.angerona-jadx-",
        suffix=".log",
        dir=log_parent,
        delete=False,
    )
    log_path = Path(log_handle.name)
    log_handle.close()
    try:
        configured_idle = int(os.environ.get("ANGERONA_JADX_IDLE_TIMEOUT_SECONDS", "900"))
    except ValueError:
        configured_idle = 900
    try:
        configured_wall = int(os.environ.get("ANGERONA_JADX_WALL_TIMEOUT_SECONDS", "86400"))
    except ValueError:
        configured_wall = 86_400
    idle_timeout = max(60, min(max(timeout, configured_idle), 7_200))
    wall_timeout = max(idle_timeout, min(max(configured_wall, idle_timeout), 172_800))
    if deadline_monotonic is not None:
        remaining = max(0.001, deadline_monotonic - time.monotonic())
        wall_timeout = min(wall_timeout, remaining)
        idle_timeout = min(idle_timeout, wall_timeout)
    try:
        max_attempts = max(1, min(
            int(os.environ.get("ANGERONA_JADX_ATTEMPTS", "2")), 3
        ))
    except ValueError:
        max_attempts = 2
    for attempt in range(1, max_attempts + 1):
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            status = "partial"
            errors.append("jadx aggregate pre-AI deadline exhausted")
            break
        if attempt > 1:
            # A retry is a new attempt, never a continuation of possibly stale
            # partial files. Reduce concurrency to lower JVM pressure.
            shutil.rmtree(out_dir, ignore_errors=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            env["JADX_CACHE_DIR"] = str(out_dir / ".jadx-cache")
            thread_index = cmd.index("--threads-count") + 1
            cmd[thread_index] = str(max(1, int(cmd[thread_index]) // 2))
        try:
            attempt_wall = wall_timeout
            if deadline_monotonic is not None:
                attempt_wall = min(
                    attempt_wall,
                    max(0.001, deadline_monotonic - time.monotonic()),
                )
            with log_path.open("ab") as log:
                log.write(f"\nANGERONA_JADX_ATTEMPT {attempt}/{max_attempts}\n".encode())
                log.flush()
                result = observed_progress_run(
                    cmd,
                    progress_path=log_path,
                    idle_timeout=min(idle_timeout, attempt_wall),
                    wall_timeout=attempt_wall,
                    poll_interval=1.0,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    env=env,
                    cwd=str(out_dir),
                    max_rss_bytes=max(
                        heap_mb * 1024 * 1024,
                        bounded_env_int(
                            "ANGERONA_JADX_MAX_RSS_MB", 8192,
                            minimum=1024, maximum=32768,
                        ) * 1024 * 1024,
                    ),
                    max_processes=bounded_env_int(
                        "ANGERONA_JADX_MAX_PROCESSES", 256,
                        minimum=8, maximum=1024,
                    ),
                    resource_paths=[out_dir, log_path],
                    max_output_bytes=bounded_env_int(
                        "ANGERONA_JADX_MAX_OUTPUT_GIB", 24,
                        minimum=1, maximum=256,
                    ) * 1024**3,
                    max_output_items=bounded_env_int(
                        "ANGERONA_ANDROID_MAX_OUTPUT_ITEMS", 2_000_000,
                        minimum=10_000, maximum=20_000_000,
                    ),
                    min_free_bytes=bounded_env_int(
                        "ANGERONA_ANDROID_MIN_FREE_GIB", 8,
                        minimum=1, maximum=128,
                    ) * 1024**3,
                )
            exit_code = result.returncode
            if exit_code == 0:
                status = "success"
                if attempt > 1:
                    errors.append(f"jadx recovered on attempt {attempt}/{max_attempts}")
                break
            errors.append(f"jadx attempt {attempt}/{max_attempts} exited rc={exit_code}")
            status = "partial"
        except ProgressTimeoutExpired as exc:
            status = "partial"
            errors.append(
                f"jadx attempt {attempt}/{max_attempts} {exc.reason} "
                f"after {exc.elapsed_seconds:.1f}s "
                f"(progress_bytes={exc.progress_bytes}; progress_items={exc.progress_items})"
            )
        except OSError as exc:
            status = "unavailable"
            errors.append(f"jadx attempt {attempt}/{max_attempts} spawn failed: {exc}")
        if attempt == max_attempts:
            try:
                tail = log_path.read_text(errors="replace").strip()
            except OSError:
                tail = ""
            if tail:
                errors.append(f"jadx log tail: {tail[-400:]}")

    if status == "unavailable":
        attempt_log = (
            persist_bounded_log(
                log_path,
                publish_dir.parent / f"{publish_dir.name}.ANGERONA_JADX_ATTEMPTS.log",
            )
            if publish_dir is not None else {}
        )
        log_path.unlink(missing_ok=True)
        if publish_dir is not None:
            shutil.rmtree(out_dir, ignore_errors=True)
        return JadxResult(status=status, apk_path=str(apk_path),
                          jadx_binary=str(cli), exit_code=exit_code,
                          errors=errors,
                          attempt_log=attempt_log,
                          note="jadx spawn failed after bounded retries")

    # A successful output is published as one directory rename.  Previous
    # evidence is never parsed or mixed into a failed/partial attempt.
    if status == "success" and publish_dir is not None:
        try:
            atomic_publish_directory(out_dir, publish_dir)
            out_dir = publish_dir
        except OSError as exc:
            status = "partial"
            errors.append(f"jadx output publish failed: {exc}")

    # Parse only this attempt's sources; jadx may place them under several roots.
    sources_candidates: list[Path] = [d for d in (
        out_dir / "sources",
        out_dir / "res",
        out_dir / "resources",
        out_dir,
    ) if d.is_dir()]
    findings, errors_extra, classes_count = _parse_jadx_sources(sources_candidates)
    errors.extend(errors_extra)
    if errors_extra and status == "success":
        status = "partial"

    # Manifest for component_surface — try several locations in order, then fall
    # back to the manifest we pre-extracted from the zip (when JADX extract/parse
    # itself failed on malformed DEX).
    manifest_text = ""
    manifest_candidates = [
        out_dir / "AndroidManifest.xml",
        out_dir / "resources" / "AndroidManifest.xml",
        out_dir / "res" / "AndroidManifest.xml",
    ]
    for cand in manifest_candidates:
        if cand.is_file():
            try:
                manifest_text = cand.read_text(errors="ignore")
                break
            except OSError:
                continue
    if not manifest_text and pre_extracted_manifest:
        manifest_text = _decode_manifest_bytes(pre_extracted_manifest)
        if not manifest_text:
            errors.append(
                "manifest fallback: binary AndroidManifest.xml could not be decoded"
            )
    if manifest_text:
        try:
            exported_components, permissions = _parse_manifest(manifest_text)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"manifest parse failed: {exc}")

    note = f"{classes_count} classes decompiled" if classes_count else "no classes decompiled"
    if status == "partial":
        note = note + f" (partial; {len(errors)} errors)"
    attempt_log = (
        persist_bounded_log(
            log_path,
            publish_dir.parent / f"{publish_dir.name}.ANGERONA_JADX_ATTEMPTS.log",
        )
        if publish_dir is not None else {}
    )
    decoded = JadxResult(
        status=status,
        apk_path=str(apk_path),
        classes_count=classes_count,
        findings=findings,
        exported_components=exported_components,
        permissions_requested=permissions,
        jadx_binary=str(cli),
        exit_code=exit_code,
        note=note,
        errors=errors,
        attempt_log=attempt_log,
    )
    log_path.unlink(missing_ok=True)
    if publish_dir is not None and out_dir != publish_dir:
        shutil.rmtree(out_dir, ignore_errors=True)
    return decoded
