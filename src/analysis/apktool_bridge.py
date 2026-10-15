"""Apktool headless bridge for APK ground-truth resources.

Apktool decodes binary AXML (compiled AndroidManifest.xml) and resources.arsc
plus smali — exactly the pieces Angerona's pure-Python pipeline cannot do by
itself.  This bridge runs apktool in an isolated subprocess (bounded
memory/timeout, path-jail cwd) and translates its decoded output into
Angerona evidence-style findings.

Design (mirrors ``jadx_bridge.py``):
  * Apktool is a **helper oracle**, never a producer of authority — every
    emitted row carries the ``untrusted_child`` trust marker until verified
    downstream.
  * ``d`` decode with ``-s`` (skip sources) → fast manifest + res + smali
    layout; JADX already owns the DEX-side decompile view.
  * Graceful: apktool missing → status="unavailable"; partial decode →
    status="partial" with errors retained.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..subprocess_observability import (
    ProgressTimeoutExpired,
    atomic_publish_directory,
    bounded_env_int,
    observed_progress_run,
    observed_run,
    persist_bounded_log,
)

TRUST_TAG = "untrusted_child"


@dataclass
class ApktoolResult:
    status: str                     # success | unavailable | partial | skipped
    apk_path: str
    manifest_xml: str = ""          # decoded text AXML (ground truth)
    permissions: list[str] = field(default_factory=list)
    exported_components: list[dict] = field(default_factory=list)
    smali_dirs: list[str] = field(default_factory=list)     # e.g. ["smali", "smali_classes2"]
    smali_files_count: int = 0
    apktool_version: str | None = None
    errors: list[str] = field(default_factory=list)
    attempt_log: dict = field(default_factory=dict)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "apk_path": self.apk_path,
            "permissions": self.permissions,
            "exported_components": self.exported_components,
            "smali_dirs": self.smali_dirs,
            "smali_files_count": self.smali_files_count,
            "apktool_version": self.apktool_version,
            "errors": self.errors,
            "attempt_log": self.attempt_log,
            "note": self.note,
            "trust": TRUST_TAG,
        }


# ------------------------------------------------------------------ discovery


def find_apktool(cfg: Config | None = None) -> Path | None:
    """Locate apktool: ``APKTOOL_CLI`` env → ``/tmp/apktool_ext/apktool`` → PATH."""
    env = os.environ.get("APKTOOL_CLI")
    if env and Path(env).is_file() and os.access(env, os.X_OK):
        return Path(env)
    vendored = Path("/tmp/apktool_ext/apktool")
    if vendored.is_file():
        return vendored
    root = Path(__file__).resolve().parents[2]
    jars = sorted((root / "vendor" / "android-tools").glob("apktool_*.jar"))
    if jars and shutil.which("java"):
        return jars[-1]
    which = shutil.which("apktool")
    return Path(which) if which else None


def _apktool_version(cli: Path, timeout: int = 30) -> str | None:
    env = os.environ.copy()
    env.pop("JAVA_TOOL_OPTIONS", None)
    env.pop("_JAVA_OPTIONS", None)
    try:
        prefix = (
            [shutil.which("java") or "java", "-jar", str(cli)]
            if cli.suffix == ".jar" else [str(cli)]
        )
        r = observed_run([*prefix, "--version"], capture_output=True, text=True,
                         timeout=timeout, check=False, env=env)
        if r.returncode == 0 and r.stdout:
            return r.stdout.strip().splitlines()[0]
    except (subprocess.TimeoutExpired, OSError):
        return None
    return None


# ------------------------------------------------------------------ manifest decode


_ANDROID = "{http://schemas.android.com/apk/res/android}"


def _parse_manifest_xml(xml_text: str) -> tuple[list[str], list[dict]]:
    """Parse apktool-decoded manifest.xml for permissions + exported components."""
    permissions: list[str] = []
    exported: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return permissions, exported
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1]
        if tag == "uses-permission":
            name = el.get(f"{_ANDROID}name") or el.get("android:name")
            if name:
                permissions.append(name)
        elif tag in ("activity", "activity-alias", "service", "provider", "receiver"):
            exp = el.get(f"{_ANDROID}exported") or el.get("android:exported")
            if exp == "true":
                name = el.get(f"{_ANDROID}name") or el.get("android:name")
                exported.append({"type": tag, "name": name or ""})
    return permissions, exported


# ------------------------------------------------------------------ driver


def decode_apk(
    apk_path: str | Path,
    *,
    cfg: Config | None = None,
    timeout: int = 180,
    skip_sources: bool = True,
    keep_output: str | Path | None = None,
    deadline_monotonic: float | None = None,
) -> ApktoolResult:
    """Run ``apktool d`` and return structured manifest/resources evidence.

    ``skip_sources=True`` (``-s``) skips DEX → smali decompile for speed when
    JADX already covers the code side; set False when smali text is wanted.
    """
    apk_path = Path(apk_path).expanduser().resolve()
    if not apk_path.is_file():
        return ApktoolResult(status="skipped", apk_path=str(apk_path),
                             note=f"missing: {apk_path}")
    cli = find_apktool(cfg)
    if cli is None:
        return ApktoolResult(status="unavailable", apk_path=str(apk_path),
                             note="apktool not found (set APKTOOL_CLI or vendor /tmp/apktool_ext/apktool)")

    ephemeral_output = keep_output is None
    publish_dir = Path(keep_output).expanduser().resolve() if keep_output else None
    if publish_dir is None:
        out_dir = Path(tempfile.mkdtemp(prefix="apktool-", dir=None))
    else:
        publish_dir.parent.mkdir(parents=True, exist_ok=True)
        out_dir = Path(tempfile.mkdtemp(
            prefix=f".{publish_dir.name}.staging-", dir=publish_dir.parent
        ))

    env = os.environ.copy()
    env.pop("JAVA_TOOL_OPTIONS", None)
    env.pop("_JAVA_OPTIONS", None)

    try:
        heap_mb = max(512, min(int(os.environ.get("ANGERONA_APKTOOL_HEAP_MB", "4096")), 8192))
    except ValueError:
        heap_mb = 4096
    if cli.suffix == ".jar":
        prefix = [shutil.which("java") or "java", f"-Xmx{heap_mb}m", "-jar", str(cli)]
    else:
        env["JAVA_OPTS"] = f"-Xmx{heap_mb}m"
        prefix = [str(cli)]
    jobs = max(1, min(8, os.cpu_count() or 1))
    cmd = [
        *prefix, "d", "--force", "--output", str(out_dir),
        "--jobs", str(jobs), "--no-assets",
    ]
    if skip_sources:
        cmd.append("--no-src")
    cmd.append(str(apk_path))

    errors: list[str] = []
    status = "success"
    log_parent = publish_dir.parent if publish_dir is not None else out_dir.parent
    log_handle = tempfile.NamedTemporaryFile(
        prefix=f".{out_dir.name}.angerona-apktool-",
        suffix=".log",
        dir=log_parent,
        delete=False,
    )
    log_path = Path(log_handle.name)
    log_handle.close()
    try:
        configured_idle = int(os.environ.get("ANGERONA_APKTOOL_IDLE_TIMEOUT_SECONDS", "600"))
    except ValueError:
        configured_idle = 600
    try:
        configured_wall = int(os.environ.get("ANGERONA_APKTOOL_WALL_TIMEOUT_SECONDS", "43200"))
    except ValueError:
        configured_wall = 43_200
    idle_timeout = max(60, min(max(timeout, configured_idle), 7_200))
    wall_timeout = max(idle_timeout, min(max(configured_wall, idle_timeout), 86_400))
    if deadline_monotonic is not None:
        remaining = max(0.001, deadline_monotonic - time.monotonic())
        wall_timeout = min(wall_timeout, remaining)
        idle_timeout = min(idle_timeout, wall_timeout)
    try:
        max_attempts = max(1, min(
            int(os.environ.get("ANGERONA_APKTOOL_ATTEMPTS", "2")), 3
        ))
    except ValueError:
        max_attempts = 2
    spawn_error: OSError | None = None
    for attempt in range(1, max_attempts + 1):
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            status = "partial"
            errors.append("apktool aggregate pre-AI deadline exhausted")
            break
        if attempt > 1:
            shutil.rmtree(out_dir, ignore_errors=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            jobs_index = cmd.index("--jobs") + 1
            cmd[jobs_index] = str(max(1, int(cmd[jobs_index]) // 2))
        try:
            attempt_wall = wall_timeout
            if deadline_monotonic is not None:
                attempt_wall = min(
                    attempt_wall,
                    max(0.001, deadline_monotonic - time.monotonic()),
                )
            with log_path.open("ab") as log:
                log.write(f"\nANGERONA_APKTOOL_ATTEMPT {attempt}/{max_attempts}\n".encode())
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
                            "ANGERONA_APKTOOL_MAX_RSS_MB", 6144,
                            minimum=1024, maximum=32768,
                        ) * 1024 * 1024,
                    ),
                    max_processes=bounded_env_int(
                        "ANGERONA_APKTOOL_MAX_PROCESSES", 128,
                        minimum=8, maximum=1024,
                    ),
                    resource_paths=[out_dir, log_path],
                    max_output_bytes=bounded_env_int(
                        "ANGERONA_APKTOOL_MAX_OUTPUT_GIB", 24,
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
            if result.returncode == 0:
                status = "success"
                if attempt > 1:
                    errors.append(f"apktool recovered on attempt {attempt}/{max_attempts}")
                break
            status = "partial"
            errors.append(
                f"apktool attempt {attempt}/{max_attempts} exited rc={result.returncode}"
            )
        except ProgressTimeoutExpired as exc:
            status = "partial"
            errors.append(
                f"apktool attempt {attempt}/{max_attempts} {exc.reason} "
                f"after {exc.elapsed_seconds:.1f}s "
                f"(progress_bytes={exc.progress_bytes}; progress_items={exc.progress_items})"
            )
        except OSError as exc:
            status = "unavailable"
            spawn_error = exc
            errors.append(
                f"apktool attempt {attempt}/{max_attempts} spawn failed: {exc}"
            )
        if attempt == max_attempts:
            try:
                tail = log_path.read_text(errors="replace").strip()
            except OSError:
                tail = ""
            if tail:
                errors.append(f"apktool log tail: {tail[-300:]}")

    if status == "unavailable":
        attempt_log = (
            persist_bounded_log(
                log_path,
                publish_dir.parent / f"{publish_dir.name}.ANGERONA_APKTOOL_ATTEMPTS.log",
            )
            if publish_dir is not None else {}
        )
        log_path.unlink(missing_ok=True)
        if ephemeral_output:
            shutil.rmtree(out_dir, ignore_errors=True)
        elif publish_dir is not None:
            shutil.rmtree(out_dir, ignore_errors=True)
        return ApktoolResult(status="unavailable", apk_path=str(apk_path),
                             errors=errors,
                             attempt_log=attempt_log,
                             note=f"apktool spawn failed: {spawn_error}")

    if status == "success" and publish_dir is not None:
        try:
            atomic_publish_directory(out_dir, publish_dir)
            out_dir = publish_dir
        except OSError as exc:
            status = "partial"
            errors.append(f"apktool output publish failed: {exc}")

    manifest_xml = ""
    manifest_file = out_dir / "AndroidManifest.xml"
    if manifest_file.is_file():
        try:
            manifest_xml = manifest_file.read_text(errors="ignore")
        except OSError as exc:
            errors.append(f"manifest read failed: {exc}")
    else:
        status = "partial" if status == "success" else status
        errors.append("AndroidManifest.xml not produced by apktool")

    permissions, exported = _parse_manifest_xml(manifest_xml) if manifest_xml else ([], [])

    smali_dirs = sorted(
        d.name for d in out_dir.iterdir()
        if d.is_dir() and (d.name == "smali" or d.name.startswith("smali_"))
    ) if out_dir.is_dir() else []
    smali_count = sum(
        1 for d in smali_dirs for _ in (out_dir / d).rglob("*.smali")
    )

    version = _apktool_version(cli)
    note = (
        f"manifest {'decoded' if manifest_xml else 'MISSING'}; "
        f"{len(permissions)} permission(s); {len(exported)} exported component(s); "
        f"{len(smali_dirs)} smali dir(s) / {smali_count} file(s)"
    )
    attempt_log = (
        persist_bounded_log(
            log_path,
            publish_dir.parent / f"{publish_dir.name}.ANGERONA_APKTOOL_ATTEMPTS.log",
        )
        if publish_dir is not None else {}
    )
    decoded = ApktoolResult(
        status=status,
        apk_path=str(apk_path),
        manifest_xml=manifest_xml,
        permissions=sorted(set(permissions)),
        exported_components=exported,
        smali_dirs=smali_dirs,
        smali_files_count=smali_count,
        apktool_version=version,
        errors=errors,
        attempt_log=attempt_log,
        note=note,
    )
    if ephemeral_output:
        shutil.rmtree(out_dir, ignore_errors=True)
    elif publish_dir is not None and out_dir != publish_dir:
        shutil.rmtree(out_dir, ignore_errors=True)
    log_path.unlink(missing_ok=True)
    return decoded


def get_decoded_manifest_text(apk_path: str | Path, **kwargs) -> str:
    """Convenience: return just the decoded manifest text (empty when unavailable)."""
    return decode_apk(apk_path, **kwargs).manifest_xml


def build_manifest(apk_path: str | Path, *, cfg: Config | None = None,
                   timeout: int = 180) -> ApktoolResult:
    """Assemble-manageable variant — used by downstream smali patches (future)."""
    return decode_apk(apk_path, cfg=cfg, timeout=timeout, skip_sources=False)
