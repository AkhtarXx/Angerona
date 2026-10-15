"""Runtime exported-surface verification via adb.

Static manifest analysis is fiction on Android 12+ — components can be
enabled/disabled at runtime (``PackageManager.setComponentEnabledSetting``),
``DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`` hidden receivers exist, and AppOps
gates can mask what the manifest claims.  A professional always asks the
running system: which components are *actually* reachable?

This module wraps `adb shell` queries against a connected device/emulator:
  * ``dumpsys package <pkg>`` — real exported/reachable components
  * ``cmd package resolve-activity -a <action>`` — which component(s) resolve
  * ``appops get <pkg>`` — permission-to-AppOps actual grants

Design: degrades to status="no_device" gracefully when adb is missing or no
device connected — useful even in headless CI.

Trust: ``untrusted_child`` — device state is mutable; always corroborate.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..subprocess_observability import observed_run

TRUST_TAG = "untrusted_child"


@dataclass
class RuntimeSurfaceResult:
    status: str                     # ok | no_device | adb_missing | package_not_installed | error
    package: str
    device_serial: str = ""
    exported_activities: list[str] = field(default_factory=list)
    exported_services: list[str] = field(default_factory=list)
    exported_receivers: list[str] = field(default_factory=list)
    exported_providers: list[str] = field(default_factory=list)
    disabled_components: list[str] = field(default_factory=list)
    runtime_permissions_granted: list[str] = field(default_factory=list)
    runtime_permissions_denied: list[str] = field(default_factory=list)
    installed_version: str = ""
    note: str = ""
    errors: list[str] = field(default_factory=list)
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "package": self.package,
            "device_serial": self.device_serial,
            "exported_activities": self.exported_activities,
            "exported_services": self.exported_services,
            "exported_receivers": self.exported_receivers,
            "exported_providers": self.exported_providers,
            "disabled_components": self.disabled_components,
            "runtime_permissions_granted": self.runtime_permissions_granted,
            "runtime_permissions_denied": self.runtime_permissions_denied,
            "installed_version": self.installed_version,
            "note": self.note,
            "errors": self.errors,
            "trust": self.trust,
        }


def find_adb(cfg: Config | None = None) -> str | None:
    found = shutil.which("adb")
    if found:
        return found
    root = Path(__file__).resolve().parents[2]
    vendored = root / "vendor" / "android-tools" / "platform-tools" / "adb"
    return str(vendored) if vendored.is_file() and os.access(vendored, os.X_OK) else None


def _adb(adb: str, *args: str, timeout: int = 30, serial: str = "") -> tuple[int, str]:
    cmd = [adb]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    try:
        r = observed_run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as exc:
        return -1, str(exc)


def list_devices(adb: str, *, adb_server_port: int = 0) -> list[str]:
    args = (["-P", str(adb_server_port)] if adb_server_port else []) + ["devices"]
    _rc, out = _adb(adb, *args, timeout=15)
    serials = []
    for line in out.splitlines()[1:]:
        if "\tdevice" in line:
            serials.append(line.split("\t")[0].strip())
    return serials


ExportedKind = str
_SECTION_RE = {
    "activity": re.compile(r"^\s*Activity Resolver Table:", re.MULTILINE),
    "service": re.compile(r"^\s*Service Resolver Table:", re.MULTILINE),
    "receiver": re.compile(r"^\s*Receiver Resolver Table:", re.MULTILINE),
    "provider": re.compile(r"^\s*Provider Resolver Table:", re.MULTILINE),
}
_COMPONENT_RE = re.compile(r"([a-zA-Z0-9_.]+/[a-zA-Z0-9_.$]+)")
_DISABLED_RE = re.compile(r"disabled", re.IGNORECASE)


def _parse_dumpsys(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k in _SECTION_RE}
    current: ExportedKind | None = None
    for line in text.splitlines():
        for kind, rx in _SECTION_RE.items():
            if rx.search(line):
                current = kind
                break
        else:
            if current and "/" in line:
                for m in _COMPONENT_RE.finditer(line):
                    entry = m.group(1)
                    if entry not in out[current]:
                        out[current].append(entry)
            # stop scanning section on blank-line boundary
            if current and not line.strip():
                current = None
    return out


def _parse_permissions(text: str) -> tuple[list[str], list[str]]:
    granted: list[str] = []
    denied: list[str] = []
    in_requested = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("requested permissions:"):
            in_requested = True
            continue
        if s.startswith(("install permissions:", "runtime permissions:")):
            in_requested = False
            continue
        if in_requested and s.startswith("android.permission"):
            name = s.split(":")[0]
            if "granted=true" in s:
                granted.append(name)
            elif "granted=false" in s:
                denied.append(name)
    return granted, denied


def _parse_version(text: str) -> str:
    m = re.search(r"versionName=([^\s]+)", text)
    return m.group(1) if m else ""


def _parse_disabled(text: str) -> list[str]:
    """Extract disabled components — component name may appear on the line
    AFTER the "Disabled components:" section header."""
    out: list[str] = []
    in_disabled_section = False
    for line in text.splitlines():
        s = line.strip().lower()
        if "disabled components" in s or "disabled_packages" in s or s.startswith("disabled"):
            in_disabled_section = True
            continue
        if (
            in_disabled_section
            and (not s or s.endswith(":"))
            and not _COMPONENT_RE.search(line)
        ):
            in_disabled_section = False
            continue
        if in_disabled_section:
            for m in _COMPONENT_RE.finditer(line):
                entry = m.group(1)
                if entry not in out and "/" in entry:
                    out.append(entry)
    return out


def query_runtime_surface(
    package: str,
    *,
    cfg: Config | None = None,
    serial: str = "",
    timeout: int = 30,
    adb_path: str = "",
    adb_server_port: int = 0,
) -> RuntimeSurfaceResult:
    """Query the actual runtime surface for a package on a connected device."""
    adb = adb_path or find_adb(cfg)
    if not adb:
        return RuntimeSurfaceResult(
            status="adb_missing", package=package,
            note="adb binary not found on PATH",
        )
    serials = (
        list_devices(adb, adb_server_port=adb_server_port)
        if adb_server_port else list_devices(adb)
    )
    if not serials:
        return RuntimeSurfaceResult(
            status="no_device", package=package,
            note="no adb device connected",
        )
    if serial and serial not in serials:
        return RuntimeSurfaceResult(
            status="no_device", package=package, device_serial=serial,
            note="explicit runtime target is not online; first-device fallback refused",
        )
    if not serial and len(serials) != 1:
        return RuntimeSurfaceResult(
            status="error", package=package,
            note="multiple adb targets connected; explicit leased serial required",
        )
    serial = serial or serials[0]

    prefix = ["-P", str(adb_server_port)] if adb_server_port else []
    rc, out = _adb(
        adb, *prefix, "shell", "dumpsys", "package", package,
        serial=serial, timeout=timeout,
    )
    if rc != 0 or "Unable to find package" in out or not out.strip():
        return RuntimeSurfaceResult(
            status="package_not_installed", package=package,
            device_serial=serial,
            note=f"package {package} not on device (rc={rc})",
            errors=[out[-300:]] if out else [],
        )

    sections = _parse_dumpsys(out)
    granted, denied = _parse_permissions(out)
    disabled = _parse_disabled(out)
    version = _parse_version(out)

    return RuntimeSurfaceResult(
        status="ok",
        package=package,
        device_serial=serial,
        exported_activities=sorted(sections["activity"]),
        exported_services=sorted(sections["service"]),
        exported_receivers=sorted(sections["receiver"]),
        exported_providers=sorted(sections["provider"]),
        disabled_components=sorted(disabled),
        runtime_permissions_granted=sorted(granted),
        runtime_permissions_denied=sorted(denied),
        installed_version=version,
        note=(
            f"runtime surface: {len(sections['activity'])} act / "
            f"{len(sections['service'])} svc / {len(sections['receiver'])} rcv / "
            f"{len(sections['provider'])} prov — {len(disabled)} disabled"
        ),
    )
