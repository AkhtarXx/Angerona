"""Baseline registry for upstream source-differencing.

The differ (``upstream_source_differ``) is only useful if a *known-good
baseline* exists.  This registry manages those baselines on disk under a
predictable layout:

    <base_root>/<package>/<version>.json
    <base_root>/<package>/latest.json      — pointer to the newest version

Writes are JSON; reads are tolerant of missing/corrupt entries.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"


@dataclass
class BaselineEntry:
    package: str
    version: str
    path: Path
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "path": str(self.path),
            "note": self.note,
            "trust": self.trust,
        }


@dataclass
class BaselineRegistry:
    root: Path

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def _pkg_dir(self, package: str) -> Path:
        safe = "".join(c for c in package if c.isalnum() or c in "._-")
        if not safe:
            raise ValueError(f"invalid package name: {package!r}")
        d = self.root / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _version_path(self, package: str, version: str) -> Path:
        return self._pkg_dir(package) / f"{version}.json"

    def _latest_path(self, package: str) -> Path:
        return self._pkg_dir(package) / "latest.json"


def save_baseline_to_registry(
    registry: BaselineRegistry,
    package: str,
    version: str,
    index: dict,
    *,
    note: str = "",
) -> BaselineEntry:
    """Persist a baseline index + mark as latest."""
    if not package:
        raise ValueError("package required")
    if not version:
        raise ValueError("version required")
    path = registry._version_path(package, version)
    payload = {
        "name": package,
        "version": version,
        "index": index,
        "tool": "angerona.baseline_registry",
        "note": note,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    # latest-pointer
    latest_payload = {"package": package, "version": version, "path": str(path)}
    registry._latest_path(package).write_text(json.dumps(latest_payload, indent=2))
    return BaselineEntry(package=package, version=version, path=path, note=note)


def load_baseline_from_registry(
    registry: BaselineRegistry,
    package: str,
    version: str | None = None,
) -> dict | None:
    """Load a specific version or the registry's ``latest`` pointer."""
    if version is None:
        latest_p = registry._latest_path(package)
        if not latest_p.is_file():
            return None
        try:
            info = json.loads(latest_p.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        version = info.get("version")
        if not version:
            return None
    p = registry._version_path(package, version)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def list_packages(registry: BaselineRegistry) -> list[str]:
    """Enumerate packages the registry has baselines for."""
    return sorted(d.name for d in registry.root.iterdir() if d.is_dir())


def list_versions(registry: BaselineRegistry, package: str) -> list[str]:
    """List known versions for a given package."""
    d = registry._pkg_dir(package)
    return sorted(p.stem for p in d.glob("*.json") if p.stem != "latest")
