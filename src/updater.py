"""Keep the vendored Ghidra runtime in sync with upstream releases.

Queries the GitHub Releases API for the latest official Ghidra build, compares
it with what is vendored under ``vendor/``, and downloads + extracts a newer one
on request. The engine always auto-selects the newest vendored release (see
``config.find_ghidra_install``), so updating is just "drop the new release in".
"""

from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import REPO_ROOT, _vendored_installs, parse_ghidra_version

RELEASES_LATEST_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
VENDOR_DIR = REPO_ROOT / "vendor"


@dataclass
class ReleaseInfo:
    tag: str
    version: tuple[int, ...]
    version_str: str
    asset_name: str
    download_url: str
    sha256: str | None = None


def _http_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "angerona", "Accept": "application/vnd.github+json"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # noqa: S310 - fixed host
        return json.loads(r.read().decode())


def latest_release() -> ReleaseInfo:
    data = _http_json(RELEASES_LATEST_API)
    tag = data.get("tag_name", "")
    asset = None
    for a in data.get("assets", []):
        name = a.get("name", "")
        if name.startswith("ghidra_") and name.endswith(".zip") and "PUBLIC" in name:
            asset = a
            break
    if not asset:
        raise RuntimeError(f"no PUBLIC .zip asset found in latest release ({tag})")
    version = parse_ghidra_version(asset["name"])
    # GitHub publishes asset digests via the "digest" field on newer API versions.
    digest = (asset.get("digest") or "").strip()
    sha256 = digest.removeprefix("sha256:") or None
    return ReleaseInfo(
        tag=tag,
        version=version,
        version_str=".".join(str(x) for x in version),
        asset_name=asset["name"],
        download_url=asset["browser_download_url"],
        sha256=sha256,
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip archive, rejecting path-traversal and absolute members.

    Zip-Slip hardening: every member's resolved final path must stay beneath
    ``dest``; symlinks are rejected outright.
    """
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(zip_path) as z:
        bad = z.testzip()
        if bad is not None:
            raise RuntimeError(f"downloaded zip is corrupt: {bad}")
        for info in z.infolist():
            name = info.filename
            if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                raise RuntimeError(f"unsafe zip member path: {name!r}")
            # external_attr high bits: unix mode; 0o120000 == symlink
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise RuntimeError(f"zip symlinks are not extracted: {name!r}")
            target = (dest_resolved / name).resolve()
            if not target.is_relative_to(dest_resolved):
                raise RuntimeError(f"zip member escapes destination: {name!r}")
        z.extractall(dest_resolved)


def installed_version() -> tuple[int, ...] | None:
    installs = _vendored_installs()
    return parse_ghidra_version(installs[0].name) if installs else None


def _download(url: str, dest: Path, on_progress=None) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "angerona"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:  # noqa: S310
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as f:
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if on_progress and total:
                    on_progress(done, total)


def update(*, check_only: bool = False, force: bool = False, prune: bool = False, on_progress=None) -> dict:
    """Check for and optionally install the newest Ghidra release.

    Returns a status dict. ``prune`` removes older vendored releases after a
    successful install.
    """
    latest = latest_release()
    current = installed_version()
    up_to_date = current is not None and current >= latest.version

    result = {
        "current_version": ".".join(str(x) for x in current) if current else None,
        "latest_version": latest.version_str,
        "latest_tag": latest.tag,
        "up_to_date": up_to_date,
        "action": "none",
    }

    if check_only or (up_to_date and not force):
        result["action"] = "up_to_date" if up_to_date else "check"
        return result

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    # asset like ghidra_12.1.2_PUBLIC_20260605.zip -> dir ghidra_12.1.2_PUBLIC
    extracted_name = "_".join(latest.asset_name.split("_")[:3])  # ghidra_12.1.2_PUBLIC
    target_dir = VENDOR_DIR / extracted_name

    if target_dir.exists() and not force:
        result["action"] = "already_present"
        result["install_dir"] = str(target_dir)
        return result

    zip_path = VENDOR_DIR / latest.asset_name
    _download(latest.download_url, zip_path, on_progress=on_progress)

    # Integrity + safe extraction.
    if latest.sha256:
        actual = _sha256_file(zip_path)
        if actual.lower() != latest.sha256.lower():
            zip_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"downloaded zip sha256 mismatch: expected {latest.sha256}, got {actual}"
            )
    try:
        _safe_extract(zip_path, VENDOR_DIR)
    except RuntimeError:
        zip_path.unlink(missing_ok=True)
        raise
    zip_path.unlink(missing_ok=True)

    if not (target_dir / "support" / "analyzeHeadless").exists():
        # Fall back: find whatever ghidra_*_PUBLIC just appeared.
        installs = _vendored_installs()
        target_dir = installs[0] if installs else target_dir

    result["action"] = "installed"
    result["install_dir"] = str(target_dir)

    if prune and current is not None:
        for old in _vendored_installs():
            if old != target_dir:
                shutil.rmtree(old, ignore_errors=True)
        result["pruned"] = True

    return result
