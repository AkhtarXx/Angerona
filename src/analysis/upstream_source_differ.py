"""Upstream source-differencing — production APK vs known-good release.

For apps that are (a) in your canonical registry, and (b) whose official
release metadata you can fetch from a controlled baseline (Play Store, GitHub
releases, vendor website), comparing *production* APK to *known-good* is the
strongest repack-detection signal.

This module computes a coarse structural diff:
  * DEX file hashes (every classesN.dex)
  * Manifest XML SHA-256
  * Native lib SHA-256 per .so
  * Asset signature index (filenames × SHA-1)

Given a *baseline* manifest (a prior audit's artifact, or a fetched known-
good release's hashes), it emits CHANGED / ADDED / REMOVED entries for each.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import CONFIRMED, LIKELY, INCONCLUSIVE, Finding

TRUST_TAG = "untrusted_child"


@dataclass
class DiffEntry:
    category: str           # dex | manifest | native | asset
    member: str
    status: str              # added | removed | changed | unknown
    baseline_hash: str
    current_hash: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "category": self.category, "member": self.member,
            "status": self.status,
            "baseline_hash": self.baseline_hash,
            "current_hash": self.current_hash,
            "trust": self.trust,
        }


@dataclass
class SourceDiffResult:
    status: str                 # ok | baseline_missing | partial | error
    apk_path: str
    baseline_name: str
    baseline_version: str
    current_version: str
    diffs: list[DiffEntry]
    summary: dict[str, int]     # {"added": N, "removed": N, "changed": N}
    note: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "apk_path": self.apk_path,
            "baseline_name": self.baseline_name,
            "baseline_version": self.baseline_version,
            "current_version": self.current_version,
            "diffs": [d.as_dict() for d in self.diffs],
            "summary": self.summary,
            "note": self.note,
            "trust": self.trust,
        }


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def index_apk(apk_path: str | Path) -> dict[str, dict[str, str]]:
    """Compute per-category member hashes for an APK."""
    out: dict[str, dict[str, str]] = {"dex": {}, "manifest": {}, "native": {}, "asset": {}}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if name.endswith(".dex"):
                    out["dex"][name] = _sha256(zf.read(name))
                elif name == "AndroidManifest.xml":
                    out["manifest"][name] = _sha256(zf.read(name))
                elif name.endswith(".so"):
                    out["native"][name] = _sha256(zf.read(name))
                elif name.startswith("assets/"):
                    out["asset"][name] = hashlib.sha1(zf.read(name)).hexdigest()
    except (zipfile.BadZipFile, OSError):
        pass
    return out


def save_baseline(idx: dict[str, dict[str, str]], out_path: str | Path,
                  *, name: str, version: str) -> None:
    data = {
        "name": name, "version": version, "index": idx,
        "tool": "angerona.upstream_source_differ",
    }
    Path(out_path).write_text(json.dumps(data, indent=2, sort_keys=True))


def load_baseline(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def diff_against_baseline(
    current_apk: str | Path,
    baseline_path: str | Path,
) -> SourceDiffResult:
    """Compare an APK against a saved baseline index."""
    baseline_file = Path(baseline_path)
    if not baseline_file.is_file():
        return SourceDiffResult(
            status="baseline_missing", apk_path=str(current_apk),
            baseline_name="", baseline_version="", current_version="",
            diffs=[], summary={"added": 0, "removed": 0, "changed": 0},
            note=f"baseline not found: {baseline_file}",
        )
    baseline = load_baseline(baseline_file)
    base_idx = baseline.get("index", {})
    base_name = baseline.get("name", "")
    base_ver = baseline.get("version", "")

    try:
        with zipfile.ZipFile(current_apk) as zf:
            ver_field = zf.read("AndroidManifest.xml")
            cur_ver = f"sha256:{_sha256(ver_field)[:16]}"
    except (zipfile.BadZipFile, OSError):
        cur_ver = ""

    current = index_apk(current_apk)
    diffs: list[DiffEntry] = []
    summary = {"added": 0, "removed": 0, "changed": 0}

    for category in ("dex", "manifest", "native", "asset"):
        base_members = base_idx.get(category, {})
        cur_members = current.get(category, {})
        all_names = set(base_members) | set(cur_members)
        for member in sorted(all_names):
            b_hash = base_members.get(member, "")
            c_hash = cur_members.get(member, "")
            if not b_hash:
                status = "added"
                summary["added"] += 1
            elif not c_hash:
                status = "removed"
                summary["removed"] += 1
            elif b_hash != c_hash:
                status = "changed"
                summary["changed"] += 1
            else:
                continue
            diffs.append(DiffEntry(
                category=category, member=member, status=status,
                baseline_hash=b_hash, current_hash=c_hash,
            ))

    note = (
        f"comparing {base_name}@{base_ver} → current; "
        f"added={summary['added']} removed={summary['removed']} changed={summary['changed']}"
    )
    return SourceDiffResult(
        status="ok",
        apk_path=str(current_apk),
        baseline_name=base_name,
        baseline_version=base_ver,
        current_version=cur_ver,
        diffs=diffs,
        summary=summary,
        note=note,
    )


def diff_to_findings(result: SourceDiffResult) -> list[Finding]:
    """Convert diff rows into canonical Finding records for report fusion."""
    findings: list[Finding] = []
    for d in result.diffs:
        sev = {
            ("manifest", "changed"): "critical",
            ("dex", "changed"): "high",
            ("dex", "added"): "high",
            ("native", "changed"): "high",
            ("native", "added"): "medium",
            ("asset", "changed"): "medium",
        }.get((d.category, d.status), "low")
        vv = LIKELY
        if d.category == "manifest" and d.status == "changed":
            vv = CONFIRMED  # manifest tamper is a cryptographic fact
        findings.append(Finding(
            module="upstream_source_differ",
            kind=f"upstream-{d.status}-{d.category}",
            severity=sev,
            verdict=vv,
            detail=f"{d.member} {d.status} vs baseline",
            evidence=f"base={d.baseline_hash[:12]} cur={d.current_hash[:12]}",
            metadata={"category": d.category, "member": d.member, "status": d.status},
        ))
    return findings
