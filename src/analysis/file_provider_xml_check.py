"""FileProvider paths.xml path-restriction verifier (file-provider-xml).

FileProvider with broad `<root-path path="."` or `<files-path path="../"``
grants read access far beyond intent.  This checks the paths.xml config.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, CONFIRMED, Finding

TRUST_TAG = "untrusted_child"

_ROOT_PATH = re.compile(r'<root-path\s+[^>]*path\s*=\s*"([^"]+)"')
_FILES_PATH = re.compile(r'<files-path\s+[^>]*path\s*=\s*"([^"]+)"')
_CACHE_PATH = re.compile(r'<cache-path\s+[^>]*path\s*=\s*"([^"]+)"')
# A <root-path> element with the path attribute omitted (FileProvider resolves
# it to the device filesystem root '/') — the regex above requires an explicit
# path="...", so match the omitted form separately via a negative lookahead.
_ROOT_PATH_OMITTED = re.compile(r'<root-path\b(?![^>]*\bpath\s*=)[^>]*>')
_PROVIDER_NAME = re.compile(
    r'<provider[^>]*android:name="([^"]+)"[^>]*android:authorities="([^"]+)"'
)


@dataclass
class FileProviderResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {"status": self.status, "findings": [f.as_dict() for f in self.findings],
                "note": self.note, "trust": self.trust}


def scan_manifest_and_paths(manifest: str, paths_xml: str) -> FileProviderResult:
    findings: list[Finding] = []
    for xml_text in (paths_xml, manifest):
        if not xml_text:
            continue
        # suspicious wide-open path configurations
        for rx, label in ((_ROOT_PATH, "root-path"), (_FILES_PATH, "files-path"),
                          (_CACHE_PATH, "cache-path")):
            for m in rx.finditer(xml_text):
                path_val = m.group(1)
                bad = path_val in (".", "/", "..", "../", "*", "")
                if bad:
                    findings.append(Finding(
                        module="file_provider_xml_check",
                        kind="file-provider-xml",
                        severity="high",
                        verdict=LIKELY,
                        detail=f"FileProvider {label} path '{path_val}' too permissive",
                        evidence=m.group(0)[:200],
                    ))
                elif path_val.startswith("/") or path_val.startswith(".."):
                    findings.append(Finding(
                        module="file_provider_xml_check",
                        kind="file-provider-xml",
                        severity="medium",
                        verdict=LIKELY,
                        detail=f"FileProvider {label} path '{path_val}' exposes parent directories",
                        evidence=m.group(0)[:200],
                    ))
        # <root-path> with no path attribute maps to the filesystem root '/',
        # the maximally permissive config — flag it at the same severity as an
        # explicit path="." / path="/".
        for m in _ROOT_PATH_OMITTED.finditer(xml_text):
            findings.append(Finding(
                module="file_provider_xml_check",
                kind="file-provider-xml",
                severity="high",
                verdict=LIKELY,
                detail="FileProvider root-path path '/' too permissive",
                evidence=m.group(0)[:200],
            ))
    return FileProviderResult(status="success", findings=findings,
                              note=f"{len(findings)} FileProvider path finding(s)")


def scan_apk(apk_path: str | Path) -> FileProviderResult:
    apk = Path(apk_path)
    if not apk.is_file():
        return FileProviderResult(status="skipped", note=f"missing: {apk}")
    try:
        with zipfile.ZipFile(apk) as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return FileProviderResult(status="skipped",
                                          note="AndroidManifest.xml missing")
            manifest = zf.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
            paths = ""
            paths_files: list[str] = []
            for name in zf.namelist():
                # Match any res/xml/*.xml whose name contains 'path' (singular/plural) OR is manifest-referenced.
                if name.endswith("xml") and ("xml" in name.lower()):
                    if "path" in name.lower() or "provider" in name.lower():
                        paths_files.append(name)
            if not paths_files:
                # Fallback: look in res/xml/ directory explicitly
                paths_files = [n for n in zf.namelist() if n.startswith("res/xml/") and n.endswith(".xml")]
            for pf in paths_files:
                try:
                    content = zf.read(pf).decode("utf-8", errors="ignore")
                    if "path" in content or "provider" in content:
                        paths += content + "\n"  # gather ALL configs, not first match
                except (OSError, KeyError):
                    continue
    except (zipfile.BadZipFile, OSError):
        return FileProviderResult(status="error", note="apk unreadable")
    return scan_manifest_and_paths(manifest, paths)
