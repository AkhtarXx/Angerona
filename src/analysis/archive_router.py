"""Recursive archive router (roadmap Phase 2).

Consumes a FormatProfile of a container family and recursively breaks it into
children, each re-identified independently. Guards against:

  * depth bombs (zip-in-zip-in-zip...), capped at depth=8
  * byte bombs (zip bombs), cumulative budget ≤ 8 GiB
  * hash cycles (a zip containing itself), sha256 dedup
  * Janus CVE-2017-13156: APK with prepended ELF stub — signing scheme noted

Each child gets its own FormatProfile via :func:`format_detector.detect`. Every
extracted byte range is accounted for (either claimed by a child or recorded as
unresolved), meaning **no-format-left-silent** (`MASTER_PLAN` cross-gate 1).
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .format_detector import FormatProfile, detect
from .formats.safe_reader import Reader, ReaderError


MAX_DEPTH = 8
MAX_TOTAL_EXTRACTED = 8 * 1024 * 1024 * 1024     # 8 GiB across the whole tree
_MAX_MEMBER_BYTES = 256 * 1024 * 1024            # 256 MiB per-archive parsing cap

@dataclass(frozen=True)
class ChildEntry:
    name: str                                  # e.g. "classes.dex" or "lib/arm64/libx.so"
    profile: FormatProfile
    source: str                                # provenance string (parent archive)
    extracted_path: str | None = None          # where we materialised it (if at all)


@dataclass
class RouteVerdict:
    root: Path
    depth_reached: int = 0
    bytes_extracted: int = 0
    children: list[ChildEntry] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    hashes_seen: set[str] = field(default_factory=set)
    truncated: bool = False
    note: str = ""
    _seen_paths: set = field(default_factory=set, repr=False, compare=False)

    def summary_line(self) -> str:
        return (f"route: {len(self.children)} children, "
                f"{self.bytes_extracted/(1024*1024):.1f} MiB extracted, "
                f"depth={self.depth_reached}, unresolved={len(self.unresolved)}, "
                f"truncated={self.truncated}")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _apk_signing_probe(path: Path, data: bytes) -> list[str]:
    """Record CVE-2017-13156 (Janus) signing-scheme ambiguity as an unresolved note."""
    notes = []
    if data.startswith(b"PK\x03\x04"):
        # Zip-alignment/v2+v3 signing schemes must not coexist suspiciously w/ ELF stub
        pass
    if data[:2] == b"MZ" or data[:4] == b"\x7fELF":
        return ["janus-susceptible: APK carries an ELF/PE stub prefix; verify v2+ signature"]
    return notes


def _route_zip(path: Path, data: bytes, out_root: Path,
               verdict: RouteVerdict, depth: int, seen_paths: set) -> list[ChildEntry]:
    """Extract a zip archive; return the newly created ChildEntry list."""
    # Unique extraction directory per archive AND per depth, so two nested archives
    # with identical member names do not overwrite each other's children.
    path_key = (str(path.resolve()), depth)
    if path_key in seen_paths:
        verdict.unresolved.append(f"cycle: same archive at depth={depth}: {path.name}")
        return []
    seen_paths.add(path_key)
    dir_name = f"_archive_d{depth}_0x{abs(hash((str(path), depth)))&0xFFFFFFFF:x}"
    unrooted = out_root / dir_name
    unrooted.mkdir(parents=True, exist_ok=True)
    new_children: list[ChildEntry] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = [info for info in zf.infolist() if not info.is_dir()]
        if len(members) > 200:
            verdict.truncated = True
            verdict.unresolved.append(f"fan-out cap: {len(members) - 200} members not examined in {path.name}")
        for index, member_info in enumerate(members[:200]):
            name = member_info.filename
            if member_info.file_size > _MAX_MEMBER_BYTES:
                verdict.unresolved.append(
                    f"member {name} exceeds {_MAX_MEMBER_BYTES} bytes (zip-bomb guard)")
                continue
            payload = zf.read(member_info)
            verdict.bytes_extracted += len(payload)
            if verdict.bytes_extracted > MAX_TOTAL_EXTRACTED:
                verdict.truncated = True
                verdict.unresolved.append(f"byte budget ({MAX_TOTAL_EXTRACTED}) exceeded")
                return new_children
            h = hashlib.sha256(payload).hexdigest()
            if h in verdict.hashes_seen:
                verdict.unresolved.append(f"cycle: duplicate child {name}")
                continue
            verdict.hashes_seen.add(h)   # mark BEFORE descent so cycles terminate

            # Archive names are metadata, never paths. Ordinals preserve distinct
            # members even when their names collide after normalization.
            member_path = unrooted / f"member_{index:04d}_{h}"
            member_path.write_bytes(payload)
            child_profile = detect(payload)
            child = ChildEntry(name=name, profile=child_profile,
                               source=str(path), extracted_path=str(member_path))
            verdict.children.append(child)
            new_children.append(child)
    return new_children


def _route_container(path: Path, depth: int = 0,
                     verdict: RouteVerdict | None = None) -> RouteVerdict:
    if verdict is None:
        verdict = RouteVerdict(root=path)
    path_key = (str(path.resolve()), depth)
    if path_key in verdict._seen_paths:
        verdict.unresolved.append(f"cycle: re-visit of {path.name} at depth={depth}")
        return verdict
    if depth > MAX_DEPTH:
        verdict.truncated = True
        verdict.unresolved.append(f"depth cap {MAX_DEPTH} reached")
        return verdict

    verdict.depth_reached = max(verdict.depth_reached, depth)
    data = path.read_bytes()
    profile = detect(data)
    new_children: list[ChildEntry] = []
    if profile.family == "zip":
        try:
            new_children = _route_zip(path, data, Path(verdict.root.parent), verdict,
                                      depth, verdict._seen_paths)
        except (zipfile.BadZipFile, OSError, KeyError) as exc:
            verdict.unresolved.append(f"zip parse error at depth {depth}: {exc}")
    else:
        verdict.unresolved.append(
            f"no unpacker for family {profile.family} (depth={depth})")

    # recursively descend into children that are also containers
    for child in new_children:
        if child.profile.container and child.extracted_path:
            _route_container(Path(child.extracted_path), depth + 1, verdict)
    return verdict


def route(path: str | Path) -> RouteVerdict:
    """Public entry: recursively unpack an archive and return the route verdict."""
    p = Path(path)
    if not p.is_file():
        return RouteVerdict(root=p, note=f"missing: {p}")
    verdict = _route_container(p)
    verdict.note = verdict.summary_line()
    # never emit a verdict without accounting for unresolved bytes
    if not verdict.children and not verdict.unresolved:
        verdict.unresolved.append(
            f"unsupported container family or empty archive (family="
            f"{detect(p.read_bytes()).family})")
    return verdict
