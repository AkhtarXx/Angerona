"""Frida Stalker trace ingest + static CFG correlator.

Angerona's ``native_anti_tamper_scanner`` produces a static hit-list of
addresses where anti-tamper *code* lives — but each hit is `uncorroborated=True`
until we know whether the running app ever actually *executes* them.  The
professional proves this with Frida's Stalker:  a coverage trace of basic
blocks the process actually ran.

This module accepts a Stalker trace (JSON lines:  `{"address": N, "tid": M}`)
or a flat list of hex addresses, and:

  * buckets the addresses per module (loaded library base → runtime coverage)
  * correlates against an input static hit-list, using **proper ELF
    virtual-address translation** (not naive `base + file_offset`) so
    matches are against the executable VADDR, not raw file bytes
  * re-emits the hit-list with each entry upgraded to `corroborated=True`
    (runtime-proven) or retained as `uncorroborated=True`

Trust: ``untrusted_child`` — runtime traces can be attacker-influenced.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from src.analysis.native_elf import PT_LOAD, parse_elf

TRUST_TAG = "untrusted_child"

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_HEX_ANY_RE = re.compile(r"^[0-9a-fA-F]{6,16}$")


@dataclass
class ModuleCoverage:
    module_name: str
    base: int
    size: int
    blocks_executed: int = 0
    addresses: list[int] = field(default_factory=list)


@dataclass
class CorrelatedFinding:
    original_offset: int          # file offset in the .so (as reported by static scan)
    vaddr: int                    # ELF virtual address (offset mapped via PT_LOAD)
    category: str
    runtime_executed: bool
    runtime_module: str
    runtime_address: int          # module_base + vaddr
    corroborated: bool
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "original_offset": self.original_offset,
            "vaddr": hex(self.vaddr),
            "category": self.category,
            "runtime_executed": self.runtime_executed,
            "runtime_module": self.runtime_module,
            "runtime_address": hex(self.runtime_address),
            "corroborated": self.corroborated,
            "trust": self.trust,
        }


@dataclass
class StalkerCorrelatorResult:
    status: str             # ok | empty_trace | no_modules
    modules_seen: list[ModuleCoverage]
    correlated_findings: list[CorrelatedFinding]
    uncorroborated_count: int
    corroborated_count: int
    note: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "modules_seen": [vars(m) for m in self.modules_seen],
            "correlated_findings": [c.as_dict() for c in self.correlated_findings],
            "uncorroborated_count": self.uncorroborated_count,
            "corroborated_count": self.corroborated_count,
            "note": self.note,
            "trust": self.trust,
        }


def parse_stalker_trace(text: str) -> list[int]:
    """Parse either JSON-lines ({"address": N} entries) or plain hex-address lines."""
    out: list[int] = []
    for line in text.splitlines():
        line = line.strip().strip(",")
        if not line:
            continue
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                addr = rec.get("address") or rec.get("addr")
                if addr is None:
                    continue
                if isinstance(addr, str):
                    addr = addr.strip()
                    if _HEX_RE.match(addr) or _HEX_ANY_RE.match(addr):
                        out.append(int(addr, 16))
                    else:
                        out.append(int(addr))
                else:
                    out.append(int(addr))
                continue
            except (ValueError, TypeError):
                continue
        token = line.split()[0] if " " in line else line
        if _HEX_RE.match(token):
            out.append(int(token, 16))
        elif _HEX_ANY_RE.match(token):
            out.append(int(token, 16))
        elif token.isdigit():
            out.append(int(token))
    return out


def parse_modules_text(text: str) -> list[ModuleCoverage]:
    """Parse `adb shell cat /proc/self/maps`-style or frida-ps style module list."""
    modules: list[ModuleCoverage] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, base_s, size_s = parts[0], parts[1], parts[2]
        try:
            base = int(base_s, 16)
            size = int(size_s, 16)
        except ValueError:
            continue
        modules.append(ModuleCoverage(
            module_name=Path(name).name,
            base=base, size=size,
        ))
    return modules


def file_offset_to_vaddr(so_bytes: bytes, offset: int) -> int | None:
    """Map a file offset to ELF virtual address via PT_LOAD segments.

    Returns None when the offset is outside every PT_LOAD mapping (e.g. inside
    section headers).  This is the correct translation; using
    ``module_base + offset`` directly is wrong whenever ``p_vaddr != p_offset``.
    """
    elf = parse_elf(so_bytes)
    if elf is None:
        return None
    for seg in elf.segments:
        if seg.p_type != PT_LOAD or seg.filesz == 0:
            continue
        if seg.offset <= offset < seg.offset + seg.filesz:
            return seg.vaddr + (offset - seg.offset)
    return None


def correlate(
    static_findings: Iterable[dict | object],
    trace_addresses: Iterable[int],
    modules: Iterable[ModuleCoverage],
    so_bytes_by_module: dict[str, bytes] | None = None,
) -> StalkerCorrelatorResult:
    """Correlate static findings against runtime coverage using ELF-aware VADDR.

    ``static_findings`` entries expose ``offset`` (file offset in the .so) and
    ``category``.  ``so_bytes_by_module[module_name]`` provides the ELF bytes
    for VADDR translation; missing entries fall back to offset-as-vaddr.
    """
    trace_set = set(trace_addresses)
    mods = list(modules)
    if not mods:
        return StalkerCorrelatorResult(
            status="no_modules", modules_seen=[], correlated_findings=[],
            uncorroborated_count=0, corroborated_count=0,
            note="no module ranges provided; correlation impossible",
        )

    if not trace_set:
        return StalkerCorrelatorResult(
            status="empty_trace", modules_seen=mods, correlated_findings=[],
            uncorroborated_count=0, corroborated_count=0,
            note="no runtime addresses in trace",
        )

    # bucket trace hits per module
    for addr in trace_set:
        for m in mods:
            if m.base <= addr < m.base + m.size:
                m.blocks_executed += 1
                m.addresses.append(addr)
                break

    correlated: list[CorrelatedFinding] = []
    corr = uncorr = 0
    for f in static_findings:
        offset = getattr(f, "offset", None) if not isinstance(f, dict) else f.get("offset")
        category = getattr(f, "category", "") if not isinstance(f, dict) else f.get("category", "")
        if offset is None:
            continue

        executed = False
        runtime_address = 0
        runtime_module = ""
        vaddr = 0

        # Try ELF-aware translation per module when we have the bytes
        candidate_module_name = ""
        if isinstance(f, dict):
            candidate_module_name = f.get("module", "") or f.get("source", "")
        else:
            candidate_module_name = getattr(f, "module", "") or getattr(f, "source", "")

        if candidate_module_name and candidate_module_name in (so_bytes_by_module or {}):
            vaddr_candidate = file_offset_to_vaddr(
                (so_bytes_by_module or {})[candidate_module_name], offset)
            if vaddr_candidate is not None:
                for m in mods:
                    if m.module_name == candidate_module_name:
                        runtime_candidate = m.base + vaddr_candidate
                        vaddr = vaddr_candidate
                        if runtime_candidate in trace_set:
                            executed = True
                            runtime_module = m.module_name
                            runtime_address = runtime_candidate
                        break
        if not executed and not candidate_module_name:
            # No module hint + no bytes — fall back to coarse match
            for m in mods:
                # ELF-aware when we have the .so for this module
                if (so_bytes_by_module or {}).get(m.module_name):
                    vaddr_candidate = file_offset_to_vaddr(
                        (so_bytes_by_module or {})[m.module_name], offset)
                    if vaddr_candidate is None:
                        continue
                    vaddr = vaddr_candidate
                    runtime_candidate = m.base + vaddr_candidate
                else:
                    # loose match: try treating offset as VADDR (guess)
                    vaddr = offset
                    runtime_candidate = m.base + offset
                if runtime_candidate in trace_set:
                    executed = True
                    runtime_module = m.module_name
                    runtime_address = runtime_candidate
                    break

        if executed:
            corr += 1
        else:
            uncorr += 1
        correlated.append(CorrelatedFinding(
            original_offset=offset, vaddr=vaddr, category=category,
            runtime_executed=executed, runtime_module=runtime_module,
            runtime_address=runtime_address,
            corroborated=executed,
        ))

    note = (
        f"{corr} findings runtime-corroborated, {uncorr} uncorroborated "
        f"(trace={len(trace_set)} addrs, {len(mods)} modules)"
    )
    return StalkerCorrelatorResult(
        status="ok", modules_seen=mods, correlated_findings=correlated,
        uncorroborated_count=uncorr, corroborated_count=corr,
        note=note,
    )
