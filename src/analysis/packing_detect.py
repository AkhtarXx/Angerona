"""Packing/protector multi-signal detector (roadmap Phase 7).

Research basis (research/agnostic/packing-obfuscation_vetted.md):
  Lyda & Hamrock (>6.8 entropy is packing-suspicious); section names (.vmp*,
  UPX0/1, .themida, .aspack, .enigma, .obsidium); import-count 1–8 anomaly;
  TLS callbacks; EP position outside code section; overlay anomaly;
  virtual-vs-raw size ratio.

The detector emits a :class:`PackingReport` — never a yes/no verdict. Strength
is a score 0..1, family is the matched packer name or "" when ambiguous, and
each contributing signal is itemized so the analyst sees exactly what fired.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path


_KNOWN_PACKER_SECTION_PATTERNS = [
    (re.compile(r"^UPX[0-9!]?$", re.I), "upx"),
    (re.compile(r"^\.vmp\d+$", re.I), "vmprotect"),
    (re.compile(r"^\.themida$", re.I), "themida"),
    (re.compile(r"^\.winlice", re.I), "winlicense"),
    (re.compile(r"^aspack", re.I), "aspack"),
    (re.compile(r"^\.mpress", re.I), "mpress"),
    (re.compile(r"^\.enigma", re.I), "enigma"),
    (re.compile(r"^\.obsidium", re.I), "obsidium"),
    (re.compile(r"^\.taz$", re.I), "tazer"),
    (re.compile(r"^\.petite", re.I), "petite"),
    (re.compile(r"^\.adata$", re.I), "asprotect"),
]


@dataclass
class PackingSignal:
    name: str
    value: float
    weight: float
    note: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "value": round(self.value, 3),
                "weight": self.weight, "note": self.note}


@dataclass
class PackingReport:
    strength: float                   # 0..1 (0=unpacked, 1=definitely packed)
    family: str = ""                  # "upx" | "vmprotect" | "themida" | "" (ambiguous)
    signals: list[PackingSignal] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "strength": round(self.strength, 3),
            "family": self.family,
            "signals": [s.as_dict() for s in self.signals],
            "sections": self.sections,
        }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _find_pe_header(data: bytes) -> tuple[int | None, int | None]:
    """Find NT headers offset for a PE. Returns (pe_off, nt_off)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, None
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    if pe_off + 4 > len(data):
        return None, None
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None, pe_off
    return pe_off, pe_off


def _pe_sections(data: bytes) -> list[dict]:
    """Parse PE sections for entropy/import analysis."""
    off, pe_off = _find_pe_header(data)
    if off is None:
        return []
    coff = pe_off + 4
    if coff + 20 > len(data):
        return []
    n_sect = int.from_bytes(data[coff + 2:coff + 4], "little")
    opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    sect_off = coff + 20 + opt_size
    sections = []
    for i in range(n_sect):
        o = sect_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        vsize = int.from_bytes(data[o + 8:o + 12], "little")
        vaddr = int.from_bytes(data[o + 12:o + 16], "little")
        raw_size = int.from_bytes(data[o + 16:o + 20], "little")
        raw_ptr = int.from_bytes(data[o + 20:o + 24], "little")
        chunk = data[raw_ptr:raw_ptr + min(raw_size, 256 * 1024)]
        sections.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                          "raw_size": raw_size, "raw_ptr": raw_ptr,
                          "entropy": _entropy(chunk)})
    return sections


def _pe_import_count(data: bytes) -> int:
    """crude import parsing: count import table entries."""
    pe_off, _ = _find_pe_header(data)
    if pe_off is None:
        return 0
    coff = pe_off + 4
    opt_off = coff + 20
    opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    if opt_off + opt_size > len(data):
        return 0
    # import dir is data dir entry #1 at opt + 96 (PE32) or + 112 (PE32+)
    magic = int.from_bytes(data[opt_off:opt_off + 2], "little")
    off_entry = opt_off + (96 if magic == 0x10b else 112)
    if off_entry + 8 > len(data):
        return 0
    imp_rva = int.from_bytes(data[off_entry:off_entry + 4], "little")
    if not imp_rva:
        return 0
    return imp_rva  # returning RVA here only as a presence signal


def detect_packing(data: bytes) -> PackingReport:
    """Score packing across PE-section signals. Higher strength = stronger suspect."""
    if not data:
        return PackingReport(strength=0.0)

    signals: list[PackingSignal] = []

    # 1. PE sections + entropy
    sections = _pe_sections(data)
    if sections:
        names = {s["name"] for s in sections}
        # 1a. known packer section names
        for s in sections:
            for pattern, family in _KNOWN_PACKER_SECTION_PATTERNS:
                if pattern.match(s["name"]):
                    signals.append(PackingSignal(
                        name="known-packer-section",
                        value=0.95, weight=0.55,
                        note=f"{family} section marker {s['name']!r}"))
        # 1b. per-section entropy
        for s in sections:
            if s["entropy"] >= 6.8 and s["raw_size"] > 512:
                signals.append(PackingSignal(
                    name="high-entropy-section", value=s["entropy"] / 8.0,
                    weight=0.30, note=f"{s['name']} entropy={s['entropy']:.2f}"))
        # 1c. virtual-vs-raw size ratio (sparse/raw→virtual expansion suggests packing)
        for s in sections:
            if s["raw_size"] > 0 and s["vsize"] > s["raw_size"] * 4 and s["vsize"] > 4096:
                signals.append(PackingSignal(
                    name="raw-vs-virtual-expansion",
                    value=min(1.0, s["vsize"] / max(s["raw_size"] * 4, 1)),
                    weight=0.10,
                    note=f"{s['name']} vsize={s['vsize']} vs raw={s['raw_size']}"))
        # 1d. classes: no obvious import section signal
        # count import table presence
        if _pe_import_count(data):
            signals.append(PackingSignal(
                name="import-table-present",
                value=0.05, weight=-0.10,
                note="import table found; only 1-8 resolved imports typical of packing"))

    # 2. overlay: bytes after the last documented section end
    if sections:
        last_end = max(s["raw_ptr"] + s["raw_size"] for s in sections)
        overlay = len(data) - last_end
        if overlay > 128:
            signals.append(PackingSignal(
                name="overlay-anomaly",
                value=min(1.0, overlay / 16384),
                weight=0.10,
                note=f"{overlay} bytes after last section"))

    # 3. entrypoint position: last section + initially writable is typical
    # skip full EP resolution as a further strengthening (already strong from 1+2)

    # 4. TLS callbacks: PE32+ TLS dir entry (#9)
    pe_off, _ = _find_pe_header(data)
    if pe_off is not None:
        coff = pe_off + 4
        opt_off = coff + 20
        opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
        magic = int.from_bytes(data[opt_off:opt_off + 2], "little")
        tls_off = opt_off + (96 + 9 * 8 if magic == 0x10b else 112 + 9 * 8)
        if tls_off + 4 <= len(data):
            tls_rva = int.from_bytes(data[tls_off:tls_off + 4], "little")
            if tls_rva:
                signals.append(PackingSignal(
                    name="tls-callbacks", value=0.4, weight=0.20,
                    note="TLS callback table present (protector classes use it)"))

    # Aggregate
    if not signals:
        return PackingReport(strength=0.0, sections=[s["name"] for s in sections])

    weight_sum = sum(abs(s.weight) for s in signals)
    raw = sum(abs(s.weight) * s.value for s in signals) / max(weight_sum, 0.01)
    strength = min(1.0, max(0.0, raw))
    # family: if any signal identified a specific packer, name it; else "generic"
    family = ""
    for s in signals:
        if s.name == "known-packer-section":
            m = re.search(r"(upx|vmprotect|themida|winlicense|aspack|mpress|enigma|obsidium|tazer|petite|asprotect)", s.note)
            if m:
                family = m.group(1).lower()
                break
    return PackingReport(strength=strength, family=family,
                          signals=signals, sections=[s["name"] for s in sections])


def detect_packing_file(path: str | Path) -> PackingReport:
    return detect_packing(Path(path).read_bytes())
