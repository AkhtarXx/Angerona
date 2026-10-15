"""Minimal, dependency-free ELF parsing for Android native-library analysis.

Purpose-built for the native .so tooling (JNI registration resolution,
anti-tamper scanning, constructor pre-emulation, key carving).  Deliberately
narrow: section headers, program headers, dynamic segment, and symbol tables
— nothing else.  All hostile-input reads are bounds-checked; malformed files
produce partial results, never exceptions, through :func:`parse_elf`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_RELRO = 0x6474E552

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_DYNAMIC = 6

SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

DT_NULL = 0
DT_NEEDED = 1
DT_INIT = 12
DT_FINI = 13
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAY = 26
DT_FINI_ARRAYSZ = 28


@dataclass(frozen=True)
class SectionInfo:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def writable(self) -> bool:
        return bool(self.flags & SHF_WRITE)


@dataclass(frozen=True)
class SegmentInfo:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)

    @property
    def writable(self) -> bool:
        return bool(self.flags & PF_W)


@dataclass(frozen=True)
class SymbolInfo:
    name: str
    addr: int
    size: int
    imported: bool  # st_shndx == SHN_UNDEF


@dataclass
class NativeElf:
    """Parsed ELF view with vaddr→offset translation helpers."""

    is64: bool
    endian: str  # "<" or ">"
    machine: int
    sections: list[SectionInfo] = field(default_factory=list)
    segments: list[SegmentInfo] = field(default_factory=list)
    dynamic: dict[int, list[int]] = field(default_factory=dict)
    symbols: list[SymbolInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # -- helpers ---------------------------------------------------------
    def vaddr_to_offset(self, vaddr: int) -> int | None:
        for seg in self.segments:
            if seg.p_type != PT_LOAD or seg.filesz == 0:
                continue
            if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                return seg.offset + (vaddr - seg.vaddr)
        return None

    def read_at(self, data: bytes, vaddr: int, n: int) -> bytes | None:
        off = self.vaddr_to_offset(vaddr)
        if off is None or off + n > len(data):
            return None
        return data[off : off + n]

    def c_string_at(self, data: bytes, vaddr: int, max_len: int = 512) -> str | None:
        if vaddr == 0:
            return None
        for seg in self.segments:
            if seg.p_type != PT_LOAD:
                continue
            if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                off = seg.offset + (vaddr - seg.vaddr)
                end = min(off + max_len, seg.offset + seg.filesz, len(data))
                chunk = data[off:end]
                nul = chunk.find(b"\x00")
                if nul >= 0:
                    chunk = chunk[:nul]
                if not chunk:
                    return None
                try:
                    return chunk.decode("ascii")
                except UnicodeDecodeError:
                    return None
        return None

    def exec_ranges(self) -> list[tuple[int, int]]:
        """(vaddr, size) pairs of executable sections."""
        sections = [(s.addr, s.size) for s in self.sections if s.executable and s.size]
        if sections:
            return sections
        # Stripped/sectionless Android ELF files still expose executable PT_LOAD
        # segments.  Falling back here prevents an empty section table from
        # disguising the native code surface as zero bytes.
        return [
            (segment.vaddr, segment.filesz)
            for segment in self.segments
            if segment.p_type == PT_LOAD and segment.executable and segment.filesz
        ]

    def in_exec(self, vaddr: int) -> bool:
        return any(a <= vaddr < a + n for a, n in self.exec_ranges())

    def read_ptr(self, data: bytes, vaddr: int) -> int | None:
        n = 8 if self.is64 else 4
        raw = self.read_at(data, vaddr, n)
        if raw is None:
            return None
        return struct.unpack(self.endian + ("Q" if self.is64 else "I"), raw)[0]


def parse_elf(data: bytes) -> NativeElf | None:
    """Best-effort parse. Returns None only when the file is not ELF."""
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        return None
    is64 = data[4] == 2
    if data[4] not in (1, 2):
        return None
    if data[5] == 1:
        en = "<"
    elif data[5] == 2:
        en = ">"
    else:
        return None  # hostile: EI_DATA must be 1|2; garbage is NOT big-endian
    hdr_need = 64 if is64 else 52
    if len(data) < hdr_need:
        return None
    # ELITE-1 R2 FRESH-1: phoff/shoff sanity — hostile offset would let an
    # attacker inject fake PT_LOAD/pshdr entries from arbitrary bytes.
    if is64:
        phoff_probe = struct.unpack(en + "Q", data[32:40])[0]
        shoff_probe = struct.unpack(en + "Q", data[40:48])[0]
    else:
        phoff_probe = struct.unpack(en + "I", data[28:32])[0]
        shoff_probe = struct.unpack(en + "I", data[32:36])[0]
    if phoff_probe and (phoff_probe < hdr_need or phoff_probe > len(data)):
        return None
    if shoff_probe and (shoff_probe < hdr_need or shoff_probe > len(data)):
        return None

    if is64:
        machine = struct.unpack(en + "H", data[18:20])[0]
        e_phoff = struct.unpack(en + "Q", data[32:40])[0]
        e_shoff = struct.unpack(en + "Q", data[40:48])[0]
        e_phentsize = struct.unpack(en + "H", data[54:56])[0]
        e_phnum = struct.unpack(en + "H", data[56:58])[0]
        e_shentsize = struct.unpack(en + "H", data[58:60])[0]
        e_shnum = struct.unpack(en + "H", data[60:62])[0]
        e_shstrndx = struct.unpack(en + "H", data[62:64])[0]
    else:
        machine = struct.unpack(en + "H", data[18:20])[0]
        e_phoff = struct.unpack(en + "I", data[28:32])[0]
        e_shoff = struct.unpack(en + "I", data[32:36])[0]
        e_phentsize = struct.unpack(en + "H", data[42:44])[0]
        e_phnum = struct.unpack(en + "H", data[44:46])[0]
        e_shentsize = struct.unpack(en + "H", data[46:48])[0]
        e_shnum = struct.unpack(en + "H", data[48:50])[0]
        e_shstrndx = struct.unpack(en + "H", data[50:52])[0]

    elf = NativeElf(is64=is64, endian=en, machine=machine)

    # ---- program headers ----
    ph_need = 56 if is64 else 32
    if e_phentsize < ph_need:
        e_phnum = 0  # hostile/punt: no valid-phdr table possible
    seen_ph_off = -1
    for i in range(min(e_phnum, 4096)):
        off = e_phoff + i * e_phentsize
        if off == seen_ph_off:
            break  # zero-stride hostile input
        seen_ph_off = off
        if off + ph_need > len(data):
            break
        p_type = struct.unpack(en + "I", data[off : off + 4])[0]
        if is64:
            p_flags = struct.unpack(en + "I", data[off + 4 : off + 8])[0]
            p_offset = struct.unpack(en + "Q", data[off + 8 : off + 16])[0]
            p_vaddr = struct.unpack(en + "Q", data[off + 16 : off + 24])[0]
            p_filesz = struct.unpack(en + "Q", data[off + 32 : off + 40])[0]
            p_memsz = struct.unpack(en + "Q", data[off + 40 : off + 48])[0]
        else:
            p_offset = struct.unpack(en + "I", data[off + 4 : off + 8])[0]
            p_vaddr = struct.unpack(en + "I", data[off + 8 : off + 12])[0]
            p_filesz = struct.unpack(en + "I", data[off + 16 : off + 20])[0]
            p_memsz = struct.unpack(en + "I", data[off + 20 : off + 24])[0]
            p_flags = struct.unpack(en + "I", data[off + 24 : off + 28])[0]
        elf.segments.append(SegmentInfo(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
        if p_type == PT_DYNAMIC:
            _parse_dynamic(elf, data, p_offset, p_filesz)

    # ---- section headers ----
    sh_raw: list[tuple[int, int, int, int, int, int, int, int]] = []
    sh_need = 64 if is64 else 40
    if e_shentsize < sh_need:
        e_shnum = 0
    seen_sh_off = -1
    for i in range(min(e_shnum, 16384)):
        off = e_shoff + i * e_shentsize
        if off == seen_sh_off:
            break
        seen_sh_off = off
        if off + sh_need > len(data):
            break
        sh_name = struct.unpack(en + "I", data[off : off + 4])[0]
        sh_type = struct.unpack(en + "I", data[off + 4 : off + 8])[0]
        if is64:
            sh_flags = struct.unpack(en + "Q", data[off + 8 : off + 16])[0]
            sh_addr = struct.unpack(en + "Q", data[off + 16 : off + 24])[0]
            sh_offset = struct.unpack(en + "Q", data[off + 24 : off + 32])[0]
            sh_size = struct.unpack(en + "Q", data[off + 32 : off + 40])[0]
            sh_link = struct.unpack(en + "I", data[off + 40 : off + 44])[0]
            sh_entsize = struct.unpack(en + "Q", data[off + 56 : off + 64])[0]
        else:
            sh_flags = struct.unpack(en + "I", data[off + 8 : off + 12])[0]
            sh_addr = struct.unpack(en + "I", data[off + 12 : off + 16])[0]
            sh_offset = struct.unpack(en + "I", data[off + 16 : off + 20])[0]
            sh_size = struct.unpack(en + "I", data[off + 20 : off + 24])[0]
            sh_link = struct.unpack(en + "I", data[off + 24 : off + 28])[0]
            sh_entsize = struct.unpack(en + "I", data[off + 36 : off + 40])[0]
        sh_raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))

    # section names
    def _name(noff: int) -> str:
        if not (0 <= e_shstrndx < len(sh_raw)):
            return ""
        _, _, _, _, soff, ssize, _, _ = sh_raw[e_shstrndx]
        if soff + noff >= len(data):
            return ""
        end = data.find(b"\x00", soff + noff, min(soff + ssize, len(data)))
        if end < 0:
            return ""
        try:
            return data[soff + noff : end].decode("ascii", "replace")
        except Exception:  # noqa: BLE001
            return ""

    strtabs: dict[int, tuple[int, int]] = {}
    for i, raw in enumerate(sh_raw):
        noff, stype, flags, addr, soff, ssize, link, entsize = raw
        elf.sections.append(SectionInfo(_name(noff), stype, flags, addr, soff, ssize))
        if stype == SHT_STRTAB:
            strtabs[i] = (soff, ssize)

    def _sym_name(stroff: int, strtab_file_range: tuple[int, int]) -> str:
        base, size = strtab_file_range
        if base + stroff >= len(data):
            return ""
        end = data.find(b"\x00", base + stroff, min(base + size, len(data)))
        if end < 0:
            return ""
        try:
            return data[base + stroff : end].decode("ascii", "replace")
        except Exception:  # noqa: BLE001
            return ""

    for i, raw in enumerate(sh_raw):
        _, stype, _, _, soff, ssize, link, entsize = raw
        if stype not in (SHT_SYMTAB, SHT_DYNSYM) or link not in strtabs:
            continue
        ent = entsize or (24 if is64 else 16)
        if ent <= 0:
            continue
        count = min(ssize // ent, 65536)
        for j in range(count):
            off = soff + j * ent
            if off + ent > len(data):
                break
            st_name = struct.unpack(en + "I", data[off : off + 4])[0]
            if is64:
                st_shndx = struct.unpack(en + "H", data[off + 6 : off + 8])[0]
                st_value = struct.unpack(en + "Q", data[off + 8 : off + 16])[0]
                st_size = struct.unpack(en + "Q", data[off + 16 : off + 24])[0]
            else:
                st_value = struct.unpack(en + "I", data[off + 4 : off + 8])[0]
                st_size = struct.unpack(en + "I", data[off + 8 : off + 12])[0]
                st_shndx = struct.unpack(en + "H", data[off + 14 : off + 16])[0]
            name = _sym_name(st_name, strtabs[link])
            if name:
                elf.symbols.append(SymbolInfo(name, st_value, st_size, st_shndx == 0))

    return elf


def _parse_dynamic(elf: NativeElf, data: bytes, off: int, size: int) -> None:
    entsize = 16 if elf.is64 else 8
    for cur in range(off, min(off + size, len(data)), entsize):
        if cur + entsize > len(data):
            break
        if elf.is64:
            tag = struct.unpack(elf.endian + "q", data[cur : cur + 8])[0]
            val = struct.unpack(elf.endian + "Q", data[cur + 8 : cur + 16])[0]
        else:
            tag = struct.unpack(elf.endian + "i", data[cur : cur + 4])[0]
            val = struct.unpack(elf.endian + "I", data[cur + 4 : cur + 8])[0]
        if tag == DT_NULL:
            break
        elf.dynamic.setdefault(tag, []).append(val)
