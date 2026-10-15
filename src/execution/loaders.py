"""Bounded executable-image loaders used by dynamic execution providers.

The loader deliberately models only facts that can be derived from the input
bytes.  It never reports imports as resolved or relocations as applied unless a
provider actually performs those operations.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PAGE_SIZE = 0x1000
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_SEGMENTS = 4096


class BinaryLoadError(ValueError):
    """The executable cannot be mapped safely or is structurally unsupported."""


def _align_down(value: int, alignment: int = PAGE_SIZE) -> int:
    return value & ~(alignment - 1)


def _align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _bounded_slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise BinaryLoadError(f"{label} exceeds input bounds")
    return data[offset:offset + size]


@dataclass
class MappedSegment:
    """One loadable segment in runtime address space."""

    name: str
    runtime_address: int
    memory_size: int
    file_offset: int
    file_size: int
    permissions: str
    data: bytes = b""
    alignment: int = PAGE_SIZE
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.runtime_address < 0 or self.memory_size < 0:
            raise BinaryLoadError("negative segment address or size")
        if self.file_offset < 0 or self.file_size < 0:
            raise BinaryLoadError("negative segment file range")
        if self.file_size > self.memory_size:
            raise BinaryLoadError("segment file size exceeds memory size")
        if len(self.data) != self.file_size:
            raise BinaryLoadError("segment data length does not match file size")
        if len(self.permissions) != 3 or any(
            ch not in allowed
            for ch, allowed in zip(self.permissions, ("r-", "w-", "x-"))
        ):
            raise BinaryLoadError("segment permissions must be an rwx mask")

    @property
    def mapped_start(self) -> int:
        return _align_down(self.runtime_address)

    @property
    def mapped_end(self) -> int:
        return _align_up(self.runtime_address + self.memory_size)

    @property
    def mapped_size(self) -> int:
        return self.mapped_end - self.mapped_start

    def materialized_bytes(self) -> bytes:
        return self.data + b"\x00" * (self.memory_size - self.file_size)

    def as_dict(self, *, include_bytes: bool = False) -> dict[str, Any]:
        row = {
            "name": self.name,
            "runtime_address": f"0x{self.runtime_address:x}",
            "memory_size": self.memory_size,
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "permissions": self.permissions,
            "alignment": self.alignment,
            "properties": dict(self.properties),
        }
        if include_bytes:
            row["data_hex"] = self.data.hex()
        return row


@dataclass
class LoadedBinary:
    """Normalized load plan for a raw or structured executable."""

    format: str
    architecture: str
    pointer_size: int
    endianness: str
    source_sha256: str
    preferred_base: int
    load_base: int
    entry_point: int
    segments: list[MappedSegment]
    is_position_independent: bool = False
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.pointer_size not in (4, 8):
            raise BinaryLoadError("unsupported pointer size")
        if self.endianness not in ("little", "big"):
            raise BinaryLoadError("unsupported byte order")
        if not self.segments:
            raise BinaryLoadError("load plan contains no segments")
        if sum(segment.mapped_size for segment in self.segments) > MAX_IMAGE_BYTES:
            raise BinaryLoadError("mapped image exceeds safety limit")
        if not any(
            segment.runtime_address <= self.entry_point
            < segment.runtime_address + segment.memory_size
            and segment.permissions[2] == "x"
            for segment in self.segments
        ):
            raise BinaryLoadError("entry point is outside executable segments")

    @property
    def load_delta(self) -> int:
        return self.load_base - self.preferred_base

    @property
    def image_start(self) -> int:
        return min(segment.mapped_start for segment in self.segments)

    @property
    def image_end(self) -> int:
        return max(segment.mapped_end for segment in self.segments)

    def static_address(self, runtime_address: int) -> int:
        return runtime_address - self.load_delta

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "architecture": self.architecture,
            "pointer_size": self.pointer_size,
            "endianness": self.endianness,
            "source_sha256": self.source_sha256,
            "preferred_base": f"0x{self.preferred_base:x}",
            "load_base": f"0x{self.load_base:x}",
            "load_delta": self.load_delta,
            "entry_point": f"0x{self.entry_point:x}",
            "image_start": f"0x{self.image_start:x}",
            "image_end": f"0x{self.image_end:x}",
            "is_position_independent": self.is_position_independent,
            "segments": [segment.as_dict() for segment in self.segments],
            "properties": dict(self.properties),
        }


_ELF_MACHINES = {
    3: "x86",
    8: "mips",
    20: "ppc",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv64",
    247: "ebpf",
}

_PE_MACHINES = {
    0x014C: "x86",
    0x01C0: "arm",
    0x01C4: "armthumb",
    0x8664: "x86_64",
    0xAA64: "aarch64",
    0x5032: "riscv",
    0x5064: "riscv64",
}

_MACH_CPU_TYPES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "aarch64",
    18: "ppc",
    0x01000012: "ppc64",
}


def _permission_mask(*, read: bool, write: bool, execute: bool) -> str:
    return f"{'r' if read else '-'}{'w' if write else '-'}{'x' if execute else '-'}"


def load_elf(data: bytes, *, requested_base: int | None = None) -> LoadedBinary:
    if len(data) < 0x34 or not data.startswith(b"\x7fELF"):
        raise BinaryLoadError("not an ELF image")
    elf_class = data[4]
    data_encoding = data[5]
    if elf_class not in (1, 2) or data_encoding not in (1, 2):
        raise BinaryLoadError("unsupported ELF class or byte order")
    pointer_size = 8 if elf_class == 2 else 4
    endian = "<" if data_encoding == 1 else ">"
    byte_order = "little" if data_encoding == 1 else "big"
    if elf_class == 2:
        header_fmt = endian + "HHIQQQIHHHHHH"
        header_size = 64
        ph_fmt = endian + "IIQQQQQQ"
        minimum_ph_size = 56
    else:
        header_fmt = endian + "HHIIIIIHHHHHH"
        header_size = 52
        ph_fmt = endian + "IIIIIIII"
        minimum_ph_size = 32
    values = struct.unpack(header_fmt, _bounded_slice(data, 16, header_size - 16, "ELF header"))
    e_type, e_machine = values[0], values[1]
    entry = values[3]
    phoff = values[4]
    phentsize = values[8]
    phnum = values[9]
    if phnum <= 0 or phnum > MAX_SEGMENTS or phentsize < minimum_ph_size:
        raise BinaryLoadError("invalid ELF program-header table")
    _bounded_slice(data, phoff, phentsize * phnum, "ELF program headers")

    raw_segments: list[tuple[int, int, int, int, int, int, int]] = []
    for index in range(phnum):
        row = _bounded_slice(data, phoff + index * phentsize, minimum_ph_size, "ELF program header")
        fields = struct.unpack(ph_fmt, row)
        if elf_class == 2:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = fields
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, p_align = fields
        if p_type != 1 or p_memsz == 0:  # PT_LOAD
            continue
        if p_filesz > p_memsz:
            raise BinaryLoadError("ELF segment file size exceeds memory size")
        _bounded_slice(data, p_offset, p_filesz, "ELF segment")
        raw_segments.append((index, p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align))
    if not raw_segments:
        raise BinaryLoadError("ELF contains no loadable segments")

    preferred_base = min(_align_down(row[2]) for row in raw_segments)
    position_independent = e_type == 3  # ET_DYN
    if requested_base is not None:
        load_base = _align_down(requested_base)
    elif position_independent:
        load_base = 0x400000
    else:
        load_base = preferred_base
    delta = load_base - preferred_base
    segments: list[MappedSegment] = []
    for index, offset, vaddr, file_size, memory_size, flags, alignment in raw_segments:
        segments.append(MappedSegment(
            name=f"PT_LOAD[{index}]",
            runtime_address=vaddr + delta,
            memory_size=memory_size,
            file_offset=offset,
            file_size=file_size,
            permissions=_permission_mask(
                read=bool(flags & 4),
                write=bool(flags & 2),
                execute=bool(flags & 1),
            ),
            data=_bounded_slice(data, offset, file_size, "ELF segment bytes"),
            alignment=max(1, alignment),
            properties={"elf_flags": flags, "original_vaddr": f"0x{vaddr:x}"},
        ))
    architecture = _ELF_MACHINES.get(e_machine, f"elf-machine-{e_machine}")
    if architecture == "riscv64" and pointer_size == 4:
        architecture = "riscv"
    if architecture == "mips" and pointer_size == 8:
        architecture = "mips64"
    return LoadedBinary(
        format="elf",
        architecture=architecture,
        pointer_size=pointer_size,
        endianness=byte_order,
        source_sha256=hashlib.sha256(data).hexdigest(),
        preferred_base=preferred_base,
        load_base=load_base,
        entry_point=entry + delta,
        segments=segments,
        is_position_independent=position_independent,
        properties={"elf_type": e_type, "elf_machine": e_machine},
    )


def load_macho(data: bytes, *, requested_base: int | None = None) -> LoadedBinary:
    """Load a thin 32/64-bit Mach-O image and honor LC_MAIN entryoff."""
    if len(data) < 28:
        raise BinaryLoadError("truncated Mach-O header")
    magic_bytes = data[:4]
    variants = {
        b"\xce\xfa\xed\xfe": ("<", 4, False),
        b"\xcf\xfa\xed\xfe": ("<", 8, True),
        b"\xfe\xed\xfa\xce": (">", 4, False),
        b"\xfe\xed\xfa\xcf": (">", 8, True),
    }
    if magic_bytes in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
        raise BinaryLoadError("fat Mach-O requires explicit architecture selection")
    if magic_bytes not in variants:
        raise BinaryLoadError("not a thin Mach-O image")
    endian, pointer_size, is_64 = variants[magic_bytes]
    header_size = 32 if is_64 else 28
    header_fmt = endian + ("IiiIIIII" if is_64 else "IiiIIII")
    header = struct.unpack(header_fmt, _bounded_slice(data, 0, header_size, "Mach-O header"))
    cpu_type, file_type, command_count, command_bytes, flags = header[1], header[3], header[4], header[5], header[6]
    if command_count < 0 or command_count > MAX_SEGMENTS * 8:
        raise BinaryLoadError("invalid Mach-O load-command count")
    _bounded_slice(data, header_size, command_bytes, "Mach-O load commands")
    segments_raw: list[dict[str, Any]] = []
    entry_file_offset: int | None = None
    cursor = header_size
    for index in range(command_count):
        command, size = struct.unpack(endian + "II", _bounded_slice(data, cursor, 8, "Mach-O command"))
        if size < 8 or cursor + size > header_size + command_bytes:
            raise BinaryLoadError("invalid Mach-O load command size")
        row = _bounded_slice(data, cursor, size, "Mach-O load command")
        if command == (0x19 if is_64 else 0x1):
            minimum = 72 if is_64 else 56
            if size < minimum:
                raise BinaryLoadError("truncated Mach-O segment command")
            if is_64:
                fields = struct.unpack_from(endian + "16sQQQQiiII", row, 8)
            else:
                fields = struct.unpack_from(endian + "16sIIIIiiII", row, 8)
            raw_name, vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, _nsects, segment_flags = fields
            if filesize > vmsize:
                raise BinaryLoadError("Mach-O segment file size exceeds VM size")
            _bounded_slice(data, fileoff, filesize, "Mach-O segment bytes")
            name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace") or f"segment[{index}]"
            if vmsize:
                segments_raw.append({
                    "name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                    "fileoff": fileoff, "filesize": filesize,
                    "initprot": initprot, "flags": segment_flags,
                })
        elif command == 0x80000028:  # LC_MAIN
            if size < 24:
                raise BinaryLoadError("truncated LC_MAIN command")
            entry_file_offset = struct.unpack_from(endian + "Q", row, 8)[0]
        cursor += size
    usable = [row for row in segments_raw if row["name"] != "__PAGEZERO"]
    if not usable:
        raise BinaryLoadError("Mach-O contains no loadable segments")
    preferred_base = min(_align_down(row["vmaddr"]) for row in usable)
    position_independent = bool(flags & 0x00200000)  # MH_PIE
    load_base = preferred_base if requested_base is None else _align_down(requested_base)
    if load_base != preferred_base and not position_independent:
        raise BinaryLoadError("non-PIE Mach-O cannot be safely rebased")
    delta = load_base - preferred_base
    segments = [MappedSegment(
        name=row["name"],
        runtime_address=row["vmaddr"] + delta,
        memory_size=row["vmsize"],
        file_offset=row["fileoff"],
        file_size=row["filesize"],
        permissions=_permission_mask(
            read=bool(row["initprot"] & 1), write=bool(row["initprot"] & 2), execute=bool(row["initprot"] & 4),
        ),
        data=_bounded_slice(data, row["fileoff"], row["filesize"], "Mach-O segment"),
        properties={"macho_flags": row["flags"], "original_vmaddr": f"0x{row['vmaddr']:x}"},
    ) for row in usable]
    entry = None
    if entry_file_offset is not None:
        for row in usable:
            if row["fileoff"] <= entry_file_offset < row["fileoff"] + row["filesize"]:
                entry = row["vmaddr"] + (entry_file_offset - row["fileoff"]) + delta
                break
    if entry is None:
        executable_segments = [segment for segment in segments if segment.permissions[2] == "x"]
        if not executable_segments:
            raise BinaryLoadError("Mach-O has no executable entry segment")
        entry = executable_segments[0].runtime_address
    return LoadedBinary(
        format="macho",
        architecture=_MACH_CPU_TYPES.get(cpu_type & 0xFFFFFFFF, f"macho-cpu-{cpu_type & 0xFFFFFFFF}"),
        pointer_size=pointer_size,
        endianness="little" if endian == "<" else "big",
        source_sha256=hashlib.sha256(data).hexdigest(),
        preferred_base=preferred_base,
        load_base=load_base,
        entry_point=entry,
        segments=segments,
        is_position_independent=position_independent,
        properties={"macho_file_type": file_type, "macho_flags": flags},
    )


def load_pe(data: bytes, *, requested_base: int | None = None) -> LoadedBinary:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise BinaryLoadError("not a PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if _bounded_slice(data, pe_offset, 4, "PE signature") != b"PE\x00\x00":
        raise BinaryLoadError("invalid PE signature")
    coff = struct.unpack(
        "<HHIIIHH",
        _bounded_slice(data, pe_offset + 4, 20, "PE COFF header"),
    )
    machine, section_count, _timestamp, _symptr, _symcount, optional_size, characteristics = coff
    if section_count <= 0 or section_count > MAX_SEGMENTS:
        raise BinaryLoadError("invalid PE section count")
    optional_offset = pe_offset + 24
    optional = _bounded_slice(data, optional_offset, optional_size, "PE optional header")
    if len(optional) < 72:
        raise BinaryLoadError("truncated PE optional header")
    magic = struct.unpack_from("<H", optional, 0)[0]
    if magic == 0x20B:
        pointer_size = 8
        image_base = struct.unpack_from("<Q", optional, 24)[0]
    elif magic == 0x10B:
        pointer_size = 4
        image_base = struct.unpack_from("<I", optional, 28)[0]
    else:
        raise BinaryLoadError("unsupported PE optional-header magic")
    entry_rva = struct.unpack_from("<I", optional, 16)[0]
    size_of_headers = struct.unpack_from("<I", optional, 60)[0]
    dll_characteristics = struct.unpack_from("<H", optional, 0x46)[0]
    load_base = image_base if requested_base is None else _align_down(requested_base)
    if load_base != image_base:
        raise BinaryLoadError("PE rebasing requires relocation application and is not yet safe")

    section_table = optional_offset + optional_size
    _bounded_slice(data, section_table, section_count * 40, "PE section table")
    segments: list[MappedSegment] = []
    header_size = min(size_of_headers, len(data))
    if header_size:
        segments.append(MappedSegment(
            name="headers",
            runtime_address=load_base,
            memory_size=_align_up(header_size),
            file_offset=0,
            file_size=header_size,
            permissions="r--",
            data=data[:header_size],
            properties={"pe_headers": True},
        ))
    for index in range(section_count):
        row = _bounded_slice(data, section_table + index * 40, 40, "PE section")
        raw_name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<8sIIII", row, 0
        )
        section_flags = struct.unpack_from("<I", row, 36)[0]
        memory_size = max(virtual_size, raw_size)
        if memory_size == 0:
            continue
        available = max(0, min(raw_size, len(data) - raw_offset)) if raw_offset <= len(data) else 0
        if raw_size and available != raw_size:
            raise BinaryLoadError("PE section exceeds input bounds")
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace") or f"section[{index}]"
        segments.append(MappedSegment(
            name=name,
            runtime_address=load_base + virtual_address,
            memory_size=memory_size,
            file_offset=raw_offset,
            file_size=raw_size,
            permissions=_permission_mask(
                read=bool(section_flags & 0x40000000),
                write=bool(section_flags & 0x80000000),
                execute=bool(section_flags & 0x20000000),
            ),
            data=_bounded_slice(data, raw_offset, raw_size, "PE section bytes"),
            properties={"pe_characteristics": section_flags, "rva": virtual_address},
        ))
    return LoadedBinary(
        format="pe",
        architecture=_PE_MACHINES.get(machine, f"pe-machine-{machine}"),
        pointer_size=pointer_size,
        endianness="little",
        source_sha256=hashlib.sha256(data).hexdigest(),
        preferred_base=image_base,
        load_base=load_base,
        entry_point=load_base + entry_rva,
        segments=segments,
        is_position_independent=bool(dll_characteristics & 0x0040),
        properties={
            "pe_machine": machine,
            "pe_characteristics": characteristics,
            "pe_dll_characteristics": dll_characteristics,
        },
    )


def load_raw(
    data: bytes,
    *,
    architecture: str,
    base_address: int = 0x1000,
    entry_point: int | None = None,
) -> LoadedBinary:
    if not data:
        raise BinaryLoadError("raw image is empty")
    pointer_size = 8 if architecture.lower() in {
        "x86_64", "amd64", "x64", "aarch64", "arm64", "riscv64",
    } else 4
    segment = MappedSegment(
        name="raw",
        runtime_address=base_address,
        memory_size=len(data),
        file_offset=0,
        file_size=len(data),
        permissions="r-x",
        data=data,
    )
    return LoadedBinary(
        format="raw",
        architecture=architecture.lower(),
        pointer_size=pointer_size,
        endianness="little",
        source_sha256=hashlib.sha256(data).hexdigest(),
        preferred_base=base_address,
        load_base=base_address,
        entry_point=entry_point if entry_point is not None else base_address,
        segments=[segment],
    )


def load_binary_bytes(
    data: bytes,
    *,
    requested_base: int | None = None,
    raw_architecture: str | None = None,
    raw_entry_point: int | None = None,
) -> LoadedBinary:
    if len(data) > MAX_INPUT_BYTES:
        raise BinaryLoadError("input exceeds loader safety limit")
    if data.startswith(b"\x7fELF"):
        return load_elf(data, requested_base=requested_base)
    if data.startswith(b"MZ"):
        return load_pe(data, requested_base=requested_base)
    if data[:4] in {
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }:
        return load_macho(data, requested_base=requested_base)
    if raw_architecture:
        return load_raw(
            data,
            architecture=raw_architecture,
            base_address=requested_base or 0x1000,
            entry_point=raw_entry_point,
        )
    raise BinaryLoadError("unknown executable format; raw architecture is required")


def load_binary(
    path: str | Path,
    *,
    requested_base: int | None = None,
    raw_architecture: str | None = None,
    raw_entry_point: int | None = None,
) -> LoadedBinary:
    source = Path(path)
    size = source.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise BinaryLoadError("input exceeds loader safety limit")
    with source.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) != size:
        raise BinaryLoadError("input changed or exceeded bounds while reading")
    return load_binary_bytes(
        data,
        requested_base=requested_base,
        raw_architecture=raw_architecture,
        raw_entry_point=raw_entry_point,
    )
