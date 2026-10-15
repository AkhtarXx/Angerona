"""Minimal in-memory ARM64 ELF fixtures for native analysis-module tests.

Builds a tiny ET_DYN shared object with two PT_LOAD segments (exec + r/w),
a .dynamic with DT_INIT_ARRAY, dynsym/dynstr, and a small .text containing
hand-assembled AArch64 that the scanners can find.  No external toolchain
needed.
"""

from __future__ import annotations

import struct


def _align(x: int, a: int = 0x1000) -> int:
    return (x + a - 1) & ~(a - 1)


def build_arm64_so(
    text: bytes,
    rodata: bytes,
    dynamic_entries: list[tuple[int, int]],
    dynstr_names: list[str],
    dynsym: list[tuple[str, int, int, bool]],  # (name, value, size, imported)
    exec_vaddr: int = 0x1000,
    data_vaddr: int = 0x3000,
) -> bytes:
    """One exec segment + one rw segment homeless ELF64."""
    dynstr_buf = b"\x00"
    name_off: dict[str, int] = {}
    for n in dynstr_names:
        name_off[n] = len(dynstr_buf)
        dynstr_buf += n.encode() + b"\x00"

    # file layout: ehdr(64) phdrs(2*56) .text .rodata/.data dynstr dynsym dynamic shstrtab shdrs
    phoff = 64
    text_off = 0x100
    rodata_off = text_off + len(text)
    dynstr_off = _align(rodata_off + len(rodata), 16)
    dynsym_off = _align(dynstr_off + len(dynstr_buf), 16)
    nsyms = len(dynsym) + 1
    dynamic_off = _align(dynsym_off + nsyms * 24, 16)
    ndyn = len(dynamic_entries) + 1
    shstr_off = _align(dynamic_off + ndyn * 16, 16)

    shstr_names = [".text", ".rodata", ".dynstr", ".dynsym", ".dynamic", ".shstrtab"]
    shstr = b"\x00"
    shname_off: dict[str, int] = {}
    for n in shstr_names:
        shname_off[n] = len(shstr)
        shstr += n.encode() + b"\x00"
    shdr_off = _align(shstr_off + len(shstr), 8)
    nsec = len(shstr_names) + 1  # + null
    file_end = shdr_off + nsec * 64

    data_vaddr = data_vaddr or 0x3000
    dyn_vaddr = data_vaddr + (dynamic_off - rodata_off)
    dynstr_vaddr = data_vaddr + (dynstr_off - rodata_off)

    # headers
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # 64-bit
    ehdr[5] = 1  # LE
    ehdr[6] = 1
    struct.pack_into("<H", ehdr, 16, 3)  # ET_DYN
    struct.pack_into("<H", ehdr, 18, 183)  # EM_AARCH64
    struct.pack_into("<I", ehdr, 20, 1)
    struct.pack_into("<Q", ehdr, 24, exec_vaddr)  # entry = start of .text
    struct.pack_into("<Q", ehdr, 32, phoff)
    struct.pack_into("<Q", ehdr, 40, shdr_off)
    struct.pack_into("<H", ehdr, 52, 64)  # ehsize
    struct.pack_into("<H", ehdr, 54, 56)  # phentsize
    struct.pack_into("<H", ehdr, 56, 3)  # phnum
    struct.pack_into("<H", ehdr, 58, 64)  # shentsize
    struct.pack_into("<H", ehdr, 60, nsec)  # shnum
    struct.pack_into("<H", ehdr, 62, nsec - 1)  # shstrndx = last

    # PT_LOAD exec: only .text + (optional read-only tail) at exec_vaddr
    ex_filesz = len(text) if text else 4
    ph1 = struct.pack("<IIQQQQQQ", 1, 5, text_off, exec_vaddr, exec_vaddr, ex_filesz, ex_filesz, 0x1000)
    # PT_LOAD rw: rodata onward at data_vaddr
    rw_off = rodata_off
    rw_filesz = file_end - rw_off
    ph2 = struct.pack("<IIQQQQQQ", 1, 6, rw_off, data_vaddr,
                      data_vaddr, rw_filesz, rw_filesz, 0x1000)
    # PT_DYNAMIC
    dynamic_total_sz = ndyn * 16
    ph3 = struct.pack("<IIQQQQQQ", 2, 6, dynamic_off, dyn_vaddr, dyn_vaddr, dynamic_total_sz, dynamic_total_sz, 8)

    blob = bytearray(file_end)
    blob[0:64] = ehdr
    blob[phoff : phoff + 56] = ph1
    blob[phoff + 56 : phoff + 112] = ph2
    blob[phoff + 112 : phoff + 168] = ph3
    blob[text_off : text_off + len(text)] = text
    blob[rodata_off : rodata_off + len(rodata)] = rodata
    blob[dynstr_off : dynstr_off + len(dynstr_buf)] = dynstr_buf

    # dynsym
    off = dynsym_off + 24  # skip null sym
    for name, value, size, imported in dynsym:
        stname = name_off.get(name, 0)
        struct.pack_into("<I", blob, off, stname)
        blob[off + 4] = 0x12 if not imported else 0x10  # FUNC/GLOBAL-ish
        blob[off + 5] = 0
        struct.pack_into("<H", blob, off + 6, 1 if not imported else 0)
        struct.pack_into("<Q", blob, off + 8, value)
        struct.pack_into("<Q", blob, off + 16, size)
        off += 24

    # dynamic
    off = dynamic_off
    for tag, val in dynamic_entries:
        struct.pack_into("<qQ", blob, off, tag, val)
        off += 16
    struct.pack_into("<qQ", blob, off, 0, 0)

    blob[shstr_off : shstr_off + len(shstr)] = shstr

    # sections: [null, .text, .rodata, .dynstr, .dynsym, .dynamic, .shstrtab]
    def sh(name, stype, flags, addr, offset, size, link, entsize):
        return struct.pack(
            "<IIQQQQIIQQ",
            shname_off.get(name, 0), stype, flags, addr, offset, size, link, 0, 0, entsize,
        )

    v = exec_vaddr
    dv = data_vaddr
    rw_base = dv  # base of rw PT_LOAD == rodata vaddr in our fixture layout
    secs = [
        bytes(64),
        sh(".text", 1, 0x6, v, text_off, len(text), 0, 0),          # PROGBITS|ALLOC|EXEC
        sh(".rodata", 1, 0x2, rw_base, rodata_off, len(rodata), 0, 0),
        sh(".dynstr", 3, 0x2, rw_base + (dynstr_off - rodata_off), dynstr_off, len(dynstr_buf), 0, 0),
        sh(".dynsym", 11, 0x2, rw_base + (dynsym_off - rodata_off), dynsym_off, nsyms * 24, 3, 24),
        sh(".dynamic", 6, 0x3, rw_base + (dynamic_off - rodata_off), dynamic_off, ndyn * 16, 3, 16),
        sh(".shstrtab", 3, 0x0, 0, shstr_off, len(shstr), 0, 0),
    ]
    off = shdr_off
    for s in secs:
        blob[off : off + 64] = s
        off += 64

    return bytes(blob)


# ---------------- AArch64 tiny helpers (little-endian encodings) -------------

def a64_movz_w(reg: int, imm16: int, shift: int = 0) -> bytes:
    return struct.pack("<I", 0x52800000 | ((shift >> 4) << 21) | ((imm16 & 0xFFFF) << 5) | reg)


def a64_movk_x(reg: int, imm16: int, shift: int = 0) -> bytes:
    return struct.pack("<I", 0xF2800000 | ((shift >> 4) << 21) | ((imm16 & 0xFFFF) << 5) | reg)


def a64_movz_x(reg: int, imm16: int, shift: int = 0) -> bytes:
    return struct.pack("<I", 0xD2800000 | ((shift >> 4) << 21) | ((imm16 & 0xFFFF) << 5) | reg)


def a64_strb_w(reg: int, base: int, imm12: int = 0) -> bytes:
    return struct.pack("<I", 0x39000000 | ((imm12 & 0xFFF) << 10) | (base << 5) | reg)


def a64_ret() -> bytes:
    return struct.pack("<I", 0xD65F03C0)


def build_keyfill_so(key: bytes) -> bytes:
    """A .so whose .text writes `key` byte-by-byte into stack buffer."""
    insns = b""
    for i, b in enumerate(key):
        insns += a64_movz_w(8, b)          # mov w8, #b
        insns += a64_strb_w(8, 31, i + 8)  # strb w8, [sp, #off]
    insns += a64_ret()
    return build_arm64_so(
        text=insns,
        rodata=b"",
        dynamic_entries=[(25, 0x2000), (27, 8)],  # DT_INIT_ARRAY + sz pointing into seg2 (unused by stub)
        dynstr_names=["Java_com_x_y", "JNI_OnLoad"],
        dynsym=[("Java_com_x_y", 0x1000, len(insns), False), ("JNI_OnLoad", 0x1000, 4, False)],
    )


def build_movk_chain_so(chunks: list[tuple[int, int]]) -> bytes:
    """movz x0, #imm / movk x0, #imm, lsl #16 / ... / ret"""
    insns = b""
    first = True
    for imm16, shift in chunks:
        insns += a64_movz_x(0, imm16, shift) if first else a64_movk_x(0, imm16, shift)
        first = False
    insns += struct.pack("<I", 0xD340FC00)  # ubfz x0, x0, #0 — consumes x0
    insns += a64_ret()
    return build_arm64_so(
        text=insns,
        rodata=b"",
        dynamic_entries=[],
        dynstr_names=[],
        dynsym=[],
    )


def build_jni_table_so(entries: list[tuple[str, str]], fn_vaddrs: list[int]) -> bytes:
    """Build a .so with a .rodata JNINativeMethod[] table resolvable by the resolver."""
    # .rodata lives at the base of the rw PT_LOAD (vaddr 0x3000).
    str_region = b""
    name_vaddrs = []
    sig_vaddrs = []
    base_str_v = 0x3000
    off = 0
    for name, sig in entries:
        str_region += name.encode() + b"\x00"
        name_vaddrs.append(base_str_v + off)
        off += len(name) + 1
        str_region += sig.encode() + b"\x00"
        sig_vaddrs.append(base_str_v + off)
        off += len(sig) + 1
    # table appended to str_region, padded to 4/8-alignment like a linker would
    while len(str_region) % 8:
        str_region += b"\x00"
    table = b""
    for i, (name, sig) in enumerate(entries):
        table += struct.pack("<QQQ", name_vaddrs[i], sig_vaddrs[i], fn_vaddrs[i])
    rodata = str_region + table
    text = b"\x1f\x20\x03\xd5" * 4  # nops at 0x1000..0x1010 so fn ptrs land in exec
    return build_arm64_so(
        text=text,
        rodata=rodata,
        dynamic_entries=[],
        dynstr_names=["JNI_OnLoad", "RegisterNatives"],
        dynsym=[("JNI_OnLoad", 0x1000, 16, False), ("RegisterNatives", 0, 0, True)],
    )
