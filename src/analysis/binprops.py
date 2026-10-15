"""Extract binary exploit-mitigation properties (the "armor") without any shell.

Pure-Python ELF parser — no readelf, no external tools, no pip deps — so a
scoped MCP-only agent can assess exploitability (PIE/ASLR, NX, stack canary,
RELRO, Fortify, CET/IBT) without needing host shell access. Reads only the
file's bytes (never executes it).

Focused on ELF (Linux). Non-ELF inputs return a clear "unsupported" result.
"""

from __future__ import annotations

import struct
from pathlib import Path

_ELF_MAGIC = b"\x7fELF"
_MAX_READ = 256 * 1024 * 1024  # cap for huge files

PT_INTERP = 3
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

_FORTIFY_NAMES = (
    b"__memcpy_chk", b"__strcpy_chk", b"__strncpy_chk", b"__strcat_chk",
    b"__sprintf_chk", b"__snprintf_chk", b"__printf_chk", b"__memset_chk",
    b"__vsnprintf_chk", b"__fprintf_chk", b"__gets_chk",
)


def _fmt_guess(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE (Windows)"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "Mach-O (macOS)"
    return "unknown"


def elf_security_properties(path: str | Path) -> dict:
    p = Path(path).expanduser()
    with p.open("rb") as fh:
        data = fh.read(_MAX_READ)
    if data[:4] != _ELF_MAGIC:
        return {
            "format": _fmt_guess(data),
            "supported": False,
            "note": "Exploit-mitigation extraction currently supports ELF only.",
        }
    try:
        return _parse_elf(data)
    except Exception as exc:  # noqa: BLE001 - malformed/hostile input
        return {"format": "ELF", "supported": False, "note": f"parse error: {exc}"}


def _parse_elf(data: bytes) -> dict:
    if data[4] not in (1, 2):
        return {"format": "ELF", "supported": False, "note": f"unsupported EI_CLASS={data[4]}"}
    if data[5] not in (1, 2):
        return {"format": "ELF", "supported": False, "note": f"unsupported EI_DATA={data[5]}"}
    is64 = data[4] == 2
    en = "<" if data[5] == 1 else ">"

    e_type = struct.unpack(en + "H", data[16:18])[0]
    if is64:
        e_phoff = struct.unpack(en + "Q", data[32:40])[0]
        e_phentsize = struct.unpack(en + "H", data[54:56])[0]
        e_phnum = struct.unpack(en + "H", data[56:58])[0]
    else:
        e_phoff = struct.unpack(en + "I", data[28:32])[0]
        e_phentsize = struct.unpack(en + "H", data[42:44])[0]
        e_phnum = struct.unpack(en + "H", data[44:46])[0]

    nx = True                 # NX on unless a PT_GNU_STACK is marked executable
    gnu_relro = False
    has_interp = False
    dyn_off = dyn_size = 0

    for i in range(min(e_phnum, 2000)):
        off = e_phoff + i * e_phentsize
        need = 56 if is64 else 32
        if off + need > len(data):
            break
        p_type = struct.unpack(en + "I", data[off:off + 4])[0]
        if is64:
            p_flags = struct.unpack(en + "I", data[off + 4:off + 8])[0]
            p_offset = struct.unpack(en + "Q", data[off + 8:off + 16])[0]
            p_filesz = struct.unpack(en + "Q", data[off + 32:off + 40])[0]
        else:
            p_offset = struct.unpack(en + "I", data[off + 4:off + 8])[0]
            p_filesz = struct.unpack(en + "I", data[off + 16:off + 20])[0]
            p_flags = struct.unpack(en + "I", data[off + 24:off + 28])[0]
        if p_type == PT_INTERP:
            has_interp = True
        elif p_type == PT_GNU_STACK:
            nx = not bool(p_flags & 0x1)
        elif p_type == PT_GNU_RELRO:
            gnu_relro = True
        elif p_type == PT_DYNAMIC:
            dyn_off, dyn_size = p_offset, p_filesz

    bind_now = False
    if dyn_off and dyn_off + dyn_size <= len(data):
        entsize = 16 if is64 else 8
        for off in range(dyn_off, dyn_off + dyn_size, entsize):
            if off + entsize > len(data):
                break
            if is64:
                tag = struct.unpack(en + "q", data[off:off + 8])[0]
                val = struct.unpack(en + "Q", data[off + 8:off + 16])[0]
            else:
                tag = struct.unpack(en + "i", data[off:off + 4])[0]
                val = struct.unpack(en + "I", data[off + 4:off + 8])[0]
            if tag == DT_NULL:
                break
            if tag == DT_BIND_NOW or (tag == DT_FLAGS and val & DF_BIND_NOW) or (tag == DT_FLAGS_1 and val & DF_1_NOW):
                bind_now = True

    relro = "full" if (gnu_relro and bind_now) else ("partial" if gnu_relro else "none")
    canary = b"__stack_chk_fail" in data
    fortify = any(name in data for name in _FORTIFY_NAMES)
    cet_ibt = b"\xf3\x0f\x1e\xfa" in data  # endbr64 opcode

    if e_type == 3:
        pie, etype = True, "ET_DYN (PIE)" if has_interp else "ET_DYN (shared object)"
    elif e_type == 2:
        pie, etype = False, "ET_EXEC (no PIE)"
    else:
        pie, etype = None, f"e_type={e_type}"

    weak = []
    if pie is False:
        weak.append("no PIE (fixed addresses)")
    if not canary:
        weak.append("no stack canary")
    if not nx:
        weak.append("executable stack (NX off)")
    if relro != "full":
        weak.append(f"{relro} RELRO")
    summary = ("Weak mitigations: " + ", ".join(weak)) if weak else \
        "Hardened: PIE + stack canary + NX + full RELRO all present."

    return {
        "format": "ELF",
        "supported": True,
        "arch_bits": 64 if is64 else 32,
        "endian": "little" if data[5] == 1 else "big",
        "elf_type": etype,
        "linking": "dynamic" if has_interp else "static / no-interp",
        "mitigations": {
            "pie_aslr": pie,
            "nx": nx,
            "stack_canary": canary,
            "relro": relro,
            "fortify_source": fortify,
            "cet_ibt_endbr": cet_ibt,
        },
        "exploit_mitigation_summary": summary,
        "notes": "Canary/Fortify/CET inferred from symbol strings and endbr64 opcodes; "
                 "PIE/NX/RELRO from the ELF header, program headers, and dynamic section.",
    }
