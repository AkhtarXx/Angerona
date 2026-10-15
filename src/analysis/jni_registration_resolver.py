"""Resolve JNI function registration in Android native libraries.

Big apps move sensitive logic into C/C++ and — critically — often do NOT use
the static ``Java_com_app_Native_xxx`` naming convention.  They register
methods dynamically inside ``JNI_OnLoad`` via ``RegisterNatives``, whose
``JNINativeMethod[]`` table lives in ``.data.rel.ro``:

    struct JNINativeMethod { const char* name; const char* sig; void* fn; }

Without resolving this table, analysts (and AI) stare at thousands of
anonymous ``FUN_00102340`` entries.  This module recovers the
``name / signature / fn_addr`` triples statically from bytes + ELF metadata,
so the audit graph can bind real names to real code.

Trust: parsed-from-untrusted-binary — TRUST_TAG "untrusted_child".
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field

from src.analysis.native_elf import NativeElf, parse_elf

TRUST_TAG = "untrusted_child"

_DESCRIPTOR_RE = re.compile(r"^\((?:[ZBSCIJFDLV\[\]/;a-zA-Z_\s]*)\)[ZBSCIJFDLV\[\]/;a-zA-Z_]+$")

_PATTERN_LENS = (1, 2, 3, 4, 8, 12)  # JNINativeMethod arrays are almost always tiny


@dataclass(frozen=True)
class RegisteredNative:
    java_name: str
    signature: str
    fn_addr: int

    def label(self) -> str:
        return f"{self.java_name}{self.signature}"


@dataclass(frozen=True)
class JniRegistrationResult:
    status: str  # resolved | partial | none | not_elf
    statically_named: list[str]  # Java_* exports already self-describing
    dynamically_registered: list[RegisteredNative]
    jni_onload_present: bool
    registernatives_imported: bool
    note: str
    trust: str = TRUST_TAG

    @property
    def resolved_count(self) -> int:
        return len(self.dynamically_registered)


def _looks_like_descriptor(sig: str) -> bool:
    return bool(_DESCRIPTOR_RE.match(sig))


def _resolve_tables(data: bytes, elf: NativeElf) -> list[RegisteredNative]:
    ent = 3 * (8 if elf.is64 else 4)
    found: list[RegisteredNative] = []
    seen_names: set[tuple[str, str]] = set()
    for sec in elf.sections:
        if not sec.size or sec.executable:
            continue
        span_end = min(sec.offset + sec.size, len(data))
        limit = sec.offset + min(sec.size, 1 << 20)
        off = sec.offset
        scan_end = min(limit, span_end - ent + 1)
        while off < scan_end:
            matched = False
            for arr_len in _PATTERN_LENS:
                need = ent * max(arr_len, 1)
                if off + need > span_end:
                    break
                triples: list[tuple[str, str, int]] = []
                ok = True
                for k in range(arr_len):
                    base = off + k * ent
                    parts = []
                    good = True
                    for w in range(3):
                        n = 8 if elf.is64 else 4
                        raw = data[base + w * n : base + (w + 1) * n]
                        if len(raw) < n:
                            good = False
                            break
                        parts.append(int.from_bytes(raw, "little" if elf.endian == "<" else "big"))
                    if not good:
                        ok = False
                        break
                    name_ptr, sig_ptr, fn_ptr = parts
                    if not (elf.in_exec(fn_ptr) and fn_ptr != 0):
                        ok = False
                        break
                    name = elf.c_string_at(data, name_ptr, 256)
                    sig = elf.c_string_at(data, sig_ptr, 256)
                    if not name or not sig or not name.isidentifier() or not _looks_like_descriptor(sig):
                        ok = False
                        break
                    triples.append((name, sig, fn_ptr))
                if ok and triples:
                    matched = True
                    for name, sig, fn_ptr in triples:
                        key = (name, sig)
                        if key in seen_names:
                            continue
                        seen_names.add(key)
                        found.append(RegisteredNative(name, sig, fn_ptr))
                    off += need
                    break
            if not matched:
                off += 2  # ARM64 tables are 4/8-aligned; data buffers often land on 2-boundaries
    return found


def resolve_jni_registration(data: bytes) -> JniRegistrationResult:
    elf = parse_elf(data)
    if elf is None:
        return JniRegistrationResult(
            status="not_elf",
            statically_named=[],
            dynamically_registered=[],
            jni_onload_present=False,
            registernatives_imported=False,
            note="input is not a parsed ELF file",
        )

    static_named = [s.name for s in elf.symbols if s.name.startswith("Java_") and not s.imported]
    jni_onload = any(s.name == "JNI_OnLoad" for s in elf.symbols)
    rn_import = any(s.name == "RegisterNatives" for s in elf.symbols)
    dynamic = _resolve_tables(data, elf)

    # Guard: a resolved entry with fn_addr==0 is a zero-fill table slot; refuse to call it resolved.
    valid_dynamic = [d for d in dynamic if d.fn_addr != 0]

    if valid_dynamic and rn_import:
        status, note = "resolved", f"{len(valid_dynamic)} RegisterNatives-registered method(s) resolved (filtered {len(dynamic)-len(valid_dynamic)} zero-fill)."
    elif valid_dynamic:
        status, note = "resolved", f"{len(valid_dynamic)} JNINativeMethod-shaped table entry/ies resolved (RegisterNatives import not listed)."
    elif dynamic:
        status, note = "partial", f"{len(dynamic)} table entries found but all fn_addr == 0 (rejected as zero-fill)."
    elif static_named:
        status, note = "partial", f"no dynamic tables found; {len(static_named)} statically-named Java_* export(s)."
    else:
        status, note = "none", "no JNI surface recovered (no Java_* symbols, no JNINativeMethod tables)."

    return JniRegistrationResult(
        status=status,
        statically_named=sorted(static_named),
        dynamically_registered=dynamic,
        jni_onload_present=jni_onload,
        registernatives_imported=rn_import,
        note=note,
    )


def scan_so_bytes(data: bytes) -> JniRegistrationResult:
    return resolve_jni_registration(data)


def scan_apk_native_libs(apk_path: str) -> dict[str, JniRegistrationResult]:
    out: dict[str, JniRegistrationResult] = {}
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                out[name] = resolve_jni_registration(zf.read(name))
    return out
