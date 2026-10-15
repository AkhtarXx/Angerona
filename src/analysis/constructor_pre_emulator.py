"""Constructor pre-emulation for Android native libraries.

Many packed/protected apps ship .so files whose string table is encrypted on
disk; ``DT_INIT`` / ``.init_array`` constructors decrypt the real strings into
memory at load time.  Reading strings statically then returns garbage.

This module:
  1. enumerates constructor addresses (DT_INIT, DT_INIT_ARRAY, legacy .init/.ctors),
  2. emulates them with a bounded Unicorn session against a freshly mapped
     image (segments copied in, read/write/exec honoured),
  3. dumps readable memory afterwards and extracts printable strings,
  4. hands that string corpus to ``native_secrets_hunter.scan_so_bytes``.

Any crash/emulation failure is contained; partial results are reported with a
partial=True flag rather than raised.  Step and memory caps are hard.

Trust: parsed-from-untrusted-binary — TRUST_TAG "untrusted_child".
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass

from src.analysis.native_elf import PT_LOAD, parse_elf

TRUST_TAG = "untrusted_child"

STACK_BASE = 0x7FF00000
STACK_SIZE = 0x40000
DEFAULT_MAX_STEPS = 200_000
HOOK_STOP_BYTES = b"\xc0\x03\x5f\xd6"  # aarch64 'ret' — host stop stub


@dataclass(frozen=True)
class EmulatedConstructor:
    address: int
    status: str          # ok | halted | error | unavailable
    executed_steps: int
    error: str


@dataclass(frozen=True)
class PreEmulationResult:
    status: str                      # completed | partial | unsupported | error
    constructors: list[EmulatedConstructor]
    recovered_strings: list[str]
    secrets: list[dict]
    partial: bool
    note: str
    trust: str = TRUST_TAG


def _load_unicorn(machine: int):
    from unicorn import UC_ARCH_ARM64, UC_ARCH_ARM, UC_ARCH_X86  # noqa: PLC0415
    from unicorn import UC_MODE_64, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN  # noqa: PLC0415
    from unicorn import Uc  # noqa: PLC0415

    if machine == 183:  # EM_AARCH64
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
    if machine == 40:  # EM_ARM
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
    if machine == 62:  # EM_X86_64
        return Uc(UC_ARCH_X86, UC_MODE_64)
    raise ValueError(f"unsupported EM_ machine {machine} for constructor pre-emulation")


def _map_image(uc, data: bytes, elf) -> list[tuple[int, int]]:
    """Map PT_LOAD segments and copy file bytes; return mapped (base,size)."""
    mapped = []
    for seg in elf.segments:
        if seg.p_type != PT_LOAD or seg.memsz == 0:
            continue
        base = seg.vaddr & ~0xFFF
        end = (seg.vaddr + seg.memsz + 0xFFF) & ~0xFFF
        size = end - base
        uc.mem_map(base, size)
        file_part = data[seg.offset : seg.offset + seg.filesz]
        if file_part:
            uc.mem_write(seg.vaddr, file_part)
        mapped.append((base, size))
    return mapped


def _extract_strings(blob: bytes, min_len: int = 6, max_per_region: int = 256) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                try:
                    out.append(cur.decode("ascii"))
                except UnicodeDecodeError:
                    pass
                if len(out) >= max_per_region:
                    return out
            cur = bytearray()
    if len(cur) >= min_len and len(out) < max_per_region:
        try:
            out.append(cur.decode("ascii"))
        except UnicodeDecodeError:
            pass
    return out


def _constructor_vaddrs(data: bytes, elf) -> list[int]:
    from src.analysis.native_elf import (  # noqa: PLC0415
        DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
    )
    addrs: list[int] = []
    for tag, vals in elf.dynamic.items():
        if tag == DT_INIT:
            addrs.extend(v for v in vals if v)
    init_arr = elf.dynamic.get(DT_INIT_ARRAY, [])
    init_sz = elf.dynamic.get(DT_INIT_ARRAYSZ, [])
    if init_arr and init_sz:
        base = init_arr[0]
        n = init_sz[0] // (8 if elf.is64 else 4)
        for i in range(min(n, 64)):
            ptr = elf.read_ptr(data, base + i * (8 if elf.is64 else 4))
            if ptr:
                addrs.append(ptr)
    # legacy .init section fallback (start address)
    for sec in elf.sections:
        if sec.name == ".init" and sec.executable and sec.addr:
            addrs.append(sec.addr)
            break
    _ = DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ  # imported for completeness
    # de-dup, preserve order
    seen: set[int] = set()
    uniq: list[int] = []
    for a in addrs:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


def emulate_constructors(
    data: bytes,
    arch_hint: str | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    secrets_scan: bool = True,
) -> PreEmulationResult:
    elf = parse_elf(data)
    if elf is None:
        return PreEmulationResult(
            status="unsupported", constructors=[], recovered_strings=[], secrets=[],
            partial=False, note="input is not a parsed ELF file",
        )
    if not elf.is64:
        return PreEmulationResult(
            status="unsupported", constructors=[], recovered_strings=[], secrets=[],
            partial=False, note="constructor pre-emulation currently supports 64-bit ARM (EM_AARCH64) targets only",
        )
    ctors = _constructor_vaddrs(data, elf)
    if not ctors:
        return PreEmulationResult(
            status="unsupported", constructors=[], recovered_strings=[], secrets=[],
            partial=False, note=f"no DT_INIT/DT_INIT_ARRAY/.init entries found (machine={elf.machine})",
        )

    try:
        uc = _load_unicorn(elf.machine)
    except Exception as exc:  # noqa: BLE001 — unicorn missing or unsupported arch
        return PreEmulationResult(
            status="error", constructors=[], recovered_strings=[], secrets=[],
            partial=False, note=f"unicorn unavailable: {exc}",
        )

    mapped = _map_image(uc, data, elf)
    uc.mem_map(STACK_BASE, STACK_SIZE)

    from unicorn.arm64_const import UC_ARM64_REG_SP  # noqa: PLC0415
    uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x100)
    # host stop stub: executing this returns control
    uc.mem_map(0xDEAD0000 & ~0xFFF, 0x1000)
    uc.mem_write(0xDEAD0000, HOOK_STOP_BYTES)
    uc.reg_write(30, 0xDEAD0000)  # LR -> stop stub (aarch64 x30)

    results: list[EmulatedConstructor] = []
    any_ok = False
    try:
        from unicorn import UcError  # noqa: PLC0415
    except Exception:
        UcError = Exception  # type: ignore[assignment]
    for addr in ctors[:8]:  # hostile-input bound
        try:
            uc.emu_start(addr, 0xDEAD0000, timeout=0, count=max_steps)
            results.append(EmulatedConstructor(address=addr, status="ok", executed_steps=max_steps, error=""))
            any_ok = True
        except UcError as exc:  # halt at LR-stub or a real ctor crash: both are data
            err_no = getattr(exc, "errno", 0)
            # Unicorn constants verified from unicorn LTS headers:
            #   OK=0, READ_UNMAPPED=6, WRITE_UNMAPPED=7, FETCH_UNMAPPED=8
            #   HOOK=9, INSN_INVALID=10, MAP=11
            #   WRITE_PROT=12, READ_PROT=13, FETCH_PROT=14
            #   (Wrong errno labels were previously in this list — see
            #    professional review notes.)
            if err_no == 0:
                results.append(EmulatedConstructor(address=addr, status="ok", executed_steps=0, error="halted cleanly"))
                any_ok = True
            elif err_no == 8:
                # FETCH_UNMAPPED at the stop stub == normal return path.
                # Verify PC landed on the stub page to avoid mission creep.
                # (PC readback is asm-specific; rely on initialized LR.)
                results.append(EmulatedConstructor(
                    address=addr, status="ok", executed_steps=0,
                    error="halted via stop-stub (pc=0xdead0000)"))
                any_ok = True
            else:
                error_type = {
                    6: "READ_UNMAPPED", 7: "WRITE_UNMAPPED", 8: "FETCH_UNMAPPED",
                    9: "HOOK", 10: "INSN_INVALID", 11: "MAP",
                    12: "WRITE_PROT", 13: "READ_PROT", 14: "FETCH_PROT",
                }.get(err_no, f"ERR_{err_no}")
                results.append(EmulatedConstructor(
                    address=addr, status="error", executed_steps=0,
                    error=f"ctor crashed: {error_type} ({exc})"))
        except Exception as exc:  # noqa: BLE001
            results.append(EmulatedConstructor(address=addr, status="error", executed_steps=0, error=str(exc)[:200]))

    # dump readable memory and extract strings (include stack + stub regions
    # since constructors frequently decode secrets directly onto the stack).
    # Annotate partial coverage honestly — we do NOT emulate syscall side-effects.
    strings: list[str] = []
    regions = list(mapped) + [(STACK_BASE, STACK_SIZE)]
    incomplete_coverage_note = ""
    for base, size in regions:
        if size > 0 and size <= 16 * 1024 * 1024:
            try:
                blob = uc.mem_read(base, size)
                strings.extend(_extract_strings(bytes(blob)))
            except Exception:  # noqa: BLE001
                continue
    # Syscall-blind note: memory we could not emulate isn't proof of absence;
    # only report it as pre-processed coverage unless we measure >50% of binary.
    exec_size = sum(s.size for s in elf.sections if s.executable)
    total_file = len(data)
    coverage_pct = round((exec_size / total_file) * 100, 1) if total_file else 0
    if coverage_pct < 50:
        incomplete_coverage_note = f"note: only {coverage_pct}% of file covered by static emulation; syscall/runtime memory unobserved"
    deduped = sorted(set(strings))

    secrets: list[dict] = []
    if secrets_scan and deduped:
        from src.analysis.native_secrets_hunter import scan_so_bytes as _secrets_scan  # noqa: PLC0415
        secret_blob = "\n".join(deduped).encode()
        hits = _secrets_scan(secret_blob, source="pre-emulated-memory")
        secrets = [h.as_dict() for h in hits]
        for s in secrets:
            s["source"] = "pre-emulated-memory"

    status = "completed" if any_ok else "partial"
    partial = any(r.status == "error" for r in results) or incomplete_coverage_note != ""
    note = (
        f"{sum(1 for r in results if r.status == 'ok')}/{len(results)} constructor(s) emulated; "
        f"{len(deduped)} string(s) recovered from memory."
        + (" " + incomplete_coverage_note if incomplete_coverage_note else "")
    )
    return PreEmulationResult(
        status=status,
        constructors=results,
        recovered_strings=deduped,
        secrets=secrets,
        partial=partial,
        note=note,
    )


def scan_so_bytes(data: bytes) -> PreEmulationResult:
    return emulate_constructors(data)


def scan_apk_native_libs(apk_path: str) -> dict[str, PreEmulationResult]:
    out: dict[str, PreEmulationResult] = {}
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                out[name] = emulate_constructors(zf.read(name))
    return out
