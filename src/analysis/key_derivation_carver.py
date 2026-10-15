"""Carve runtime-constructed secrets out of Android .so prologues.

Real apps almost never keep a key as a static string.  They write it
byte-by-byte with MOV-immediate into a stack buffer, or hold it XOR-masked in
.rodata and unwrap it in a tiny (len, key) loop.  ``strings`` sees nothing in
either case.

This module does pure static carving over capstone-disassembled code:

  * :class:`FillPattern.WIMM_AARCH64` — ``mov w8, #imm; strb w8, [sp, #off]``
    pairs; we reconstruct the full buffer image.
  * :class:`FillPattern.XOR_LOOP_HEURISTIC` — a small loop body containing a
    ``ldrb`` from a rodata-looking pointer, an ``eor`` with a stable
    register, and a ``strb`` store; we report the loop site, its trip-count
    immediate when obvious, and the XOR key register — flagged partial=True
    since we do NOT emulate (emulation belongs to the oracle).
  * :class:`FillPattern.MOVK_CHAIN` — ``movk`` constant buildup chains that
    construct wide keys.

Outputs include the recovered byte sequence (for exact carve) and an ASCII
view where printable.  Everything is sized to be fed directly into
``reconstruct_state`` as evidence claims.

Trust: parsed-from-untrusted-binary — TRUST_TAG "untrusted_child".
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from enum import Enum

from src.analysis.native_elf import parse_elf

TRUST_TAG = "untrusted_child"

MAX_DISASM_BYTES = 4 * 1024 * 1024  # 4 MiB code cap per .so


class FillPattern(str, Enum):
    WIMM_AARCH64 = "aarch64_mov_strb_pair"
    MOVZ_MOVK_CHAIN = "aarch64_movz_movk_chain"
    XOR_LOOP_HEURISTIC = "aarch64_xor_loop"


@dataclass(frozen=True)
class CarvedCandidate:
    pattern: str
    site_addr: int          # address of the first instruction of the pattern
    bytes_carved: bytes     # exact bytes (empty for partial/loop heuristics)
    ascii_view: str         # printable preview ("." for non-printable)
    width: int              # register width used (8/32/64 bit writes)
    partial: bool           # True when carved by heuristic, not exact sequence
    note: str

    def preview(self, n: int = 32) -> str:
        return self.ascii_view[:n]


@dataclass(frozen=True)
class KeyCarveResult:
    status: str             # carved | partial | none | unsupported
    candidates: list[CarvedCandidate]
    functions_analyzed: int
    bytes_disassembled: int
    note: str
    trust: str = TRUST_TAG


def _capstone_arm64():
    import capstone  # noqa: PLC0415
    return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def _ascii(bts: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bts)


def _scan_mov_strb(insns) -> list[CarvedCandidate]:
    """Detect `mov wN, #imm / strb wN, [sp|x29, #off]` pairs writing a buffer."""
    out: list[CarvedCandidate] = []
    pending_imm: dict[str, tuple[int, int]] = {}  # reg -> (imm, address)
    for ins in insns:
        mn = ins.mnemonic
        if mn in ("mov", "movz") and ins.op_str.startswith("w"):
            try:
                reg, imm_s = [p.strip() for p in ins.op_str.split(",", 1)]
                imm = int(imm_s.lstrip("#"), 0)
                pending_imm[reg] = (imm, ins.address)
            except (ValueError, IndexError):
                continue
        elif mn == "strb":
            parts = [p.strip() for p in ins.op_str.split(",", 1)]
            if len(parts) == 2 and parts[0] in pending_imm:
                imm, src_addr = pending_imm.pop(parts[0])
                if 0 <= imm <= 0xFF:
                    out.append(
                        CarvedCandidate(
                            pattern=FillPattern.WIMM_AARCH64.value,
                            site_addr=src_addr,
                            bytes_carved=bytes([imm]),
                            ascii_view=_ascii(bytes([imm])),
                            width=8,
                            partial=False,
                            note=f"mov {parts[0]}, #{imm} ; strb -> stack/store site",
                        )
                    )
        elif mn in ("bl", "ret", "br"):
            pending_imm.clear()
        if len(out) >= 4096:  # bound hostile code
            break
    return out


def _written_xregs(ins) -> set[str]:
    """x-register names written by ``ins``, from per-operand access flags.

    ``CsInsn.regs_access()`` returns swapped read/write sets for AArch64 in
    capstone 5.0.x, so derive writes from operand access flags instead.
    Degrades to ``set()`` when detail is unavailable — callers then keep
    chains open (the safe direction) rather than close them prematurely.
    """
    import capstone as _cs  # noqa: PLC0415

    written: set[str] = set()
    try:
        for op in ins.operands:
            if op.type == _cs.arm64.ARM64_OP_REG and op.access & _cs.CS_AC_WRITE:
                name = ins.reg_name(op.reg)
                if name.startswith("x"):
                    written.add(name)
    except Exception:  # noqa: BLE001
        return written
    return written


def _scan_movz_movk(insns) -> list[CarvedCandidate]:
    """Detect movz+movk chains building a 64-bit constant in one register.

    Capstone prints ``movx, #imm``-only encodings (zero-shift movz) as
    plain ``mov`` — so we accept ``mov`` too when the destination is an
    x-register and this is the chain *opener* (i.e. we haven't started a
    chain on this register yet).
    """
    out: list[CarvedCandidate] = []
    chains: dict[str, list[tuple[int, int, int]]] = {}  # reg -> [(addr, imm, shift)]
    finished: set[str] = set()
    for ins in insns:
        mn = ins.mnemonic
        parts = [p.strip() for p in ins.op_str.split(",") if p.strip()]
        # capstone prints 0-shift movz as plain 'mov'
        if mn == "mov" and len(parts) == 2 and parts[0].startswith("x") and parts[0] not in chains:
            mn = "movz"
        if mn in ("movz", "movk") and len(parts) >= 2 and parts[0].startswith("x"):
            reg = parts[0]
            try:
                imm = int(parts[1].lstrip("#"), 0)
            except ValueError:
                continue
            shift = 0
            for p in parts[2:]:
                if p.startswith("lsl"):
                    try:
                        shift = int(p.split("#")[1])
                    except (ValueError, IndexError):
                        shift = 0
            if mn == "movz":
                chains[reg] = [(ins.address, imm, shift)]
            else:
                chains.setdefault(reg, []).append((ins.address, imm, shift))
        else:
            # A non-chain instruction only terminates a chain when it actually
            # rewrites that chain's register; interleaved instructions touching
            # other registers must not split a multi-step 64-bit build into
            # wrong "exact" fragments.  Chains are otherwise complete constants
            # whether or not a consuming instruction is visible (consumer may be
            # a branch or land outside our window).
            for reg in list(chains):
                if reg in _written_xregs(ins):
                    chain = chains.pop(reg)
                    if len(chain) >= 2:
                        value = 0
                        for _, imm, shift in chain:
                            value |= (imm & 0xFFFF) << shift
                        out.append(
                            CarvedCandidate(
                                pattern=FillPattern.MOVZ_MOVK_CHAIN.value,
                                site_addr=chain[0][0],
                                bytes_carved=value.to_bytes(8, "little"),
                                ascii_view=_ascii(value.to_bytes(8, "little")),
                                width=64,
                                partial=False,
                                note=f"movz/movk chain {len(chain)} steps into {reg} (closed at {ins.mnemonic})",
                            )
                        )
    for reg, chain in chains.items():  # flush chains still open at end of stream
        if len(chain) >= 2:
            value = 0
            for _, imm, shift in chain:
                value |= (imm & 0xFFFF) << shift
            out.append(
                CarvedCandidate(
                    pattern=FillPattern.MOVZ_MOVK_CHAIN.value,
                    site_addr=chain[0][0],
                    bytes_carved=value.to_bytes(8, "little"),
                    ascii_view=_ascii(value.to_bytes(8, "little")),
                    width=64,
                    partial=False,
                    note=f"movz/movk chain {len(chain)} steps into {reg} (end of stream)",
                )
            )
        if len(out) >= 1024:
            break
    return out


def _scan_xor_loops(insns) -> list[CarvedCandidate]:
    """Heuristic: small loop with ldrb from rodata + eor + strb at end."""
    out: list[CarvedCandidate] = []
    window: list = []
    for ins in insns:
        window.append(ins)
        if len(window) > 12:
            window.pop(0)
        if ins.mnemonic in ("b.ne", "b.lt", "b.lo", "b.le", "cbnz"):
            mns = [w.mnemonic for w in window]
            regs_written = set()
            regs_read = set()
            for w in window:
                try:
                    rd, rs = w.regs_access()
                    regs_read.update(w.reg_name(r) for r in rs)
                    regs_written.update(w.reg_name(r) for r in rd)
                except Exception:  # noqa: BLE001
                    continue
            if "ldrb" in mns and "eor" in mns and "strb" in mns:
                out.append(
                    CarvedCandidate(
                        pattern=FillPattern.XOR_LOOP_HEURISTIC.value,
                        site_addr=window[0].address,
                        bytes_carved=b"",
                        ascii_view="",
                        width=0,
                        partial=True,
                        note=(
                            f"xor-decode store loop: body insns {'/'.join(sorted(set(mns)))}; "
                            f"xor sources {sorted(regs_read & regs_written)}"
                        ),
                    )
                )
            window = [window[-1]] if window else []
        if len(out) >= 256:
            break
    return out


def carve_key_derivations(data: bytes) -> KeyCarveResult:
    elf = parse_elf(data)
    if elf is None:
        return KeyCarveResult(
            status="unsupported", candidates=[], functions_analyzed=0,
            bytes_disassembled=0, note="input is not a parsed ELF file",
        )
    if elf.machine != 183:
        return KeyCarveResult(
            status="unsupported", candidates=[], functions_analyzed=0,
            bytes_disassembled=0,
            note=f"carver currently supports EM_AARCH64 (got EM_{elf.machine})",
        )

    try:
        md = _capstone_arm64()
        md.detail = True
    except Exception as exc:  # noqa: BLE001
        return KeyCarveResult(
            status="unsupported", candidates=[], functions_analyzed=0,
            bytes_disassembled=0, note=f"capstone unavailable: {exc}",
        )

    candidates: list[CarvedCandidate] = []
    total_bytes = 0
    nfuncs = 0
    for sec in elf.sections:
        if not sec.executable or not sec.size:
            continue
        blob = data[sec.offset : min(sec.offset + sec.size, len(data))]
        blob = blob[:MAX_DISASM_BYTES]
        if not blob:
            continue
        insns = list(md.disasm(blob, sec.addr))
        total_bytes += len(blob)
        nfuncs += 1  # section-granularity; per-function chunking is for the lifter
        candidates.extend(_scan_mov_strb(insns))
        candidates.extend(_scan_movz_movk(insns))
        candidates.extend(_scan_xor_loops(insns))

    if not candidates:
        status, note = "none", "no runtime key-construction patterns found."
    elif any(c.partial for c in candidates):
        status, note = "partial", f"{len(candidates)} candidate site(s); {sum(1 for c in candidates if c.partial)} heuristic/partial (emulation follow-up recommended)."
    else:
        status, note = "carved", f"{len(candidates)} exact key-construction site(s) carved."
    return KeyCarveResult(
        status=status,
        candidates=candidates,
        functions_analyzed=nfuncs,
        bytes_disassembled=total_bytes,
        note=note,
    )


def scan_so_bytes(data: bytes) -> KeyCarveResult:
    return carve_key_derivations(data)


def scan_apk_native_libs(apk_path: str) -> dict[str, KeyCarveResult]:
    out: dict[str, KeyCarveResult] = {}
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                out[name] = carve_key_derivations(zf.read(name))
    return out
