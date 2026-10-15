"""VEX lifter via pyvex — fast path for angr-supported guests (10 ISAs)."""

from __future__ import annotations

from .base import LiftOutcome, LiftRequest, LifUnavailable

_VEX_GUESTS = {
    "x86-64": "amd64", "x86-32": "x86",
    "arm-le-32": "arm", "aarch64": "arm64",
    "ppc-be-32": "ppc32", "ppc-le-64": "ppc64",
    "mips-le-32": "mips32le", "mips-be-32": "mips32be",
    "mips-le-64": "mips64le", "mips-be-64": "mips64be",
    "s390x": "s390x",
}


def lift(req: LiftRequest) -> LiftOutcome:
    try:
        import pyvex  # type: ignore
        import archinfo  # type: ignore
    except ImportError as exc:
        raise LifUnavailable(f"pyvex/archinfo not installed: {exc}") from exc

    guest = _VEX_GUESTS.get(req.isa.lower())
    if guest is None:
        raise LifUnavailable(f"pyvex does not support isa={req.isa!r}")
    arch_name = {"amd64": "ArchAMD64", "x86": "ArchX86", "arm": "ArchARM",
                 "arm64": "ArchAArch64", "ppc32": "ArchPPC32", "ppc64": "ArchPPC64",
                 "mips32le": "ArchMIPS32", "mips32be": "ArchMIPS32",
                 "mips64le": "ArchMIPS64", "mips64be": "ArchMIPS64",
                 "s390x": "ArchS390X"}.get(guest)
    if arch_name is None:
        raise LifUnavailable(f"no archinfo class for guest {guest!r}")
    arch_cls = getattr(archinfo, arch_name, None)
    if arch_cls is None:
        raise LifUnavailable(f"archinfo.{arch_name} missing")

    try:
        if guest in ("mips32be", "mips64be", "ppc32", "s390x"):
            arch = arch_cls(archinfo.Endness.BE)
        else:
            arch = arch_cls(archinfo.Endness.LE)
        irsb = pyvex.lift(req.bytes_code, req.base_address, arch)
    except Exception as exc:  # noqa: BLE001
        raise LifUnavailable(f"pyvex lift failed: {exc}") from exc

    ops = []
    for stmt in getattr(irsb, "statements", []):
        ops.append({"tag": stmt.tag, "body": _stmt_summary(stmt)})
    return LiftOutcome(
        request=req,
        ir=ops,
        confidence=0.90,
        provenance="pyvex",
    )


def _stmt_summary(stmt) -> str:
    tag = getattr(stmt, "tag", "")
    if tag == "Ist_IMark":
        return f"IMark(0x{stmt.addr:x})"
    if tag == "Ist_Put":
        return f"Put({stmt.offset})"
    if tag == "Ist_tmpPut":
        return f"TmpPut({stmt.tmp})"
    if tag == "Ist_WrTmp":
        return f"WrTmp({stmt.tmp})"
    if tag == "Ist_Store":
        return "Store"
    if tag == "Ist_Exit":
        return f"Exit({stmt.dst})"
    return tag
