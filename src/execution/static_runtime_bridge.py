"""Static ↔ runtime bridge — connect static anti-tamper locations with runtime hooks.

When a static scanner locates suspicious code at file-offset `X` inside a .so,
the runtime side needs to translate that into something actionable:

    (library, file_offset) + running_process_map → runtime_hook_address

The bridge consumes the static module's findings (e.g.
``native_anti_tamper_scanner.sites``) and produces a structured "hook plan"
that a Frida/Runtime driver can apply.  No assumption about which process
model/arch is running.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from src.analysis.native_elf import parse_elf

TRUST_TAG = "untrusted_child"


@dataclass
class HookPlan:
    library_name: str
    file_offset: int      # static scan offset
    vaddr: int            # translated ELF virtual address
    category: str
    severity: str
    runtime_rva: int = 0   # expected RVA (runtime base + vaddr)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "library_name": self.library_name,
            "file_offset": self.file_offset,
            "vaddr": hex(self.vaddr),
            "category": self.category,
            "severity": self.severity,
            "runtime_rva": hex(self.runtime_rva) if self.runtime_rva else None,
            "note": self.note,
            "trust": self.trust,
        }


@dataclass
class StaticRuntimeBridgeResult:
    status: str                          # built | empty | error
    hook_plans: list[HookPlan]
    libraries_seen: list[str]
    note: str
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "hook_plans": [p.as_dict() for p in self.hook_plans],
            "libraries_seen": self.libraries_seen,
            "note": self.note,
            "trust": self.trust,
        }


def _file_offset_to_vaddr(elf_data: bytes, off: int) -> int | None:
    elf = parse_elf(elf_data)
    if elf is None:
        return None
    from src.analysis.native_elf import PT_LOAD
    for seg in elf.segments:
        if seg.p_type != PT_LOAD or seg.filesz == 0:
            continue
        if seg.offset <= off < seg.offset + seg.filesz:
            return seg.vaddr + (off - seg.offset)
    return None


def build_hook_plans(
    static_findings: Iterable,
    *,
    library_name: str,
    so_bytes: bytes,
    runtime_base: int = 0,
) -> StaticRuntimeBridgeResult:
    """Convert static findings into runtime hook plans.

    Each finding must have ``offset`` attribute.  Uses ELF PT_LOAD to translate
    file offsets into VADDRs; ``runtime_base`` is the library's load address
    if already known (0 = leave RVA unresolved; runtime driver computes).
    """
    plans: list[HookPlan] = []
    for f in static_findings:
        off = getattr(f, "offset", None) if not isinstance(f, dict) else f.get("offset")
        if off is None:
            continue
        vaddr = _file_offset_to_vaddr(so_bytes, off)
        category = getattr(f, "category", "") if not isinstance(f, dict) else f.get("category", "")
        severity = getattr(f, "severity", "medium") if not isinstance(f, dict) else f.get("severity", "medium")

        plans.append(HookPlan(
            library_name=library_name,
            file_offset=off,
            vaddr=vaddr if vaddr is not None else 0,
            category=category,
            severity=severity,
            runtime_rva=runtime_base + vaddr if (runtime_base and vaddr is not None) else 0,
            note="elf-translated" if vaddr is not None else "no PT_LOAD cover",
        ))

    return StaticRuntimeBridgeResult(
        status="built" if plans else "empty",
        hook_plans=plans,
        libraries_seen=[library_name] if plans else [],
        note=f"{len(plans)} hook plans for {library_name}",
    )


def frida_hook_script(plans: list[HookPlan], *, module_name: str | None = None) -> str:
    """Emit a Frida/JavaScript snippet that hooks all planned addresses.

    The caller supplies the actual runtime base address at attach time.
    """
    if not plans:
        return "// empty plan"
    module = module_name or plans[0].library_name
    hooks = []
    for p in plans:
        if not p.runtime_rva and not p.vaddr:
            continue
        target_expr = f"base_addr.add(0x{p.vaddr:x})"
        hooks.append(f"""
    try {{
        Interceptor.attach({target_expr}, {{
            onEnter: function(args) {{
                send({{type: 'hook-hit', category: '{p.category}',
                      vaddr: 0x{p.vaddr:x}, sev: '{p.severity}'}});
            }}
        }});
    }} catch (e) {{
        console.log('hook-fail at 0x{p.vaddr:x}: ' + e);
    }}""")

    return f"""
var base_addr = Module.findBaseAddress('{module}');
if (base_addr) {{
    console.log('bridge: {module} base=' + base_addr);
{chr(10).join(hooks)}
}} else {{
    console.log('bridge: module {module} not loaded yet');
}}
"""
