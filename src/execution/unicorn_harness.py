"""Loader-backed Unicorn execution with evidence-grade state capture."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.execution.loaders import BinaryLoadError, LoadedBinary, PAGE_SIZE, load_binary
from src.execution.models import (
    DynamicEvent,
    MemoryImage,
    MemoryRegion,
    MemorySnapshot,
    ModuleMapping,
)
from src.execution.runners.base import RunnerResult


MAX_TRACE_EVENTS = 16_384
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_MAPPED_PAGES = 262_144
DEFAULT_STACK_SIZE = 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _align_down(value: int) -> int:
    return value & ~(PAGE_SIZE - 1)


def _align_up(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


@dataclass(frozen=True)
class _Architecture:
    arch: int
    mode: int
    pc: int
    sp: int
    return_value: int | None
    return_address: int | None
    argument_registers: tuple[int, ...]
    register_names: tuple[tuple[str, int], ...]
    byte_order: str = "little"


def _architecture(
    unicorn: Any,
    isa: str,
    image_format: str,
    byte_order: str = "little",
) -> _Architecture:
    isa = isa.lower()
    if isa in {"x86_64", "x64", "amd64"}:
        from unicorn import x86_const as c

        arguments = (
            (c.UC_X86_REG_RCX, c.UC_X86_REG_RDX, c.UC_X86_REG_R8, c.UC_X86_REG_R9)
            if image_format == "pe"
            else (
                c.UC_X86_REG_RDI, c.UC_X86_REG_RSI, c.UC_X86_REG_RDX,
                c.UC_X86_REG_RCX, c.UC_X86_REG_R8, c.UC_X86_REG_R9,
            )
        )
        return _Architecture(
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_64,
            c.UC_X86_REG_RIP,
            c.UC_X86_REG_RSP,
            c.UC_X86_REG_RAX,
            None,
            arguments,
            (
                ("rip", c.UC_X86_REG_RIP), ("rsp", c.UC_X86_REG_RSP),
                ("rax", c.UC_X86_REG_RAX), ("rbx", c.UC_X86_REG_RBX),
                ("rcx", c.UC_X86_REG_RCX), ("rdx", c.UC_X86_REG_RDX),
                ("rsi", c.UC_X86_REG_RSI), ("rdi", c.UC_X86_REG_RDI),
                ("rbp", c.UC_X86_REG_RBP), ("r8", c.UC_X86_REG_R8),
                ("r9", c.UC_X86_REG_R9),
            ),
        )
    if isa in {"x86", "i386"}:
        from unicorn import x86_const as c

        return _Architecture(
            unicorn.UC_ARCH_X86,
            unicorn.UC_MODE_32,
            c.UC_X86_REG_EIP,
            c.UC_X86_REG_ESP,
            c.UC_X86_REG_EAX,
            None,
            (),
            (
                ("eip", c.UC_X86_REG_EIP), ("esp", c.UC_X86_REG_ESP),
                ("eax", c.UC_X86_REG_EAX), ("ebx", c.UC_X86_REG_EBX),
                ("ecx", c.UC_X86_REG_ECX), ("edx", c.UC_X86_REG_EDX),
                ("esi", c.UC_X86_REG_ESI), ("edi", c.UC_X86_REG_EDI),
                ("ebp", c.UC_X86_REG_EBP),
            ),
        )
    if isa in {"aarch64", "arm64"}:
        from unicorn import arm64_const as c

        args = tuple(getattr(c, f"UC_ARM64_REG_X{index}") for index in range(8))
        return _Architecture(
            unicorn.UC_ARCH_ARM64,
            unicorn.UC_MODE_ARM,
            c.UC_ARM64_REG_PC,
            c.UC_ARM64_REG_SP,
            c.UC_ARM64_REG_X0,
            c.UC_ARM64_REG_X30,
            args,
            tuple(
                [("pc", c.UC_ARM64_REG_PC), ("sp", c.UC_ARM64_REG_SP)]
                + [(f"x{index}", getattr(c, f"UC_ARM64_REG_X{index}")) for index in range(31)]
            ),
        )
    if isa in {"arm", "armthumb"}:
        from unicorn import arm_const as c

        mode = unicorn.UC_MODE_THUMB if isa == "armthumb" else unicorn.UC_MODE_ARM
        return _Architecture(
            unicorn.UC_ARCH_ARM,
            mode,
            c.UC_ARM_REG_PC,
            c.UC_ARM_REG_SP,
            c.UC_ARM_REG_R0,
            c.UC_ARM_REG_LR,
            (c.UC_ARM_REG_R0, c.UC_ARM_REG_R1, c.UC_ARM_REG_R2, c.UC_ARM_REG_R3),
            tuple(
                [("pc", c.UC_ARM_REG_PC), ("sp", c.UC_ARM_REG_SP), ("lr", c.UC_ARM_REG_LR)]
                + [(f"r{index}", getattr(c, f"UC_ARM_REG_R{index}")) for index in range(13)]
            ),
        )
    if isa in {"riscv", "riscv64"}:
        from unicorn import riscv_const as c

        mode = unicorn.UC_MODE_RISCV64 if isa == "riscv64" else unicorn.UC_MODE_RISCV32
        args = tuple(getattr(c, f"UC_RISCV_REG_A{index}") for index in range(8))
        return _Architecture(
            unicorn.UC_ARCH_RISCV,
            mode,
            c.UC_RISCV_REG_PC,
            c.UC_RISCV_REG_SP,
            c.UC_RISCV_REG_A0,
            c.UC_RISCV_REG_RA,
            args,
            (
                ("pc", c.UC_RISCV_REG_PC), ("sp", c.UC_RISCV_REG_SP),
                ("ra", c.UC_RISCV_REG_RA),
                *tuple((f"a{index}", getattr(c, f"UC_RISCV_REG_A{index}")) for index in range(8)),
            ),
        )
    if isa in {"mips", "mips32", "mips64"}:
        from unicorn import mips_const as c

        mode = unicorn.UC_MODE_MIPS64 if isa == "mips64" else unicorn.UC_MODE_MIPS32
        mode |= unicorn.UC_MODE_BIG_ENDIAN if byte_order == "big" else unicorn.UC_MODE_LITTLE_ENDIAN
        return _Architecture(
            unicorn.UC_ARCH_MIPS,
            mode,
            c.UC_MIPS_REG_PC,
            c.UC_MIPS_REG_SP,
            c.UC_MIPS_REG_V0,
            c.UC_MIPS_REG_RA,
            (c.UC_MIPS_REG_A0, c.UC_MIPS_REG_A1, c.UC_MIPS_REG_A2, c.UC_MIPS_REG_A3),
            (
                ("pc", c.UC_MIPS_REG_PC), ("sp", c.UC_MIPS_REG_SP),
                ("ra", c.UC_MIPS_REG_RA), ("v0", c.UC_MIPS_REG_V0),
                ("a0", c.UC_MIPS_REG_A0), ("a1", c.UC_MIPS_REG_A1),
                ("a2", c.UC_MIPS_REG_A2), ("a3", c.UC_MIPS_REG_A3),
            ),
            byte_order=byte_order,
        )
    raise BinaryLoadError(f"Unicorn harness does not support architecture {isa}")


def _permission_value(unicorn: Any, mask: str) -> int:
    value = 0
    if mask[0] == "r":
        value |= unicorn.UC_PROT_READ
    if mask[1] == "w":
        value |= unicorn.UC_PROT_WRITE
    if mask[2] == "x":
        value |= unicorn.UC_PROT_EXEC
    return value


def _page_permissions(image: LoadedBinary) -> dict[int, int]:
    pages: dict[int, int] = {}
    for segment in image.segments:
        bits = 0
        if segment.permissions[0] == "r":
            bits |= 1
        if segment.permissions[1] == "w":
            bits |= 2
        if segment.permissions[2] == "x":
            bits |= 4
        for address in range(segment.mapped_start, segment.mapped_end, PAGE_SIZE):
            pages[address] = pages.get(address, 0) | bits
            if len(pages) > MAX_MAPPED_PAGES:
                raise BinaryLoadError("Unicorn page plan exceeds safety limit")
    return pages


def _permission_string(bits: int) -> str:
    return f"{'r' if bits & 1 else '-'}{'w' if bits & 2 else '-'}{'x' if bits & 4 else '-'}"


def _group_pages(pages: dict[int, int]) -> list[tuple[int, int, int]]:
    groups: list[tuple[int, int, int]] = []
    for address in sorted(pages):
        bits = pages[address]
        if groups and groups[-1][0] + groups[-1][1] == address and groups[-1][2] == bits:
            start, size, old_bits = groups[-1]
            groups[-1] = (start, size + PAGE_SIZE, old_bits)
        else:
            groups.append((address, PAGE_SIZE, bits))
    return groups


class UnicornHarness:
    """Execute one mapped image while emitting normalized runtime evidence."""

    name = "unicorn-loader"

    @staticmethod
    def available() -> bool:
        try:
            import unicorn  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    def run_path(
        self,
        path: str | Path,
        *,
        entry_point: int | None = None,
        architecture: str | None = None,
        args: list[int] | None = None,
        capture_ranges: list[tuple[str, int, int]] | None = None,
        max_instructions: int = 2_000,
        max_events: int = MAX_TRACE_EVENTS,
        stack_size: int = DEFAULT_STACK_SIZE,
    ) -> RunnerResult:
        try:
            image = load_binary(
                path,
                raw_architecture=architecture,
                raw_entry_point=entry_point,
            )
        except (OSError, BinaryLoadError) as exc:
            return RunnerResult(status="error", note=f"loader failed: {exc}")
        return self.run_image(
            image,
            entry_point=entry_point,
            args=args,
            capture_ranges=capture_ranges,
            max_instructions=max_instructions,
            max_events=max_events,
            stack_size=stack_size,
            source_path=str(path),
        )

    def run_image(
        self,
        image: LoadedBinary,
        *,
        entry_point: int | None = None,
        args: list[int] | None = None,
        capture_ranges: list[tuple[str, int, int]] | None = None,
        max_instructions: int = 2_000,
        max_events: int = MAX_TRACE_EVENTS,
        stack_size: int = DEFAULT_STACK_SIZE,
        source_path: str | None = None,
    ) -> RunnerResult:
        if not self.available():
            return RunnerResult(status="unavailable", note="unicorn engine not installed")
        if not 1 <= max_instructions <= 10_000_000:
            return RunnerResult(status="error", note="max_instructions is outside safety bounds")
        if not 0 <= max_events <= MAX_TRACE_EVENTS:
            return RunnerResult(status="error", note="max_events is outside safety bounds")
        if stack_size < PAGE_SIZE or stack_size > 64 * 1024 * 1024:
            return RunnerResult(status="error", note="stack_size is outside safety bounds")
        requested_captures = list(capture_ranges or [])
        if any(address < 0 or length < 0 for _name, address, length in requested_captures):
            return RunnerResult(status="error", note="capture ranges must be non-negative")
        if sum(length for _name, _address, length in requested_captures) > MAX_CAPTURE_BYTES:
            return RunnerResult(status="error", note="capture request exceeds safety limit")

        try:
            import unicorn
            architecture = _architecture(
                unicorn, image.architecture, image.format, image.endianness
            )
            machine = unicorn.Uc(architecture.arch, architecture.mode)
        except Exception as exc:  # noqa: BLE001
            return RunnerResult(status="unavailable", note=f"Unicorn architecture unavailable: {exc}")

        events: list[DynamicEvent] = []
        instruction_count = 0
        trace_truncated = False
        stop_reason = "instruction_limit"
        start = entry_point if entry_point is not None else image.entry_point
        if not any(
            segment.runtime_address <= start < segment.runtime_address + segment.memory_size
            and segment.permissions[2] == "x"
            for segment in image.segments
        ):
            return RunnerResult(status="error", note="requested entry point is not executable")

        try:
            pages = _page_permissions(image)
            for address, size, _bits in _group_pages(pages):
                machine.mem_map(address, size, unicorn.UC_PROT_ALL)
            for segment in image.segments:
                if segment.data:
                    machine.mem_write(segment.runtime_address, segment.data)
            for address, size, bits in _group_pages(pages):
                machine.mem_protect(address, size, _permission_value(unicorn, _permission_string(bits)))

            stack_size = _align_up(stack_size)
            stack_base = 0x7FFF00000000 if image.pointer_size == 8 else 0x7F000000
            if not (stack_base + stack_size <= image.image_start or stack_base >= image.image_end):
                stack_base = _align_up(image.image_end + 0x100000)
            machine.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)

            sentinel = _align_up(max(image.image_end, stack_base + stack_size) + 0x100000)
            machine.mem_map(sentinel, PAGE_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
            stack_pointer = stack_base + stack_size - 0x100
            stack_pointer &= ~(max(image.pointer_size, 8) - 1)
            machine.reg_write(architecture.sp, stack_pointer)
            machine.reg_write(architecture.pc, start)

            word_mask = (1 << (image.pointer_size * 8)) - 1
            concrete_args = [int(value) & word_mask for value in (args or [])]
            for register, value in zip(architecture.argument_registers, concrete_args):
                machine.reg_write(register, value)
            if image.architecture in {"x86", "i386"}:
                values = [sentinel, *concrete_args]
                stack_pointer -= len(values) * image.pointer_size
                machine.mem_write(
                    stack_pointer,
                    b"".join(value.to_bytes(image.pointer_size, "little", signed=False) for value in values),
                )
                machine.reg_write(architecture.sp, stack_pointer)
            elif image.architecture in {"x86_64", "x64", "amd64"}:
                # At function entry RSP points at the synthetic return address.
                # The Windows x64 32-byte home area lives above it.
                stack_pointer -= image.pointer_size
                machine.mem_write(stack_pointer, sentinel.to_bytes(image.pointer_size, "little"))
                machine.reg_write(architecture.sp, stack_pointer)
            elif architecture.return_address is not None:
                machine.reg_write(architecture.return_address, sentinel)

            stack_arguments = concrete_args[len(architecture.argument_registers):]
            if stack_arguments and image.architecture not in {"x86", "i386"}:
                argument_offset = (
                    40 if image.architecture in {"x86_64", "x64", "amd64"} and image.format == "pe"
                    else image.pointer_size if image.architecture in {"x86_64", "x64", "amd64"}
                    else 0
                )
                machine.mem_write(
                    stack_pointer + argument_offset,
                    b"".join(
                        value.to_bytes(image.pointer_size, architecture.byte_order, signed=False)
                        for value in stack_arguments
                    ),
                )

            def append_event(kind: str, address: int | None = None, **properties: Any) -> None:
                nonlocal trace_truncated
                if len(events) >= max_events:
                    trace_truncated = True
                    return
                static_address = None
                module_id = None
                if address is not None and image.image_start <= address < image.image_end:
                    static_address = image.static_address(address)
                    module_id = "main"
                events.append(DynamicEvent.create(
                    len(events),
                    kind,
                    self.name,
                    timestamp=_utc_now(),
                    runtime_address=address,
                    static_address=static_address,
                    module_id=module_id,
                    properties=properties,
                ))

            def on_code(_machine: Any, address: int, size: int, _user: Any) -> None:
                nonlocal instruction_count, stop_reason
                if address == sentinel:
                    stop_reason = "returned"
                    append_event("return", address, instruction_count=instruction_count)
                    _machine.emu_stop()
                    return
                instruction_count += 1

            def on_block(_machine: Any, address: int, size: int, _user: Any) -> None:
                append_event("basic_block", address, size=size)

            def on_invalid(
                _machine: Any,
                access: int,
                address: int,
                size: int,
                value: int,
                _user: Any,
            ) -> bool:
                append_event(
                    "invalid_memory",
                    address,
                    access=access,
                    size=size,
                    value=value,
                )
                return False

            machine.hook_add(unicorn.UC_HOOK_CODE, on_code)
            machine.hook_add(unicorn.UC_HOOK_BLOCK, on_block)
            machine.hook_add(
                unicorn.UC_HOOK_MEM_READ_UNMAPPED
                | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED
                | unicorn.UC_HOOK_MEM_FETCH_UNMAPPED
                | unicorn.UC_HOOK_MEM_READ_PROT
                | unicorn.UC_HOOK_MEM_WRITE_PROT
                | unicorn.UC_HOOK_MEM_FETCH_PROT,
                on_invalid,
            )
            try:
                machine.emu_start(start, sentinel + PAGE_SIZE, count=max_instructions)
                if stop_reason != "returned":
                    current_pc = int(machine.reg_read(architecture.pc))
                    stop_reason = "instruction_limit" if instruction_count >= max_instructions else "stopped"
                    append_event("stop", current_pc, reason=stop_reason)
                emulation_error = ""
            except Exception as exc:  # noqa: BLE001 - normalize optional backend errors
                current_pc = int(machine.reg_read(architecture.pc))
                stop_reason = "backend_error"
                emulation_error = str(exc)
                append_event("backend_error", current_pc, error=emulation_error)

            registers = {
                name: int(machine.reg_read(register))
                for name, register in architecture.register_names
            }
            snapshots: list[MemorySnapshot] = []
            captured_regions: list[MemoryRegion] = []
            capture_errors: list[str] = []
            for name, address, length in requested_captures:
                if length < 0:
                    capture_errors.append(f"{name}: negative length")
                    continue
                try:
                    payload = bytes(machine.mem_read(address, length))
                except Exception as exc:  # noqa: BLE001
                    capture_errors.append(f"{name}: {exc}")
                    append_event("capture_error", address, name=name, length=length, error=str(exc))
                    continue
                properties = {
                    "target_sha256": image.source_sha256,
                    "capture_provider": self.name,
                    "memory_image_format": image.format,
                }
                snapshots.append(MemorySnapshot.from_bytes(
                    address,
                    payload,
                    source=self.name,
                    name=name,
                    properties=properties,
                ))
                captured_regions.append(MemoryRegion.from_bytes(
                    name=name,
                    address=address,
                    payload=payload,
                    permissions="rw-",
                    kind="requested_capture",
                    properties=properties,
                ))

            module = ModuleMapping(
                module_id="main",
                name=Path(source_path).name if source_path else "main",
                path=source_path,
                runtime_base=image.load_base,
                preferred_base=image.preferred_base,
                size=image.image_end - image.image_start,
                sha256=image.source_sha256,
                properties={"format": image.format},
            )
            descriptor_regions = [
                MemoryRegion(
                    name=segment.name,
                    address=f"0x{segment.runtime_address:x}",
                    size=segment.memory_size,
                    permissions=segment.permissions,
                    kind="module",
                    module_id="main",
                    file_offset=segment.file_offset,
                    properties={
                        "file_size": segment.file_size,
                        **dict(segment.properties),
                    },
                )
                for segment in image.segments
            ]
            descriptor_regions.append(MemoryRegion(
                name="stack",
                address=f"0x{stack_base:x}",
                size=stack_size,
                permissions="rw-",
                kind="stack",
            ))
            memory_image = MemoryImage.create(
                provider=self.name,
                target_sha256=image.source_sha256,
                architecture=image.architecture,
                pointer_size=image.pointer_size,
                regions=[*descriptor_regions, *captured_regions],
                modules=[module],
                registers=registers,
                events=events,
                load_base=image.load_base,
                entry_point=start,
                properties={
                    "loader": image.as_dict(),
                    "instruction_count": instruction_count,
                    "stop_reason": stop_reason,
                    "trace_truncated": trace_truncated,
                    "capture_errors": capture_errors,
                    "emulation_error": emulation_error,
                },
            )
            status = "success" if stop_reason == "returned" and not capture_errors else "inconclusive"
            return RunnerResult(
                status=status,
                snapshots=snapshots,
                memory_image=memory_image,
                events=events,
                note=(
                    f"loader-backed Unicorn stopped: {stop_reason}; "
                    f"instructions={instruction_count}; captures={len(snapshots)}"
                ),
                detail={
                    "executed": True,
                    "loader": image.as_dict(),
                    "instruction_count": instruction_count,
                    "stop_reason": stop_reason,
                    "trace_truncated": trace_truncated,
                    "capture_errors": capture_errors,
                    "emulation_error": emulation_error,
                    "capture_id": memory_image.capture_id,
                    "target_sha256": image.source_sha256,
                },
            )
        except Exception as exc:  # noqa: BLE001 - no backend exception may escape
            return RunnerResult(
                status="error",
                events=events,
                note=f"loader-backed Unicorn failed: {exc}",
                detail={"executed": False, "loader": image.as_dict()},
            )
