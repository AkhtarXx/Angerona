"""V8 Ignition bytecode processor (experimental, BytecodeArray-only)."""

from __future__ import annotations

from typing import Any

from src.processors.base import Instruction, ProcessorModule


# V8 Ignition opcodes (subset ~30 most-used; BytecodeArray format varies by V8 version).
_V8_OPS = {
    0x00: "Wide", 0x01: "ExtraWide", 0x02: "DebugBreak", 0x03: "Ldar",
    0x04: "LdaZero", 0x05: "LdaSmi", 0x06: "LdaUndefined",
    0x07: "LdaNull", 0x08: "LdaTheHole", 0x09: "LdaTrue", 0x0A: "LdaFalse",
    0x0B: "LdaConstant", 0x0C: "LdaGlobal", 0x0D: "LdaGlobalInsideTypeof",
    0x0E: "LdaContextSlot", 0x0F: "LdaImmutableContextSlot",
    0x10: "LdaCurrentContextSlot", 0x11: "LdaImmutableCurrentContextSlot",
    0x12: "Star", 0x13: "Mov", 0x14: "LdaNamedProperty",
    0x15: "LdaNamedPropertyNoFeedback", 0x16: "LdaKeyedProperty",
    0x17: "LdaModuleVariable", 0x18: "StaNamedProperty",
    0x19: "StaNamedPropertyNoFeedback", 0x1A: "StaKeyedProperty",
    0x1B: "StaInArrayLiteral", 0x1C: "StaDataPropertyInLiteral",
    0x1D: "LdaModuleVariableInTypeof", 0x1E: "LdaImmutableModuleVariable",
    0x1F: "StaContextSlot", 0x20: "StaImmutableContextSlot",
    0x21: "StaCurrentContextSlot", 0x22: "StaImmutableCurrentContextSlot",
    0x23: "Add", 0x24: "Sub", 0x25: "Mul", 0x26: "Div", 0x27: "Mod",
    0x28: "Exp", 0x29: "BitwiseOr", 0x2A: "BitwiseXor", 0x2B: "BitwiseAnd",
    0x2C: "ShiftLeft", 0x2D: "ShiftRight", 0x2E: "ShiftRightLogical",
    0x2F: "AddSmi", 0x30: "SubSmi", 0x31: "MulSmi", 0x32: "DivSmi", 0x33: "ModSmi",
    0x34: "ExpSmi", 0x35: "BitwiseOrSmi", 0x36: "BitwiseXorSmi",
    0x37: "BitwiseAndSmi", 0x38: "ShiftLeftSmi", 0x39: "ShiftRightSmi",
    0x3A: "ShiftRightLogicalSmi", 0x3B: "Negate", 0x3C: "BitwiseNot",
    0x3D: "Inc", 0x3E: "Dec", 0x3F: "ToNumber", 0x40: "ToNumeric",
    0x41: "TestEqual", 0x42: "TestEqualStrict", 0x43: "TestLessThan",
    0x44: "TestGreaterThan", 0x45: "TestLessThanOrEqual",
    0x46: "TestGreaterThanOrEqual", 0x47: "TestReferenceEqual",
    0x48: "TestInstanceOf", 0x49: "TestIn", 0x4A: "TestTypeOf",
    0x4B: "LogicalNot", 0x4C: "TypeOf", 0x4D: "ToString", 0x4E: "ToName",
    0x4F: "Delete", 0x50: "CreateClosure",
    0x51: "CreateRegExpLiteral", 0x52: "CreateArrayLiteral",
    0x53: "CreateArrayFromIterable", 0x54: "CreateEmptyArrayLiteral",
    0x55: "CreateObjectLiteral", 0x56: "CreateEmptyObjectLiteral",
    0x57: "CollectTypeProfileN", 0x58: "CreateMappedArguments",
    0x59: "CreateUnmappedArguments", 0x5A: "CreateRestParameter",
    0x5B: "New", 0x5C: "Construct", 0x5D: "ConstructWithSpread",
    0x5E: "CallAnyReceiver", 0x5F: "CallProperty", 0x60: "CallProperty0",
    0x61: "CallProperty1", 0x62: "CallProperty2", 0x63: "CallUndefinedReceiver",
    0x64: "CallUndefinedReceiver0", 0x65: "CallUndefinedReceiver1",
    0x66: "CallUndefinedReceiver2", 0x67: "CallNoFeedback",
    0x68: "CallWithSpread", 0x69: "CallRuntime",
    0x6A: "CallRuntimeForPair", 0x6B: "CallJSRuntime",
    0x6C: "InvokeIntrinsic", 0x6D: "DefineKeyedOwnPropertyInLiteral",
    0x6E: "StoreIC_NoFeedback", 0x6F: "LoadIC_NoFeedback",
}


class V8IgnitionProcessor(ProcessorModule):
    name = "v8-ignition"
    arch = "v8"
    bits = 64
    pointer_size = 8
    max_instr_size = 8

    def decode(self, data: bytes, addr: int, *, metadata: dict[str, Any] | None = None) -> Instruction | None:
        if len(data) < 1:
            return None
        op = data[0]
        name = _V8_OPS.get(op)
        if name is None:
            return None
        size = 1
        # Heuristic size: look at common operand widths

        if name.startswith(("Lda", "Ldar", "Star", "Mov", "CallProperty")):
            # common short-form: 1-2 operand bytes
            size = min(len(data), 3)
        elif "Smi" in name or name in ("LdaConstant", "CallAnyReceiver"):
            size = min(len(data), 4)
        return Instruction(address=addr, mnemonic=name, operands=data[1:size].hex(),
                           size=size, bytes=data[:size])

    def emulate(self, insn: Instruction) -> list[dict[str, Any]]:
        if insn.mnemonic.startswith(("Call", "Invoke", "New", "Construct")):
            return [{"kind": "call", "target": insn.operands or None}]
        if insn.mnemonic in ("Jump", "JumpIfFalse", "JumpIfTrue", "JumpLoop",
                             "JumpConstant", "SwitchOnSmiNoFeedback"):
            return [{"kind": "jump"}]
        return []
