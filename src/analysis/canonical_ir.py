"""Canonical p-code-like IR, SSA construction, def-use, taint, and slicing."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable


IR_SCHEMA_VERSION = "angerona.canonical-ir/v1"
MAX_IR_OPERATIONS = 5_000_000


@dataclass(frozen=True)
class IRValue:
    id: str
    name: str
    size: int = 0
    space: str = "unique"
    offset: int | None = None
    version: str = "0"
    properties: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "size": self.size,
            "space": self.space, "offset": self.offset, "version": self.version,
            "properties": dict(self.properties),
        }


@dataclass(frozen=True)
class IROperation:
    id: str
    opcode: str
    block_id: str
    inputs: tuple[str, ...] = ()
    output: str | None = None
    address: str | None = None
    properties: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "opcode": self.opcode, "block_id": self.block_id,
            "inputs": list(self.inputs), "output": self.output,
            "address": self.address, "properties": dict(self.properties),
        }


@dataclass
class CanonicalIR:
    function_id: str
    entry_block: str
    blocks: dict[str, list[str]]
    successors: dict[str, list[str]]
    values: dict[str, IRValue]
    operations: dict[str, IROperation]
    schema_version: str = IR_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if len(self.operations) > MAX_IR_OPERATIONS:
            raise ValueError("IR operation count exceeds safety limit")
        if self.entry_block not in self.blocks:
            raise ValueError("IR entry block is missing")
        operation_ids = [op_id for ids in self.blocks.values() for op_id in ids]
        if len(operation_ids) != len(set(operation_ids)) or set(operation_ids) != set(self.operations):
            raise ValueError("IR block operation membership is inconsistent")
        for operation in self.operations.values():
            if operation.output is not None and operation.output not in self.values:
                raise ValueError(f"undefined output value {operation.output}")
            if any(value not in self.values for value in operation.inputs):
                raise ValueError(f"operation {operation.id} references an undefined input")

    @property
    def predecessors(self) -> dict[str, list[str]]:
        result = {block: [] for block in self.blocks}
        for source, targets in self.successors.items():
            for target in targets:
                if target in result:
                    result[target].append(source)
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "function_id": self.function_id,
            "entry_block": self.entry_block,
            "blocks": {key: list(value) for key, value in self.blocks.items()},
            "successors": {key: list(value) for key, value in self.successors.items()},
            "values": {key: value.as_dict() for key, value in self.values.items()},
            "operations": {key: value.as_dict() for key, value in self.operations.items()},
        }


class SSAConverter:
    """Convert named p-code records into SSA using reaching definitions and PHIs."""

    def convert(
        self,
        function_id: str,
        blocks: dict[str, list[dict[str, Any]]],
        successors: dict[str, list[str]],
        *,
        entry_block: str,
    ) -> CanonicalIR:
        if entry_block not in blocks:
            raise ValueError("entry block is missing")
        total = sum(len(rows) for rows in blocks.values())
        if total > MAX_IR_OPERATIONS:
            raise ValueError("IR operation count exceeds safety limit")
        predecessors = {block: [] for block in blocks}
        for source, targets in successors.items():
            if source not in blocks:
                raise ValueError(f"unknown successor source {source}")
            for target in targets:
                if target not in blocks:
                    raise ValueError(f"unknown successor target {target}")
                predecessors[target].append(source)

        counters: dict[str, int] = defaultdict(int)
        output_ids: dict[tuple[str, int], str] = {}
        block_generates: dict[str, dict[str, str]] = {block: {} for block in blocks}
        for block, rows in blocks.items():
            for index, row in enumerate(rows):
                name = row.get("output")
                if name:
                    name = str(name)
                    counters[name] += 1
                    value_id = f"{name}@{counters[name]}"
                    output_ids[(block, index)] = value_id
                    block_generates[block][name] = value_id

        in_defs: dict[str, dict[str, set[str]]] = {block: {} for block in blocks}
        out_defs: dict[str, dict[str, set[str]]] = {block: {} for block in blocks}
        changed = True
        iterations = 0
        while changed:
            changed = False
            iterations += 1
            if iterations > max(4, len(blocks) * 4):
                raise ValueError("SSA reaching-definition analysis did not converge")
            for block in blocks:
                incoming: dict[str, set[str]] = defaultdict(set)
                for predecessor in predecessors[block]:
                    for name, definitions in out_defs[predecessor].items():
                        incoming[name].update(definitions)
                outgoing = {name: set(definitions) for name, definitions in incoming.items()}
                for name, definition in block_generates[block].items():
                    outgoing[name] = {definition}
                normalized_in = dict(incoming)
                if normalized_in != in_defs[block] or outgoing != out_defs[block]:
                    in_defs[block] = normalized_in
                    out_defs[block] = outgoing
                    changed = True

        values: dict[str, IRValue] = {}
        operations: dict[str, IROperation] = {}
        block_ops: dict[str, list[str]] = {block: [] for block in blocks}
        for block, rows in blocks.items():
            current: dict[str, str] = {}
            for name, definitions in sorted(in_defs[block].items()):
                if len(definitions) > 1:
                    value_id = f"{name}@phi:{block}"
                    values[value_id] = IRValue(value_id, name, version=f"phi:{block}")
                    operation_id = f"{block}:phi:{name}"
                    operations[operation_id] = IROperation(
                        operation_id, "PHI", block, tuple(sorted(definitions)), value_id
                    )
                    block_ops[block].append(operation_id)
                    current[name] = value_id
                elif definitions:
                    current[name] = next(iter(definitions))
            for index, row in enumerate(rows):
                inputs: list[str] = []
                for raw_name in row.get("inputs") or []:
                    name = str(raw_name)
                    value_id = current.get(name, f"{name}@0")
                    values.setdefault(value_id, IRValue(value_id, name, version=value_id.rsplit("@", 1)[-1]))
                    inputs.append(value_id)
                raw_output = row.get("output")
                output = output_ids.get((block, index))
                if output and raw_output:
                    name = str(raw_output)
                    values[output] = IRValue(
                        output, name, size=int(row.get("size") or 0),
                        space=str(row.get("space") or "unique"),
                        offset=row.get("offset"), version=output.rsplit("@", 1)[-1],
                    )
                    current[name] = output
                operation_id = str(row.get("id") or f"{block}:{index}")
                if operation_id in operations:
                    raise ValueError(f"duplicate IR operation id {operation_id}")
                properties = dict(row.get("properties") or {})
                operations[operation_id] = IROperation(
                    operation_id,
                    str(row.get("opcode") or "UNIMPLEMENTED").upper(),
                    block,
                    tuple(inputs),
                    output,
                    str(row["address"]) if row.get("address") is not None else None,
                    properties,
                )
                block_ops[block].append(operation_id)

        # PHI operands may refer to definitions materialized in later blocks.
        for operation in operations.values():
            for value_id in operation.inputs:
                if value_id not in values:
                    name, version = value_id.rsplit("@", 1)
                    values[value_id] = IRValue(value_id, name, version=version)
        return CanonicalIR(function_id, entry_block, block_ops, successors, values, operations)


@dataclass(frozen=True)
class DefUseIndex:
    definitions: dict[str, str]
    uses: dict[str, tuple[str, ...]]

    @classmethod
    def build(cls, ir: CanonicalIR) -> "DefUseIndex":
        definitions: dict[str, str] = {}
        uses: dict[str, list[str]] = defaultdict(list)
        for operation in ir.operations.values():
            if operation.output is not None:
                if operation.output in definitions:
                    raise ValueError(f"SSA value {operation.output} has multiple definitions")
                definitions[operation.output] = operation.id
            for value in operation.inputs:
                uses[value].append(operation.id)
        return cls(definitions, {key: tuple(value) for key, value in uses.items()})


class ProgramSlicer:
    def __init__(self, ir: CanonicalIR) -> None:
        self.ir = ir
        self.index = DefUseIndex.build(ir)

    def backward(self, operation_ids: Iterable[str]) -> set[str]:
        pending = deque(operation_ids)
        selected: set[str] = set()
        while pending:
            operation_id = pending.popleft()
            if operation_id in selected:
                continue
            operation = self.ir.operations.get(operation_id)
            if operation is None:
                continue
            selected.add(operation_id)
            for value in operation.inputs:
                definition = self.index.definitions.get(value)
                if definition is not None:
                    pending.append(definition)
        return selected

    def forward(self, value_ids: Iterable[str]) -> set[str]:
        pending = deque(value_ids)
        seen_values: set[str] = set()
        selected: set[str] = set()
        while pending:
            value = pending.popleft()
            if value in seen_values:
                continue
            seen_values.add(value)
            for operation_id in self.index.uses.get(value, ()):
                selected.add(operation_id)
                output = self.ir.operations[operation_id].output
                if output is not None:
                    pending.append(output)
        return selected


@dataclass(frozen=True)
class TaintFinding:
    sink_operation: str
    tainted_inputs: tuple[str, ...]
    slice_operations: tuple[str, ...]


class TaintEngine:
    """Explicit-flow SSA taint propagation with configurable sanitizers and sinks."""

    def analyze(
        self,
        ir: CanonicalIR,
        *,
        sources: Iterable[str],
        sink_opcodes: Iterable[str] = ("CALLIND", "STORE", "BRANCHIND"),
        sanitizer_opcodes: Iterable[str] = (),
    ) -> list[TaintFinding]:
        tainted = set(sources)
        sinks = {opcode.upper() for opcode in sink_opcodes}
        sanitizers = {opcode.upper() for opcode in sanitizer_opcodes}
        findings: list[TaintFinding] = []
        ordered = [ir.operations[op_id] for block in ir.blocks.values() for op_id in block]
        changed = True
        while changed:
            changed = False
            for operation in ordered:
                tainted_inputs = tuple(value for value in operation.inputs if value in tainted)
                if operation.opcode in sinks and tainted_inputs:
                    slice_ops = ProgramSlicer(ir).backward([operation.id])
                    finding = TaintFinding(operation.id, tainted_inputs, tuple(sorted(slice_ops)))
                    if finding not in findings:
                        findings.append(finding)
                if (
                    operation.output is not None
                    and operation.opcode not in sanitizers
                    and tainted_inputs
                    and operation.output not in tainted
                ):
                    tainted.add(operation.output)
                    changed = True
        return findings
