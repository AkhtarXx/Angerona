"""Ownership-neutral, exhaustive structural evidence for a DEX container.

This module never decompiles code and never assigns ownership.  It records
definitions, hierarchy, annotations, constants, references, calls and override
candidates with exact byte occurrences so a later signed policy can make a
decision without package-name guessing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct
from typing import Any

from .evidence_signing import canonical_payload
from .signed_artifact_io import write_signed_canonical


SCHEMA = "angerona/dex-relationship-index/v1"
NO_INDEX = 0xFFFFFFFF


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _u16(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(blob):
        raise ValueError(f"DEX u16 out of bounds: {offset}")
    return struct.unpack_from("<H", blob, offset)[0]


def _u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        raise ValueError(f"DEX u32 out of bounds: {offset}")
    return struct.unpack_from("<I", blob, offset)[0]


def _uleb(blob: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(blob):
            raise ValueError("DEX uleb128 out of bounds")
        byte = blob[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("DEX uleb128 exceeds 32 bits")


def _sized_int(blob: bytes, cursor: int, width: int, *, signed: bool = False) -> tuple[int, int]:
    if width < 1 or width > 8 or cursor + width > len(blob):
        raise ValueError("DEX encoded value is out of bounds")
    return int.from_bytes(blob[cursor:cursor + width], "little", signed=signed), cursor + width


class _Dex:
    def __init__(self, blob: bytes, apk_sha256: str) -> None:
        if len(blob) < 112 or blob[:4] != b"dex\n" or blob[7] != 0:
            raise ValueError("invalid DEX header")
        if _u32(blob, 32) != len(blob) or _u32(blob, 36) != 112 or _u32(blob, 40) != 0x12345678:
            raise ValueError("unsupported DEX size/header/endian tag")
        self.blob = blob
        self.apk_sha256 = apk_sha256
        self.dex_sha256 = _sha(blob)
        self.string_count, self.string_off = _u32(blob, 56), _u32(blob, 60)
        self.type_count, self.type_off = _u32(blob, 64), _u32(blob, 68)
        self.proto_count, self.proto_off = _u32(blob, 72), _u32(blob, 76)
        self.field_count, self.field_off = _u32(blob, 80), _u32(blob, 84)
        self.method_count, self.method_off = _u32(blob, 88), _u32(blob, 92)
        self.class_count, self.class_off = _u32(blob, 96), _u32(blob, 100)
        for count, offset, width, label in (
            (self.string_count, self.string_off, 4, "strings"),
            (self.type_count, self.type_off, 4, "types"),
            (self.proto_count, self.proto_off, 12, "prototypes"),
            (self.field_count, self.field_off, 8, "fields"),
            (self.method_count, self.method_off, 8, "methods"),
            (self.class_count, self.class_off, 32, "classes"),
        ):
            if count and (offset < 112 or offset + count * width > len(blob)):
                raise ValueError(f"DEX {label} table is out of bounds")
        self._strings: dict[int, str] = {}
        self._types: dict[int, str] = {}
        self._protos: dict[int, str] = {}
        self.methods = [self._method(index) for index in range(self.method_count)]
        self.fields = [self._field(index) for index in range(self.field_count)]

    def string(self, index: int) -> str:
        if index < 0 or index >= self.string_count:
            raise ValueError(f"DEX string index out of bounds: {index}")
        if index not in self._strings:
            offset = _u32(self.blob, self.string_off + index * 4)
            _size, cursor = _uleb(self.blob, offset)
            end = self.blob.find(b"\0", cursor)
            if end < 0:
                raise ValueError(f"unterminated DEX string: {index}")
            self._strings[index] = self.blob[cursor:end].decode("utf-8", errors="replace")
        return self._strings[index]

    def type(self, index: int) -> str:
        if index < 0 or index >= self.type_count:
            raise ValueError(f"DEX type index out of bounds: {index}")
        if index not in self._types:
            self._types[index] = self.string(_u32(self.blob, self.type_off + index * 4))
        return self._types[index]

    def proto(self, index: int) -> str:
        if index < 0 or index >= self.proto_count:
            raise ValueError(f"DEX prototype index out of bounds: {index}")
        if index not in self._protos:
            row = self.proto_off + index * 12
            return_type, params_off = _u32(self.blob, row + 4), _u32(self.blob, row + 8)
            params: list[str] = []
            if params_off:
                count = _u32(self.blob, params_off)
                if params_off + 4 + count * 2 > len(self.blob):
                    raise ValueError("DEX prototype parameter list is out of bounds")
                params = [self.type(_u16(self.blob, params_off + 4 + item * 2)) for item in range(count)]
            self._protos[index] = "(" + "".join(params) + ")" + self.type(return_type)
        return self._protos[index]

    def method_id(self, index: int, qualified: str) -> str:
        stable = _sha(f"{self.apk_sha256}\0{self.dex_sha256}\0{index}\0{qualified}".encode())
        return f"dex-method:{stable}"

    def class_entity_id(self, descriptor: str) -> str:
        return _sha(canonical_payload({"dex_sha256": self.dex_sha256, "class_descriptor": descriptor}))

    def _method(self, index: int) -> dict[str, Any]:
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.blob, self.method_off + index * 8)
        owner, name, prototype = self.type(class_idx), self.string(name_idx), self.proto(proto_idx)
        qualified = f"{owner}->{name}{prototype}"
        return {
            "method_index": index, "declaring_class": owner, "name": name,
            "prototype": prototype, "qualified_name": qualified,
            "method_id": self.method_id(index, qualified),
        }

    def _field(self, index: int) -> dict[str, Any]:
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.blob, self.field_off + index * 8)
        owner, field_type, name = self.type(class_idx), self.type(type_idx), self.string(name_idx)
        qualified = f"{owner}->{name}:{field_type}"
        return {
            "field_index": index, "declaring_class": owner, "name": name,
            "field_type": field_type, "qualified_name": qualified,
            "field_id": "dex-field:" + _sha(f"{self.dex_sha256}\0{index}\0{qualified}".encode()),
        }

    def type_list(self, offset: int) -> list[str]:
        if not offset:
            return []
        count = _u32(self.blob, offset)
        if offset + 4 + count * 2 > len(self.blob):
            raise ValueError("DEX type list is out of bounds")
        return [self.type(_u16(self.blob, offset + 4 + item * 2)) for item in range(count)]

    def encoded_value(self, cursor: int, depth: int = 0) -> tuple[Any, int]:
        if depth > 32 or cursor >= len(self.blob):
            raise ValueError("DEX encoded value nesting is invalid")
        header = self.blob[cursor]
        cursor += 1
        value_type, value_arg = header & 0x1F, header >> 5
        width = value_arg + 1
        if value_type in {0x00, 0x02, 0x04, 0x06}:
            value, cursor = _sized_int(self.blob, cursor, width, signed=True)
            return {"kind": "integer", "value": value}, cursor
        if value_type == 0x03:
            value, cursor = _sized_int(self.blob, cursor, width)
            return {"kind": "char", "value": value}, cursor
        if value_type in {0x10, 0x11}:
            value, cursor = _sized_int(self.blob, cursor, width)
            return {"kind": "floating-bits", "value": value, "encoded_width": width}, cursor
        if value_type in {0x15, 0x16, 0x19, 0x1B}:
            value, cursor = _sized_int(self.blob, cursor, width)
            table = {0x15: "method-type", 0x16: "method-handle", 0x19: "field", 0x1B: "enum"}
            return {"kind": table[value_type], "index": value}, cursor
        if value_type == 0x17:
            value, cursor = _sized_int(self.blob, cursor, width)
            return {"kind": "string", "index": value, "value": self.string(value)}, cursor
        if value_type == 0x18:
            value, cursor = _sized_int(self.blob, cursor, width)
            return {"kind": "type", "index": value, "value": self.type(value)}, cursor
        if value_type == 0x1A:
            value, cursor = _sized_int(self.blob, cursor, width)
            return {"kind": "method", "index": value, "value": self.methods[value]["qualified_name"]}, cursor
        if value_type == 0x1C:
            count, cursor = _uleb(self.blob, cursor)
            values = []
            for _ in range(count):
                item, cursor = self.encoded_value(cursor, depth + 1)
                values.append(item)
            return {"kind": "array", "values": values}, cursor
        if value_type == 0x1D:
            annotation, cursor = self.encoded_annotation(cursor, depth + 1)
            return {"kind": "annotation", "value": annotation}, cursor
        if value_type == 0x1E:
            if value_arg:
                raise ValueError("DEX null encoded value has a nonzero argument")
            return {"kind": "null", "value": None}, cursor
        if value_type == 0x1F:
            if value_arg not in {0, 1}:
                raise ValueError("DEX boolean encoded value is invalid")
            return {"kind": "boolean", "value": bool(value_arg)}, cursor
        raise ValueError(f"unsupported DEX encoded value type: {value_type:#x}")

    def encoded_annotation(self, cursor: int, depth: int = 0) -> tuple[dict[str, Any], int]:
        type_index, cursor = _uleb(self.blob, cursor)
        size, cursor = _uleb(self.blob, cursor)
        elements = []
        for _ in range(size):
            name_index, cursor = _uleb(self.blob, cursor)
            value, cursor = self.encoded_value(cursor, depth + 1)
            elements.append({"name": self.string(name_index), "value": value})
        return {"annotation_type": self.type(type_index), "elements": elements}, cursor

    def annotation_set(self, offset: int) -> list[dict[str, Any]]:
        if not offset:
            return []
        size = _u32(self.blob, offset)
        if offset + 4 + size * 4 > len(self.blob):
            raise ValueError("DEX annotation set is out of bounds")
        result = []
        for item in range(size):
            annotation_off = _u32(self.blob, offset + 4 + item * 4)
            if annotation_off >= len(self.blob):
                raise ValueError("DEX annotation item is out of bounds")
            visibility = self.blob[annotation_off]
            annotation, end = self.encoded_annotation(annotation_off + 1)
            result.append({**annotation, "visibility": visibility, "byte_start": annotation_off, "byte_end": end})
        return result

    def annotation_directory(self, offset: int) -> dict[str, Any]:
        if not offset:
            return {"class": [], "fields": {}, "methods": {}, "parameters": {}}
        if offset + 16 > len(self.blob):
            raise ValueError("DEX annotation directory is out of bounds")
        class_off, fields_size, methods_size, parameters_size = struct.unpack_from("<4I", self.blob, offset)
        cursor = offset + 16
        result: dict[str, Any] = {"class": self.annotation_set(class_off), "fields": {}, "methods": {}, "parameters": {}}
        for kind, count in (("fields", fields_size), ("methods", methods_size), ("parameters", parameters_size)):
            for _ in range(count):
                index, annotations_off = struct.unpack_from("<2I", self.blob, cursor)
                cursor += 8
                if kind == "parameters":
                    parameter_count = _u32(self.blob, annotations_off)
                    result[kind][str(index)] = [
                        self.annotation_set(_u32(self.blob, annotations_off + 4 + item * 4))
                        for item in range(parameter_count)
                    ]
                else:
                    result[kind][str(index)] = self.annotation_set(annotations_off)
        return result


def _instruction_width(units: list[int], cursor: int) -> int:
    opcode = units[cursor] & 0xFF
    if 0xE3 <= opcode <= 0xF9:
        raise ValueError(f"unsupported quickened/reserved DEX opcode 0x{opcode:02x}")
    if opcode == 0:
        signature = units[cursor]
        if signature == 0x0100:
            return 4 + _require_units(units, cursor + 1, 1)[0] * 2
        if signature == 0x0200:
            return 2 + _require_units(units, cursor + 1, 1)[0] * 4
        if signature == 0x0300:
            width, size_low, size_high = _require_units(units, cursor + 1, 3)
            return 4 + ((width * (size_low | size_high << 16) + 1) // 2)
        return 1
    widths = {
        0x02: 2, 0x03: 3, 0x05: 2, 0x06: 3, 0x08: 2, 0x09: 3,
        0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5,
        0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1F: 2, 0x20: 2,
        0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x29: 2,
        0x2A: 3, 0x2B: 3, 0x2C: 3,
    }
    if 0x2D <= opcode <= 0x3D or 0x44 <= opcode <= 0x6D or 0x90 <= opcode <= 0xAF or 0xD0 <= opcode <= 0xE2:
        return 2
    if 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78 or opcode in {0xFC, 0xFD}:
        return 3
    if opcode in {0xFA, 0xFB}:
        return 4
    if opcode in {0xFE, 0xFF}:
        return 2
    return widths.get(opcode, 1)


def _require_units(units: list[int], cursor: int, count: int) -> list[int]:
    if cursor < 0 or cursor + count > len(units):
        raise ValueError("DEX instruction operand is out of bounds")
    return units[cursor:cursor + count]


def _signed_literal(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _scan_code(dex: _Dex, method: dict[str, Any], code_offset: int) -> dict[str, Any]:
    if code_offset < 112 or code_offset + 16 > len(dex.blob):
        raise ValueError("DEX method code header is out of bounds")
    units_count = _u32(dex.blob, code_offset + 12)
    start = code_offset + 16
    end = start + units_count * 2
    if not units_count or end > len(dex.blob):
        raise ValueError("DEX instruction stream is out of bounds")
    units = list(struct.unpack_from(f"<{units_count}H", dex.blob, start))
    refs: dict[str, list[dict[str, Any]]] = {
        "calls": [], "fields": [], "types": [], "strings": [],
        "literals": [], "resource_ids": [],
    }
    cursor = 0
    while cursor < len(units):
        opcode = units[cursor] & 0xFF
        width = _instruction_width(units, cursor)
        if width < 1 or cursor + width > len(units):
            raise ValueError("DEX instruction width is invalid")
        byte_start, byte_end = start + cursor * 2, start + (cursor + width) * 2
        base = {
            "code_unit_offset": cursor, "byte_start": byte_start,
            "byte_end": byte_end, "opcode": opcode,
            "excerpt_sha256": _sha(dex.blob[byte_start:byte_end]),
        }
        target_kind = None
        target_index = None
        if opcode == 0x1A:
            target_kind, target_index = "strings", units[cursor + 1]
        elif opcode == 0x1B:
            target_kind, target_index = "strings", units[cursor + 1] | units[cursor + 2] << 16
        elif opcode in {0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25}:
            target_kind, target_index = "types", units[cursor + 1]
        elif 0x52 <= opcode <= 0x6D:
            target_kind, target_index = "fields", units[cursor + 1]
        elif 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78 or opcode in {0xFA, 0xFB}:
            target_kind, target_index = "calls", units[cursor + 1]
        if target_kind is not None:
            if target_kind == "strings":
                if target_index >= dex.string_count:
                    raise ValueError("DEX string instruction index is invalid")
                target = {"string_index": target_index, "value": dex.string(target_index)}
            elif target_kind == "types":
                if target_index >= dex.type_count:
                    raise ValueError("DEX type instruction index is invalid")
                target = {"type_index": target_index, "descriptor": dex.type(target_index)}
            elif target_kind == "fields":
                if target_index >= dex.field_count:
                    raise ValueError("DEX field instruction index is invalid")
                target = {"field_index": target_index, "field_id": dex.fields[target_index]["field_id"], "qualified_name": dex.fields[target_index]["qualified_name"]}
            else:
                if target_index >= dex.method_count:
                    raise ValueError("DEX method instruction index is invalid")
                target = {"method_index": target_index, "method_id": dex.methods[target_index]["method_id"], "qualified_name": dex.methods[target_index]["qualified_name"]}
            occurrence = {**base, **target, "occurrence_id": "dex-occurrence:" + _sha(canonical_payload({"dex": dex.dex_sha256, "method": method["method_id"], "role": target_kind, "offset": byte_start, "target": target_index}))}
            refs[target_kind].append(occurrence)
        literal = None
        if opcode == 0x12:
            literal = _signed_literal((units[cursor] >> 12) & 0xF, 4)
        elif opcode in {0x13, 0x16}:
            literal = _signed_literal(units[cursor + 1], 16)
        elif opcode in {0x14, 0x17}:
            literal = _signed_literal(units[cursor + 1] | units[cursor + 2] << 16, 32)
        elif opcode == 0x15:
            literal = _signed_literal(units[cursor + 1], 16) << 16
        if literal is not None:
            literal_row = {
                **base, "value": literal,
                "occurrence_id": "dex-occurrence:" + _sha(canonical_payload({
                    "dex": dex.dex_sha256, "method": method["method_id"],
                    "role": "literal", "offset": byte_start, "value": literal,
                })),
            }
            refs["literals"].append(literal_row)
        if literal is not None and literal & 0xFF000000 == 0x7F000000:
            refs["resource_ids"].append({**base, "resource_id": f"0x{literal & 0xFFFFFFFF:08x}", "occurrence_id": "dex-occurrence:" + _sha(canonical_payload({"dex": dex.dex_sha256, "method": method["method_id"], "role": "resource-id", "offset": byte_start, "value": literal}))})
        cursor += width
    if cursor != len(units):
        raise ValueError("DEX instruction stream was not exactly partitioned")
    return {"code_offset": code_offset, "instruction_code_units": units_count, "instruction_bytes_sha256": _sha(dex.blob[start:end]), **refs}


def build_dex_relationship_index(
    blob: bytes, output_path: str | Path, *, apk_sha256: str,
    member_name: str, plan_id: str, routing_set_id: str,
    ownership_policy: dict[str, Any], audit_epoch: dict[str, Any] | None,
    artifact: dict[str, str],
) -> dict[str, str]:
    dex = _Dex(blob, apk_sha256)
    if artifact.get("sha256") != dex.dex_sha256:
        raise ValueError("DEX relationship artifact hash mismatch")
    definitions: list[dict[str, Any]] = []
    defined_methods: dict[int, dict[str, Any]] = {}
    field_definitions: dict[int, dict[str, Any]] = {}
    class_by_descriptor: dict[str, dict[str, Any]] = {}
    for class_index in range(dex.class_count):
        row = dex.class_off + class_index * 32
        class_idx, access, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from("<8I", blob, row)
        descriptor = dex.type(class_idx)
        if descriptor in class_by_descriptor:
            raise ValueError("DEX contains duplicate class definitions")
        interfaces = dex.type_list(interfaces_off)
        annotations = dex.annotation_directory(annotations_off)
        static_fields: list[int] = []
        instance_fields: list[int] = []
        direct: list[int] = []
        virtual: list[int] = []
        if class_data_off:
            cursor = class_data_off
            sizes = []
            for _ in range(4):
                value, cursor = _uleb(blob, cursor)
                sizes.append(value)
            for target, count in ((static_fields, sizes[0]), (instance_fields, sizes[1])):
                index = 0
                for _ in range(count):
                    diff, cursor = _uleb(blob, cursor)
                    flags, cursor = _uleb(blob, cursor)
                    index += diff
                    if index >= dex.field_count or index in field_definitions:
                        raise ValueError("DEX field definition index is invalid or duplicated")
                    target.append(index)
                    field_definitions[index] = {**dex.fields[index], "access_flags": flags, "class_def_index": class_index, "static": target is static_fields}
            for target, count in ((direct, sizes[2]), (virtual, sizes[3])):
                index = 0
                for _ in range(count):
                    diff, cursor = _uleb(blob, cursor)
                    flags, cursor = _uleb(blob, cursor)
                    code_off, cursor = _uleb(blob, cursor)
                    index += diff
                    if index >= dex.method_count or index in defined_methods:
                        raise ValueError("DEX method definition index is invalid or duplicated")
                    target.append(index)
                    defined_methods[index] = {"access_flags": flags, "code_offset": code_off, "class_def_index": class_index, "virtual": target is virtual}
        static_values: list[Any] = []
        if static_values_off:
            count, cursor = _uleb(blob, static_values_off)
            if count > len(static_fields):
                raise ValueError("DEX static value count exceeds static fields")
            for _ in range(count):
                value, cursor = dex.encoded_value(cursor)
                static_values.append(value)
        for item, value in zip(static_fields, static_values):
            field_definitions[item]["static_value"] = value
        definition = {
            "class_def_index": class_index, "descriptor": descriptor,
            "entity_id": dex.class_entity_id(descriptor), "access_flags": access,
            "superclass": None if superclass_idx == NO_INDEX else dex.type(superclass_idx),
            "interfaces": interfaces,
            "source_file": None if source_file_idx == NO_INDEX else dex.string(source_file_idx),
            "annotations": annotations["class"],
            "nest_enclosing_kotlin_metadata": [
                row for row in annotations["class"]
                if row["annotation_type"] in {
                    "Ldalvik/annotation/EnclosingClass;", "Ldalvik/annotation/EnclosingMethod;",
                    "Ldalvik/annotation/InnerClass;", "Ldalvik/annotation/MemberClasses;",
                    "Ldalvik/annotation/NestHost;", "Ldalvik/annotation/NestMembers;",
                    "Lkotlin/Metadata;",
                }
            ],
            "defined_field_indexes": static_fields + instance_fields,
            "defined_method_indexes": direct + virtual,
            "definition_byte_start": row, "definition_byte_end": row + 32,
            "definition_sha256": _sha(blob[row:row + 32]),
        }
        definitions.append(definition)
        class_by_descriptor[descriptor] = definition
    methods = []
    for index, method in enumerate(dex.methods):
        definition = defined_methods.get(index)
        refs = {"calls": [], "fields": [], "types": [], "strings": [], "literals": [], "resource_ids": []}
        if definition and definition["code_offset"]:
            refs = _scan_code(dex, method, definition["code_offset"])
        methods.append({
            **method, "defined": definition is not None,
            "access_flags": definition["access_flags"] if definition else None,
            "class_def_index": definition["class_def_index"] if definition else None,
            **refs,
        })
    declared = {(row["declaring_class"], row["name"], row["prototype"]): row for row in methods}
    override_edges = []
    for method in methods:
        if not method["defined"] or method["name"] in {"<init>", "<clinit>"}:
            continue
        owner = class_by_descriptor.get(method["declaring_class"])
        if not owner:
            continue
        frontier = [item for item in [owner["superclass"], *owner["interfaces"]] if item]
        visited = set()
        while frontier:
            ancestor = frontier.pop(0)
            if ancestor in visited:
                continue
            visited.add(ancestor)
            target = declared.get((ancestor, method["name"], method["prototype"]))
            if target:
                override_edges.append({
                    "edge_id": "dex-override:" + _sha(canonical_payload({"source": method["method_id"], "target": target["method_id"]})),
                    "source_method_id": method["method_id"], "target_method_id": target["method_id"],
                    "target_defined_in_dex": bool(target["defined"]), "evidence": "exact-name-prototype-and-hierarchy",
                    "ownership_semantics": "corroboration-only-no-auto-promotion",
                })
            ancestor_definition = class_by_descriptor.get(ancestor)
            if ancestor_definition:
                frontier.extend(item for item in [ancestor_definition["superclass"], *ancestor_definition["interfaces"]] if item)
    all_occurrences = [
        occurrence
        for method in methods
        for role in ("calls", "fields", "types", "strings", "literals", "resource_ids")
        for occurrence in method.get(role) or []
    ]
    occurrence_ids = [row["occurrence_id"] for row in all_occurrences]
    if len(occurrence_ids) != len(set(occurrence_ids)):
        raise ValueError("DEX relationship occurrence identities are duplicated")
    body = {
        "schema": SCHEMA, "plan_id": plan_id, "routing_set_id": routing_set_id,
        "ownership_policy": ownership_policy, "audit_epoch": audit_epoch,
        "apk_sha256": apk_sha256, "member_name": member_name,
        "dex_artifact": artifact, "dex_sha256": dex.dex_sha256,
        "class_definitions": definitions, "fields": [field_definitions[index] for index in sorted(field_definitions)],
        "methods": methods, "override_edges": override_edges,
        "counts": {
            "class_definitions": len(definitions), "defined_fields": len(field_definitions),
            "method_ids": len(methods), "defined_methods": len(defined_methods),
            "direct_calls": sum(len(row.get("calls") or []) for row in methods),
            "type_references": sum(len(row.get("types") or []) for row in methods),
            "field_references": sum(len(row.get("fields") or []) for row in methods),
            "string_references": sum(len(row.get("strings") or []) for row in methods),
            "resource_id_occurrences": sum(len(row.get("resource_ids") or []) for row in methods),
            "override_edges": len(override_edges), "occurrences": len(all_occurrences),
        },
        "occurrence_id_stream_sha256": _sha("".join(value + "\n" for value in sorted(occurrence_ids)).encode()),
        "exhaustive_definition_accounting": len(definitions) == dex.class_count and len(methods) == dex.method_count,
        "instruction_partition_complete": True,
        "ownership_claim": "NONE_INDEXING_ONLY",
        "call_override_ownership_semantics": "corroboration-only-no-auto-promotion",
    }
    return write_signed_canonical(Path(output_path), body)
