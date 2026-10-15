"""Bounded PRE-RE normalized function signatures without an RE workspace."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any


SCHEMA = "angerona/native-bounded-structural-signatures/v2"
_HEADER = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
_INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s+([A-Za-z.][A-Za-z0-9_.]*)\s*(.*?)\s*$")
_NUMBER = re.compile(r"(?<![A-Za-z_])(?:0x)?[0-9a-fA-F]{2,}(?![A-Za-z_])")
_SYMBOL = re.compile(r"<[^>]+>")
_BRANCH = re.compile(r"^(?:b(?:\.[a-z]+)?|j[a-z]+|cbz|cbnz|tbz|tbnz|ret|bx|br)$", re.I)
_CALL = re.compile(r"^(?:callq?|blx?|jalr?)$", re.I)


def _sha(value: Any) -> str:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(payload).hexdigest()


def _normalized_instruction(mnemonic: str, operands: str) -> str:
    operands = _SYMBOL.sub("<symbol>", operands.lower())
    operands = _NUMBER.sub("<imm>", operands)
    operands = re.sub(r"\s+", " ", operands).strip()
    return f"{mnemonic.lower()} {operands}".rstrip()


def _elf_virtual_bytes(binary: Path, address: int, size: int) -> bytes | None:
    data = binary.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] not in {1, 2}:
        return None
    endian = "little" if data[5] == 1 else "big"
    bits = data[4]
    if bits == 2:
        phoff = int.from_bytes(data[32:40], endian)
        phentsize = int.from_bytes(data[54:56], endian)
        phnum = int.from_bytes(data[56:58], endian)
        offsets = (8, 16, 32, 40)
    elif bits == 1:
        phoff = int.from_bytes(data[28:32], endian)
        phentsize = int.from_bytes(data[42:44], endian)
        phnum = int.from_bytes(data[44:46], endian)
        offsets = (4, 8, 16, 20)
    else:
        return None
    for index in range(phnum):
        base = phoff + index * phentsize
        header = data[base:base + phentsize]
        if len(header) != phentsize or int.from_bytes(header[:4], endian) != 1:
            continue
        file_offset = int.from_bytes(header[offsets[0]:offsets[0] + (8 if bits == 2 else 4)], endian)
        virtual = int.from_bytes(header[offsets[1]:offsets[1] + (8 if bits == 2 else 4)], endian)
        file_size = int.from_bytes(header[offsets[2]:offsets[2] + (8 if bits == 2 else 4)], endian)
        memory_size = int.from_bytes(header[offsets[3]:offsets[3] + (8 if bits == 2 else 4)], endian)
        if virtual <= address and address + size <= virtual + min(file_size, memory_size):
            start = file_offset + address - virtual
            payload = data[start:start + size]
            return payload if len(payload) == size else None
    return None


def extract_structural_signatures(
    binary: Path, function_records: list[dict[str, Any]], objdump_path: Path,
    *, timeout: int = 30, maximum_output_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    process = subprocess.Popen(
        [str(objdump_path), "-d", "--no-show-raw-insn", "--wide", str(binary)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    functions: dict[int, list[tuple[str, str]]] = {}
    current: int | None = None
    consumed = 0
    truncated = False
    started = time.monotonic()
    try:
        assert process.stdout is not None
        for line in process.stdout:
            if time.monotonic() - started > timeout:
                truncated = True
                process.kill()
                break
            consumed += len(line.encode("utf-8", "replace"))
            if consumed > maximum_output_bytes:
                truncated = True
                process.kill()
                break
            header = _HEADER.match(line)
            if header:
                current = int(header.group(1), 16)
                functions.setdefault(current, [])
                continue
            match = _INSN.match(line)
            if match and current is not None:
                functions[current].append((match.group(2), match.group(3)))
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        truncated = True
        process.kill()
        process.wait()
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    rows = []
    for record in function_records:
        address = int(record["address"])
        instructions = functions.get(address) or []
        if not instructions:
            continue
        normalized = [_normalized_instruction(mnemonic, operands) for mnemonic, operands in instructions]
        mnemonics = Counter(mnemonic.lower() for mnemonic, _operands in instructions)
        branches = [index for index, (mnemonic, _operands) in enumerate(instructions) if _BRANCH.match(mnemonic)]
        calls = sum(bool(_CALL.match(mnemonic)) for mnemonic, _operands in instructions)
        vector = {
            "instruction_count": len(instructions),
            "basic_block_count": max(1, len(branches) + 1),
            "callsite_count": calls,
            "mnemonic_histogram": sorted(mnemonics.items()),
        }
        raw = _elf_virtual_bytes(binary, address, int(record["size"]))
        rows.append({
            "name": record["name"], "address": address, "size": int(record["size"]),
            "normalized_cfg_sha256": _sha({"instructions": normalized, "branch_indexes": branches}),
            "function_vector_sha256": _sha(vector),
            "raw_function_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "raw_function_bytes": len(raw) if raw is not None else 0,
            **{key: value for key, value in vector.items() if key != "mnemonic_histogram"},
        })
    rows.sort(key=lambda row: (row["address"], row["name"], row["size"]))
    return {
        "schema": SCHEMA,
        "producer_mode": "bounded-pre-re-objdump",
        "normal_re_project_created": False,
        "complete": bool(not truncated and process.returncode in {0, 1}),
        "truncated": truncated,
        "output_bytes": consumed,
        "function_count": len(rows),
        "rows_sha256": _sha(rows),
        "rows": rows,
    }
