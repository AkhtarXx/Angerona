#!/usr/bin/env python3
"""Fail-closed operator-pinned wrapper for clean Android audit tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

from src.analysis.evidence_signing import sign_document, verify_document


SCHEMA = "angerona/operator-tool-prerequisite/v1"
WRAPPER_SCHEMA = "angerona/pinned-python-tool-wrapper/v1"
ENVIRONMENT = {
    "baksmali": "ANGERONA_BAKSMALI_CLI",
    "hermes-indexer": "ANGERONA_HERMES_INDEXER",
    "hermes-decompiler": "ANGERONA_HERMES_DECOMPILER",
}


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_executable(value: str | None) -> Path | None:
    if not value:
        return None
    located = value if Path(value).is_absolute() else shutil.which(value)
    if not located:
        return None
    path = Path(located).expanduser().absolute()
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        return None
    return path.resolve(strict=True)


def _probe(role: str, output: Path) -> int:
    configured = os.environ.get(ENVIRONMENT[role])
    candidate = _regular_executable(configured)
    if candidate is None and role == "baksmali":
        candidate = _regular_executable("baksmali")
    document = sign_document({
        "schema": SCHEMA, "role": role,
        "status": "AVAILABLE" if candidate else "HOLD",
        "tool": ({"path": str(candidate), "sha256": _sha(candidate)} if candidate else None),
        "selection": "operator-explicit" if configured else "path-discovery",
        "reason": None if candidate else f"real-{role}-tool-unavailable",
        "contract": {
            "baksmali": "baksmali-disassemble-cli/v1",
            "hermes-indexer": "hermes-module-jsonl-byte-range-index/v1",
            "hermes-decompiler": "hermes-single-module-source/v1",
        }[role],
    })
    if not verify_document(document, require_signature=True):
        raise ValueError("operator signing is required for tool prerequisite receipts")
    payload = json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return 0 if candidate else 2


def _descriptor(path: Path) -> dict[str, str]:
    resolved = path.expanduser().resolve(strict=True)
    return {"path": str(resolved), "sha256": _sha(resolved)}


def _seal_wrapper(role: str, probe_value: str, output: Path) -> int:
    probe_path = Path(probe_value).expanduser().absolute()
    metadata = probe_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("tool prerequisite receipt is not a regular file")
    probe = json.loads(probe_path.read_bytes())
    if (
        probe.get("schema") != SCHEMA
        or not verify_document(probe, require_signature=True)
        or probe.get("status") != "AVAILABLE"
        or probe.get("role") != role
    ):
        raise ValueError("wrapper descriptor requires a matching signed AVAILABLE prerequisite")
    document = sign_document({
        "schema": WRAPPER_SCHEMA, "role": role,
        "python": _descriptor(Path(sys.executable)),
        "script": _descriptor(Path(__file__)),
        "probe_receipt": _descriptor(probe_path),
    })
    if not verify_document(document, require_signature=True):
        raise ValueError("operator signing is required for wrapper descriptors")
    payload = json.dumps(document, indent=2, sort_keys=True).encode() + b"\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return 0


def _run(arguments: list[str]) -> int:
    receipt_value = os.environ.get("ANGERONA_TOOL_PROBE_RECEIPT")
    if not receipt_value:
        raise ValueError("ANGERONA_TOOL_PROBE_RECEIPT is required")
    receipt_path = Path(receipt_value).expanduser().absolute()
    metadata = receipt_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("tool prerequisite receipt is not a regular file")
    receipt = json.loads(receipt_path.read_bytes())
    if receipt.get("schema") != SCHEMA or not verify_document(receipt, require_signature=True):
        raise ValueError("tool prerequisite receipt is unsigned or unknown")
    if receipt.get("status") != "AVAILABLE" or not isinstance(receipt.get("tool"), dict):
        raise RuntimeError(str(receipt.get("reason") or "tool prerequisite is HOLD"))
    role = str(receipt.get("role") or "")
    if role == "baksmali":
        contract_parser = argparse.ArgumentParser(prog="clean-android-tool-wrapper disassemble", add_help=False)
        contract_parser.add_argument("command", choices=["disassemble"])
        contract_parser.add_argument("input")
        contract_parser.add_argument("--classes", required=True)
        contract_parser.add_argument("--output", required=True)
    elif role == "hermes-indexer":
        contract_parser = argparse.ArgumentParser(prog="clean-android-tool-wrapper --index-only", add_help=False)
        contract_parser.add_argument("--index-only", action="store_true", required=True)
        contract_parser.add_argument("--input", required=True)
        contract_parser.add_argument("--output", required=True)
    elif role == "hermes-decompiler":
        contract_parser = argparse.ArgumentParser(prog="clean-android-tool-wrapper --decompile-module", add_help=False)
        contract_parser.add_argument("--decompile-module", action="store_true", required=True)
        contract_parser.add_argument("--input", required=True)
        contract_parser.add_argument("--module-id", required=True)
        contract_parser.add_argument("--output", required=True)
    else:
        raise ValueError("wrapper invocation has an unknown signed tool role")
    contract_parser.parse_args(arguments)
    tool = Path(receipt["tool"]["path"]).absolute()
    tool_metadata = tool.lstat()
    if stat.S_ISLNK(tool_metadata.st_mode) or not stat.S_ISREG(tool_metadata.st_mode):
        raise ValueError("pinned tool is not a regular file")
    if _sha(tool) != receipt["tool"].get("sha256"):
        raise ValueError("pinned tool bytes changed after prerequisite sealing")
    os.execv(str(tool), [str(tool), *arguments])
    return 127


def main() -> int:
    arguments = sys.argv[1:]
    parser = argparse.ArgumentParser(
        description="Probe, seal, or execute an operator-pinned Android audit tool",
        epilog=(
            "Execution forms are passed through only after signed prerequisite validation: "
            "disassemble ..., --index-only ..., or --decompile-module ..."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--seal-wrapper-descriptor", action="store_true")
    parser.add_argument("--role", choices=sorted(ENVIRONMENT), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--probe-receipt")
    if any(value in {"-h", "--help"} for value in arguments):
        parser.print_help()
        return 0
    management_mode = "--probe" in arguments or "--seal-wrapper-descriptor" in arguments
    if not management_mode:
        if not arguments:
            parser.error("an explicit probe, seal, or tool execution form is required")
        return _run(arguments)
    args = parser.parse_args(arguments)
    if args.probe:
        if args.probe_receipt:
            raise ValueError("--probe does not accept --probe-receipt")
        return _probe(args.role, Path(args.output).expanduser().absolute())
    if not args.probe_receipt:
        raise ValueError("--seal-wrapper-descriptor requires --probe-receipt")
    return _seal_wrapper(
        args.role, args.probe_receipt, Path(args.output).expanduser().absolute(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
