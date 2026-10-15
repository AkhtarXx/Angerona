"""Export the current IDA database from an ``idat -S`` headless session.

This is the custom-loader counterpart to :mod:`src.scripts.ida_dump`.
``ida_dump.py`` is driven by idalib and opens the input itself; Solana/SBF ELF
needs IDA's native loader selection (``-T "Solana SBF/eBPF ELF"``), so this
script runs *inside* IDA after the custom loader has already accepted the file.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile

import idaapi
import idc


def _repo_root() -> pathlib.Path:
    # src/scripts/ida_idat_dump.py -> repo root
    return pathlib.Path(__file__).resolve().parents[2]


def _load_export_helpers():
    root = _repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from src.scripts import ida_dump

    return ida_dump


def _write_json_atomic(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        delete=False,
    ) as fh:
        json.dump(data, fh)
        tmp = pathlib.Path(fh.name)
    tmp.replace(path)


def _export_current_database() -> dict:
    helpers = _load_export_helpers()
    mode = os.environ.get("ANGERONA_IDA_IDAT_MODE", "meta")
    max_functions_raw = os.environ.get("ANGERONA_IDA_IDAT_MAX_FUNCTIONS", "0")
    try:
        max_functions = int(max_functions_raw)
    except ValueError:
        max_functions = 0

    if mode == "function":
        func = os.environ.get("ANGERONA_IDA_IDAT_FUNCTION", "")
        if not func:
            return {"error": "function mode requires ANGERONA_IDA_IDAT_FUNCTION"}
        ea = helpers._find_function_ea(func)
        if ea is None:
            return {"error": "function not found: %s" % func}
        entry = helpers._function_entry(ea, decompile=True)
        entry["disassembly"] = helpers._disassembly(ea)
        return entry

    decompile = mode == "full"
    exception_regions = helpers.collect_exception_regions()
    funcs = helpers.collect_functions(
        decompile=decompile,
        max_functions=max_functions,
        exception_regions=exception_regions,
    )
    external_count = sum(1 for fn in funcs if fn.get("is_external"))
    return {
        "metadata": helpers.collect_metadata(len(funcs), external_count),
        "functions": funcs,
        "exception_regions": exception_regions,
        "strings": helpers.collect_strings(),
        "imports": helpers.collect_imports(),
        "exports": helpers.collect_exports(),
        "symbols": helpers.collect_symbols(),
    }


def main() -> int:
    force_processor = os.environ.get("ANGERONA_IDA_IDAT_PROCESSOR")
    if force_processor:
        try:
            idaapi.set_processor_type(force_processor, idaapi.SETPROC_LOADER)
        except Exception as exc:  # noqa: BLE001
            print("[ida_idat_dump] set_processor_type(%s) failed: %s" % (force_processor, exc))

    idaapi.auto_wait()
    out = os.environ.get("ANGERONA_IDA_IDAT_OUT")
    if not out:
        print("[ida_idat_dump] ANGERONA_IDA_IDAT_OUT is required")
        return 2

    data = _export_current_database()
    out_path = pathlib.Path(out)
    _write_json_atomic(out_path, data)
    func_count = len(data.get("functions") or []) if isinstance(data, dict) else 0
    print("[ida_idat_dump] wrote %s functions=%d" % (out_path, func_count))

    if os.environ.get("ANGERONA_IDA_IDAT_QEXIT", "1") != "0":
        idc.qexit(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
