"""Headless IDA (idalib) analysis dump — the IDA counterpart of REDump.java.

Run under a Python that has the ``idapro`` (idalib) module activated, e.g.::

    IDADIR=/path/to/ida  python ida_dump.py <binary> <out.json> <mode> [max_funcs] [func]

Modes:
    meta                 metadata + functions (no C) + strings + imports + exports + symbols
    full [max_funcs]     as meta, plus decompiled C for up to max_funcs functions (0 = all)
    function <name|addr> decompile + disassemble a single function

Produces the same JSON *shape* (for every field the pipeline consumes) as the Ghidra
REDump script so export/overview/CLI are engine-agnostic::

    {"metadata": {...}, "functions": [...], "strings": [...],
     "imports": [...], "exports": [...], "symbols": [...]}

Output is bounded (decompiled-C size, per-list caps) so a large/stripped binary cannot
blow up the JSON or exceed the caller's timeout. ``idapro`` MUST be imported first (it
initializes the kernel and extends sys.path with the bundled IDAPython modules), so all
other imports are deferred into functions.
"""

from __future__ import annotations

import json
import hashlib
import os
import sys
import threading

# Output bounds (override via env). Mirror the Ghidra engine's caps in spirit.
_MAX_DECOMPILED_CHARS = int(os.environ.get("ANGERONA_IDA_MAX_DECOMPILED_CHARS", "60000"))
_MAX_DISASM = int(os.environ.get("ANGERONA_IDA_MAX_DISASM", "6000"))
_MAX_REFS = int(os.environ.get("ANGERONA_IDA_MAX_REFS", "200"))
_MAX_STRINGS = int(os.environ.get("ANGERONA_IDA_MAX_STRINGS", "50000"))
_MAX_SYMBOLS = int(os.environ.get("ANGERONA_IDA_MAX_SYMBOLS", "50000"))

# Per-function Hex-Rays decompilation wall-clock budget. IDA's decompiler has no
# built-in timeout: the only cancellation path is the GUI "wait box" (ctrl-break),
# which polls IDA's global cancel flag at internal optimization checkpoints. In
# headless idalib there is no wait box, so a function that sends the microcode
# optimizer into a non-deterministic sprawl (CFG flattening / opaque predicates /
# memory pressure on a large binary) can pin one CPU core forever. We replicate
# the GUI cancel path from a watchdog thread: after this budget elapses, the
# thread sets IDA's global "cancelled" flag (``ida_kernwin.set_cancelled``), the
# decompiler observes it at its next checkpoint and unwinds with MERR_CANCELED,
# and we preserve the function's disassembly + metadata evidence rather than
# dropping it. Set to 0 to disable the watchdog (legacy behaviour).
_DECOMPILE_TIMEOUT = float(os.environ.get("ANGERONA_IDA_DECOMPILE_TIMEOUT_SECONDS", "900"))

_HEXRAYS = {"init": False, "ok": False}
_CANCEL_LOCK = threading.Lock()
_CANCEL_ACTIVE = {"thread": None, "armed": False}
_ALLOWED_RANGES: list[tuple[int, int]] = []
_RANGE_AUTHORITY_SHA256 = ""


def _progress(stage: str, completed: int = 0, expected: int = 0, **extra) -> None:
    """Emit a controller-consumable heartbeat without exposing target content."""

    payload = {"stage": stage, "completed": completed, "expected": expected}
    payload.update(extra)
    sys.stderr.write(
        "ANGERONA_IDA_PROGRESS "
        + json.dumps(payload, sort_keys=True)
        + "\n"
    )
    sys.stderr.flush()


def _hex(ea) -> str:
    try:
        return "0x%x" % (int(ea) & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        return str(ea)


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _allowed(address: int) -> bool:
    return not _ALLOWED_RANGES or any(start <= int(address) < end for start, end in _ALLOWED_RANGES)


_NATIVE_LAUNCH_AUTHORITY_TOKEN = None


def _configure_restricted(spec: str, authority_sha256: str, launch_token: str) -> None:
    global _ALLOWED_RANGES, _RANGE_AUTHORITY_SHA256, _NATIVE_LAUNCH_AUTHORITY_TOKEN
    if len(authority_sha256) != 64 or any(c not in "0123456789abcdef" for c in authority_sha256):
        raise SystemExit("invalid IDA restricted range authority")
    ranges = []
    for item in spec.split(","):
        if not item:
            continue
        raw_start, raw_size = item.split(":", 1)
        start, size = int(raw_start, 16), int(raw_size)
        if size <= 0:
            raise SystemExit("invalid IDA restricted range")
        ranges.append((start, start + size))
    if not ranges:
        raise SystemExit("empty IDA restricted range queue")
    _ALLOWED_RANGES = sorted(ranges)
    _RANGE_AUTHORITY_SHA256 = authority_sha256
    if len(launch_token) != 64 or any(c not in "0123456789abcdef" for c in launch_token):
        raise SystemExit("invalid IDA native launch authority token")
    _NATIVE_LAUNCH_AUTHORITY_TOKEN = launch_token


def _sanitize_restricted_text(value: str) -> tuple[str, dict]:
    pattern = re.compile(r"(?P<prefix>0x|sub_|off_|loc_|FUN_|DAT_)(?P<value>[0-9a-fA-F]{4,16})")
    redacted = []
    def replace(match):
        address = int(match.group("value"), 16)
        if _allowed(address):
            return match.group(0)
        redacted.append(match.group(0))
        return "REDACTED_OUTSIDE_NATIVE_AUTHORITY"
    result = pattern.sub(replace, value)
    return result, {
        "source_sha256": hashlib.sha256(value.encode()).hexdigest(),
        "sanitized_sha256": hashlib.sha256(result.encode()).hexdigest(),
        "redaction_count": len(redacted),
    }


def _sanitize_restricted_value(value, key=None):
    address_keys = {
        "address", "entry", "start", "end", "from", "to", "target_address",
        "source_address", "caller_address", "callee_address", "xref_address",
        "instruction_address", "pcode_address",
    }
    if isinstance(value, dict):
        return {child_key: _sanitize_restricted_value(child, child_key) for child_key, child in value.items()}
    if isinstance(value, list):
        return [_sanitize_restricted_value(child, key) for child in value]
    if key in address_keys:
        try:
            address = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)
        except (TypeError, ValueError):
            return value
        return value if _allowed(address) else "REDACTED_OUTSIDE_NATIVE_AUTHORITY"
    return value


def _finalize_restricted(functions, imports, exports, symbols):
    sanitized = []
    covered = []
    for function in functions:
        entry = int(str(function.get("entry") or "0"), 16)
        body = function.get("body_ranges") or []
        if not _allowed(entry) or any(
            not _allowed(int(str(row.get("start") or "0"), 16))
            or not _allowed(int(str(row.get("end") or "0"), 16))
            for row in body
        ):
            raise SystemExit("IDA restricted function body escapes allowed ranges")
        for row in body:
            covered.append((int(str(row["start"]), 16), int(str(row["end"]), 16) + 1))
        if function.get("decompiled"):
            text, receipt = _sanitize_restricted_text(function["decompiled"])
            function["decompiled"] = text
            function["restricted_decompiled_receipt"] = receipt
        sanitized.append(_sanitize_restricted_value(function))
    merged = []
    for start, end in sorted(covered):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    allowed = [[start, end] for start, end in _ALLOWED_RANGES]
    if merged != allowed:
        raise SystemExit("IDA restricted function bodies do not exactly cover signed allowed ranges")
    return sanitized, _sanitize_restricted_value(imports), _sanitize_restricted_value(exports), _sanitize_restricted_value(symbols), {
        "allowed_bytes": sum(end - start for start, end in _ALLOWED_RANGES),
        "covered_bytes": sum(end - start for start, end in merged),
        "range_count": len(_ALLOWED_RANGES),
        "complete": True,
    }


def _prepare_restricted_functions() -> None:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_nalt
    import ida_segment
    import ida_ua

    ida_auto.enable_auto(False)
    image_base = int(_safe(lambda: ida_nalt.get_imagebase(), 0) or 0)
    translated = []
    for raw_start, raw_end in _ALLOWED_RANGES:
        start, end = raw_start, raw_end
        if _safe(lambda: ida_segment.getseg(start)) is None:
            start, end = raw_start + image_base, raw_end + image_base
        translated.append((start, end))
    _ALLOWED_RANGES[:] = translated
    for start, end in _ALLOWED_RANGES:
        cursor = start
        while cursor < end:
            created = int(_safe(lambda: ida_ua.create_insn(cursor), 0) or 0)
            size = max(1, int(_safe(lambda: ida_bytes.get_item_size(cursor), created or 1) or 1))
            cursor += min(size, end - cursor)
        if not _safe(lambda: ida_funcs.add_func(start, end), False):
            function = _safe(lambda: ida_funcs.get_func(start))
            if function is None or int(function.start_ea) != start or int(function.end_ea) > end:
                raise SystemExit("IDA restricted function creation failed")


# --------------------------------------------------------------------- metadata

def collect_metadata(func_count: int, external_count: int = 0) -> dict:
    import ida_nalt
    import ida_ida
    import ida_loader

    def _procname():
        v = _safe(lambda: ida_ida.inf_get_procname())
        if not v:
            import idc
            v = _safe(lambda: idc.get_inf_attr(idc.INF_PROCNAME))
        if isinstance(v, bytes):
            return v.decode("utf-8", "replace")
        return v or "unknown"

    def _is64():
        v = _safe(lambda: ida_ida.inf_is_64bit())
        return bool(v)

    def _bits():
        if _is64():
            return 64
        if _safe(lambda: ida_ida.inf_is_32bit_exactly()):
            return 32
        if _safe(lambda: ida_ida.inf_is_16bit()):
            return 16
        return 32

    def _endian():
        return "big" if _safe(lambda: ida_ida.inf_is_be()) else "little"

    def _filetype_name():
        name = _safe(lambda: ida_loader.get_file_type_name())
        if name:
            return name
        ft = _safe(lambda: ida_ida.inf_get_filetype())
        return str(ft) if ft is not None else "unknown"

    def _digest(fn):
        b = _safe(fn)
        if isinstance(b, (bytes, bytearray)):
            return b.hex()
        return b if isinstance(b, str) else None

    procname = _procname()
    bits = _bits()
    endian = _endian()
    language_id = "%s:%s:%d" % (procname, "BE" if endian == "big" else "LE", bits)
    return {
        "filename": _safe(lambda: ida_nalt.get_root_filename()),
        "name": _safe(lambda: ida_nalt.get_root_filename()),  # REDump alias
        "executable_format": _filetype_name(),
        "processor": procname,
        "bits": bits,
        "pointer_size": bits // 8,
        "endian": endian,
        "language_id": language_id,
        "image_base": _hex(_safe(lambda: ida_nalt.get_imagebase(), 0)),
        "entry_point": _hex(_safe(lambda: ida_ida.inf_get_start_ea(), 0)),
        "sha256": _digest(lambda: ida_nalt.retrieve_input_file_sha256()),
        "md5": _digest(lambda: ida_nalt.retrieve_input_file_md5()),
        "function_count": func_count,
        "internal_function_count": max(0, func_count - external_count),
        "external_function_count": external_count,
        "emitted_function_count": func_count,
        "executable_coverage": collect_executable_coverage(),
        "engine": "ida",
    }


def collect_executable_coverage() -> dict:
    """Account for every byte in IDA executable segments.

    Code outside an IDA function, undefined gaps, and unknown items stay
    explicit blockers. Data/alignment in an executable segment is retained as
    classified evidence instead of being silently counted as a function.
    """
    import ida_bytes
    import ida_funcs
    import ida_lines
    import ida_segment
    import idautils

    totals = {
        "executable_bytes": 0,
        "function_code_bytes": 0,
        "linker_stub_bytes": 0,
        "unowned_code_bytes": 0,
        "data_bytes": 0,
        "alignment_bytes": 0,
        "unknown_item_bytes": 0,
        "gap_bytes": 0,
    }
    blockers: list[dict] = []
    classified: list[dict] = []
    segment = _safe(lambda: ida_segment.get_first_seg())
    while segment is not None:
        start, end = int(segment.start_ea), int(segment.end_ea)
        if end > start and int(segment.perm) & int(ida_segment.SEGPERM_EXEC):
            name = str(_safe(lambda: ida_segment.get_segm_name(segment), "") or "")
            totals["executable_bytes"] += end - start
            cursor = start
            for head in _safe(lambda: list(idautils.Heads(start, end)), []):
                head = int(head)
                if head > cursor:
                    size = head - cursor
                    totals["gap_bytes"] += size
                    blockers.append({
                        "segment": name, "kind": "undefined-gap",
                        "start": _hex(cursor), "size": size,
                    })
                flags = int(_safe(lambda: ida_bytes.get_full_flags(head), 0) or 0)
                size = max(1, int(_safe(lambda: ida_bytes.get_item_size(head), 1) or 1))
                item_end = min(end, head + size)
                size = max(0, item_end - head)
                if _safe(lambda: ida_bytes.is_code(flags), False):
                    owner = _safe(lambda: ida_funcs.get_func(head))
                    if owner is not None:
                        kind, key = "function-code", "function_code_bytes"
                    elif name in {".plt", ".plt.sec", ".plt.got"}:
                        kind, key = "linker-stub", "linker_stub_bytes"
                    else:
                        kind, key = "unowned-code", "unowned_code_bytes"
                elif _safe(lambda: ida_bytes.is_align(flags), False):
                    kind, key = "alignment", "alignment_bytes"
                elif _safe(lambda: ida_bytes.is_data(flags), False):
                    kind, key = "data", "data_bytes"
                else:
                    kind, key = "unknown-item", "unknown_item_bytes"
                totals[key] += size
                if kind != "function-code":
                    row = {
                        "segment": name, "kind": kind,
                        "start": _hex(head), "size": size,
                    }
                    if kind in {"linker-stub", "unowned-code"}:
                        rendered = _safe(
                            lambda: ida_lines.generate_disasm_line(head, 0), ""
                        ) or ""
                        row["disassembly"] = str(
                            _safe(lambda: ida_lines.tag_remove(rendered), rendered)
                            or rendered
                        )
                    classified.append(row)
                    if kind in {"unowned-code", "unknown-item"}:
                        blockers.append(row)
                cursor = max(cursor, item_end)
            if cursor < end:
                size = end - cursor
                totals["gap_bytes"] += size
                blockers.append({
                    "segment": name, "kind": "undefined-gap",
                    "start": _hex(cursor), "size": size,
                })
        segment = _safe(lambda: ida_segment.get_next_seg(int(segment.start_ea)))
    accounted = sum(
        totals[key] for key in (
            "function_code_bytes", "linker_stub_bytes", "unowned_code_bytes", "data_bytes",
            "alignment_bytes", "unknown_item_bytes", "gap_bytes",
        )
    )
    return {
        **totals,
        "accounted_bytes": accounted,
        "complete": bool(
            totals["executable_bytes"] > 0
            and accounted == totals["executable_bytes"]
            and totals["unowned_code_bytes"] == 0
            and totals["unknown_item_bytes"] == 0
            and totals["gap_bytes"] == 0
        ),
        "blockers": blockers[:10_000],
        "classified_non_function_ranges": classified[:50_000],
        "evidence_truncated": len(blockers) > 10_000 or len(classified) > 50_000,
    }


# --------------------------------------------------------------------- functions

def _func_name(ea) -> str:
    import ida_funcs
    n = _safe(lambda: ida_funcs.get_func_name(ea))
    if not n:
        import idc
        n = _safe(lambda: idc.get_func_name(ea))
    return n or ("sub_%X" % (int(ea) if isinstance(ea, int) else 0))


def _is_external(ea) -> bool:
    import ida_funcs
    import ida_segment
    f = _safe(lambda: ida_funcs.get_func(ea))
    if f is not None and (f.flags & ida_funcs.FUNC_THUNK):
        return True
    seg = _safe(lambda: ida_segment.getseg(ea))
    if seg is not None:
        name = (_safe(lambda: ida_segment.get_segm_name(seg)) or "").lower()
        if name in ("extern", ".plt", ".idata", ".plt.sec"):
            return True
    return False


def _segment_name(ea) -> str:
    import ida_segment
    seg = _safe(lambda: ida_segment.getseg(ea))
    if seg is None:
        return ""
    return str(_safe(lambda: ida_segment.get_segm_name(seg)) or "")


def _signature(ea, cfunc=None) -> str:
    import ida_typeinf
    name = _func_name(ea)
    # Prefer the decompiler's recovered prototype.
    if cfunc is not None:
        tif = _safe(lambda: ida_typeinf.tinfo_t())
        if tif is not None and _safe(lambda: cfunc.get_func_type(tif)):
            s = _safe(lambda: ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE,
                                                      tif, name, ""))
            if s:
                return s
    # Else the type stored in the database.
    import ida_nalt
    tif = _safe(lambda: ida_typeinf.tinfo_t())
    if tif is not None and _safe(lambda: ida_nalt.get_tinfo(tif, ea)):
        s = _safe(lambda: ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE,
                                                  tif, name, ""))
        if s:
            return s
    import idc
    return _safe(lambda: idc.get_type(ea)) or name


def _callers(ea) -> list:
    import idautils
    import ida_funcs
    out, seen = [], set()
    for xref in _safe(lambda: list(idautils.XrefsTo(ea, 0)), []):
        if not getattr(xref, "iscode", 0):
            continue  # skip data refs (GOT/vtable/lea) — count only code refs
        f = _safe(lambda: ida_funcs.get_func(xref.frm))
        if f is not None:
            nm = _func_name(f.start_ea)
            if nm not in seen:
                seen.add(nm)
                out.append(nm)
                if len(out) >= _MAX_REFS:
                    break
    return out


def _callees(ea) -> list:
    import idautils
    import ida_funcs
    out, seen = [], set()
    for item in _safe(lambda: list(idautils.FuncItems(ea)), []):
        for xref in _safe(lambda: list(idautils.XrefsFrom(item, 0)), []):
            if not getattr(xref, "iscode", 0):
                continue
            tf = _safe(lambda: ida_funcs.get_func(xref.to))
            if tf is not None and tf.start_ea == xref.to and tf.start_ea != ea:
                nm = _func_name(tf.start_ea)
                if nm not in seen:
                    seen.add(nm)
                    out.append(nm)
        if len(out) >= _MAX_REFS:
            break
    return out


def _referenced_symbols(ea) -> list:
    """Return named non-code dependencies used by a function.

    This preserves evidence such as weak ``_ITM_*`` GOT slots even when IDA
    cannot turn the final indirect jump into a callee edge.
    """
    import idautils
    import idc

    out, seen = [], set()
    for item in _safe(lambda: list(idautils.FuncItems(ea)), []):
        for xref in _safe(lambda: list(idautils.XrefsFrom(item, 0)), []):
            if getattr(xref, "iscode", 0):
                continue
            name = str(_safe(lambda: idc.get_name(xref.to), "") or "")
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(name)
        if len(out) >= _MAX_REFS:
            break
    return out


def _xrefs_to(ea) -> list:
    import idautils
    import ida_funcs
    import ida_xref

    def _xref_type(xref) -> str:
        value = getattr(xref, "type", None)
        if value in (ida_xref.fl_CF, ida_xref.fl_CN):
            return "UNCONDITIONAL_CALL"
        if value in (ida_xref.fl_JF, ida_xref.fl_JN):
            return "UNCONDITIONAL_JUMP"
        if value == ida_xref.dr_R:
            return "READ"
        if value == ida_xref.dr_W:
            return "WRITE"
        if value == ida_xref.dr_O:
            return "OFFSET"
        return "CODE" if getattr(xref, "iscode", 0) else "DATA"

    out = []
    for x in _safe(lambda: list(idautils.XrefsTo(ea, 0)), []):
        owner = _safe(lambda: ida_funcs.get_func(x.frm))
        out.append({
            "from": _hex(x.frm),
            "type": _xref_type(x),
            "from_function": _func_name(owner.start_ea) if owner is not None else "",
            "from_memory_block": _segment_name(x.frm),
        })
        if len(out) >= _MAX_REFS:
            break
    return out


def _ensure_hexrays() -> bool:
    if not _HEXRAYS["init"]:
        _HEXRAYS["init"] = True
        try:
            import ida_hexrays
            _HEXRAYS["ok"] = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            _HEXRAYS["ok"] = False
    return _HEXRAYS["ok"]


def _arm_cancel_watchdog(timeout: float):
    """Start a background thread that sets IDA's global cancel flag after ``timeout``
    seconds. The flag is the same one the GUI "wait box" sets on Ctrl-Break; the
    Hex-Rays optimizer polls it at its internal checkpoints and unwinds with
    MERR_CANCELED. The caller is responsible for disarming the watchdog
    (``_disarm_cancel_watchdog``) and clearing the flag once the decompile call
    returns, so a timeout on one function cannot poison the rest of the run."""
    if not timeout or timeout <= 0:
        return None

    def _fire():
        # The decompiler is still inside ``ida_hexrays.decompile`` on the main
        # thread; setting the kernel cancel flag is the documented interrupt path.
        # Re-check the armed flag under the lock: a fire that lands after the
        # watchdog was disarmed must not set the cancel flag, or it would poison
        # the next function's decompile (see _disarm_cancel_watchdog).
        with _CANCEL_LOCK:
            if not _CANCEL_ACTIVE["armed"]:
                return
        try:
            import ida_kernwin
            ida_kernwin.set_cancelled()
        except Exception:
            pass

    with _CANCEL_LOCK:
        prev = _CANCEL_ACTIVE["thread"]
        if prev is not None and prev.is_alive():
            # A previous watchdog never got disarmed (should not happen, but be safe).
            return None
        t = threading.Timer(timeout, _fire)
        t.daemon = True
        _CANCEL_ACTIVE["thread"] = t
        _CANCEL_ACTIVE["armed"] = True
        t.start()
        return t


def _disarm_cancel_watchdog() -> None:
    """Cancel the pending watchdog and clear any cancel flag it may have raised so
    later functions decompile normally.

    Ordering matters: ``threading.Timer.cancel`` is a no-op once the timer thread
    has passed its ``finished.is_set()`` check, so a fire can land after ``cancel``.
    We mark the watchdog disarmed under the lock (so a fire that has not yet passed
    the check bails out), then ``join`` the timer thread (so a fire that already
    passed the check finishes its ``set_cancelled`` before we clear), and only then
    clear the flag. This closes the fire-vs-clear race that would otherwise leave
    IDA's global cancel flag set and poison the next function's decompile."""
    with _CANCEL_LOCK:
        t = _CANCEL_ACTIVE["thread"]
        _CANCEL_ACTIVE["thread"] = None
        _CANCEL_ACTIVE["armed"] = False
    if t is not None:
        t.cancel()
        t.join()
    try:
        import ida_kernwin
        ida_kernwin.clr_cancelled()
    except Exception:
        pass


def _decompile(ea, *, timeout: float = _DECOMPILE_TIMEOUT):
    """Return (c_text, cfunc, status) where status is one of "ok", "unavailable",
    "timeout", "failed". Best-effort; the decompiler may be unavailable for some
    architectures. Hex-Rays is initialized once.

    A per-function wall-clock watchdog guards against non-deterministic decompiler
    sprawl (IDA's decompiler has no built-in timeout). On timeout the function is
    *not* skipped: callers still emit its disassembly + metadata, annotated with
    ``decompile_skipped=True`` / ``decompile_skip_reason="hexrays_timeout"`` so the
    evidence is preserved and the reason is auditable.
    """
    if not _ensure_hexrays():
        return None, None, "unavailable"
    _arm_cancel_watchdog(timeout)
    try:
        import ida_hexrays
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            # Distinguish a genuine cancellation (our watchdog fired) from a normal
            # "cannot decompile" by checking the kernel cancel flag we just set.
            try:
                import ida_kernwin
                if ida_kernwin.user_cancelled():
                    return None, None, "timeout"
            except Exception:
                pass
            return None, None, "failed"
        return str(cf), cf, "ok"
    except Exception:
        # ida_hexrays surfaces MERR_CANCELED as a Python exception in some builds.
        try:
            import ida_kernwin
            if ida_kernwin.user_cancelled():
                return None, None, "timeout"
        except Exception:
            pass
        return None, None, "failed"
    finally:
        _disarm_cancel_watchdog()


def _disassembly(ea) -> list:
    import idautils
    import ida_lines
    import idc
    out = []
    for item in _safe(lambda: list(idautils.FuncItems(ea)), []):
        line = _safe(lambda: ida_lines.generate_disasm_line(item, 0))
        if line is not None:
            line = _safe(lambda: ida_lines.tag_remove(line)) or line
        else:
            line = _safe(lambda: idc.generate_disasm_line(item, 0)) or ""
        out.append({"addr": _hex(item), "text": line})
        if len(out) >= _MAX_DISASM:
            break
    return out


def _function_entry(ea, *, decompile: bool) -> dict:
    import ida_funcs
    f = _safe(lambda: ida_funcs.get_func(ea))
    start = f.start_ea if f is not None else ea
    size = (f.end_ea - f.start_ea) if f is not None else 0
    c_text, cfunc = (None, None)
    dc_status = None
    if decompile:
        c_text, cfunc, dc_status = _decompile(start)
    entry = {
        "name": _func_name(start),
        "entry": _hex(start),
        "size": int(size),
        "body_ranges": _body_ranges(start),
        "signature": _signature(start, cfunc),
        "is_external": _is_external(start),
        "is_thunk": bool(f is not None and (f.flags & ida_funcs.FUNC_THUNK)),
        "memory_block": _segment_name(start),
        "callers": _callers(start),
        "callees": _callees(start),
        "referenced_symbols": _referenced_symbols(start),
        "xrefs_to": _xrefs_to(start),
    }
    if decompile:
        if c_text is not None:
            entry["decompiled"] = c_text[:_MAX_DECOMPILED_CHARS]
            entry["decompiled_truncated"] = len(c_text) > _MAX_DECOMPILED_CHARS
        elif dc_status == "timeout":
            # The decompiler sprawled past its per-function budget. We do NOT drop
            # the function: its disassembly + metadata above are already populated,
            # and we additionally capture the disassembly view so the analyst still
            # has the function's instructions, with an auditable skip reason.
            entry["decompile_skipped"] = True
            entry["decompile_skip_reason"] = "hexrays_timeout"
            entry["disassembly"] = _disassembly(start)
    return entry


def _body_ranges(ea) -> list[dict]:
    """Return IDA function chunks using an engine-neutral inclusive schema."""
    import idautils

    ranges = []
    for start, end_exclusive in _safe(lambda: list(idautils.Chunks(ea)), []):
        if end_exclusive <= start:
            continue
        ranges.append({
            "start": _hex(start),
            "end": _hex(end_exclusive - 1),
            "size": int(end_exclusive - start),
            "end_inclusive": True,
        })
    return ranges


def _ida_range_entry(start, end_exclusive) -> dict:
    """Serialize an IDA half-open range without leaking BADADDR as a real end."""
    import ida_idaapi

    start_i = int(start)
    end_i = int(end_exclusive)
    result = {"start": _hex(start_i)}
    if end_i <= start_i or end_i == int(ida_idaapi.BADADDR):
        return result
    result.update({
        "end": _hex(end_i - 1),
        "size": end_i - start_i,
        "end_inclusive": True,
    })
    return result


def _unwind_range_for(address: int, try_blocks: list) -> dict | None:
    """Return IDA's exact unwind/FDE range containing an EH flow target."""
    for try_block in try_blocks:
        if not _safe(lambda: bool(try_block.is_seh()), False):
            continue
        for block_range in try_block:
            start = int(block_range.start_ea)
            end = int(block_range.end_ea)
            if start <= address < end:
                return _ida_range_entry(start, end)
    return None


def _handler_control_targets(entry: int, try_blocks: list) -> list[dict]:
    """Follow explicit non-fallthrough flow from a native catch landing pad.

    GCC commonly places a tiny landing pad inside the owning function and jumps
    from it to a cold handler range that IDA did not promote to a function.  A
    bounded instruction scan retains that exact jump; it does not guess based
    on address proximity.
    """
    import ida_funcs
    import ida_xref
    import idautils
    import idc

    owner = _safe(lambda: ida_funcs.get_func(entry))
    stop = min(entry + 0x40, int(owner.end_ea) if owner is not None else entry + 0x40)
    targets: list[dict] = []
    seen: set[int] = set()
    for head in _safe(lambda: list(idautils.Heads(entry, stop)), []):
        for xref in _safe(lambda: list(idautils.XrefsFrom(head, 0)), []):
            if getattr(xref, "type", None) not in (ida_xref.fl_JF, ida_xref.fl_JN):
                continue
            target = int(xref.to)
            if target in seen:
                continue
            seen.add(target)
            item = {
                "from": _hex(head),
                "address": _hex(target),
                "type": "UNCONDITIONAL_JUMP",
            }
            unwind_range = _unwind_range_for(target, try_blocks)
            if unwind_range:
                item["unwind_range"] = unwind_range
            targets.append(item)
        mnemonic = str(_safe(lambda: idc.print_insn_mnem(head), "") or "").lower()
        if mnemonic.startswith(("ret", "iret")) or targets:
            break
    return targets


def collect_exception_regions() -> list[dict]:
    """Export native IDA C++ try/catch metadata in an engine-neutral schema."""
    import ida_funcs
    import ida_ida
    import ida_range
    import ida_tryblks

    try_blocks = ida_tryblks.tryblks_t()
    image_range = ida_range.range_t(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())
    _safe(lambda: ida_tryblks.get_tryblks(try_blocks, image_range), 0)
    blocks = list(try_blocks)
    result: list[dict] = []
    for try_block in blocks:
        if not _safe(lambda: bool(try_block.is_cpp()), False):
            continue
        protected = [_ida_range_entry(r.start_ea, r.end_ea) for r in try_block]
        if not protected:
            continue
        owner = _safe(lambda: ida_funcs.get_func(int(try_block[0].start_ea)))
        handlers = []
        for catch in try_block.cpp():
            ranges = [_ida_range_entry(r.start_ea, r.end_ea) for r in catch]
            if not ranges:
                continue
            entry = int(catch[0].start_ea)
            handlers.append({
                "kind": "catch",
                "entry": _hex(entry),
                "ranges": ranges,
                "control_targets": _handler_control_targets(entry, blocks),
                "type_id": int(catch.type_id),
                "object_offset": int(catch.obj),
                "stack_adjustment": int(catch.disp),
                "frame_register": int(catch.fpreg),
            })
        if not handlers:
            continue
        result.append({
            "kind": "cpp",
            "level": int(try_block.level),
            "protected_ranges": protected,
            "handlers": handlers,
            "owner": (
                {
                    "name": _func_name(owner.start_ea),
                    "entry": _hex(owner.start_ea),
                }
                if owner is not None else None
            ),
            "source": "ida_tryblks",
            "confidence": 1.0,
        })
    return result


def _range_callees(body_range: dict) -> list:
    """Collect cross-range code targets for a synthetic EH handler body."""
    import ida_funcs
    import ida_xref
    import idautils

    try:
        start = int(str(body_range["start"]), 16)
        size = int(body_range.get("size") or 0)
    except (KeyError, TypeError, ValueError):
        return []
    if size <= 0:
        return []
    end = start + size
    result, seen = [], set()
    flow_types = (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN)
    for head in _safe(lambda: list(idautils.Heads(start, end)), []):
        for xref in _safe(lambda: list(idautils.XrefsFrom(head, 0)), []):
            if getattr(xref, "type", None) not in flow_types:
                continue
            target = int(xref.to)
            if start <= target < end:
                continue
            target_function = _safe(lambda: ida_funcs.get_func(target))
            if target_function is None or int(target_function.start_ea) != target:
                continue
            name = _func_name(target)
            if name not in seen:
                seen.add(name)
                result.append(name)
        if len(result) >= _MAX_REFS:
            break
    return result


def _exception_handler_functions(exception_regions: list[dict]) -> list[dict]:
    """Promote native-metadata-backed cold EH ranges IDA missed as functions."""
    import ida_funcs

    result = []
    seen: set[int] = set()
    for region in exception_regions:
        for handler in region.get("handlers") or []:
            for target in handler.get("control_targets") or []:
                body_range = target.get("unwind_range")
                if not body_range:
                    continue
                try:
                    entry = int(str(target["address"]), 16)
                except (KeyError, TypeError, ValueError):
                    continue
                if entry in seen or _safe(lambda: ida_funcs.get_func(entry)) is not None:
                    continue
                try:
                    range_start = int(str(body_range["start"]), 16)
                    size = int(body_range.get("size") or 0)
                except (KeyError, TypeError, ValueError):
                    continue
                if size <= 0 or not (range_start <= entry < range_start + size):
                    continue
                seen.add(entry)
                result.append({
                    "name": "exception_handler_%x" % entry,
                    "entry": _hex(entry),
                    "size": size - (entry - range_start),
                    "body_ranges": [{
                        "start": _hex(entry),
                        "end": body_range["end"],
                        "size": size - (entry - range_start),
                        "end_inclusive": True,
                    }],
                    "signature": "int exception_handler_%x(void)" % entry,
                    "is_external": False,
                    "memory_block": _segment_name(entry),
                    "callers": _callers(entry),
                    "callees": _range_callees(body_range),
                    "xrefs_to": _xrefs_to(entry),
                    "is_exception_handler": True,
                    "synthetic": True,
                    "inferred_from": "ida_tryblks_control_target",
                    "confidence": 1.0,
                })
    return result


def collect_functions(
    *,
    decompile: bool,
    max_functions: int,
    exception_regions: list[dict] | None = None,
) -> list:
    import idautils
    eas = [ea for ea in _safe(lambda: list(idautils.Functions()), []) if _allowed(ea)]
    out = []
    decompiled = 0
    timed_out = 0
    _progress("functions", 0, len(eas))
    for index, ea in enumerate(eas, 1):
        do_dc = decompile and (max_functions == 0 or decompiled < max_functions)
        entry = _function_entry(ea, decompile=do_dc)
        if do_dc:
            if "decompiled" in entry:
                decompiled += 1
            elif entry.get("decompile_skipped"):
                timed_out += 1
        out.append(entry)
        if index == len(eas) or index % 25 == 0:
            _progress("functions", index, len(eas), decompiled=decompiled, timed_out=timed_out)
    out.extend(_exception_handler_functions(exception_regions or []))
    return out


# ----------------------------------------------------------- strings / imports / etc.

def collect_strings() -> list:
    import idautils
    out = []
    for s in _safe(lambda: list(idautils.Strings()), []):
        if s is None:
            continue
        val = _safe(lambda: str(s))
        if not val:
            continue
        ea = _safe(lambda: s.ea)
        byte_length = int(getattr(s, "length", len(val)) or len(val))
        out.append({
            "address": _hex(ea) if ea is not None else "0x0",
            "value": val,
            # Keep decoded character length engine-neutral.  IDA's StringItem
            # length commonly includes the trailing NUL while Ghidra's Java
            # String length does not.
            "length": len(val),
            "byte_length": byte_length,
            "memory_block": _segment_name(ea) if ea is not None else "",
            "xrefs_to": _xrefs_to(ea) if ea is not None else [],
            "rtti_vtable_candidates": (
                _rtti_vtable_candidates(ea, val)
                if ea is not None else []
            ),
            "rtti_typeinfo_candidates": (
                _rtti_typeinfo_candidates(ea, val)
                if ea is not None else []
            ),
        })
        if len(out) >= _MAX_STRINGS:
            break
    return out


def _rtti_vtable_candidates(type_name_ea, value: str) -> list[dict]:
    """Export validated primary and secondary Itanium vtable headers."""
    import re
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_name
    import ida_segment
    import idautils
    import idc

    if not re.fullmatch(r"N(?:\d+[A-Za-z_][A-Za-z0-9_]*)+E", value or ""):
        return []
    pointer_size = 8 if _safe(lambda: ida_ida.inf_is_64bit()) else 4
    width = pointer_size * 8

    def read_pointer(ea: int, *, signed: bool = False) -> int:
        raw = (
            int(_safe(lambda: ida_bytes.get_qword(ea), 0) or 0)
            if pointer_size == 8
            else int(_safe(lambda: ida_bytes.get_dword(ea), 0) or 0)
        )
        if signed and raw & (1 << (width - 1)):
            return raw - (1 << width)
        return raw

    def target_or_pointer(ea: int) -> int:
        refs = _safe(lambda: list(idautils.XrefsFrom(ea, 0)), []) or []
        if refs:
            return int(refs[0].to)
        return read_pointer(ea)

    def callable_target(ea: int) -> bool:
        if ea <= 0:
            return False
        if _safe(lambda: ida_funcs.get_func(ea), None) is not None:
            return True
        segment = _safe(lambda: ida_segment.getseg(ea), None)
        return bool(
            segment is not None
            and int(segment.perm) & int(ida_segment.SEGPERM_EXEC)
        )

    def executable_reference_to(ea: int) -> bool:
        for ref in _safe(lambda: list(idautils.XrefsTo(ea, 0)), []) or []:
            segment = _safe(
                lambda source=int(ref.frm): ida_segment.getseg(source),
                None,
            )
            if (
                segment is not None
                and int(segment.perm) & int(ida_segment.SEGPERM_EXEC)
            ):
                return True
        return False

    def signed_mangled_offset(token: str) -> int:
        return -int(token[1:]) if token.startswith("n") else int(token)

    def thunk_adjustment_candidates(ea: int) -> list[dict]:
        candidates = []
        seen_candidates = set()

        def append_candidate(record: dict) -> None:
            key = (
                record.get("kind"),
                record.get("fixed_delta"),
                record.get("vcall_offset_slot"),
            )
            if key not in seen_candidates:
                seen_candidates.add(key)
                candidates.append(record)

        symbol_name = str(
            _safe(lambda: ida_name.get_name(ea), "") or ""
        )
        virtual_match = re.search(
            r"_ZTv(?P<fixed>n?\d+)_(?P<vcall>n?\d+)_",
            symbol_name,
        )
        fixed_match = re.search(
            r"_ZTh(?P<fixed>n?\d+)_",
            symbol_name,
        )
        if virtual_match:
            append_candidate({
                "kind": "virtual_vcall",
                "fixed_delta": signed_mangled_offset(
                    virtual_match.group("fixed")
                ),
                "vcall_offset_slot": signed_mangled_offset(
                    virtual_match.group("vcall")
                ),
                "evidence": "itanium_mangled_thunk_symbol",
                "source_name": symbol_name,
                "confidence": 1.0,
            })
        elif fixed_match:
            append_candidate({
                "kind": "fixed",
                "fixed_delta": signed_mangled_offset(
                    fixed_match.group("fixed")
                ),
                "vcall_offset_slot": None,
                "evidence": "itanium_mangled_thunk_symbol",
                "source_name": symbol_name,
                "confidence": 1.0,
            })

        vptr_registers = set()
        for instruction_ea in (
            _safe(lambda: list(idautils.FuncItems(ea)), []) or []
        ):
            mnemonic = str(
                _safe(
                    lambda item=instruction_ea:
                        idc.print_insn_mnem(item),
                    "",
                ) or ""
            ).lower()
            operand0 = str(
                _safe(
                    lambda item=instruction_ea:
                        idc.print_operand(item, 0),
                    "",
                ) or ""
            ).lower().replace(" ", "")
            operand1 = str(
                _safe(
                    lambda item=instruction_ea:
                        idc.print_operand(item, 1),
                    "",
                ) or ""
            ).lower().replace(" ", "")
            if (
                mnemonic == "mov"
                and re.fullmatch(r"[a-z][a-z0-9]*", operand0)
                and re.search(r"\[(?:rdi|edi)\]", operand1)
            ):
                vptr_registers.add(operand0)
                continue
            if (
                mnemonic == "sub"
                and operand0 in {"rdi", "edi"}
            ):
                immediate = int(
                    _safe(
                        lambda item=instruction_ea:
                            idc.get_operand_value(item, 1),
                        0,
                    ) or 0
                )
                if immediate > 0:
                    append_candidate({
                        "kind": "fixed",
                        "fixed_delta": -immediate,
                        "vcall_offset_slot": None,
                        "evidence": (
                            "x86_sysv_this_adjustment_instruction_pattern"
                        ),
                        "source_name": None,
                        "confidence": 0.99,
                    })
                continue
            if mnemonic != "add" or operand0 not in {"rdi", "edi"}:
                continue
            displacement_match = re.search(
                r"\[(?P<base>[a-z][a-z0-9]*)"
                r"(?P<sign>[+-])"
                r"(?P<value>(?:0x)?[0-9a-f]+h?)\]",
                operand1,
            )
            if (
                displacement_match is None
                or displacement_match.group("base")
                not in vptr_registers
            ):
                continue
            raw_value = displacement_match.group("value")
            if raw_value.endswith("h"):
                raw_value = "0x" + raw_value[:-1]
            displacement = int(raw_value, 0)
            if displacement_match.group("sign") == "-":
                displacement = -displacement
            append_candidate({
                "kind": "virtual_vcall",
                "fixed_delta": 0,
                "vcall_offset_slot": displacement,
                "evidence": (
                    "x86_sysv_this_adjustment_instruction_pattern"
                ),
                "source_name": None,
                "confidence": 0.99,
            })
        return candidates

    def typeinfo_kind(typeinfo: int) -> str:
        vptr_target = target_or_pointer(typeinfo)
        if vptr_target <= 0:
            return "unknown"
        for address in (vptr_target, vptr_target - 2 * pointer_size):
            name = str(
                _safe(lambda a=address: ida_name.get_name(a), "") or ""
            )
            if "__vmi_class_type_info" in name:
                return "vmi_class_type_info"
            if "__si_class_type_info" in name:
                return "si_class_type_info"
            if "__class_type_info" in name:
                return "class_type_info"
        return "unknown"

    def primary_vbase_prefix_entries(
        typeinfo: int,
        address_point: int,
        segment,
    ) -> list[dict]:
        if typeinfo_kind(typeinfo) != "vmi_class_type_info":
            return []
        flags_address = typeinfo + 2 * pointer_size
        count_address = flags_address + 4
        base_array_address = flags_address + 8
        base_count = int(
            _safe(lambda: ida_bytes.get_dword(count_address), 0) or 0
        )
        record_size = 2 * pointer_size
        available = max(0, int(segment.end_ea) - base_array_address)
        if base_count <= 0 or base_count > available // record_size:
            return []
        entries = []
        for index in range(base_count):
            record_address = base_array_address + index * record_size
            offset_flags_address = record_address + pointer_size
            raw_offset_flags = read_pointer(offset_flags_address)
            flags = raw_offset_flags & 0xFF
            if not flags & 0x1:
                continue
            signed_offset_flags = (
                raw_offset_flags - (1 << width)
                if raw_offset_flags & (1 << (width - 1))
                else raw_offset_flags
            )
            slot_offset = signed_offset_flags >> 8
            slot_address = address_point + slot_offset
            if (
                slot_offset >= -2 * pointer_size
                or slot_address < int(segment.start_ea)
                or slot_address + pointer_size > int(segment.end_ea)
            ):
                return []
            entries.append({
                "relative_to_address_point": slot_offset,
                "pointer_address": _hex(slot_address),
                "value": read_pointer(slot_address, signed=True),
                "entry_kind": "vbase_offset",
                "base_typeinfo_address": _hex(
                    target_or_pointer(record_address)
                ),
            })
        entries.sort(key=lambda entry: int(entry["pointer_address"], 16))
        for entry_index, entry in enumerate(entries):
            entry["entry_index"] = entry_index
        return entries

    def secondary_prefix_entries(
        vtable: int,
        address_point: int,
        segment,
    ) -> list[dict]:
        entries = []
        cursor = vtable - pointer_size
        boundary_is_callable = False
        while cursor >= int(segment.start_ea):
            # Prefix cells are signed ABI offsets, not pointer objects.  IDA
            # may synthesize offset xrefs for small negative words; reading
            # the stored word avoids turning those scalars into false data
            # pointers while still recognizing the preceding method slot.
            raw_target = read_pointer(cursor)
            if callable_target(raw_target):
                boundary_is_callable = True
                break
            if (
                raw_target != 0
                and _safe(
                    lambda: ida_segment.getseg(raw_target),
                    None,
                ) is not None
            ):
                return []
            entries.append({
                "relative_to_address_point": cursor - address_point,
                "pointer_address": _hex(cursor),
                "value": read_pointer(cursor, signed=True),
                "entry_kind": "vcall_or_vbase_offset",
                "base_typeinfo_address": None,
            })
            cursor -= pointer_size
        if not entries or not boundary_is_callable:
            return []
        entries.reverse()
        for entry_index, entry in enumerate(entries):
            entry["entry_index"] = entry_index
        return entries

    def direct_base_typeinfos(typeinfo: int) -> list[int] | None:
        segment = _safe(lambda: ida_segment.getseg(typeinfo), None)
        if segment is None or ".data.rel.ro" not in _segment_name(typeinfo):
            return None
        kind = typeinfo_kind(typeinfo)
        if kind == "class_type_info":
            return []
        if kind == "si_class_type_info":
            base = target_or_pointer(typeinfo + 2 * pointer_size)
            if (
                base <= 0
                or ".data.rel.ro" not in _segment_name(base)
            ):
                return None
            return [base]
        if kind != "vmi_class_type_info":
            return []
        flags_address = typeinfo + 2 * pointer_size
        count_address = flags_address + 4
        base_array_address = flags_address + 8
        base_count = int(
            _safe(lambda: ida_bytes.get_dword(count_address), 0) or 0
        )
        record_size = 2 * pointer_size
        available = max(0, int(segment.end_ea) - base_array_address)
        if base_count <= 0 or base_count > available // record_size:
            return None
        bases = []
        for index in range(base_count):
            base = target_or_pointer(
                base_array_address + index * record_size
            )
            if (
                base <= 0
                or ".data.rel.ro" not in _segment_name(base)
            ):
                return None
            bases.append(base)
        return bases

    def base_typeinfo_closure(typeinfo: int) -> set[int]:
        allowed = {typeinfo}
        pending = [typeinfo]
        while pending:
            current = pending.pop()
            bases = direct_base_typeinfos(current)
            if bases is None:
                # Malformed/unknown RTTI can still support an old-style,
                # same-RTTI VTT, but never authorizes foreign construction
                # table entries.
                return {typeinfo}
            for base in bases:
                if base not in allowed:
                    allowed.add(base)
                    pending.append(base)
        return allowed

    virtual_base_cache: dict[int, bool] = {}

    def typeinfo_has_virtual_base(
        typeinfo: int,
        visiting: set[int] | None = None,
    ) -> bool:
        if typeinfo in virtual_base_cache:
            return virtual_base_cache[typeinfo]
        active = set(visiting or set())
        if typeinfo in active:
            return False
        active.add(typeinfo)
        bases = direct_base_typeinfos(typeinfo)
        if bases is None:
            virtual_base_cache[typeinfo] = False
            return False
        kind = typeinfo_kind(typeinfo)
        if kind == "vmi_class_type_info":
            base_array_address = typeinfo + 2 * pointer_size + 8
            for index, base in enumerate(bases):
                raw_offset_flags = read_pointer(
                    base_array_address
                    + index * 2 * pointer_size
                    + pointer_size
                )
                if raw_offset_flags & 0x1:
                    virtual_base_cache[typeinfo] = True
                    return True
                if typeinfo_has_virtual_base(base, active):
                    virtual_base_cache[typeinfo] = True
                    return True
        elif kind == "si_class_type_info" and bases:
            if typeinfo_has_virtual_base(bases[0], active):
                virtual_base_cache[typeinfo] = True
                return True
        virtual_base_cache[typeinfo] = False
        return False

    def address_point_record(
        target: int,
        root_typeinfo: int,
        allowed_typeinfos: set[int],
    ) -> dict | None:
        segment = _safe(lambda: ida_segment.getseg(target), None)
        if segment is None or ".data.rel.ro" not in _segment_name(target):
            return None
        if target - 2 * pointer_size < int(segment.start_ea):
            return None
        rtti_pointer = target - pointer_size
        vtable = target - 2 * pointer_size
        entry_typeinfo = target_or_pointer(rtti_pointer)
        if entry_typeinfo not in allowed_typeinfos:
            return None
        offset_to_top = read_pointer(vtable, signed=True)
        if (
            offset_to_top > 0
            or offset_to_top % pointer_size != 0
        ):
            return None
        table_role = (
            "complete_object"
            if entry_typeinfo == root_typeinfo
            else "construction"
        )
        if (
            table_role == "construction"
            and not typeinfo_has_virtual_base(entry_typeinfo)
        ):
            return None
        leading_null_slot_count = 0
        first_target = target_or_pointer(target)
        while (
            not callable_target(first_target)
            and leading_null_slot_count < 2
            and first_target == 0
        ):
            leading_null_slot_count += 1
            first_target = target_or_pointer(
                target + leading_null_slot_count * pointer_size
            )
        if (
            not callable_target(first_target)
            or (
                table_role == "complete_object"
                and leading_null_slot_count != 0
            )
        ):
            return None
        return {
            "address_point_address": _hex(target),
            "vtable_address": _hex(vtable),
            "typeinfo_address": _hex(entry_typeinfo),
            "offset_to_top": offset_to_top,
            "table_kind": (
                "primary" if offset_to_top == 0 else "secondary"
            ),
            "table_role": table_role,
            "leading_null_slot_count": leading_null_slot_count,
        }

    def vtt_candidate(
        typeinfo: int,
        current_address_point: int,
        segment,
    ) -> dict | None:
        runs = []
        run = []
        allowed_typeinfos = base_typeinfo_closure(typeinfo)
        cursor = int(segment.start_ea)
        cursor += (-cursor) % pointer_size

        def finish_run() -> None:
            nonlocal run
            targets = {
                int(entry["address_point_address"], 16) for entry in run
            }
            if (
                len(run) >= 2
                and len(targets) >= 2
                and current_address_point in targets
                and run[0]["typeinfo_address"] == _hex(typeinfo)
                and run[0]["table_role"] == "complete_object"
                and run[0]["offset_to_top"] == 0
            ):
                runs.append(run)
            run = []

        while cursor + pointer_size <= int(segment.end_ea):
            target = target_or_pointer(cursor)
            record = address_point_record(
                target,
                typeinfo,
                allowed_typeinfos,
            )
            if record is None:
                finish_run()
            else:
                run.append({
                    "pointer_address": _hex(cursor),
                    **record,
                })
            cursor += pointer_size
        finish_run()
        if len(runs) != 1:
            return None
        entries = runs[0]
        for entry_index, entry in enumerate(entries):
            entry["entry_index"] = entry_index
        mixed_rtti = any(
            entry["table_role"] == "construction" for entry in entries
        )
        return {
            "vtt_address": entries[0]["pointer_address"],
            "entry_count": len(entries),
            "entries": entries,
            "evidence": (
                (
                    "contiguous_data_pointers_start_at_complete_object_"
                    "and_cover_valid_base_construction_address_points"
                )
                if mixed_rtti
                else (
                    "contiguous_data_pointers_cover_distinct_"
                    "same_rtti_vtable_address_points"
                )
            ),
            "confidence": 0.99,
        }

    out = []
    seen = set()

    def append_candidate(
        typeinfo: int,
        name_pointer: int,
        rtti_pointer: int,
        discovery: str,
    ) -> None:
        if ".data.rel.ro" not in _segment_name(rtti_pointer):
            return
        vtable = rtti_pointer - pointer_size
        offset_to_top = read_pointer(vtable, signed=True)
        if offset_to_top > 0 or offset_to_top % pointer_size != 0:
            return
        address_point = rtti_pointer + pointer_size
        first_method_target = target_or_pointer(address_point)
        if not callable_target(first_method_target):
            return
        segment = _safe(lambda: ida_segment.getseg(rtti_pointer), None)
        if segment is None:
            return
        method_slots = []
        slot_address = address_point
        slot_index = 0
        slot_boundary_reason = "memory_block_end"
        while slot_address + pointer_size <= int(segment.end_ea):
            if slot_index > 0 and executable_reference_to(slot_address):
                slot_boundary_reason = "code_reference_to_next_data_object"
                break
            target = target_or_pointer(slot_address)
            if not callable_target(target):
                slot_boundary_reason = "non_callable_pointer"
                break
            method_slots.append({
                "slot_index": slot_index,
                "method_offset": slot_index * pointer_size,
                "pointer_address": _hex(slot_address),
                "target_address": _hex(target),
                "this_adjustment_candidates": (
                    thunk_adjustment_candidates(target)
                    if offset_to_top < 0 else []
                ),
            })
            slot_index += 1
            slot_address += pointer_size
        if not method_slots:
            return
        key = (typeinfo, vtable)
        if key in seen:
            return
        seen.add(key)
        table_kind = "primary" if offset_to_top == 0 else "secondary"
        prefix_entries = (
            primary_vbase_prefix_entries(typeinfo, address_point, segment)
            if table_kind == "primary"
            else secondary_prefix_entries(vtable, address_point, segment)
        )
        prefix_boundary_reason = (
            "vmi_virtual_base_slots"
            if table_kind == "primary" and prefix_entries
            else (
                "preceding_callable_vtable_slot"
                if prefix_entries else None
            )
        )
        recovered_vtt = vtt_candidate(
            typeinfo,
            address_point,
            segment,
        )
        out.append({
            "typeinfo_address": _hex(typeinfo),
            "name_pointer_address": _hex(name_pointer),
            "vtable_address": _hex(vtable),
            "rtti_pointer_address": _hex(rtti_pointer),
            "address_point_address": _hex(address_point),
            "first_method_pointer_address": _hex(address_point),
            "first_method_target_address": _hex(first_method_target),
            "offset_to_top": offset_to_top,
            "table_kind": table_kind,
            "slot_count": len(method_slots),
            "method_slots": method_slots,
            "slot_boundary_reason": slot_boundary_reason,
            "prefix_entry_count": len(prefix_entries),
            "prefix_entries": prefix_entries,
            "prefix_boundary_reason": prefix_boundary_reason,
            "vtt_candidate": recovered_vtt,
            "memory_block": _segment_name(rtti_pointer),
            "discovery": discovery,
            "evidence": (
                "itanium_name_pointer_and_zero_offset_vtable_header"
                if offset_to_top == 0
                else (
                    "itanium_name_pointer_negative_offset_and_"
                    "callable_vtable_header"
                )
            ),
            "confidence": 0.97 if offset_to_top == 0 else 0.98,
        })

    for name_ref in (
        _safe(lambda: list(idautils.XrefsTo(type_name_ea, 0)), []) or []
    ):
        name_pointer = int(name_ref.frm)
        if ".data.rel.ro" not in _segment_name(name_pointer):
            continue
        typeinfo = name_pointer - pointer_size
        for typeinfo_ref in (
            _safe(lambda ea=typeinfo: list(idautils.XrefsTo(ea, 0)), [])
            or []
        ):
            append_candidate(
                typeinfo,
                name_pointer,
                int(typeinfo_ref.frm),
                "xref_scan",
            )

        segment = _safe(lambda: ida_segment.getseg(typeinfo), None)
        if segment is None:
            continue
        cursor = int(segment.start_ea)
        cursor += (-cursor) % pointer_size
        while cursor + pointer_size <= int(segment.end_ea):
            if read_pointer(cursor) == typeinfo:
                append_candidate(
                    typeinfo,
                    name_pointer,
                    cursor,
                    "aligned_pointer_scan",
                )
            cursor += pointer_size
    return out


def _rtti_typeinfo_candidates(type_name_ea, value: str) -> list[dict]:
    """Export validated Itanium type_info/base records for hierarchy recovery."""
    import re
    import ida_bytes
    import ida_ida
    import ida_name
    import ida_segment
    import idautils

    if not re.fullmatch(r"N(?:\d+[A-Za-z_][A-Za-z0-9_]*)+E", value or ""):
        return []
    pointer_size = 8 if _safe(lambda: ida_ida.inf_is_64bit()) else 4

    def target_or_pointer(ea):
        refs = _safe(lambda: list(idautils.XrefsFrom(ea, 0)), []) or []
        if refs:
            return int(refs[0].to)
        if pointer_size == 8:
            return int(_safe(lambda: ida_bytes.get_qword(ea), 0) or 0)
        return int(_safe(lambda: ida_bytes.get_dword(ea), 0) or 0)

    def typeinfo_kind(vptr_target: int) -> str:
        if vptr_target <= 0:
            return "unknown"
        for address in (vptr_target, vptr_target - 2 * pointer_size):
            name = str(_safe(lambda a=address: ida_name.get_name(a), "") or "")
            if "__vmi_class_type_info" in name:
                return "vmi_class_type_info"
            if "__si_class_type_info" in name:
                return "si_class_type_info"
            if "__class_type_info" in name:
                return "class_type_info"
        return "unknown"

    out = []
    seen = set()
    for ref in _safe(lambda: list(idautils.XrefsTo(type_name_ea, 0)), []) or []:
        name_pointer = int(ref.frm)
        if ".data.rel.ro" not in _segment_name(name_pointer):
            continue
        typeinfo = name_pointer - pointer_size
        if typeinfo in seen:
            continue
        seen.add(typeinfo)
        vptr_target = target_or_pointer(typeinfo)
        kind = typeinfo_kind(vptr_target)
        base_pointer = typeinfo + 2 * pointer_size
        base_typeinfo = (
            target_or_pointer(base_pointer)
            if kind == "si_class_type_info" else 0
        )
        if (
            kind == "si_class_type_info"
            and ".data.rel.ro" not in _segment_name(base_typeinfo)
        ):
            continue
        vmi_flags = 0
        bases = []
        if kind == "vmi_class_type_info":
            flags_address = typeinfo + 2 * pointer_size
            count_address = flags_address + 4
            base_array_address = flags_address + 8
            segment = _safe(lambda: ida_segment.getseg(typeinfo), None)
            if segment is None:
                continue
            vmi_flags = int(
                _safe(lambda: ida_bytes.get_dword(flags_address), 0) or 0
            )
            base_count = int(
                _safe(lambda: ida_bytes.get_dword(count_address), 0) or 0
            )
            record_size = 2 * pointer_size
            available = max(0, int(segment.end_ea) - base_array_address)
            if base_count <= 0 or base_count > available // record_size:
                continue
            valid_bases = True
            for index in range(base_count):
                record_address = base_array_address + index * record_size
                offset_flags_address = record_address + pointer_size
                base_typeinfo_address = target_or_pointer(record_address)
                if (
                    ".data.rel.ro"
                    not in _segment_name(base_typeinfo_address)
                ):
                    valid_bases = False
                    break
                raw_offset_flags = (
                    int(_safe(
                        lambda ea=offset_flags_address:
                            ida_bytes.get_qword(ea),
                        0,
                    ) or 0)
                    if pointer_size == 8
                    else int(_safe(
                        lambda ea=offset_flags_address:
                            ida_bytes.get_dword(ea),
                        0,
                    ) or 0)
                )
                width = pointer_size * 8
                signed_offset_flags = (
                    raw_offset_flags - (1 << width)
                    if raw_offset_flags & (1 << (width - 1))
                    else raw_offset_flags
                )
                base_flags = raw_offset_flags & 0xFF
                base_offset = signed_offset_flags >> 8
                is_virtual = bool(base_flags & 0x1)
                bases.append({
                    "base_pointer_address": _hex(record_address),
                    "base_typeinfo_address": _hex(base_typeinfo_address),
                    "offset_flags_address": _hex(offset_flags_address),
                    "offset": base_offset,
                    "offset_kind": (
                        "vbase_offset_slot"
                        if is_virtual else "object_offset"
                    ),
                    "object_offset": (
                        None if is_virtual else base_offset
                    ),
                    "vbase_offset_slot_offset": (
                        base_offset if is_virtual else None
                    ),
                    "flags": base_flags,
                    "is_virtual": is_virtual,
                    "is_public": bool(base_flags & 0x2),
                })
            if not valid_bases or len(bases) != base_count:
                continue
        out.append({
            "typeinfo_address": _hex(typeinfo),
            "name_pointer_address": _hex(name_pointer),
            "vptr_target_address": _hex(vptr_target) if vptr_target else "",
            "typeinfo_kind": kind,
            "base_pointer_address": (
                _hex(base_pointer) if kind == "si_class_type_info" else ""
            ),
            "base_typeinfo_address": (
                _hex(base_typeinfo) if base_typeinfo else ""
            ),
            "vmi_flags": vmi_flags,
            "base_count": len(bases),
            "bases": bases,
            "memory_block": _segment_name(typeinfo),
            "evidence": (
                "itanium_type_name_vptr_kind_and_base_array"
                if kind == "vmi_class_type_info"
                else "itanium_type_name_vptr_kind_and_base_pointer"
            ),
            "confidence": (
                1.0
                if kind in {
                    "si_class_type_info",
                    "class_type_info",
                    "vmi_class_type_info",
                }
                else 0.5
            ),
        })
    return out


def collect_imports() -> list:
    import ida_nalt
    import idautils
    out = []
    seen: set[str] = set()
    qty = _safe(lambda: ida_nalt.get_import_module_qty(), 0) or 0
    for i in range(qty):
        lib = _safe(lambda: ida_nalt.get_import_module_name(i)) or ""
        names: list[str] = []

        def _cb(ea, name, ordinal, _names=names):
            if name:
                _names.append(name)
            return True

        _safe(lambda: ida_nalt.enum_import_names(i, _cb))
        for nm in names:
            seen.add(nm)
            out.append({"name": nm, "library": lib})
    # Custom loaders/processors (notably Solana SBF/eBPF) often materialize
    # unresolved dynsym entries as named functions in an ``extern`` segment
    # without populating IDA's import-module table. Preserve those syscall/API
    # names because downstream RE agents use imports as semantic anchors.
    for ea, name in _safe(lambda: list(idautils.Names()), []):
        if not name or name in seen:
            continue
        if _segment_name(ea).lower() != "extern":
            continue
        seen.add(name)
        out.append({"name": name, "library": "extern", "address": _hex(ea)})
    return out


def collect_exports() -> list:
    import idautils
    out = []
    for entry in _safe(lambda: list(idautils.Entries()), []):
        try:
            _, _, ea, name = entry  # (index, ordinal, ea, name)
        except Exception:
            continue
        out.append({"address": _hex(ea), "name": name or ""})
    return out


def collect_symbols() -> list:
    import idautils
    import ida_funcs
    out = []
    for ea, name in _safe(lambda: list(idautils.Names()), []):
        typ = "function" if _safe(lambda: ida_funcs.get_func(ea)) is not None else "data"
        out.append({"address": _hex(ea), "type": typ, "name": name or ""})
        if len(out) >= _MAX_SYMBOLS:
            break
    return out


# --------------------------------------------------------------------------- main

def _find_function_ea(name_or_addr: str):
    import ida_name
    import idautils
    import ida_funcs
    BADADDR = 0xFFFFFFFFFFFFFFFF
    s = name_or_addr.strip()
    if s.lower().startswith("0x"):
        try:
            ea = int(s, 16)
            f = _safe(lambda: ida_funcs.get_func(ea))
            return f.start_ea if f is not None else ea
        except ValueError:
            pass
    ea = _safe(lambda: ida_name.get_name_ea(BADADDR, s))
    if ea is not None and ea != BADADDR:
        return ea
    for fea in _safe(lambda: list(idautils.Functions()), []):
        if _func_name(fea) == s:
            return fea
    return None


def run(binary: str, out_path: str, mode: str, max_functions: int, func: str | None) -> dict:
    import idapro
    _progress("open-database")
    restricted = mode == "restricted"
    rc = idapro.open_database(binary, not restricted)
    if rc != 0:
        raise SystemExit("idapro.open_database failed (rc=%s) for %s" % (rc, binary))
    try:
        if restricted:
            _prepare_restricted_functions()
        if mode == "function":
            if not func:
                raise SystemExit("function mode requires a function name/address")
            ea = _find_function_ea(func)
            if ea is None:
                data = {"error": "function not found: %s" % func}
            else:
                f = _function_entry(ea, decompile=True)
                f["disassembly"] = _disassembly(ea)
                data = f
        else:
            decompile = mode in {"full", "restricted"}
            _progress("exception-regions")
            exception_regions = [] if restricted else collect_exception_regions()
            funcs = collect_functions(
                decompile=decompile,
                max_functions=max_functions,
                exception_regions=exception_regions,
            )
            external_count = sum(1 for fn in funcs if fn.get("is_external"))
            imports, exports, symbols = collect_imports(), collect_exports(), collect_symbols()
            restricted_coverage = None
            if restricted:
                funcs, imports, exports, symbols, restricted_coverage = _finalize_restricted(
                    funcs, imports, exports, symbols,
                )
            _progress("metadata")
            data = {
                "metadata": collect_metadata(len(funcs), external_count),
                "functions": funcs,
                "exception_regions": exception_regions,
                "strings": [] if restricted else collect_strings(),
                "imports": imports,
                "exports": exports,
                "symbols": symbols,
                "analysis_scope": "selective_ranges" if restricted else "whole_target",
                "range_authority_sha256": _RANGE_AUTHORITY_SHA256 if restricted else None,
                "native_launch_authority_token": _NATIVE_LAUNCH_AUTHORITY_TOKEN if restricted else None,
                "restricted_allowed_coverage": restricted_coverage,
                "allowed_executable_ranges": [
                    {"address": start, "size": end - start} for start, end in _ALLOWED_RANGES
                ] if restricted else [],
            }
    finally:
        _safe(lambda: idapro.close_database(False))  # False = do not save the .i64

    with open(out_path, "w") as fh:
        json.dump(data, fh)
        fh.flush()
        os.fsync(fh.fileno())
    _progress("complete", 1, 1)
    return data


def main(argv: list) -> int:
    if len(argv) < 3:
        sys.stderr.write("usage: ida_dump.py <binary> <out.json> <mode> [mode args]\n")
        return 2
    binary, out_path, mode = argv[0], argv[1], argv[2]
    max_functions = 0
    func = None
    if mode == "full" and len(argv) >= 4:
        try:
            max_functions = int(argv[3])
        except ValueError:
            max_functions = 0
    if mode == "function":
        func = argv[3] if len(argv) >= 4 else None
    if mode == "restricted":
        if len(argv) < 6:
            raise SystemExit("restricted mode requires range spec, authority hash, and launch token")
        _configure_restricted(argv[3], argv[4], argv[5])
    run(binary, out_path, mode, max_functions, func)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
