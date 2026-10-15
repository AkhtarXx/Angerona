"""IDA-side adapter for an Angerona write-back JSON plan.

Run inside IDA with ``-Sida_writeback.py <plan.json> <receipt.json>``.
"""

from __future__ import annotations

import json


def run(plan_path: str, receipt_path: str) -> None:
    import ida_name
    import ida_nalt
    import idc

    try:
        import ida_bytes
    except ImportError:  # pragma: no cover - very old IDA
        ida_bytes = None

    def decode_hex(value: str) -> bytes:
        if not value or len(value) % 2 != 0:
            raise RuntimeError(f"invalid patch hex: {value!r}")
        return bytes.fromhex(value)

    def apply_patch(address: int, payload: bytes) -> bool:
        if ida_bytes is None:
            return False
        patched = ida_bytes.patch_bytes(address, payload)
        if patched:
            return True
        # Older API fallbacks: byte/qword granular patching.
        ok = True
        offset = 0
        while offset < len(payload):
            remaining = len(payload) - offset
            ea = address + offset
            if remaining >= 8 and hasattr(ida_bytes, "patch_qword"):
                ok = bool(ida_bytes.patch_qword(
                    ea, int.from_bytes(payload[offset:offset + 8], "little"))) and ok
                offset += 8
            else:
                ok = bool(ida_bytes.patch_byte(ea, payload[offset])) and ok
                offset += 1
        return ok

    def read_patch(address: int, length: int) -> str:
        if ida_bytes is None:
            raise RuntimeError("ida_bytes unavailable for patch read")
        data = ida_bytes.get_bytes(address, length)
        if data is None or len(data) != length:
            raise RuntimeError(f"IDA failed to read {length} bytes at 0x{address:x}")
        return bytes(data).hex()


    def save_database() -> None:
        database_path = idc.get_idb_path()
        if not database_path:
            raise RuntimeError("IDA database path is unavailable")
        result = idc.save_database(database_path)
        if result is False:
            raise RuntimeError(f"IDA failed to save database: {database_path}")

    def apply_value(row: dict, value: str) -> bool:
        """Apply one mutation; returns False when the mutation was skipped."""
        address = int(str(row["address"]), 0)
        kind = row["kind"]
        if kind == "rename":
            ok = ida_name.set_name(address, value, ida_name.SN_FORCE)
        elif kind == "comment":
            ok = idc.set_cmt(address, value, bool(row.get("repeatable", False)))
        elif kind == "type":
            ok = idc.SetType(address, value or None)
        elif kind == "patch":
            payload = decode_hex(value)
            declared = row.get("old_value")
            if declared:
                current = read_patch(address, len(payload))
                if current.lower() != str(declared).lower():
                    raise RuntimeError(
                        f"patch precondition failed at 0x{address:x}: "
                        "database bytes do not match old_value"
                    )
            if ida_bytes is None:
                return False  # patch skipped: idalib byte API unavailable
            ok = apply_patch(address, payload)
        else:
            raise RuntimeError(f"unsupported mutation: {kind}")
        if not ok:
            raise RuntimeError(f"IDA rejected {kind} at 0x{address:x}")
        return True

    def read_value(row: dict) -> str:
        address = int(str(row["address"]), 0)
        kind = row["kind"]
        if kind == "rename":
            return ida_name.get_name(address) or ""
        if kind == "comment":
            return idc.get_cmt(address, bool(row.get("repeatable", False))) or ""
        if kind == "type":
            return idc.get_type(address) or ""
        if kind == "patch":
            return read_patch(address, len(decode_hex(row["new_value"])))
        raise RuntimeError(f"unsupported mutation: {kind}")

    with open(plan_path, "r", encoding="utf-8") as handle:
        plan = json.load(handle)
    actual = bytes(ida_nalt.retrieve_input_file_sha256()).hex()
    if actual.lower() != str(plan["target_sha256"]).lower():
        raise RuntimeError("write-back target hash mismatch")
    applied = []
    skipped = []
    rollback_errors = []
    try:
        for row in plan.get("mutations", []):
            old = read_value(row)
            if not apply_value(row, row["new_value"]):
                skipped.append({
                    **row, "old_value": old, "receipt_status": "patch skipped",
                })
                continue
            observed = read_value(row)
            if row["kind"] not in {"type", "patch"} and observed != row["new_value"]:
                raise RuntimeError(
                    f"IDA read-back mismatch for {row['kind']} at {row['address']}"
                )
            if row["kind"] == "patch" and observed.lower() != row["new_value"].lower():
                raise RuntimeError(
                    f"IDA patch read-back mismatch at {row['address']}"
                )
            applied.append({**row, "old_value": old})
        save_database()
        status, error = "applied", None
    except Exception as exc:
        error = str(exc)
        for row in reversed(applied):
            try:
                if row["kind"] == "patch":
                    # Restore the pre-image bytes directly: apply_value's
                    # old_value precondition compares against the now-patched
                    # bytes and would always fail for a genuine patch, leaving
                    # the mutation persisted in the saved database.
                    address = int(str(row["address"]), 0)
                    payload = decode_hex(row["old_value"])
                    if ida_bytes is None:
                        raise RuntimeError("ida_bytes unavailable for patch rollback")
                    if not apply_patch(address, payload):
                        raise RuntimeError(f"IDA rejected patch rollback at 0x{address:x}")
                else:
                    apply_value(row, row["old_value"])
            except Exception as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        try:
            save_database()
        except Exception as rollback_save_exc:
            rollback_errors.append(str(rollback_save_exc))
        status = "rolled_back" if not rollback_errors else "partial_failure"
    with open(receipt_path, "w", encoding="utf-8") as handle:
        json.dump({
            "plan_id": plan["plan_id"],
            "status": status,
            "applied": applied,
            "skipped": skipped,
            "error": error,
            "rollback_errors": rollback_errors,
        }, handle, indent=2)
    if error:
        raise RuntimeError(error)


def main() -> None:
    import idc
    if len(idc.ARGV) < 3:
        raise RuntimeError("usage: ida_writeback.py plan.json receipt.json")
    try:
        run(idc.ARGV[1], idc.ARGV[2])
    except Exception:
        idc.qexit(1)
    idc.qexit(0)


if __name__ == "__main__":
    main()
