import hashlib
import py_compile
import subprocess
from pathlib import Path

import pytest

from src.analysis.writeback import (
    PatchWritebackAdapter,
    WritebackMutation,
    WritebackPlan,
    WritebackTransaction,
    verify_patch,
    write_ghidra_plan,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class _Adapter:
    def __init__(self, fail_at=None):
        self.values = {("rename", 0x1000): "sub_1000", ("comment", 0x1000): ""}
        self.fail_at = fail_at

    def read(self, mutation):
        return self.values[(mutation.kind, mutation.address)]

    def apply(self, mutation):
        if mutation.kind == self.fail_at and mutation.new_value != "sub_1000":
            raise RuntimeError("engine rejected mutation")
        self.values[(mutation.kind, mutation.address)] = mutation.new_value


def _plan(target_hash="a" * 64):
    return WritebackPlan(target_hash, "ida", [
        WritebackMutation("rename", 0x1000, "parse_header", evidence_ids=("finding:1",)),
        WritebackMutation("comment", 0x1000, "validated parser"),
    ])


def test_writeback_receipt_builds_reverse_order_rollback() -> None:
    adapter = _Adapter()
    receipt = WritebackTransaction(adapter).apply(_plan())
    assert receipt.status == "applied"
    assert adapter.values[("rename", 0x1000)] == "parse_header"
    rollback = receipt.rollback_plan
    assert [row.kind for row in rollback.mutations] == ["comment", "rename"]
    assert rollback.mutations[-1].new_value == "sub_1000"


def test_partial_failure_rolls_back_prior_mutations() -> None:
    adapter = _Adapter(fail_at="comment")
    receipt = WritebackTransaction(adapter).apply(_plan())
    assert receipt.status == "rolled_back"
    assert adapter.values[("rename", 0x1000)] == "sub_1000"


def test_target_hash_binding_prevents_cross_database_write(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"binary")
    with pytest.raises(ValueError, match="hash"):
        WritebackTransaction.verify_target(_plan(), target)
    correct = _plan(hashlib.sha256(b"binary").hexdigest())
    WritebackTransaction.verify_target(correct, target)


def test_plan_rejects_duplicate_mutation_targets() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        WritebackPlan("b" * 64, "ghidra", [
            WritebackMutation("rename", 1, "one"),
            WritebackMutation("rename", 1, "two"),
        ])


def test_ghidra_bundle_is_dependency_free_and_target_bound(tmp_path: Path) -> None:
    plan = WritebackPlan("c" * 64, "ghidra", [WritebackMutation("rename", 0x401000, "main")])
    output = tmp_path / "plan.tsv"
    write_ghidra_plan(plan, output)
    text = output.read_text()
    assert f"target_sha256\t{'c' * 64}" in text
    assert f"plan_id\t{plan.plan_id}" in text
    assert "mutation\trename\t0x401000\t0\t" in text


# ---------------------------------------------------------------------------
# Byte-level patching
# ---------------------------------------------------------------------------

FAKE_BINARY = bytes(range(16))  # 16-byte fake binary: 00 01 02 ... 0f


def _fake_binary(tmp_path: Path) -> Path:
    target = tmp_path / "fake.bin"
    target.write_bytes(FAKE_BINARY)
    return target


def _patch_plan(target: Path, mutation: WritebackMutation) -> WritebackPlan:
    return WritebackPlan(
        hashlib.sha256(target.read_bytes()).hexdigest(), "ida", [mutation]
    )


def test_byte_patch_round_trip(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    mutation = WritebackMutation.patch("90c3", 4, original_hex="0405")
    assert mutation.new_value == "90c3"
    assert mutation.old_value == "0405"
    with PatchWritebackAdapter(target) as adapter:
        assert adapter.read(mutation) == "0405"
        adapter.apply(mutation)
        assert adapter.read(mutation) == "90c3"
        # rollback restores the original bytes
        adapter.apply(mutation.inverse())
        assert adapter.read(mutation) == "0405"
    assert target.read_bytes() == FAKE_BINARY  # fully restored


def test_byte_patch_hex_validation() -> None:
    with pytest.raises(ValueError, match="hex"):
        WritebackMutation.patch("9", 0)  # odd length
    with pytest.raises(ValueError, match="hex"):
        WritebackMutation.patch("zz", 0)  # non-hex
    with pytest.raises(ValueError, match="hex"):
        WritebackMutation.patch("", 0)  # empty
    with pytest.raises(ValueError, match="limit"):
        WritebackMutation.patch("90" * 4097, 0)  # over the 4096-byte cap
    with pytest.raises(ValueError, match="equal lengths"):
        WritebackMutation.patch("90c3", 0, original_hex="90")  # length mismatch
    # case-insensitive normalisation
    assert WritebackMutation.patch("90C3", 0).new_value == "90c3"


def test_byte_patch_dry_run(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    mutation = WritebackMutation.patch("90c3", 4, original_hex="0405")
    with PatchWritebackAdapter(target, dry_run=True) as adapter:
        assert adapter.read(mutation) == "0405"
        adapter.apply(mutation)
    assert target.read_bytes() == FAKE_BINARY  # untouched


def test_byte_patch_mismatch_rejected_fails_closed(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    # Declare old bytes that do NOT match the file content (file has 04 05).
    mutation = WritebackMutation.patch("90c3", 4, original_hex="beef")
    plan = _patch_plan(target, mutation)
    with pytest.raises(ValueError, match="precondition"):
        verify_patch(plan, target)
    with PatchWritebackAdapter(target) as adapter:
        with pytest.raises(ValueError, match="precondition"):
            adapter.apply(mutation)
    assert target.read_bytes() == FAKE_BINARY  # no partial write
    # Transaction-level: a mid-plan mismatch rolls back the earlier patch.
    plan2 = WritebackPlan(
        hashlib.sha256(target.read_bytes()).hexdigest(),
        "ida",
        [
            WritebackMutation.patch("90c3", 0, original_hex="0001"),
            WritebackMutation.patch("90c3", 4, original_hex="beef"),
        ],
    )
    with PatchWritebackAdapter(target) as adapter:
        receipt = WritebackTransaction(adapter).apply(plan2)
    assert receipt.status == "rolled_back"
    assert "precondition" in receipt.error
    assert target.read_bytes() == FAKE_BINARY  # first patch was rolled back


def test_byte_patch_transaction_applies_and_receipt_rolls_back(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    mutation = WritebackMutation.patch("90c3", 4, original_hex="0405")
    plan = _patch_plan(target, mutation)
    verify_patch(plan, target)  # precondition passes on the real bytes
    with PatchWritebackAdapter(target) as adapter:
        receipt = WritebackTransaction(adapter).apply(plan)
    assert receipt.status == "applied"
    assert target.read_bytes()[4:6] == b"\x90\xc3"
    # receipt carries the read old_value, so rollback restores the file
    rollback = receipt.rollback_plan
    assert rollback.mutations[0].new_value == "0405"
    with PatchWritebackAdapter(target) as adapter:
        undo = WritebackTransaction(adapter).apply(rollback)
    assert undo.status == "applied"
    assert target.read_bytes() == FAKE_BINARY


def test_byte_patch_without_old_value_cannot_rollback(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    mutation = WritebackMutation.patch("90c3", 4)  # non-reversible
    plan = _patch_plan(target, mutation)
    verify_patch(plan, target)  # range-check only; must not raise
    with PatchWritebackAdapter(target) as adapter:
        ok = WritebackTransaction(adapter).apply(plan)
    assert ok.status == "applied"
    assert target.read_bytes()[4:6] == b"\x90\xc3"
    # A bare patch mutation without old_value has no inverse — its rollback
    # path is statically impossible (see the receipt-level test below).
    with pytest.raises(ValueError, match="previous value"):
        mutation.inverse()


def test_byte_patch_receipt_without_old_values_has_no_rollback_plan() -> None:
    from src.analysis.writeback import WritebackReceipt

    receipt = WritebackReceipt(
        "p" * 64,
        "a" * 64,
        "ida",
        "applied",
        (WritebackMutation("patch", 4, "90c3", None),),
    )
    with pytest.raises(ValueError, match="old values"):
        receipt.rollback_plan


def test_byte_patch_out_of_range_rejected(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    mutation = WritebackMutation.patch("90c3", 15)  # 2 bytes at offset 15 > 16
    plan = _patch_plan(target, mutation)
    with pytest.raises(ValueError, match="exceeds target size"):
        verify_patch(plan, target)
    with PatchWritebackAdapter(target) as adapter:
        with pytest.raises(ValueError, match="outside file size"):
            adapter.read(mutation)


def test_byte_patch_refuses_symlink(tmp_path: Path) -> None:
    target = _fake_binary(tmp_path)
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    mutation = WritebackMutation.patch("90c3", 4)
    with pytest.raises(ValueError, match="symlink"):
        PatchWritebackAdapter(link)
    with pytest.raises(ValueError, match="symlink"):
        verify_patch(_patch_plan(target, mutation), link)


def test_patch_engine_scripts_still_parse() -> None:
    ida_script = REPO_ROOT / "src" / "scripts" / "ida_writeback.py"
    py_compile.compile(str(ida_script), doraise=True)
    ghidra_script = REPO_ROOT / "src" / "scripts" / "GhidraWriteback.java"
    text = ghidra_script.read_text()
    assert '"patch"' in text
    assert "setBytes" in text
    result = subprocess.run(
        ["python3", "-m", "py_compile", str(ida_script)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
