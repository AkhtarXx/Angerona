import hashlib
from pathlib import Path

import pytest

from src.analysis.fuzzing import AflPlusPlusCampaign, FuzzTarget, SeedCorpus
from src.analysis.rule_scanners import CapaAdapter


def test_seed_corpus_deduplicates_and_hashes(tmp_path: Path) -> None:
    records = SeedCorpus().build([b"abc", b"abc", b"def"], tmp_path / "in")
    assert len(records) == 2
    assert records[0]["sha256"] == hashlib.sha256(b"abc").hexdigest()


def test_afl_plan_models_file_input_and_qemu_mode(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"binary")
    inputs = tmp_path / "in"
    SeedCorpus().build([b"seed"], inputs)
    monkeypatch.setattr("src.analysis.fuzzing.shutil.which", lambda name: f"/usr/bin/{name}")
    target = FuzzTarget(str(binary), ("--input", "@@"))
    plan = AflPlusPlusCampaign().plan(target, inputs, tmp_path / "out", mode="qemu")
    assert "-Q" in plan.argv
    assert plan.argv[-2:] == ("--input", "@@")
    assert plan.environment["AFL_NO_UI"] == "1"


def test_fuzz_target_refuses_ambiguous_placeholder(tmp_path: Path) -> None:
    binary = tmp_path / "target"
    binary.write_bytes(b"binary")
    with pytest.raises(ValueError, match="exactly one"):
        FuzzTarget(str(binary), ("@@", "@@"))


def test_afl_status_collects_crashes_and_queue(tmp_path: Path) -> None:
    root = tmp_path / "out" / "default"
    (root / "crashes").mkdir(parents=True)
    (root / "queue").mkdir()
    (root / "crashes" / "id:000001").write_bytes(b"boom")
    (root / "queue" / "id:000000").write_bytes(b"seed")
    (root / "fuzzer_stats").write_text("execs_done : 123\nunique_crashes : 1\n")
    status = AflPlusPlusCampaign.status(tmp_path / "out")
    assert status["stats"]["execs_done"] == "123"
    assert status["queue_count"] == 1
    assert len(status["crashes"]) == 1


def test_capa_json_is_normalized_with_rule_provenance() -> None:
    matches = CapaAdapter().ingest({"rules": {
        "allocate memory": {
            "meta": {"namespace": "host-interaction/process", "attack": ["T1055"]},
            "matches": [[{"address": "0x401000"}]],
        }
    }}, target_sha256="f" * 64)
    assert matches[0].rule == "allocate memory"
    assert matches[0].locations == ("0x401000",)
    assert matches[0].tags == ("T1055",)


def test_capa_plan_accepts_explicit_rules_and_signatures(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    rules = tmp_path / "rules"
    signatures = tmp_path / "sigs"
    rules.mkdir()
    signatures.mkdir()
    monkeypatch.setattr("src.analysis.rule_scanners.shutil.which", lambda name: "/usr/bin/capa")

    plan = CapaAdapter().plan(target, rules, signatures)

    assert plan[1:6:2] == ("--json", str(rules), str(signatures))
    assert "--rules" in plan and "--signatures" in plan
