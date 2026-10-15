from __future__ import annotations

from src.analysis.finding import LIKELY, Finding
from src.analysis.runtime_attestation import attest, maybe_upgrade_finding


def test_no_witnesses_not_corroborated():
    r = attest(finding_module="m", finding_kind="k")
    assert r.is_corroborated is False
    assert r.corroborating_witness_count == 0


def test_one_witness_not_enough():
    r = attest(finding_module="m", finding_kind="k",
               static_native_sites=[{"offset": 0x100}], stalker_hits=[])
    assert r.corroborating_witness_count == 1
    assert r.is_corroborated is False


def test_two_witnesses_corroborates():
    r = attest(finding_module="m", finding_kind="k",
               static_native_sites=[{"offset": 0x100}],
               stalker_hits=[0x70000000])
    assert r.corroborating_witness_count == 2
    assert r.is_corroborated is True


def test_three_witnesses_stronger():
    r = attest(finding_module="m", finding_kind="k",
               static_native_sites=[{"offset": 0x100}],
               stalker_hits=[0x70000000, 0x70000010],
               frida_hook_planned=True)
    assert r.corroborating_witness_count == 3
    assert r.is_corroborated is True


def test_maybe_upgrade_preserves_metadata():
    att = attest(finding_module="m", finding_kind="k",
                 static_native_sites=[{"offset": 0x100}],
                 stalker_hits=[0x70000000])
    f = Finding(module="m", kind="k", severity="high", verdict=LIKELY, detail="d",
                evidence="e", metadata={"k": "v"})
    upgraded = maybe_upgrade_finding(f, att)
    assert upgraded.runtime_corroborated is True
    assert upgraded.metadata.get("k") == "v"
    assert "double_attest" in upgraded.metadata


def test_maybe_upgrade_not_corroborated_returns_same():
    att = attest(finding_module="m", finding_kind="k")
    f = Finding(module="m", kind="k", severity="high", verdict=LIKELY, detail="d",
                runtime_corroborated=False)
    upgraded = maybe_upgrade_finding(f, att)
    assert upgraded.runtime_corroborated is False
