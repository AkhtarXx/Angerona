"""Real pinned-APK corroboration test (ELITE-2 roadmap F5)."""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from src.pipeline.android_audit import run_android_audit


def _mk_pinned_apk(path: Path) -> Path:
    """Build a synthetic APK with proper OkHttp pinning + native .so with ptrace markers."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.pinnedapp">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <application android:label="PinnedApp"
        android:allowBackup="false"
        android:usesCleartextTraffic="false">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>"""
    classes = b"dex\n035\x00" + b"\x00" * 64
    # native .so bytes with ptrace/tracerpid markers for static + fn-site detection
    so_bytes = b"\x7fELF" + b"\x00" * 32 + b"ptrace\x00/proc/self/maps\x00" + b"\x00" * 256
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", classes)
        zf.writestr("lib/arm64-v8a/libtest.so", so_bytes)
        zf.writestr("assets/okhttp_marker.txt", b"Lokhttp3/CertificatePinner;")
    return path


def test_pinned_apk_static_only_does_not_self_corroborate(tmp_path: Path):
    """A pinned APK whose only anti-tamper evidence is *static* byte-pattern
    categories (ptrace + frida_scan) must NOT earn ``runtime_corroborated=True``.

    This is the ELITE-2 verdict fix: two static categories share ONE trust
    boundary (a single ``scan_so_bytes`` pass), so one obfuscation defeats
    both.  Static-only multi-category self-corroboration was theatre; the
    double-attest invariant now requires a runtime/dynamic witness (stalker,
    frida hook, or reachable device) alongside the static evidence.
    """
    apk = _mk_pinned_apk(tmp_path / "pinned.apk")
    r = run_android_audit(apk, try_runtime_extract=False)
    assert r.status == "error"
    assert r.metadata["native_static_evidence"]["launch_blocked"] is True
    # The audit finds ptrace + frida_scan static categories, but no runtime
    # extraction was attempted -> no runtime witness -> NOT corroborated.
    tamper = [f for f in r.findings if f.module == "native_anti_tamper_scanner"]
    assert tamper, "expected static anti-tamper findings"
    hits = [f for f in r.findings if f.runtime_corroborated]
    assert not hits, (
        f"static-only self-corroboration is theatre: got corroborated=True on "
        f"{[f.kind for f in hits]} with no runtime witness"
    )


def test_pinned_apk_corroborates_when_runtime_witness_present(tmp_path: Path):
    """When a runtime witness with REAL evidentiary content (a frida probe
    that observed the finding's anti-tamper category surviving on-device) is
    present alongside static anti-tamper evidence, the double-attest bar IS
    met -> corroborated=True.

    This proves the round-5 evidentiary-content invariant did not break real
    corroboration: a frida witness whose ``frida_witness_categories`` include
    the finding's kind genuinely corroborates the static finding.
    """
    from src.analysis.runtime_attestation import attest
    # static ptrace site + a frida probe that observed ptrace SURVIVE ->
    # corroborated (runtime probe carries evidentiary content about the finding)
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[{"offset": 0x100, "category": "ptrace"}],
        stalker_hits=[], frida_hook_planned=True,
        frida_witness_categories=["ptrace"], device_available=False,
    )
    assert a.is_corroborated is True, (
        f"frida probe that observed the finding's category surviving MUST "
        f"corroborate the static finding — got note={a.note!r}"
    )
    assert a.witnesses and any(w.kind == "instrument-planned" for w in a.witnesses)
    # the runtime witness must carry the category it corroborated
    frida_w = [w for w in a.witnesses if w.kind == "instrument-planned"][0]
    assert "ptrace" in frida_w.evidence, (
        f"frida witness evidence must name the corroborated category; got "
        f"{frida_w.evidence!r}"
    )


def test_packed_apk_pipeline_propagates_hook_plan_categories_to_corroborated(
    tmp_path: Path, monkeypatch,
):
    """ELITE-2 verdict round-7 F5 tautology fix (end-to-end positive case).

    The prior positive test called ``attest()`` directly with hand-fed kwargs
    — no real APK triggered runtime_dex_extractor, no frida probe populated
    hook_plan_categories, so the ``getattr/hook_plan_categories`` wiring at
    android_audit.py:279/650 that no test touched was never exercised.  This
    test runs the FULL pipeline: a packed synthetic APK whose static
    anti-tamper scan finds ptrace + frida_scan, with a MOCK runtime_dex_extractor
    returning a DexDumpResult whose ``anti_tamper_probes`` record the ptrace
    probe SURVIVING on-device.  The pipeline must (a) propagate
    hook_plan_categories into report.metadata, (b) feed them into attest() as
    frida_witness_categories, and (c) upgrade the matching static finding to
    runtime_corroborated=True — exercising the end-to-end wiring the tautology
    skipped.
    """
    from src.execution import runtime_dex_extractor as rde

    # Build a PACKED synthetic APK: a packer lib soname triggers
    # detect_android_packer -> _is_packed -> runtime extract path.
    apk = _mk_pinned_apk(tmp_path / "packed.apk")
    # add a packer lib that detect_android_packer fingerprints as "identified"
    import zipfile
    with zipfile.ZipFile(apk, "a") as zf:
        zf.writestr("lib/arm64-v8a/libbangcle.so", b"\x7fELF" + b"\x00" * 64 + b"bangcle\x00")

    # Mock extract_dex_runtime to return a DexDumpResult whose on-device probe
    # observed the ptrace anti-tamper category SURVIVING.  This is the evidentiary
    # content that must flow through hook_plan_categories -> attest() ->
    # runtime_corroborated.
    def _mock_extract(package, **kwargs):
        return rde.DexDumpResult(
            status="ok",
            package=package,
            dumped_files=["/data/local/tmp/angerona-dex-dump/classes.dex"],
            bytes_dumped=4096,
            device_serial="emulator-5554",
            anti_tamper_probes=[
                {"category": "ptrace", "survived": True,
                 "detail": "libc ptrace hook observed on-device"},
            ],
        )

    monkeypatch.setattr(rde, "extract_dex_runtime", _mock_extract)

    r = run_android_audit(
        apk,
        try_runtime_extract=True,
        expected_package="com.example.pinnedapp",
        authorization_ref="unit-test-authorized",
    )
    # (a) the pipeline propagated hook_plan_categories from the DexDumpResult
    cats = r.metadata.get("hook_plan_categories", [])
    assert "ptrace" in cats, (
        f"hook_plan_categories did not propagate from DexDumpResult to report "
        f"metadata — the end-to-end wiring at android_audit.py:279 is broken; "
        f"got {cats!r}"
    )
    # (b)(c) the matching static ptrace finding upgraded to runtime_corroborated
    tamper = [f for f in r.findings if f.module == "native_anti_tamper_scanner"
              and f.kind == "ptrace"]
    assert tamper, "expected a static ptrace anti-tamper finding from the packed APK"
    corroborated = [f for f in tamper if f.runtime_corroborated]
    assert corroborated, (
        f"the ptrace finding was NOT upgraded to runtime_corroborated despite a "
        f"frida probe observing ptrace survive end-to-end — the pipeline does not "
        f"propagate hook_plan_categories through attest() (F5 positive tautology "
        f"is still open); report runtime_extract_status={r.runtime_extract_status!r}, "
        f"hook_plan_emitted={r.metadata.get('hook_plan_emitted')}, "
        f"double_attest={[f.metadata.get('double_attest') for f in tamper]}"
    )


def test_frida_witness_without_matching_category_does_not_corroborate(tmp_path: Path):
    """ELITE-2 verdict round-5: a frida hook that RAN but whose on-device probe
    did NOT observe the static finding's category surviving is a runtime-
    AVAILABILITY signal, NOT survival corroboration.  ``corroborated=True`` must
    require evidentiary content, not just a bare hook-plan bool.

    This is the core provenance-theatre fix: the old invariant upgraded a
    static ptrace finding to runtime_corroborated=True whenever ANY frida DEX
    dump happened, even though runtime_dex_extractor has zero anti-tamper
    detection.  Now the runtime witness must carry the category it corroborates.
    """
    from src.analysis.runtime_attestation import attest
    # static ptrace site + a frida hook whose probe observed frida_scan survive
    # (NOT ptrace) -> does NOT corroborate the ptrace finding.
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[{"offset": 0x100, "category": "ptrace"}],
        stalker_hits=[], frida_hook_planned=True,
        frida_witness_categories=["frida_scan"], device_available=False,
    )
    assert a.is_corroborated is False, (
        f"a frida witness whose probe observed a DIFFERENT category must not "
        f"corroborate the static finding — provenance-theatre; got note={a.note!r}"
    )


def test_frida_hook_without_probe_content_does_not_corroborate(tmp_path: Path):
    """ELITE-2 verdict round-5: a bare ``frida_hook_planned=True`` with NO
    ``frida_witness_categories`` (device absent / agent older / probe did not
    survive) is a runtime-availability signal only — it must NOT by itself meet
    the runtime-origin bar for the anti-tamper finding.  This is the case that
    the old tautological test passed (attest(True)==True) and which the verdict
    flagged as theatre.
    """
    from src.analysis.runtime_attestation import attest
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[{"offset": 0x100, "category": "ptrace"}],
        stalker_hits=[], frida_hook_planned=True, device_available=False,
    )
    assert a.is_corroborated is False, (
        f"a bare frida hook plan with no probe content must not corroborate a "
        f"static anti-tamper finding — it only proves a DEX dump ran; "
        f"got note={a.note!r}"
    )


def test_bare_device_available_does_not_manufacture_corroboration() -> None:
    """ELITE-2 verdict round-7: a bare ``device_available=True`` whose adb probe
    finds NO serials must NOT be treated as corroborating runtime evidence.
    The prior attest() let ``or device_available`` satisfy
    has_corroborating_runtime and the ``runtime_count >= 2`` disjunct let two
    weak availability witnesses (0.3 frida + 0.4 empty-serials) self-corroborate
    to is_corroborated=True with zero real evidence.  The success note even
    claimed a probe observed the category surviving when it did not.
    """
    from src.analysis.runtime_attestation import attest
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[{"offset": 0x100, "category": "ptrace"}],
        stalker_hits=[], frida_hook_planned=True, device_available=True,
    )
    assert a.is_corroborated is False, (
        f"a bare device_available=True (no serials, no frida probe content) must "
        f"not manufacture corroboration; got note={a.note!r}"
    )


def test_two_weak_availability_witnesses_do_not_self_corroborate() -> None:
    """ELITE-2 verdict round-7: two WEAK runtime availability witnesses (a frida
    hook that did NOT observe the finding's category + an empty adb serial
    list) must NOT self-corroborate via runtime_count >= 2.  At least one
    runtime witness must carry real evidentiary content.
    """
    from src.analysis.runtime_attestation import attest
    # frida_hook_planned=True with non-matching categories -> weak 0.3 witness;
    # device_available=True with no device -> weak 0.4 witness.  Two weak
    # availability witnesses, neither with real content, must NOT corroborate.
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[{"offset": 0x100, "category": "ptrace"}],
        stalker_hits=[], frida_hook_planned=True,
        frida_witness_categories=["crc_check"],  # does NOT match finding_kind=ptrace
        device_available=True,  # adb finds nothing (test monkeypatches _ad -> [])
    )
    assert a.is_corroborated is False, (
        f"two weak availability witnesses (mismatched frida probe + empty adb) "
        f"must not self-corroborate; got note={a.note!r}"
    )


def test_double_attest_static_two_categories_does_not_corroborate() -> None:
    """The negative test the old suite deliberately omitted (ELITE-2 verdict fix).

    Two static byte-pattern categories (ptrace + frida_scan) from a single
    scan_so_bytes pass MUST NOT corroborate — they share one trust boundary,
    so one obfuscation defeats both.  This is the theatre the old invariant
    permitted (is_corroborated=True with zero runtime evidence).
    """
    from src.analysis.runtime_attestation import attest
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[
            {"offset": 0x100, "category": "ptrace"},
            {"offset": 0x200, "category": "frida_scan"},
        ],
        stalker_hits=[], frida_hook_planned=False, device_available=False,
    )
    assert a.is_corroborated is False, (
        "static-only multi-category self-corroboration is theatre: two static "
        "categories must not corroborate without a runtime/dynamic witness"
    )
    assert a.corroborating_witness_count >= 2  # witnesses ARE counted for scoring


def test_double_attest_single_static_category_does_not_corroborate() -> None:
    from src.analysis.runtime_attestation import attest
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=[{"offset": 0x100, "category": "ptrace"}],
        stalker_hits=[], frida_hook_planned=False, device_available=False,
    )
    assert a.is_corroborated is False


def test_double_attest_runtime_only_corroborates_with_two_runtime_streams() -> None:
    """Two runtime witnesses (stalker + frida) corroborate even without static."""
    from src.analysis.runtime_attestation import attest
    a = attest(
        finding_module="native_anti_tamper_scanner", finding_kind="ptrace",
        static_native_sites=None,
        stalker_hits=[0x40, 0x48], frida_hook_planned=True, device_available=False,
    )
    assert a.is_corroborated is True
