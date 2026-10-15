"""Opt-in real KVM/AVD smoke; never replaced by mocks in release CI."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.execution.runtime_dex_extractor import extract_dex_runtime


@pytest.mark.android_e2e
def test_real_owned_avd_boot_frida_install_observe_and_destroy():
    if os.environ.get("ANGERONA_RUN_ANDROID_AVD_E2E") != "1":
        pytest.skip("set ANGERONA_RUN_ANDROID_AVD_E2E=1 on a KVM Android runner")
    apk = Path(os.environ["ANGERONA_ANDROID_E2E_APK"]).expanduser().resolve()
    package = os.environ["ANGERONA_ANDROID_E2E_PACKAGE"]
    sdk_root = os.environ.get("ANGERONA_ANDROID_SDK_ROOT", "")
    expected_status = os.environ["ANGERONA_ANDROID_E2E_EXPECT_STATUS"]
    assert expected_status in {"ok", "partial"}
    # The manager reads these directly and verifies schema, freshness, file
    # permissions, exact APK binding, and the out-of-band digest.
    assert os.environ["ANGERONA_ANDROID_CONTAINMENT_RECEIPT"]
    assert os.environ["ANGERONA_ANDROID_CONTAINMENT_RECEIPT_SHA256"]

    result = extract_dex_runtime(
        package,
        apk_path=apk,
        runtime_provider="avd",
        runtime_api=int(os.environ.get("ANGERONA_ANDROID_E2E_API", "35")),
        runtime_abi=os.environ.get("ANGERONA_ANDROID_E2E_ABI", "auto"),
        runtime_sdk_root=sdk_root,
        runtime_auto_provision=False,
        runtime_network="deny",
        wait_seconds=30,
        timeout=600,
    )

    assert result.status == expected_status, f"{result.note}; errors={result.errors!r}"
    lease = result.runtime_target.get("managed_lease", {})
    assert lease.get("cold_clean_boot") is True
    assert lease.get("frida_ready") is True
    assert result.runtime_target.get("verified_exact_apk") is True
    assert result.runtime_surface.get("status") == "ok"
    assert lease.get("network_policy", {}).get("host_containment_verified") is True
    assert lease.get("frida_transport", {}).get("authenticated") is True
    assert lease.get("frida_transport", {}).get("complete") is True
    workload = result.runtime_target.get("workload_ledger", {})
    assert workload.get("workload_id") == "baseline-launch-idle-v1"
    assert workload.get("complete") is True
    assert workload.get("claims_excluded")
    coverage = result.runtime_target.get("coverage", {})
    assert coverage.get("process_coverage_complete") is True
    assert coverage.get("hook_health_complete") is True
    assert coverage.get("frida_transport_complete") is True
    assert coverage.get("host_containment_complete") is True
    if expected_status == "ok":
        assert coverage.get("complete") is True
        assert result.validated_files
    else:
        # A normal unpacked fixture has no novel runtime DEX.  That is an exact
        # partial result, not a transport/workload failure and never "complete".
        assert coverage.get("complete") is False
        assert result.validated_files == []
    assert lease.get("cleanup", {}).get("success") is True
