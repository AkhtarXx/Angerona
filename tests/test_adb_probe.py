from __future__ import annotations

from unittest.mock import patch

from src.execution.adb_probe import (
    RuntimeSurfaceResult,
    _parse_disabled,
    _parse_dumpsys,
    _parse_permissions,
    _parse_version,
    list_devices,
    query_runtime_surface,
)


def test_no_adb_binary_graceful(monkeypatch):
    monkeypatch.setattr("src.execution.adb_probe.find_adb", lambda cfg=None: None)
    r = query_runtime_surface("com.x")
    assert r.status == "adb_missing"
    assert r.trust == "untrusted_child"


def test_no_device_graceful(monkeypatch):
    monkeypatch.setattr("src.execution.adb_probe.find_adb", lambda cfg=None: "/usr/bin/adb")
    monkeypatch.setattr("src.execution.adb_probe.list_devices", lambda adb: [])
    r = query_runtime_surface("com.x")
    assert r.status == "no_device"


def test_parse_dumpsys_activities():
    text = """
Activity Resolver Table:
    Non-Data Actions:
        android.intent.action.MAIN:
            com.example.app/.MainActivity
            com.example.app/.AltActivity

Service Resolver Table:
        com.example.app/.BgService

    disabled_components:
        com.example.app/.SecretActivity
    """
    sections = _parse_dumpsys(text)
    assert "com.example.app/.MainActivity" in sections["activity"]
    assert "com.example.app/.BgService" in sections["service"]
    disabled = _parse_disabled(text)
    assert "com.example.app/.SecretActivity" in disabled


def test_parse_permissions_runtime():
    text = """
requested permissions:
    android.permission.INTERNET: granted=true
    android.permission.READ_SMS: granted=false
    android.permission.CAMERA: granted=true

install permissions:
    android.permission.INTERNET: granted=true
"""
    granted, denied = _parse_permissions(text)
    assert "android.permission.INTERNET" in granted
    assert "android.permission.READ_SMS" in denied


def test_parse_version():
    text = "versionName=8.20.5 targetSdk=35"
    assert _parse_version(text) == "8.20.5"


def test_full_query_mock(monkeypatch):
    monkeypatch.setattr("src.execution.adb_probe.find_adb", lambda cfg=None: "/usr/bin/adb")
    monkeypatch.setattr("src.execution.adb_probe.list_devices", lambda adb: ["emulator-5554"])
    fake_out = """
Activity Resolver Table:
    Non-Data Actions:
        android.intent.action.MAIN:
            com.bank.app/.MainActivity

Service Resolver Table:
    com.bank.app/.SyncService

Provider Resolver Table:
    com.bank.app/.FileProvider

versionName=4.2.1
requested permissions:
    android.permission.INTERNET: granted=true
    android.permission.CAMERA: granted=false
"""
    monkeypatch.setattr(
        "src.execution.adb_probe._adb",
        lambda adb, *args, timeout=30, serial="": (0, fake_out),
    )
    r = query_runtime_surface("com.bank.app")
    assert r.status == "ok"
    assert r.exported_activities == ["com.bank.app/.MainActivity"]
    assert r.exported_services == ["com.bank.app/.SyncService"]
    assert r.installed_version == "4.2.1"
    assert "android.permission.INTERNET" in r.runtime_permissions_granted
    assert "android.permission.CAMERA" in r.runtime_permissions_denied
