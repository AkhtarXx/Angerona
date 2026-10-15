from __future__ import annotations

import json
from pathlib import Path

from src.analysis.baseline_registry import (
    BaselineRegistry,
    list_packages,
    list_versions,
    load_baseline_from_registry,
    save_baseline_to_registry,
)


def test_save_and_load(tmp_path):
    reg = BaselineRegistry(tmp_path / "reg")
    idx = {"dex": {"classes.dex": "abc"}, "manifest": {"AndroidManifest.xml": "xyz"}}
    entry = save_baseline_to_registry(reg, "com.bank", "1.0", idx, note="first release")
    assert entry.package == "com.bank"
    assert entry.path.exists()
    bl = load_baseline_from_registry(reg, "com.bank", "1.0")
    assert bl["name"] == "com.bank"
    assert bl["version"] == "1.0"


def test_latest_pointer(tmp_path):
    reg = BaselineRegistry(tmp_path / "reg")
    idx = {"dex": {}}
    save_baseline_to_registry(reg, "com.x", "1.0", idx)
    save_baseline_to_registry(reg, "com.x", "2.0", idx)
    bl = load_baseline_from_registry(reg, "com.x")
    assert bl["version"] == "2.0"


def test_missing_returns_none(tmp_path):
    reg = BaselineRegistry(tmp_path / "reg")
    assert load_baseline_from_registry(reg, "nope") is None


def test_list_packages_and_versions(tmp_path):
    reg = BaselineRegistry(tmp_path / "reg")
    idx = {"dex": {}}
    save_baseline_to_registry(reg, "com.a", "1.0", idx)
    save_baseline_to_registry(reg, "com.a", "1.1", idx)
    save_baseline_to_registry(reg, "com.b", "2.0", idx)
    assert list_packages(reg) == ["com.a", "com.b"]
    assert list_versions(reg, "com.a") == ["1.0", "1.1"]


def test_invalid_package_rejected(tmp_path):
    reg = BaselineRegistry(tmp_path / "reg")
    import pytest
    with pytest.raises(ValueError):
        save_baseline_to_registry(reg, "", "1.0", {"dex": {}})


def test_corrupt_latest_graceful(tmp_path):
    reg = BaselineRegistry(tmp_path / "reg")
    pkg_dir = reg._pkg_dir("com.corrupt")
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "latest.json").write_text("{bad json")
    assert load_baseline_from_registry(reg, "com.corrupt") is None
