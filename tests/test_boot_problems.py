"""Boot problems checklist tests."""
from __future__ import annotations

import os
from pathlib import Path

from src.boot_problems import BootProblem, BootReport, check_boot, fail_fast


def test_binary_missing_is_error(tmp_path: Path) -> None:
    report = check_boot(binary=tmp_path / "nope", require_agent=False)
    assert not report.ok
    code = next(p.code for p in report.problems if p.severity == "error")
    assert code == "binary.missing"


def test_binary_empty_is_error(tmp_path: Path) -> None:
    b = tmp_path / "empty"
    b.write_bytes(b"")
    report = check_boot(binary=b, require_agent=False)
    assert not report.ok
    assert any(p.code == "binary.empty" for p in report.problems)


def test_binary_symlink_is_error(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"MZ header")
    link = tmp_path / "link"
    link.symlink_to(real)
    report = check_boot(binary=link, require_agent=False)
    assert any(p.code == "binary.symlink" for p in report.problems)


def test_binary_ok(tmp_path: Path) -> None:
    real = tmp_path / "ok"
    real.write_bytes(b"MZ header")
    report = check_boot(binary=real, require_agent=False)
    # engine check may produce its own error; only binary problems must be absent
    assert not any(p.code.startswith("binary.") for p in report.problems)


def test_engine_invalid() -> None:
    report = check_boot(engine="bogus", require_agent=False)
    assert not report.ok
    assert any(p.code == "engine.invalid" for p in report.problems)


def test_agent_invalid() -> None:
    report = check_boot(agent="gpt4", require_agent=True)
    assert not report.ok
    assert any(p.code == "agent.invalid" for p in report.problems)


def test_sandbox_requires_bwrap() -> None:
    import shutil
    if shutil.which("bwrap"):
        return  # cannot test absence when present
    report = check_boot(sandbox=True, require_agent=False)
    assert not report.ok
    assert any(p.code == "sandbox.bwrap_missing" for p in report.problems)


def test_boot_report_formatting() -> None:
    report = BootReport(problems=(BootProblem("x.y", "error", "bad thing"),))
    assert not report.ok
    text = report.format()
    assert "error" in text and "x.y" in text


def test_fail_fast_returns_1_on_error() -> None:
    report = BootReport(problems=(BootProblem("x.y", "error", "bad"),))
    assert fail_fast(report) == 1
    report_ok = BootReport(problems=())
    assert fail_fast(report_ok) == 0
