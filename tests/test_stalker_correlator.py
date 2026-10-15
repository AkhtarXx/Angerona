from __future__ import annotations

from src.execution.stalker_correlator import (
    ModuleCoverage,
    correlate,
    parse_modules_text,
    parse_stalker_trace,
)


def test_parse_trace_json_lines():
    text = '\n'.join([
        '{"address": 4198401, "tid": 123}',
        '{"address": 4198402, "tid": 123}',
        'junk line',
        '{"address": "0x400005", "tid": 999}',
        '',
        '{"address": null}',
    ])
    addrs = parse_stalker_trace(text)
    assert 4198401 in addrs
    assert 4198402 in addrs
    assert 0x400005 in addrs


def test_parse_trace_hex_lines():
    text = "0x1000\n0x2000\nbad\n0x\n\n"
    addrs = parse_stalker_trace(text)
    assert addrs == [0x1000, 0x2000]


def test_parse_modules_text():
    text = "libdummy.so 0x70000000 0x1000\nlibleaky.so 0x80000000 0x2000\ninvalid_line\n"
    mods = parse_modules_text(text)
    assert len(mods) == 2
    assert mods[0].module_name == "libdummy.so"
    assert mods[0].base == 0x70000000


def test_correlate_finds_runtime_match():
    static = [{"offset": 0x40, "category": "ptrace"}, {"offset": 0x80, "category": "frida_scan"}]
    trace = {0x70000040, 0x70000080}
    mods = [ModuleCoverage(module_name="libdummy.so", base=0x70000000, size=0x1000)]
    r = correlate(static, trace, mods)
    assert r.status == "ok"
    assert r.corroborated_count == 2
    assert r.uncorroborated_count == 0
    assert all(c.corroborated for c in r.correlated_findings)


def test_correlate_marks_uncorroborated():
    static = [{"offset": 0x40, "category": "ptrace"}, {"offset": 0x99, "category": "frida_scan"}]
    trace = {0x70000040}
    mods = [ModuleCoverage(module_name="libdummy.so", base=0x70000000, size=0x1000)]
    r = correlate(static, trace, mods)
    assert r.corroborated_count == 1
    assert r.uncorroborated_count == 1


def test_correlate_no_modules():
    r = correlate([{"offset": 0x40, "category": "x"}], {0x40}, [])
    assert r.status == "no_modules"


def test_mod_coverage_tracking():
    static = [{"offset": 0x10, "category": "ptrace"}]
    trace = {0x70000010, 0x70000020, 0x70000030}
    mods = [ModuleCoverage(module_name="libt.so", base=0x70000000, size=0x1000)]
    r = correlate(static, trace, mods)
    assert r.modules_seen[0].blocks_executed == 3
