from __future__ import annotations

from src.analysis.jni_runtime_fusion import (
    _evidence_tokens,
    _matches,
    fuse_static_with_runtime,
    parse_runtime_events,
)


def test_evidence_tokens():
    ev = 'boolean check() { return validate("master_token_2026"); }'
    tokens = _evidence_tokens(ev)
    assert "boolean" in tokens
    assert "validate" in tokens
    # short tokens filtered
    t = _evidence_tokens('a b c dd')
    assert not any(len(x) < 4 for x in t)


def test_parse_events_jsonl():
    lines = [
        '{"kind":"loadlibrary","java_class":"System","java_method":"loadLibrary","args_summary":"native-lib"}',
        '{"kind":"call","java_class":"com.x.Auth","java_method":"validate","native_fn":"Java_com_x_Auth_validate","args":"tok"}',
        '{"kind":"string-escape","java_class":"com.x","java_method":"j","native_fn":"NewStringUTF","args_summary":"sk_live_secret"}',
        'garbage',
    ]
    events = parse_runtime_events(lines)
    assert len(events) == 3
    assert events[0].kind == "loadlibrary"
    assert events[1].native_fn == "Java_com_x_Auth_validate"
    assert events[2].kind == "string-escape"


def test_matches_load_library():
    ev = [e for e in parse_runtime_events([
        '{"kind":"loadlibrary","java_class":"System","java_method":"loadLibrary","args_summary":"dummy"}'
    ])][0]
    tokens = ["dummy", "loadLibrary"]
    assert _matches(ev, "load_library", tokens)
    # tokens that have nothing to do with the event should NOT match
    # (the event args say "dummy", not "otherLib")
    assert not _matches(ev, "load_library", ["otherLib", "koroneum"])


def test_full_fusion_corroborates():
    static = [
        {"kind": "load_library", "evidence": 'System.loadLibrary("dummy")', "line_no": 5},
        {"kind": "native_literal_arg", "evidence": 'validate("master_token_2026")', "line_no": 10},
    ]
    events = parse_runtime_events([
        '{"kind":"loadlibrary","java_class":"System","java_method":"loadLibrary","args_summary":"dummy"}',
        '{"kind":"call","java_class":"com.x","java_method":"validate","native_fn":"Java_com_x_validate","args_summary":"master_token_2026"}',
    ])
    r = fuse_static_with_runtime(static, events)
    assert r.status == "ok"
    assert r.corroborated == 2
    assert r.uncorroborated == 0
    assert all(f.severity_boosted for f in r.fused)


def test_full_fusion_marks_unverified():
    static = [
        {"kind": "native_literal_arg", "evidence": 'validate("master_token")', "line_no": 1},
    ]
    events = parse_runtime_events([
        '{"kind":"loadlibrary","java_class":"System","java_method":"loadLibrary","args_summary":"other"}',
    ])
    r = fuse_static_with_runtime(static, events)
    assert r.corroborated == 0
    assert r.uncorroborated == 1
    assert r.fused[0].runtime_corroboration == "not_observed_in_window"


def test_no_runtime_events_graceful():
    r = fuse_static_with_runtime([{"kind": "x", "evidence": "y", "line_no": 0}], [])
    assert r.status == "no_runtime_events"
    assert r.corroborated == 0 and r.uncorroborated == 0
