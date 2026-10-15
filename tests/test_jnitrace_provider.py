"""Behavior tests for jnitrace agent template + stream parsing (roadmap Android #3)."""
from __future__ import annotations

import json
from pathlib import Path

from src.execution.jnitrace_provider import (
    _JNITRACE_AGENT,
    JnilTraceEvent,
    launch_jnitrace_plan,
    parse_jnitrace_stream,
    write_jnitrace_agent,
)


def test_agent_template_has_jni_hooks():
    # agent includes the most-audited JNI calls
    for required in ("RegisterNatives", "FindClass", "GetMethodID",
                      "NewStringUTF", "GetStringUTFChars",
                      "CallObjectMethod", "CallStaticObjectMethod",
                      "ExceptionOccurred"):
        assert required in _JNITRACE_AGENT


def test_agent_template_is_valid_javascript():
    # rough sanity: balanced braces and send() call
    body = _JNITRACE_AGENT
    assert body.count("{") == body.count("}")
    assert "send(JSON.stringify" in body


def test_write_agent_materialises_script():
    p = write_jnitrace_agent(None)
    assert p.is_file()
    text = p.read_text()
    assert "RegisterNatives" in text
    assert "send(JSON.stringify" in text
    p.unlink()


def test_parse_stream_robust_to_malformed_json():
    stream = "\n".join([
        '{"event":"jnitrace-start","count":49}',
        '{"event":"jni-enter","call":"FindClass","thread":"1234","args":["Lcom/x/B;"]}',
        'this is not json',
        '{"event":123}',       # missing string event
        '{"event":"jni-exit","call":"FindClass","thread":"1234","ret":"0xdeadbeef"}',
    ])
    events = parse_jnitrace_stream(stream)
    assert len(events) == 3
    assert events[1].call == "FindClass"
    assert events[2].ret == "0xdeadbeef"


def test_parse_stream_inner_json_parse_error():
    events = parse_jnitrace_stream('{"event":"broken" incomplete json')
    assert events == []


def test_launch_plan_structure(tmp_path):
    target = tmp_path / "target.apk"
    target.write_bytes(b"\x00" * 100)
    plan = launch_jnitrace_plan(target)
    assert plan["provider"] == "frida"
    assert "-l" in plan["argv"]
    assert plan["metadata"]["agent"] == "jnitrace"
    assert plan["metadata"]["trust_boundary"] == "untrusted_child_events"
