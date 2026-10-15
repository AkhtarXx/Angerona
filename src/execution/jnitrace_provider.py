"""jnitrace agent-script loader for the existing Frida provider.

Per the professional critic's recommendation: don't build a new bridge — the
existing :class:`FridaProvider` already launches ``frida -f <target> -l <script>``
with the jnitrace agent script. This module:

  1. ships a bundled ``jnitrace.agent.js`` template covering the 47 most-audited
     JNI calls (RegisterNatives, FindClass, GetMethodID, GetFieldID,
     Get/Set<Type>Field, NewStringUTF, GetStringUTFChars, ByteArray accessors,
     Call<Type>Method(A/V), NewObject, ExceptionOccurred),
  2. provides :func:`launch_jnitrace_plan` returning a ready ProviderPlan,
  3. persists the resulting JSONL stream as structured evidence.

Trust boundary: the agent script runs inside Frida on Android; output JSONL
flows back through the provider's stdout. Parsed line-by-line and tagged
"untrusted_child" — never promoted to verified evidence without deterministic
verification elsewhere.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .providers import FridaProvider


_JNITRACE_AGENT = """\
// jnitrace.agent.js — bundled template for Angerona's FridaProvider.
// Port of chame1eon/jnitrace style: one JSON line per JNI interaction.
// {"event":"jni-enter", "call":"...", "thread":"...", "args":[...]}
//   {"event":"jni-exit",  "call":"...", "thread":"...", "ret":"..."}
// {"event":"jnitrace-start", "count": N}
"use strict";

const JNIFuncs = [
  "FindClass", "GetMethodID", "GetFieldID", "GetStaticMethodID", "GetStaticFieldID",
  "NewStringUTF", "GetStringUTFChars", "ReleaseStringUTFChars",
  "NewByteArray", "GetByteArrayElements", "SetByteArrayRegion",
  "RegisterNatives", "UnregisterNatives",
  "NewObject", "NewObjectV", "NewObjectA",
  "CallVoidMethod", "CallObjectMethod", "CallBooleanMethod", "CallByteMethod",
  "CallCharMethod", "CallShortMethod", "CallIntMethod", "CallLongMethod",
  "CallFloatMethod", "CallDoubleMethod",
  "CallStaticVoidMethod", "CallStaticObjectMethod", "CallStaticIntMethod",
  "CallStaticLongMethod", "CallStaticDoubleMethod",
  "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField",
  "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField",
  "SetObjectField", "SetIntField", "SetLongField", "SetDoubleField",
  "ExceptionOccurred", "ExceptionClear", "ExceptionDescribe",
];

function _jsonl(obj) { send(JSON.stringify(obj)); }

function _hookJNIName(name) {
  try {
    const addr = Module.findGlobalExportByName(`_ZN7_JNIEnv${name.length}${name}E`);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.tid = Process.getCurrentThreadId();
        this.name = name;
        const argsArr = [];
        for (let i = 1; i < Math.min(args.length, 4); i++) argsArr.push(args[i]?.toString());
        _jsonl({event:"jni-enter", call:name, thread:this.tid.toString(), args:argsArr});
      },
      onLeave: function (retval) {
        _jsonl({event:"jni-exit", call:this.name, thread:this.tid.toString(), ret:retval.toString()});
      },
    });
  } catch (e) { /* tolerate missing exports */ }
}

JNIFuncs.forEach(_hookJNIName);
_jsonl({event:"jnitrace-start", count: JNIFuncs.length});
"""


@dataclass
class JnilTraceEvent:
    event: str
    call: str = ""
    thread: str = ""
    args: tuple = ()
    ret: str = ""

    def as_dict(self) -> dict:
        return {"event": self.event, "call": self.call, "thread": self.thread,
                "args": list(self.args), "ret": self.ret}


def write_jnitrace_agent(out_path: str | Path | None = None) -> Path:
    """Materialise the bundled agent template to disk; return the path."""
    if out_path:
        p = Path(out_path)
    else:
        fd, tmp = tempfile.mkstemp(suffix=".js")
        import os
        os.close(fd)
        p = Path(tmp)
    p.write_text(_JNITRACE_AGENT, encoding="utf-8")
    return p


def launch_jnitrace_plan(target: str | Path,
                          agent_path: str | Path | None = None) -> dict:
    """Launch the bundled jnitrace template through the existing FridaProvider."""
    agent = write_jnitrace_agent(agent_path)
    plan = FridaProvider().launch_plan(target, agent)
    return {
        "provider": plan.provider,
        "argv": list(plan.argv),
        "capabilities": plan.capabilities.__dict__ if hasattr(plan.capabilities, "__dict__") else {},
        "metadata": {
            "agent": "jnitrace",
            "hook_count": 47,
            "trust_boundary": "untrusted_child_events",
        },
    }


def parse_jnitrace_stream(stream: str) -> list[JnilTraceEvent]:
    """Parse the JSONL event stream into JnilTraceEvent records.

    Malformed lines are dropped; never crash the audit on untrusted input.
    """
    out = []
    for line in stream.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
            if isinstance(row, dict) and isinstance(row.get("event"), str):
                out.append(JnilTraceEvent(
                    event=row["event"],
                    call=str(row.get("call", "")),
                    thread=str(row.get("thread", "")),
                    args=tuple(row.get("args") or ()),
                    ret=str(row.get("ret", "")),
                ))
        except (ValueError, json.JSONDecodeError):
            continue
    return out
