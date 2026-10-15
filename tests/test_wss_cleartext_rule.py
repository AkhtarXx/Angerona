from __future__ import annotations

import zipfile
from pathlib import Path

from src.analysis.finding import CONFIRMED, LIKELY, INCONCLUSIVE
from src.analysis.wss_cleartext_rule import (
    scan_apk,
    scan_so_bytes,
    scan_source_text,
)


def test_empty_source():
    r = scan_source_text("")
    assert r.status == "empty"
    assert r.findings == []


def test_plain_ws_detected_java():
    src = '''
import okhttp3.WebSocket;
public class WS {
    void open() {
        WebSocket ws = client.newWebSocket(new Request.Builder()
            .url("ws://chat.bank.example:8090/socket")
            .build());
    }
}
'''
    r = scan_source_text(src)
    assert r.status == "ok"
    assert "ws://chat.bank.example:8090/socket" in r.ws_plaintext_urls
    plaintext = [f for f in r.findings if f.kind == "websocket-cleartext"]
    assert plaintext
    assert plaintext[0].verdict in (LIKELY, CONFIRMED)
    assert plaintext[0].severity == "high"


def test_wss_tls_not_flagged():
    src = 'WebSocket ws = client.newWebSocket(req.url("wss://secure.example.com/s"));'
    r = scan_source_text(src)
    assert r.ws_plaintext_urls == []
    assert "wss://secure.example.com/s" in r.ws_tls_urls


def test_okhttp_socket_detection():
    src = "WebSocket sock = client.newWebSocket(request, listener);"
    r = scan_source_text(src)
    assert r.okhttp_ws_sites > 0


def test_javax_websocket_detected():
    src = """
import javax.websocket.ClientEndpoint;
import javax.websocket.WebSocketContainer;
@ClientEndpoint
public class Echo {}
"""
    r = scan_source_text(src)
    assert r.javax_ws_sites > 0


def test_combined_okhttp_and_plain_url():
    src = '''
public void go() {
    client.newWebSocket(new Request.Builder()
        .url("ws://insecure.api/rt").build(), listener);
}
'''
    r = scan_source_text(src)
    assert "ws://insecure.api/rt" in r.ws_plaintext_urls
    assert r.okhttp_ws_sites > 0
    plaintext = [f for f in r.findings if f.kind == "websocket-cleartext"]
    # Static-only after ELITE-2 demotion — CONFIRMED never earned via regex alone
    assert all(f.verdict == LIKELY for f in plaintext)


def test_native_scan_finds_ws_url():
    blob = b"\x7fELF" + b"\x00" * 32 + b"ws://banking.internal/rt\x00" + b"\x00" * 64
    findings = scan_so_bytes(blob, source_name="libx.so")
    assert findings
    assert findings[0].rule_layer == "native"
    assert findings[0].verdict == INCONCLUSIVE


def test_real_apk_scan(signal_dir="/tmp"):
    sig = Path("/tmp/signal.apk")
    if not sig.exists():
        import pytest
        pytest.skip("signal unavailable")
    r = scan_apk(sig)
    assert r.status == "ok"
    # Signal mostly uses wss:// or custom TLS for signaling — should not
    # have plaintext ws:// findings in production code.
    print(f"signal websocket scan: {r.note}")
