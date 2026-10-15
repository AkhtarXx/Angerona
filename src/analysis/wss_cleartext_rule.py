"""WebSocket cleartext detection (``ws://`` scheme + OkHttp/javax.websocket sinks).

20-year veteran review flagged this as a critical blind spot: modern fintech
uses WebSockets heavily (chat, support, real-time data), but every existing
scanner only looked at ``http://`` / ``https://``.  Cleartext ``ws://`` is
exactly as bad as cleartext HTTP — byte-for-byte sniffable.

Layers:
  * Manifest — no direct signal; source/java only.
  * OkHttp — ``okhttp3.WebSocket`` / ``newWebSocket(`` / ``okhttp3.Request$Builder.url("ws://…")``
  * Javax / Tyrus / others — ``javax.websocket``, ``@ClientEndpoint``, ``WebSocketContainer.connectToServer(URI)``
  * Raw URI — any literal ``ws://`` (plain) or ``wss://`` (TLS) in source.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import CONFIRMED, LIKELY, INCONCLUSIVE, Finding

TRUST_TAG = "untrusted_child"

_WS_PLAIN = re.compile(r"\bws://[A-Za-z0-9][A-Za-z0-9.-]+[A-Za-z0-9](?::\d+)?(?:/[A-Za-z0-9_/.-]*)?(?:\?[^\s\"'<>)\]]*)?")
_WS_TLS = re.compile(r"\bwss://[A-Za-z0-9][A-Za-z0-9.-]+[A-Za-z0-9](?::\d+)?(?:/[A-Za-z0-9_/.-]*)?(?:\?[^\s\"'<>)\]]*)?")
_OKHTTP_WS = re.compile(r"okhttp3\.WebSocket|newWebSocket\s*\(")
_JAVAX_WS = re.compile(r"javax\.websocket|@ClientEndpoint|WebSocketContainer")
# Valid: at least 3 chars after scheme, plus a real hostname char
_NATIVE_WS = re.compile(rb"ws://[A-Za-z0-9][A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}")


@dataclass
class WssScanResult:
    status: str                     # ok | empty | error
    ws_plaintext_urls: list[str] = field(default_factory=list)
    ws_tls_urls: list[str] = field(default_factory=list)
    okhttp_ws_sites: int = 0
    javax_ws_sites: int = 0
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "ws_plaintext_urls": self.ws_plaintext_urls,
            "ws_tls_urls": self.ws_tls_urls,
            "okhttp_ws_sites": self.okhttp_ws_sites,
            "javax_ws_sites": self.javax_ws_sites,
            "findings": [f.as_dict() for f in self.findings],
            "note": self.note,
            "trust": self.trust,
        }


def scan_source_text(source_text: str, *, source_name: str = "source") -> WssScanResult:
    """Scan Java / Kotlin / smali source for WebSocket usage + scheme tier."""
    if not source_text.strip():
        return WssScanResult(status="empty", note="empty source")

    findings: list[Finding] = []
    plain_urls: list[str] = []
    tls_urls: list[str] = []

    for line in source_text.splitlines():
        for m in _WS_PLAIN.finditer(line):
            url = m.group(0).rstrip('",;)')
            plain_urls.append(url)
        for m in _WS_TLS.finditer(line):
            url = m.group(0).rstrip('",;)')
            tls_urls.append(url)

    okhttp_sites = sum(1 for line in source_text.splitlines() if _OKHTTP_WS.search(line))
    javax_sites = sum(1 for line in source_text.splitlines() if _JAVAX_WS.search(line))

    for url in sorted(set(plain_urls)):
        findings.append(Finding(
            module="wss_cleartext_rule",
            kind="websocket-cleartext",
            severity="high",
            verdict=LIKELY,
            detail=f"WebSocket plaintext URL: {url}",
            evidence=url,
            rule_layer="java",
            metadata={"url": url, "security_equivalent": "cleartext_http"},
        ))
    if okhttp_sites or javax_sites:
        evidence = f"okhttp={okhttp_sites} javax={javax_sites}"
        findings.append(Finding(
            module="wss_cleartext_rule",
            kind="websocket-library-present",
            severity="info",
            verdict=LIKELY,
            detail=f"WebSocket library detected ({evidence})",
            evidence=evidence, rule_layer="java",
            metadata={"okhttp_sites": okhttp_sites, "javax_sites": javax_sites},
        ))

    status = "ok"
    note = (
        f"ws://={len(plain_urls)} wss://={len(tls_urls)} "
        f"okhttp={okhttp_sites} javax={javax_sites}"
    )
    return WssScanResult(
        status=status,
        ws_plaintext_urls=sorted(set(plain_urls)),
        ws_tls_urls=sorted(set(tls_urls)),
        okhttp_ws_sites=okhttp_sites,
        javax_ws_sites=javax_sites,
        findings=findings,
        note=note,
    )


def scan_so_bytes(data: bytes, *, source_name: str = "lib.so") -> list[Finding]:
    """Search a native library for embedded ws:// URLs."""
    findings: list[Finding] = []
    seen: set[bytes] = set()
    for m in _NATIVE_WS.finditer(data):
        url = m.group(0)
        if url in seen:
            continue
        seen.add(url)
        findings.append(Finding(
            module="wss_cleartext_rule",
            kind="websocket-cleartext-native",
            severity="high",
            verdict=INCONCLUSIVE,
            detail=f"native ws:// URL at +{hex(m.start())}: {url.decode('ascii', 'replace')[:60]}",
            evidence=url.decode("ascii", "replace")[:60],
            rule_layer="native",
        ))
    return findings


def scan_apk(apk_path: str | Path) -> WssScanResult:
    """APK-level aggregate: DEX strings for URL scan, plus .so native scan."""
    apk = Path(apk_path)
    if not apk.is_file():
        return WssScanResult(status="error", note=f"missing: {apk}")

    all_findings: list[Finding] = []
    plain_total: set[str] = set()
    tls_total: set[str] = set()
    okhttp_ws_sites: int = 0
    javax_ws_sites: int = 0

    with zipfile.ZipFile(apk) as zf:
        for name in zf.namelist():
            if name.endswith(".dex"):
                try:
                    blob = zf.read(name)[: 4 * 1024 * 1024]
                    text = blob.decode("utf-8", errors="ignore")
                except (OSError, RuntimeError, KeyError):
                    continue
                sub = scan_source_text(text, source_name=name)
                plain_total.update(sub.ws_plaintext_urls)
                tls_total.update(sub.ws_tls_urls)
                okhttp_ws_sites += sub.okhttp_ws_sites
                javax_ws_sites += sub.javax_ws_sites
                all_findings.extend(sub.findings)
            elif name.endswith(".so"):
                try:
                    blob = zf.read(name)[: 8 * 1024 * 1024]
                except (OSError, RuntimeError, KeyError):
                    continue
                all_findings.extend(scan_so_bytes(blob, source_name=name))

    return WssScanResult(
        status="ok",
        ws_plaintext_urls=sorted(plain_total),
        ws_tls_urls=sorted(tls_total),
        okhttp_ws_sites=okhttp_ws_sites,
        javax_ws_sites=javax_ws_sites,
        findings=all_findings,
        note=f"apk-level: ws://={len(plain_total)} wss://={len(tls_total)} findings={len(all_findings)}",
    )
