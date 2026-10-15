"""Crypto constant / table fingerprinting in Android native libraries.

Not every secret is a string.  The reliable way to find *where* a library
does crypto is to look for the algorithm's fingerprints: AES S-box/T-tables,
SHA-2 round constants, ChaCha sigma, and — very useful for mutated codecs —
a custom base64 alphabet (any 64-byte window containing all 64 unique
printable characters).  A custom alphabet is itself a signal the codec was
mutated, so naive decoders elsewhere will fail on it.

This module scans parsed-ELF readable data sections and the raw file for
these tables, reports offsets/confidences, and labels its claims
uncorroborated=False since an exact constant match is factual evidence, not
a heuristic.

Trust: parsed-from-untrusted-binary — TRUST_TAG "untrusted_child".
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass

from src.analysis.native_elf import parse_elf

TRUST_TAG = "untrusted_child"


@dataclass(frozen=True)
class CryptoSite:
    algorithm: str   # aes | sha256 | chacha20 | base64_custom | md5 | tea | base64_standard
    offset: int      # absolute byte offset within the .so file
    size: int
    confidence: float
    note: str


@dataclass(frozen=True)
class CryptoFingerprintResult:
    status: str                      # found | none | unsupported
    sites: list[CryptoSite]
    algorithms: list[str]
    custom_base64_alphabets: list[str]
    bytes_scanned: int
    note: str
    trust: str = TRUST_TAG


# -- exact constant fingerprints ------------------------------------------

_AES_TE0_FIRST8 = bytes.fromhex("a56363c6847c7cf8")  # first two words of AES Te0 (LE)
_SHA256_K_FIRST8 = bytes.fromhex("982f8a4291443771")  # first two SHA-256 K words (LE)
_CHACHA_SIGMA = b"expand 32-byte k"
_MD5_K_FIRST8 = bytes.fromhex("78a46ad756b7c7e8")  # first two MD5 K words (LE)
_BASE64_STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_URL = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_TEA_DELTA_LE = bytes.fromhex("b979379e")  # 0x9E3779B9 little-endian

_PRINTABLE = set(range(32, 127))

# ARM64 AES hardware-instruction encodings (ae{aes,d,mc,imc} + pmull).
# Modern BoringSSL/rust-aes builds use these INSTEAD of software tables —
# missing them produces false negatives on every serious 2020s app (Signal,
# WhatsApp, banking apps).
_ARM64_AES_OPS: tuple[tuple[str, bytes], ...] = (
    ("aese", bytes.fromhex("4e284800")),    # aese Vd.16B, Vn.16B
    ("aesd", bytes.fromhex("4e285800")),    # aesd Vd.16B, Vn.16B
    ("aesmc", bytes.fromhex("4e286800")),   # aesmc Vd.16B
    ("aesimc", bytes.fromhex("4e287800")),  # aesimc Vd.16B
    ("pmull_p64", bytes.fromhex("0ee0e000")),  # pmull Vd.1Q, Vn.1D, Vm.1D
)


def _arm64_aes_sites(data: bytes, elf) -> list[CryptoSite]:
    """Disassemble exec sections and count HW-AES instructions per section."""
    sites: list[CryptoSite] = []
    if elf is None or elf.machine != 183:
        return sites
    try:
        import capstone
    except ImportError:
        return sites
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    for sec in elf.sections:
        if not sec.executable or not sec.size:
            continue
        code = data[sec.offset : min(sec.offset + sec.size, len(data))]
        if not code:
            continue
        counts: dict[str, int] = {}
        for ins in md.disasm(code, sec.addr):
            if ins.mnemonic in ("aese", "aesd", "aesmc", "aesimc", "pmull", "pmull2"):
                counts[ins.mnemonic] = counts.get(ins.mnemonic, 0) + 1
        if counts:
            total = sum(counts.values())
            ops = "/".join(sorted(counts))
            sites.append(CryptoSite(
                algorithm="aes_hw",
                offset=sec.offset,
                size=sec.size,
                confidence=min(0.95, 0.5 + total / 200.0),
                note=f"ARM64 AES-NI in section {sec.name}: {ops} (×{total})",
            ))
    return sites


def _find_all(data: bytes, needle: bytes) -> list[int]:
    offs, start = [], 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return offs
        offs.append(idx)
        start = idx + 1


def _custom_base64_windows(data: bytes, window: int = 64) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    n = len(data)
    i = 0
    while i + window <= n and len(hits) < 64:
        chunk = data[i : i + window]
        if len(set(chunk)) == 64 and all(b in _PRINTABLE for b in chunk):
            if chunk not in (_BASE64_STD, _BASE64_URL):
                hits.append((i, chunk.decode("ascii", "replace")))
                i += window
                continue
        i += 1
    return hits


def _is_custom_alphabet(s: str) -> bool:
    std = set(_BASE64_STD.decode())
    return set(s) != std


def scan_so_bytes(data: bytes) -> CryptoFingerprintResult:
    elf = parse_elf(data)
    if elf is None:
        return CryptoFingerprintResult(
            status="unsupported", sites=[], algorithms=[], custom_base64_alphabets=[],
            bytes_scanned=len(data), note="input is not a parsed ELF file",
        )

    sites: list[CryptoSite] = []

    for off in _find_all(data, _AES_TE0_FIRST8):
        sites.append(CryptoSite("aes", off, 0x400, 0.95, "AES T-table Te0 first words"))
    for off in _find_all(data, _SHA256_K_FIRST8):
        sites.append(CryptoSite("sha256", off, 0x100, 0.9, "SHA-256 round constants prefix"))
    for off in _find_all(data, _CHACHA_SIGMA):
        sites.append(CryptoSite("chacha20", off, 16, 0.85, "ChaCha20 sigma string"))
    for off in _find_all(data, _MD5_K_FIRST8):
        sites.append(CryptoSite("md5", off, 0x100, 0.85, "MD5 K constants prefix (weak legacy)"))
    for off in _find_all(data, _TEA_DELTA_LE):
        sites.append(CryptoSite("tea", off, 4, 0.7, "TEA/XTEA delta constant 0x9E3779B9"))

    # Modern HW-AES (2020s apps): instruction-pattern detection
    sites.extend(_arm64_aes_sites(data, elf))

    if data.find(_BASE64_STD) >= 0 and len(_custom_base64_windows(data)) == 0:
        sites.append(CryptoSite("base64_standard", data.find(_BASE64_STD), 64, 0.6, "standard base64 alphabet"))

    custom = _custom_base64_windows(data)
    alphabets: list[str] = []
    for off, alpha in custom:
        sites.append(
            CryptoSite(
                "base64_custom", off, 64, 0.9,
                "custom base64 alphabet (mutated codec — naive decoder will fail)",
            )
        )
        alphabets.append(alpha)

    algorithms = sorted({s.algorithm for s in sites})
    # Fold hw-aes into the "aes" umbrella so callers doing "aes in algos" work
    # on both software-table and hardware-instruction AES.
    if "aes_hw" in algorithms and "aes" not in algorithms:
        algorithms.append("aes")
        algorithms.sort()
    if sites:
        status = "found"
        note = f"{len(sites)} crypto site(s): {', '.join(algorithms)}"
    else:
        status, note = "none", "no crypto constant fingerprints."
    return CryptoFingerprintResult(
        status=status,
        sites=sites,
        algorithms=algorithms,
        custom_base64_alphabets=alphabets,
        bytes_scanned=len(data),
        note=note,
    )


def scan_apk_native_libs(apk_path: str) -> dict[str, CryptoFingerprintResult]:
    out: dict[str, CryptoFingerprintResult] = {}
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                out[name] = scan_so_bytes(zf.read(name))
    return out
