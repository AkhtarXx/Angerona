"""APK Janus (CVE-2017-13156) signature-conflation check (Android SOTA 12).

Research basis (the original Janus disclosure by GuardSquare, CVE-2017-13156;
Android's fix in the v2-signature verifier): a v1-signed APK is both a ZIP
(read end-first by the verifier) and a DEX (read start-first by the Dalvik
loader). An attacker prepends a malicious DEX over ``classes.dex`` so the
verified bytes and the executed bytes diverge.

Deterministic structural signals (each checkable without a signature oracle):
  1. The file simultaneously parses as a DEX (magic at offset 0) and as a ZIP
     (EOCD record present).
  2. The first local-file-header entry is ``classes.dex`` but its declared
     compressed/uncompressed payload disagrees with the central directory.
No crypto verification is done here — that is the signature gate's job; this
module reports the conflation preconditions, tagged ``untrusted_child``.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_DEX_MAGIC = b"dex\n"
_EOCD_SIG = b"PK\x05\x06"
_LFH_SIG = b"PK\x03\x04"
_V2_BLOCK_SIG = b"APK Sig Block 42"

# Bounded reads: the structural checks need only the file head (DEX/LFH magic
# plus a short first-entry name) and the EOCD window (last ~64 KiB), never the
# whole file. The v2 signing block is located via the EOCD's central-directory
# offset (a 24-byte seek), not by scanning a fixed tail window.
_HEAD_BYTES = 64
_EOCD_WINDOW = 22 + 65536  # EOCD record + max ZIP comment length


@dataclass
class JanusResult:
    status: str            # success | error | skipped
    is_zip: bool = False
    is_dex_at_offset0: bool = False
    v1_signed: bool = False
    v2_signed: bool = False
    first_entry_is_dex: bool = False
    suspicious: bool = False
    signals: list[str] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "is_zip": self.is_zip,
            "is_dex_at_offset0": self.is_dex_at_offset0,
            "v1_signed": self.v1_signed,
            "v2_signed": self.v2_signed,
            "first_entry_is_dex": self.first_entry_is_dex,
            "suspicious": self.suspicious,
            "signals": list(self.signals),
            "note": self.note,
            "trust": self.trust,
            "policy": "structural precondition check; not a signature-verification oracle",
        }


def _has_v2_sig_block(path: Path, eocd_tail: bytes, eocd_rel: int, size: int) -> bool:
    """Detect the APK Signing Block v2 magic via the EOCD central-directory offset.

    The block sits immediately before the central directory, so its last 24 bytes
    are ``[8-byte length][16-byte "APK Sig Block 42" magic]`` at ``cd_offset - 24``.
    Scanning a fixed tail window instead misses it whenever the central directory
    exceeds that window (many entries) — a false negative the bounded-read fix
    must not introduce.
    """
    if eocd_rel < 0:
        return False
    try:
        cd_offset = struct.unpack_from("<I", eocd_tail, eocd_rel + 16)[0]
    except struct.error:
        return False
    if cd_offset == 0xFFFFFFFF or cd_offset < 24 or cd_offset > size:
        return False  # ZIP64 sentinel / corrupt offset: no v2 block we can verify
    try:
        with path.open("rb") as fh:
            fh.seek(cd_offset - 24)
            block_tail = fh.read(24)
    except OSError:
        return False
    return block_tail[8:24] == _V2_BLOCK_SIG


def check_apk(apk_path: str | Path) -> JanusResult:
    """Check one APK for the Janus v1/ZIP+DEX conflation preconditions."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return JanusResult(status="skipped", note=f"missing: {apk_path}")
    try:
        with apk_path.open("rb") as fh:
            head = fh.read(_HEAD_BYTES)
            size = fh.seek(0, 2)
            eocd_window = min(size, _EOCD_WINDOW)
            fh.seek(size - eocd_window)
            eocd_tail = fh.read(eocd_window)
    except OSError as exc:
        return JanusResult(status="error", note=f"unreadable: {exc}")
    if size < 22:
        return JanusResult(status="error", note="file too small to be APK")

    is_dex0 = head[:4] == _DEX_MAGIC
    eocd_rel = eocd_tail.rfind(_EOCD_SIG)
    is_zip = eocd_rel != -1
    v2 = _has_v2_sig_block(apk_path, eocd_tail, eocd_rel, size) if is_zip else False
    v1 = False
    first_dex = False
    signals: list[str] = []

    if is_zip:
        try:
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()
                v1 = any(n.startswith("META-INF/") and
                         n.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))
                         for n in names)
        except (zipfile.BadZipFile, OSError):
            is_zip = False

    # First local-file header: does it claim to be classes.dex while offset 0
    # of the whole file carries a DEX magic (the conjoined smell)?
    if head[:4] == _LFH_SIG and size >= 30:
        name_len = struct.unpack_from("<H", head, 26)[0]
        first_name = head[30:30 + name_len].decode("ascii", errors="ignore")
        first_dex = first_name == "classes.dex"
    elif is_dex0:
        # DEX at offset 0 in a file that is also a ZIP: the Janus shape. The
        # DEX bytes double as (junk) extra-field space for the first entry.
        first_dex = True
        signals.append("dex-magic-at-offset-0 with ZIP EOCD present")

    if is_dex0 and is_zip:
        signals.append("parses as both DEX (offset 0) and ZIP (EOCD)")
    if v1 and not v2:
        signals.append("v1(JAR)-signed without v2 block: Janus-applicable target")
    if first_dex and is_dex0:
        signals.append("first archive entry is classes.dex behind a DEX header")

    suspicious = is_dex0 and is_zip and (v1 and not v2 or first_dex)
    note = ("JANUS-SUSPICIOUS: " if suspicious else "no Janus preconditions: ")
    note += "; ".join(signals) if signals else "clean ZIP container"
    return JanusResult(
        status="success",
        is_zip=is_zip, is_dex_at_offset0=is_dex0,
        v1_signed=v1, v2_signed=v2, first_entry_is_dex=first_dex,
        suspicious=suspicious, signals=signals, note=note,
    )
