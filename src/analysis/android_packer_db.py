"""Android packer/protector family database.

The existing ``packing_detect`` module was trained on PE-world packers
(UPX/Themida/VMProtect).  Android has its own ecosystem of commercial
protectors, each with different fingerprints (library names, asset paths,
section names, loader behaviours).  Mis-attributing an Android packer to a
PE-family is a classic false-positive a professional never makes.

This module is a *pure data* companion:  a fingerprint table mapping
well-known protectors to evidence signals (library sonames, asset paths,
string markers, section names, DEX magic), plus a matcher that scores a
given APK against every entry.  Higher score = more evidence.

Trust: ``untrusted_child`` — attacker-controlled APK can spoof markers.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"


@dataclass(frozen=True)
class PackerSignature:
    family: str
    vendor: str
    description: str = ""
    lib_sonames: tuple[str, ...] = ()
    asset_paths: tuple[str, ...] = ()
    section_names: tuple[str, ...] = ()
    string_markers: tuple[bytes, ...] = ()


_ANDROID_PACKERS: tuple[PackerSignature, ...] = (
    PackerSignature(
        family="bangcle",
        vendor="Bangcle (爱加密)",
        description="Chinese commercial packer — VM at native layer",
        lib_sonames=("libbangcle", "libsecexe", "libexec.so", "libexecmain"),
        asset_paths=("assets/bangcle", "assets/libsecexe.so"),
        string_markers=(b"bangcle", b"secexe"),
    ),
    PackerSignature(
        family="secneo",
        vendor="SecNeo (网易易盾)",
        description="NetEase protector — heavily used by Chinese fintech/banks",
        lib_sonames=("libsecneo", "libsecmain", "libnesec", "libSecShell"),
        asset_paths=("assets/libsecmain.so", "assets/secneoinfo"),
        string_markers=(b"secneo", b"secnebo"),
    ),
    PackerSignature(
        family="legu",
        vendor="Tencent Legu (乐固)",
        description="Tencent's official packer — used by QQ music/video",
        lib_sonames=("libexec.so", "libmain", "libshell", "libtbs", "libalgms"),
        asset_paths=("assets/libtup.so", "assets/tencent/legu"),
        string_markers=(b"legu", b"tencent_shell"),
    ),
    PackerSignature(
        family="jiagu_360",
        vendor="360 Jiagu (Qihoo 360)",
        description="Qihoo 360's commercial packer — popular Chinese market",
        lib_sonames=("libjiagu", "libdexprotect", "libdexHelper", "lib360jsafe"),
        asset_paths=("assets/libjiagu.so", "assets/360jiagu"),
        string_markers=(b"jiagu", b"qihoo360"),
    ),
    PackerSignature(
        family="ijiami",
        vendor="iJiami (爱加密)",
        description="iJiami APK packer — also common in games",
        lib_sonames=("libijiami", "libIjiamiSoad", "libdexjnienv", "libkdp"),
        asset_paths=("assets/ijiami.dat", "assets/ijiami.ajm"),
        string_markers=(b"ijiami", b"apkprotect"),
    ),
    PackerSignature(
        family="dexguard_native",
        vendor="Guardsquare DexGuard",
        description="DexGuard — used by legitimate banking/fintech",
        lib_sonames=("libdexhelper", "libdgcode", "libdgnative", "libDexGuard"),
        asset_paths=("assets/dexguard/",),
        section_names=(".dgstrtab", ".dgcode", ".dgdata"),
        string_markers=(b"dexguard", b"guardsquare", b"DexGuard"),
    ),
    PackerSignature(
        family="ollvm",
        vendor="Obfuscator-LLVM (generic)",
        description="Generic LLVM obfuscation — Synopsys/in-house",
        section_names=(".obf_str", ".ollvm"),
        string_markers=(b"OLLVM", b"llvm-obf", b"obfuscator-llvm"),
    ),
    PackerSignature(
        family="appdome",
        vendor="Appdome (commercial SaaS)",
        description="SaaS security wrapper — popular for retail/banking",
        lib_sonames=("libappdome", "libappdome_analytics", "libappdome_jni"),
        asset_paths=("assets/appdome",),
        string_markers=(b"appdome", b"fused_by_appdome"),
    ),
    PackerSignature(
        family="promon_shield",
        vendor="Promon SHIELD",
        description="Scandinavian RASP — used by Nordic banks",
        lib_sonames=("libpromon", "libpromonShield", "libshield"),
        asset_paths=("assets/promon",),
        string_markers=(b"promon", b"SHIELD"),
    ),
    PackerSignature(
        family="defencore",
        vendor="Build38 / Defencore",
        description="German fintech RASP — used by European banks",
        lib_sonames=("libbuild38", "libdx", "libdxc"),
        asset_paths=("assets/build38",),
        string_markers=(b"build38", b"DefenCore", b"defencore"),
    ),
    PackerSignature(
        family="alibaba_dexprotector",
        vendor="Alibaba Jiagu (阿里加固)",
        description="Alibaba's in-house packer — Alipay ecosystem",
        lib_sonames=("libsgmain", "libsgsecuritybody", "libsgavmp"),
        asset_paths=("assets/libsgmain.so",),
        string_markers=(b"alijiagu", b"Alibaba Jiagu"),
    ),
)


@dataclass
class PackerMatch:
    family: str
    vendor: str
    score: float                    # 0.0-1.0 evidence strength
    matched_signals: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class PackerDetectionResult:
    status: str                     # identified | multiple_candidates | none | error
    matches: list[PackerMatch] = field(default_factory=list)
    apk_libs_seen: list[str] = field(default_factory=list)
    apk_assets_seen: list[str] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "matches": [vars(m) for m in self.matches],
            "apk_libs_seen": self.apk_libs_seen,
            "apk_assets_seen": self.apk_assets_seen,
            "note": self.note,
            "trust": self.trust,
        }


def detect_android_packer(apk_path: str | Path) -> PackerDetectionResult:
    """Fingerprint an APK's protector (if any) against the Android packer DB."""
    apk = Path(apk_path)
    if not apk.is_file():
        return PackerDetectionResult(
            status="error", note=f"missing: {apk}",
        )

    libs: list[str] = []
    assets: list[str] = []
    sections: set[str] = set()
    blob_bags: list[bytes] = []

    try:
        with zipfile.ZipFile(apk) as zf:
            for n in zf.namelist():
                if n.endswith(".so"):
                    libs.append(n)
                elif n.startswith("assets/"):
                    assets.append(n)
            # read small libs and manifest as string evidence (bounded)
            for n in libs[:16]:
                info = zf.getinfo(n)
                if info.file_size > 4 * 1024 * 1024:
                    continue
                try:
                    blob_bags.append(zf.read(n))
                except (OSError, RuntimeError, KeyError):
                    continue
            try:
                blob_bags.append(zf.read("AndroidManifest.xml")[:256 * 1024])
            except (OSError, RuntimeError, KeyError):
                pass
            # ELF section names from a small sample lib for the section signal
            from .native_elf import parse_elf
            for n in libs[:4]:
                try:
                    blob = zf.read(n)
                except (OSError, RuntimeError, KeyError):
                    continue
                elf = parse_elf(blob)
                if elf is not None:
                    sections.update(s.name for s in elf.sections)
    except (zipfile.BadZipFile, OSError) as exc:
        return PackerDetectionResult(
            status="error", note=f"apk unreadable: {exc}",
        )

    matches: list[PackerMatch] = []
    for sig in _ANDROID_PACKERS:
        matched: list[str] = []
        score = 0.0
        n_categories = sum(1 for bucket in (
            sig.lib_sonames, sig.asset_paths, sig.section_names, sig.string_markers,
        ) if bucket)
        weight = 1.0 / max(1, n_categories)

        for so in sig.lib_sonames:
            for lib in libs:
                if so.lower() in Path(lib).name.lower():
                    score += weight * 0.9
                    matched.append(f"lib:{lib}")
                    break
        for asset in sig.asset_paths:
            for a in assets:
                if asset.lower() in a.lower():
                    score += weight * 0.8
                    matched.append(f"asset:{a}")
                    break
        for sec in sig.section_names:
            if sec in sections:
                score += weight * 0.7
                matched.append(f"section:{sec}")
        for marker in sig.string_markers:
            for blob in blob_bags:
                if marker in blob:
                    score += weight * 0.6
                    matched.append(f"string:{marker.decode('ascii', 'replace')}")
                    break

        if score > 0.0:
            matches.append(PackerMatch(
                family=sig.family, vendor=sig.vendor,
                score=min(1.0, score), matched_signals=matched,
                description=sig.description,
            ))

    matches.sort(key=lambda m: m.score, reverse=True)
    if not matches:
        status = "none"
        note = f"no Android packer fingerprints matched ({len(libs)} libs, {len(assets)} assets scanned)"
    elif matches[0].score > 0.45 and (len(matches) == 1 or matches[0].score - matches[1].score > 0.2):
        status = "identified"
        note = f"primary match: {matches[0].vendor} (score={matches[0].score:.2f})"
    else:
        status = "multiple_candidates"
        note = f"{len(matches)} candidates; top: {matches[0].vendor} ({matches[0].score:.2f})"

    return PackerDetectionResult(
        status=status,
        matches=matches,
        apk_libs_seen=sorted(libs),
        apk_assets_seen=sorted(assets),
        note=note,
    )
