"""Android audit pipeline orchestrator.

Implements the professional's strict ordering:

  1. **Provenance** — ``apksigner_bridge.verify_apk_signature``
     If the cert doesn't match canonical, NOTHING else matters.
  2. **Packer triage** — ``android_packer_db.detect_android_packer``
     Everything downstream is conditional on this.
  3. **Structural inventory** — ``multidex_coverage``, ``assets_blob_detector``.
  4. **Runtime DEX extraction** — when packer confidence ≥ 0.4, try
     ``runtime_dex_extractor``.  Failure here = refusal-tier finding.
  5. **TLS stack + MTLS tier** — choose the right rule layer, not guess.
  6. **Rule scanners** — gated on (a) TLS layer from step 5 and (b) packer
     verdict from step 2.
  7. **Fusion** — every emitted finding carries a verdict tier.

Verdict tiers:

  * ``CONFIRMED`` — runtime-corroborated or protocol-level proof
  * ``LIKELY`` — strong multi-signal static evidence
  * ``INCONCLUSIVE`` — static-only, no runtime gate
  * ``NOT_APPLICABLE`` — wrong layer, obsolete platform, etc.
  * ``REFUSAL`` — pipeline honestly declines (packer-resistance, etc.)

Never emits "SAFE" — that word is the root cause of blind-trust AI failures.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

# verdict tier constants — callers compare against these names
V_CONFIRMED = "CONFIRMED"
V_LIKELY = "LIKELY"
V_INCONCLUSIVE = "INCONCLUSIVE"
V_NOT_APPLICABLE = "NOT_APPLICABLE"
V_REFUSAL = "REFUSAL"


@dataclass
class AuditFinding:
    module: str
    kind: str
    severity: str           # critical | high | medium | low | info
    verdict: str            # see V_* constants
    detail: str
    runtime_corroborated: bool = False
    evidence: str = ""
    metadata: dict = field(default_factory=dict)
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "module": self.module,
            "kind": self.kind,
            "severity": self.severity,
            "verdict": self.verdict,
            "detail": self.detail,
            "runtime_corroborated": self.runtime_corroborated,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "trust": self.trust,
        }


@dataclass
class AuditReport:
    apk_path: str
    status: str                          # completed | partial | refusal | error
    steps_executed: list[str] = field(default_factory=list)
    steps_skipped: list[str] = field(default_factory=list)
    provenance_verdict: str = ""
    packer_verdict: str = ""
    tls_stack: str = ""
    runtime_extract_status: str = ""
    findings: list[AuditFinding] = field(default_factory=list)
    refusal_reasons: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    duration_s: float = 0.0
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "apk_path": self.apk_path,
            "status": self.status,
            "steps_executed": self.steps_executed,
            "steps_skipped": self.steps_skipped,
            "provenance_verdict": self.provenance_verdict,
            "packer_verdict": self.packer_verdict,
            "tls_stack": self.tls_stack,
            "runtime_extract_status": self.runtime_extract_status,
            "findings": [f.as_dict() for f in self.findings],
            "refusal_reasons": self.refusal_reasons,
            "metadata": self.metadata,
            "duration_s": self.duration_s,
            "trust": self.trust,
        }

    def summary_line(self) -> str:
        counts = {}
        for f in self.findings:
            counts[f.verdict] = counts.get(f.verdict, 0) + 1
        verdicts = " ".join(f"{v}={c}" for v, c in sorted(counts.items())) or "EMPTY"
        return (
            f"audit[{self.status}] steps={len(self.steps_executed)}"
            f"+skip:{len(self.steps_skipped)} | {verdicts}"
        )


# ------------------------------------------------------------------ helpers


def _audit_from_finding(f, default_module: str = "") -> AuditFinding:
    """Convert a canonical Finding (or legacy dict) into AuditFinding.

    When module name is missing, uses ``default_module``.
    """
    if isinstance(f, AuditFinding):
        return f
    # duck-typing: read attrs that might be Finding or dict
    def get(attr, default=""):
        if isinstance(f, dict):
            return f.get(attr, default)
        return getattr(f, attr, default)

    kind = get("kind", "unknown")
    module = get("module", "") or default_module
    severity = get("severity", "medium")
    detail = get("detail", get("message", ""))
    evidence = get("evidence", "")
    verdict = get("verdict", V_LIKELY)
    line_no = get("line_no", 0)
    corr = bool(get("runtime_corroborated", False))
    metadata = get("metadata", {}) if isinstance(get("metadata", {}), dict) else {}
    return AuditFinding(
        module=module, kind=kind, severity=severity, verdict=verdict,
        detail=detail, runtime_corroborated=corr, evidence=evidence,
        metadata={**metadata, "line_no": line_no},
    )


def dl_findings(res):
    """Yield canonical Finding from legacy dict or native Finding."""
    yield from getattr(res, "findings", []) or []


def _is_packed(pack) -> bool:
    if pack is None:
        return False
    if pack.status == "identified":
        return True
    if pack.status == "multiple_candidates":
        return bool(pack.matches and pack.matches[0].score >= 0.4)
    return False


def _apk_lib_bytes(apk_path: str, lib_name: str) -> bytes | None:
    try:
        with zipfile.ZipFile(apk_path) as zf:
            return zf.read(lib_name)
    except (zipfile.BadZipFile, OSError, KeyError):
        return None


def _load_smali_corpus(
    decoded_root: Path,
    smali_dirs: list[str],
    *,
    max_bytes: int = 64 * 1024 * 1024,
) -> tuple[str, dict]:
    """Read decoded Smali with a byte budget and report exact coverage."""
    chunks: list[str] = []
    files_seen = 0
    files_read = 0
    bytes_read = 0
    truncated = False
    for relative_dir in smali_dirs:
        directory = decoded_root / relative_dir
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.smali")):
            files_seen += 1
            remaining = max_bytes - bytes_read
            if remaining <= 0:
                truncated = True
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if len(raw) > remaining:
                raw = raw[:remaining]
                truncated = True
            chunks.append(raw.decode("utf-8", errors="replace"))
            bytes_read += len(raw)
            files_read += 1
    return "\n".join(chunks), {
        "files_seen": files_seen,
        "files_read": files_read,
        "bytes_read": bytes_read,
        "max_bytes": max_bytes,
        "truncated": truncated,
    }


def _canonical_android_component(name: str, package: str) -> str:
    """Normalize manifest and dumpsys component spellings for comparison."""
    value = name.strip()
    if "/" in value:
        owner, value = value.split("/", 1)
        if value.startswith("."):
            return owner + value
        return value
    if value.startswith("."):
        return package + value
    if "." not in value and package:
        return f"{package}.{value}"
    return value


def _dex_semantic_coverage(mdex, jadx_coverage: dict) -> dict:
    """Return per-target DEX closure; aggregate class counts never suffice."""
    inventory_complete = bool(mdex is not None and mdex.status == "success")
    expected = int(jadx_coverage.get("dex_targets_expected", 0))
    complete = int(jadx_coverage.get("dex_targets_complete", 0))
    inventory_count = int(getattr(mdex, "dex_count", 0) or 0)
    return {
        "inventory_complete": inventory_complete,
        "inventory_count": inventory_count,
        "targets_expected": expected,
        "targets_complete": complete,
        "complete": bool(
            inventory_complete
            and expected >= inventory_count
            and complete == expected
        ),
    }


# ------------------------------------------------------------------ driver


_DETERMINISTIC_CHECKPOINT_NAME = "android-audit.checkpoint.json"


def _write_deterministic_checkpoint(
    persistent_artifacts: Path | None,
    *,
    apk_sha256: str,
    report: "AuditReport",
    stages: dict[str, dict],
    elapsed_seconds: float,
) -> Path | None:
    """Atomically record deterministic-phase progress (R10).

    The deterministic phase previously persisted its report only at the very end,
    so a crash mid-phase discarded every completed stage. This checkpoint is
    written after each EXPENSIVE stage so a crash leaves a durable record of
    ``steps_executed`` and per-stage output markers that a resume can replay.
    """
    if persistent_artifacts is None:
        return None
    persistent_artifacts.mkdir(parents=True, exist_ok=True)
    checkpoint = {
        "schema_version": 1,
        "apk_sha256": apk_sha256,
        "steps_executed": list(report.steps_executed),
        "steps_skipped": list(report.steps_skipped),
        "status": report.status,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "stages": {key: dict(value) for key, value in stages.items()},
    }
    target = persistent_artifacts / _DETERMINISTIC_CHECKPOINT_NAME
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(checkpoint, indent=2, default=str) + "\n", encoding="utf-8"
    )
    os.replace(temporary, target)
    return target


def run_android_audit(
    apk_path: str | Path,
    *,
    expected_package: str | None = None,
    try_runtime_extract: bool = False,
    device_serial: str = "",
    runtime_provider: str = "auto",
    runtime_api: int = 35,
    runtime_abi: str = "auto",
    runtime_image_tag: str = "default",
    runtime_auto_provision: bool = False,
    runtime_sdk_root: str = "",
    allow_native_translation: bool = False,
    runtime_network: str = "deny",
    timeout_per_step: int = 120,
    run_rules: bool = True,
    related_apks: list[str | Path] | None = None,
    baseline_path: str | Path | None = None,
    authorization_ref: str | None = None,
    artifact_output_dir: str | Path | None = None,
    audit_input_snapshot_dir: str | Path | None = None,
    native_ownership_manifest: str | Path | None = None,
    native_universe: str | Path | None = None,
    native_lane_epoch_id: str = "",
) -> AuditReport:
    """Run the professional-ordered audit sequence on one APK."""
    import time
    start = time.time()
    pre_ai_started = time.monotonic()
    try:
        pre_ai_budget_seconds = int(
            os.environ.get("ANGERONA_ANDROID_PRE_AI_BUDGET_SECONDS", "86400")
        )
    except ValueError:
        pre_ai_budget_seconds = 86_400
    pre_ai_budget_seconds = max(3600, min(pre_ai_budget_seconds, 7 * 86_400))
    pre_ai_deadline = pre_ai_started + pre_ai_budget_seconds

    original_apk = Path(apk_path).expanduser().absolute()
    report = AuditReport(apk_path=str(original_apk), status="completed")
    report.metadata["pre_ai_budget"] = {
        "seconds": pre_ai_budget_seconds,
        "started_monotonic": pre_ai_started,
        "deadline_monotonic": pre_ai_deadline,
    }
    report.metadata["engagement"] = {
        "authorization_ref": authorization_ref or "not-recorded",
        "authorized_scope_asserted": bool(authorization_ref),
    }
    report.metadata["runtime_requested"] = bool(try_runtime_extract)
    runtime_authorized = bool(authorization_ref)
    report.metadata["runtime_authorized"] = runtime_authorized
    # Every producer must consume the same immutable bytes.  Capturing through
    # one O_NOFOLLOW file descriptor closes the report-wide path-replacement
    # race between validation, decompilation, installation, and replay export.
    # AI runs provide a durable workspace directory; standalone calls use a
    # private temporary snapshot that remains alive for this whole function.
    input_snapshot_workspace: tempfile.TemporaryDirectory[str] | None = None
    snapshot_root: Path
    if audit_input_snapshot_dir is None:
        input_snapshot_workspace = tempfile.TemporaryDirectory(
            prefix="angerona-android-input-"
        )
        snapshot_root = Path(input_snapshot_workspace.name)
    else:
        snapshot_root = Path(audit_input_snapshot_dir).expanduser().absolute()
    try:
        from src.analysis.target_snapshot import materialize_audit_target_snapshot

        apk, snapshot_identity = materialize_audit_target_snapshot(
            original_apk, snapshot_root, target_suffix=".apk"
        )
    except Exception as exc:  # noqa: BLE001 - input capture is a hard gate
        report.status = "error"
        report.refusal_reasons.append(
            f"immutable APK snapshot failed: {type(exc).__name__}: {exc}"
        )
        report.steps_skipped.append("artifact-snapshot:failed")
        return report
    report.metadata["audit_input_snapshot"] = {
        "path": str(apk),
        "original_path": str(original_apk),
        "sha256": snapshot_identity["sha256"],
        "size": snapshot_identity["size"],
        "mode": "durable" if audit_input_snapshot_dir is not None else "ephemeral",
    }
    report.steps_executed.append("artifact-snapshot")
    persistent_artifacts = (
        Path(artifact_output_dir).expanduser().resolve()
        if artifact_output_dir is not None else None
    )
    if persistent_artifacts is not None:
        persistent_artifacts.mkdir(parents=True, exist_ok=True)
        report.metadata["artifact_workspace"] = str(persistent_artifacts)
    stages: dict[str, dict] = {}

    def checkpoint(stage: str, output: str | Path | None = None) -> None:
        """Record one completed EXPENSIVE stage so a crash can be resumed."""
        stages[stage] = {
            "complete": True,
            "output": str(output) if output is not None else "",
        }
        _write_deterministic_checkpoint(
            persistent_artifacts,
            apk_sha256=snapshot_identity["sha256"],
            report=report,
            stages=stages,
            elapsed_seconds=time.time() - start,
        )

    binary_payload_workspace: tempfile.TemporaryDirectory[str] | None = None
    dex_semantic_workspace: tempfile.TemporaryDirectory[str] | None = None
    from src.analysis.android_artifact import validate_apk

    artifact = validate_apk(apk)
    report.metadata["artifact_validation"] = {
        "status": artifact.status,
        "format": artifact.format,
        "member_count": artifact.member_count,
        "uncompressed_bytes": artifact.uncompressed_bytes,
        "dex_entries": artifact.dex_entries,
        "note": artifact.note,
        "sha256": snapshot_identity["sha256"],
    }
    if not artifact.valid:
        report.status = "error"
        report.refusal_reasons.append(artifact.note)
        report.steps_skipped.append(f"artifact-validation:{artifact.status}")
        return report
    report.steps_executed.append("artifact-validation")
    package_name = expected_package or ""

    # 1) provenance
    try:
        from src.analysis.apksigner_bridge import verify_apk_signature
        prov = verify_apk_signature(apk, expected_package=expected_package,
                                    timeout=timeout_per_step)
        report.steps_executed.append("apksigner_bridge")
        report.provenance_verdict = prov.status
        package_name = prov.package_name or package_name
        report.metadata["package_name"] = package_name
        report.findings.append(AuditFinding(
            module="apksigner_bridge", kind="origin",
            severity="critical" if prov.status == "mismatch" else (
                "high" if prov.status == "unknown_app" else "info"),
            verdict=V_CONFIRMED if prov.status == "verified" else (
                V_LIKELY if prov.status == "unknown_app" else V_INCONCLUSIVE
                if prov.status in ("tool_unavailable", "unsigned") else V_CONFIRMED),
            detail=prov.note, runtime_corroborated=False,
            evidence=prov.package_name,
        ))
        if prov.status == "mismatch":
            report.status = "refusal"
            report.refusal_reasons.append(prov.note)
            # Attribution is refused, but the authorized forensic analysis must
            # continue.  Findings remain useful while the report status makes
            # the origin uncertainty impossible to miss.
        elif prov.status in ("unknown_app", "tool_unavailable", "unsigned"):
            report.status = "partial"
            report.refusal_reasons.append(f"origin not canonically anchored: {prov.note}")
    except Exception as exc:  # noqa: BLE001 — module errors must not crash pipeline
        report.steps_skipped.append(f"apksigner_bridge:{exc}")

    # 2) packer triage
    pack = None
    packer_failed = False
    try:
        from src.analysis.android_packer_db import detect_android_packer
        pack = detect_android_packer(apk)
        report.steps_executed.append("android_packer_db")
        report.packer_verdict = pack.status
        if pack.matches:
            top = pack.matches[0]
            sev = "high" if top.score > 0.7 else "medium"
            report.findings.append(AuditFinding(
                module="android_packer_db", kind="packer-identified",
                severity=sev, verdict=V_LIKELY,
                detail=f"{top.vendor} ({top.score:.2f}) — {top.description}",
            ))
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"android_packer_db:{exc}")
        # Conservative safety net: when packer DETECTION itself fails,
        # assume packed=True so that step-9 downgrade logic triggers
        # (and CONFIRMED verdicts are refused).  （ ELITE-2 C1. ）
        pack = None
        packer_failed = True

    # 3) structural inventory
    mdex = None
    try:
        from src.analysis.multidex_coverage import inventory_apk
        mdex = inventory_apk(apk)
        report.metadata["dex_inventory"] = mdex.as_dict()
        report.steps_executed.append("multidex_coverage")
        report.findings.append(AuditFinding(
            module="multidex_coverage", kind="dex-inventory",
            severity="info" if mdex.status == "success" else "medium",
            verdict=V_CONFIRMED if mdex.status == "success" else V_INCONCLUSIVE,
            detail=mdex.note, runtime_corroborated=False,
            evidence=f"status={mdex.status};dex_count={mdex.dex_count}",
        ))
        if mdex.status != "success":
            report.status = "partial" if report.status == "completed" else report.status
            report.refusal_reasons.append(f"DEX inventory incomplete: {mdex.note}")
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"multidex_coverage:{exc}")

    packed = _is_packed(pack)
    # Magic-first inventory happens before the runtime decision.  Unknown
    # protectors and high-entropy payloads must be able to escalate even when
    # the named-packer database has no match (or failed altogether).
    try:
        from src.analysis.android_binary_inventory import (
            analyze_native_static_evidence,
            scan_apk_binary_members,
        )

        payload_export = (
            persistent_artifacts / "binary_payloads"
            if persistent_artifacts is not None else None
        )
        if payload_export is None:
            binary_payload_workspace = tempfile.TemporaryDirectory(
                prefix="angerona-android-binary-payloads-"
            )
            payload_export = Path(binary_payload_workspace.name)
        binary_inventory = scan_apk_binary_members(apk, export_dir=payload_export)
        report.metadata["binary_inventory"] = binary_inventory
        report.metadata["embedded_code_files"] = list(
            binary_inventory.get("exported_code_files", [])
        )
        report.metadata["embedded_code_targets"] = list(
            binary_inventory.get("exported_code_targets", [])
        )
        native_paths = [
            str(item.get("exported_path"))
            for item in binary_inventory.get("members", [])
            if item.get("format") == "elf" and item.get("exported_path")
        ]
        native_evidence_root = (
            persistent_artifacts / "native_static_evidence"
            if persistent_artifacts is not None
            else payload_export / "native_static_evidence"
        )

        def native_progress(event: dict) -> None:
            now = time.monotonic()
            payload = {
                **event,
                "elapsed_seconds": round(now - pre_ai_started, 3),
                "remaining_budget_seconds": round(max(0.0, pre_ai_deadline - now), 3),
            }
            report.metadata["native_static_progress"] = payload
            if persistent_artifacts is not None:
                progress_path = persistent_artifacts / "ANDROID_DETERMINISTIC_PROGRESS.json"
                temporary_progress = progress_path.with_suffix(".json.tmp")
                temporary_progress.write_text(
                    json.dumps(payload, indent=2, default=str) + "\n",
                    encoding="utf-8",
                )
                os.replace(temporary_progress, progress_path)
            print(
                f"android-native {payload.get('completed', 0)}/{payload.get('expected', 0)} "
                f"cache={'hit' if payload.get('cache_hit') else 'miss'} "
                f"remaining={payload['remaining_budget_seconds']}s",
                file=sys.stderr,
                flush=True,
            )

        if not native_paths:
            native_static = {"complete": True, "records": [], "status": "not-applicable"}
        elif not (native_ownership_manifest and native_universe and native_lane_epoch_id):
            native_static = {
                "complete": False, "records": [], "launch_blocked": True,
                "status": "unverifiable",
                "reason": "native analysis requires an ownership manifest, target universe and lane epoch",
            }
        else:
            native_static = analyze_native_static_evidence(
                native_paths,
                evidence_root=native_evidence_root,
                ownership_manifest=native_ownership_manifest,
                native_universe=native_universe,
                lane_epoch_id=native_lane_epoch_id,
                timeout=timeout_per_step,
                progress_callback=native_progress,
                deadline_monotonic=pre_ai_deadline,
            )
        native_static["ownership_manifest_path"] = str(Path(native_ownership_manifest).absolute()) if native_ownership_manifest else ""
        native_static["native_universe_path"] = str(Path(native_universe).absolute()) if native_universe else ""
        native_static["native_lane_epoch_id"] = native_lane_epoch_id
        report.metadata["native_static_evidence"] = native_static
        unresolved_opaque = list(binary_inventory.get("unresolved_opaque_members", []))
        native_static_incomplete = bool(native_paths and not native_static.get("complete"))
        if native_static.get("launch_blocked"):
            report.status = "error"
            report.refusal_reasons.append(
                "native ownership HOLD blocked IDA and all downstream native AI launch"
            )
        runtime_reasons = (
            (["packer-detected"] if packed else [])
            + (["packer-detection-failed"] if packer_failed else [])
            + (["opaque-payload-unresolved"] if unresolved_opaque else [])
            + (["dex-inventory-incomplete"] if mdex is None or mdex.status != "success" else [])
            + (["binary-members-skipped"] if binary_inventory.get("skipped") else [])
            + (["native-static-evidence-incomplete"] if native_static_incomplete else [])
        )
        report.metadata["runtime_escalation"] = {
            "required": bool(runtime_reasons),
            "reasons": runtime_reasons,
            "attempted": bool(try_runtime_extract and runtime_authorized),
            "physical_device_mandatory": False,
            "acceptable_runtime_targets": ["isolated-emulator", "authorized-test-device"],
        }
        report.steps_executed.append("android_binary_inventory")
        if native_paths:
            report.steps_executed.append("android_native_static_evidence")
            checkpoint("native_static_evidence", output=native_evidence_root)
        if native_static_incomplete:
            if report.status == "completed":
                report.status = "partial"
            report.refusal_reasons.append(
                "native static evidence is incomplete; total native-code coverage is refused"
            )
        if binary_inventory.get("skipped"):
            if report.status == "completed":
                report.status = "partial"
            report.refusal_reasons.append(
                "binary member inventory incomplete; see metadata.binary_inventory.skipped"
            )
        if unresolved_opaque:
            report.findings.append(AuditFinding(
                module="android_binary_inventory",
                kind="opaque-runtime-payload",
                severity="medium",
                verdict=V_INCONCLUSIVE,
                detail=(
                    f"{len(unresolved_opaque)} high-entropy opaque APK member(s) require "
                    "unpacking or a runtime witness before complete code coverage can be claimed"
                ),
                evidence=", ".join(unresolved_opaque[:20]),
                metadata={"members": unresolved_opaque},
            ))
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"android_binary_inventory:{exc}")
        report.metadata["runtime_escalation"] = {
            "required": True,
            "reasons": ["binary-inventory-failed"],
            "attempted": bool(try_runtime_extract and runtime_authorized),
            "physical_device_mandatory": False,
            "acceptable_runtime_targets": ["isolated-emulator", "authorized-test-device"],
        }
        report.status = "error"
        report.refusal_reasons.append(
            "binary/native routing inventory failed; IDA and downstream AI launch are refused"
        )

    # 4) runtime DEX extraction when any professional escalation signal fires.
    runtime_required = bool(report.metadata["runtime_escalation"]["required"])
    if try_runtime_extract and not runtime_authorized:
        report.steps_skipped.append("runtime_dex_extractor:authorization-required")
        if report.status == "completed":
            report.status = "partial"
        report.refusal_reasons.append(
            "runtime execution refused: a non-empty engagement authorization reference is required"
        )
    elif try_runtime_extract:
        if not package_name:
            report.runtime_extract_status = "missing_package"
            report.steps_skipped.append("runtime_dex_extractor:package-name-unavailable")
            report.refusal_reasons.append(
                "packed APK requires a verified package name before runtime extraction"
            )
        else:
            try:
                from src.execution.runtime_dex_extractor import extract_dex_runtime
                dex_result = extract_dex_runtime(
                    package_name,
                    serial=device_serial, wait_seconds=min(90, timeout_per_step),
                    apk_path=apk,
                    runtime_provider=runtime_provider,
                    runtime_api=runtime_api,
                    runtime_abi=runtime_abi,
                    runtime_image_tag=runtime_image_tag,
                    runtime_auto_provision=runtime_auto_provision,
                    runtime_sdk_root=runtime_sdk_root,
                    allow_native_translation=allow_native_translation,
                    runtime_network=runtime_network,
                )
                report.runtime_extract_status = dex_result.status
                report.metadata["runtime_extraction"] = dex_result.as_dict()
                if dex_result.runtime_surface:
                    report.metadata["runtime_surface"] = dict(dex_result.runtime_surface)
                report.steps_executed.append("runtime_dex_extractor")
                # Category-specific probe observations remain valid narrow
                # evidence even when the global workload/runtime coverage is
                # partial.  Preserve them independently; they never satisfy the
                # runtime-completeness gate by themselves.
                runtime_categories = list(
                    getattr(dex_result, "hook_plan_categories", [])
                )
                report.metadata["hook_plan_emitted"] = bool(
                    getattr(dex_result, "hook_script_path", "")
                    or runtime_categories
                )
                if getattr(dex_result, "hook_script_path", ""):
                    report.metadata["hook_plan_path"] = dex_result.hook_script_path
                report.metadata["hook_plan_categories"] = runtime_categories
                report.metadata["anti_tamper_probes"] = list(
                    getattr(dex_result, "anti_tamper_probes", [])
                )
                if dex_result.status == "ok" and dex_result.dumped_files:
                    report.metadata["runtime_dex_files"] = list(dex_result.dumped_files)
                if dex_result.status != "ok":
                    report.findings.append(AuditFinding(
                        module="runtime_dex_extractor", kind="extraction-skipped",
                        severity="medium", verdict=V_INCONCLUSIVE,
                        detail=(
                            f"runtime validation was requested but extraction failed: "
                            f"{dex_result.note} — downstream STATIC findings stay INCONCLUSIVE"
                        ),
                    ))
            except Exception as exc:  # noqa: BLE001
                report.steps_skipped.append(f"runtime_dex_extractor:{exc}")
                report.runtime_extract_status = "error"
                report.metadata["runtime_extraction"] = {
                    "status": "error", "error": type(exc).__name__
                }
    elif runtime_required:
        report.steps_skipped.append("runtime_dex_extractor:disabled")
        if report.status == "completed":
            report.status = "partial"
        report.refusal_reasons.append(
            "runtime escalation required but no emulator/device observation was requested; "
            "static findings remain useful but total code coverage is refused"
        )

    # 5) TLS stack + MTLS tier
    tls_layer = "unknown"
    try:
        from src.analysis.tls_stack_identifier import identify_tls_stack
        tls = identify_tls_stack(apk)
        tls_layer = tls.recommended_rule_layer
        report.tls_stack = tls.primary_stack
        report.steps_executed.append("tls_stack_identifier")
        report.findings.append(AuditFinding(
            module="tls_stack_identifier", kind="tls-stack",
            severity="info", verdict=V_LIKELY,
            detail=tls.note, evidence=tls.primary_stack,
        ))
        if tls.cert_pinning_likely:
            report.findings.append(AuditFinding(
                module="tls_stack_identifier", kind="pinning",
                severity="info", verdict=V_LIKELY,
                detail="certificate pinning likely present (OkHttp CertificatePinner)",
            ))
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"tls_stack_identifier:{exc}")

    # 6) manifest-driven rules (always safe: manifest is ground-truth)
    manifest_text = ""
    smali_blob = ""
    static_exported_components: list[dict] = []
    decode_workspace: tempfile.TemporaryDirectory[str] | None = None
    try:
        from src.analysis.apktool_bridge import decode_apk
        if persistent_artifacts is None:
            decode_workspace = tempfile.TemporaryDirectory(prefix="angerona-apktool-")
            decoded_root = Path(decode_workspace.name)
        else:
            decoded_root = persistent_artifacts / "apktool"
            decoded_root.mkdir(parents=True, exist_ok=True)
        apkt = decode_apk(
            apk,
            timeout=timeout_per_step,
            skip_sources=not run_rules,
            keep_output=decoded_root,
            deadline_monotonic=pre_ai_deadline,
        )
        manifest_text = apkt.manifest_xml if apkt.status in ("success", "partial") else ""
        static_exported_components = list(apkt.exported_components)
        if apkt.status in ("success", "partial"):
            report.steps_executed.append("apktool_bridge")
            if apkt.status == "partial" and report.status == "completed":
                report.status = "partial"
        else:
            report.steps_skipped.append(f"apktool_bridge:{apkt.status}:{apkt.note}")
        if run_rules and apkt.smali_dirs:
            smali_blob, smali_coverage = _load_smali_corpus(decoded_root, apkt.smali_dirs)
            report.metadata["smali_coverage"] = smali_coverage
            if smali_blob:
                report.steps_executed.append("smali-corpus")
            if smali_coverage["truncated"]:
                report.refusal_reasons.append(
                    "Smali corpus exceeded 64 MiB analysis budget; coverage is partial"
                )
                if report.status == "completed":
                    report.status = "partial"

        # Plain-text manifests in synthetic/test APKs are safe to use directly.
        # Binary AXML is not falsely represented as decoded XML when apktool is
        # missing or fails.
        if not manifest_text:
            try:
                with zipfile.ZipFile(apk) as zf:
                    raw = zf.read("AndroidManifest.xml")
                    candidate = raw.decode("utf-8", errors="strict").lstrip()
                    if candidate.startswith(("<?xml", "<manifest")):
                        manifest_text = candidate
                        if persistent_artifacts is not None:
                            # Keep the exact fallback witness available to the
                            # downstream file-by-file AI review. Apktool may
                            # leave an empty placeholder when it cannot parse a
                            # synthetic/plain-text manifest.
                            (decoded_root / "AndroidManifest.xml").write_text(
                                candidate, encoding="utf-8"
                            )
                        report.steps_executed.append("manifest-plain-xml-fallback")
            except (zipfile.BadZipFile, OSError, KeyError):
                pass
            except UnicodeDecodeError:
                report.steps_skipped.append("manifest-fallback:binary-axml-requires-decoder")

        if manifest_text:
            from src.analysis.allow_backup_check import scan_manifest_text
            backup = scan_manifest_text(manifest_text)
            for f in backup.findings:
                report.findings.append(_audit_from_finding(f))
            report.steps_executed.append("allow_backup_check")

            from src.analysis.deeplink_injection import scan_manifest_text as dl_scan
            dl = dl_scan(manifest_text)
            for f in dl_findings(dl):
                report.findings.append(_audit_from_finding(f, "deeplink_injection"))
            report.steps_executed.append("deeplink_injection")

            from src.analysis.contentprovider_traversal import (
                scan_manifest_text as cp_scan,
            )
            cp = cp_scan(manifest_text)
            for f in dl_findings(cp):
                report.findings.append(_audit_from_finding(f, "contentprovider_traversal"))
            report.steps_executed.append("contentprovider_traversal")
        else:
            report.steps_skipped.append("manifest-rules:no-manifest-xml")
        checkpoint("apktool_manifest", output=decoded_root)
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"apktool/manifest:{exc}")

    # Lossless per-DEX semantic witness.  Every magic-identified DEX is decoded
    # independently and its Smali class/method declarations must exactly match
    # the DEX class-data tables. JADX remains a readable, non-authoritative view.
    dex_semantic_results: list[dict] = []
    try:
        from src.analysis.dex_semantic import disassemble_dex

        if persistent_artifacts is not None:
            dex_semantic_root = persistent_artifacts / "dex_semantic"
        else:
            dex_semantic_workspace = tempfile.TemporaryDirectory(
                prefix="angerona-dex-semantic-"
            )
            dex_semantic_root = Path(dex_semantic_workspace.name)
        dex_semantic_root.mkdir(parents=True, exist_ok=True)
        semantic_targets = [
            dict(item)
            for item in report.metadata.get("embedded_code_targets", [])
            if item.get("format") == "dex"
        ]
        for runtime_path in report.metadata.get("runtime_dex_files", []):
            semantic_targets.append({
                "path": runtime_path,
                "format": "dex",
                "member": "runtime-recovered",
                "sha256": "",
                "runtime": True,
            })
        semantic_by_hash: dict[str, dict] = {}
        for index, target in enumerate(semantic_targets, start=1):
            candidate = Path(str(target.get("path", ""))).expanduser().resolve()
            if not candidate.is_file():
                dex_semantic_results.append({
                    **target, "status": "missing", "complete": False,
                })
                continue
            with candidate.open("rb") as candidate_stream:
                digest = hashlib.file_digest(candidate_stream, "sha256").hexdigest()
            cached_semantic = semantic_by_hash.get(digest)
            if cached_semantic is not None:
                dex_semantic_results.append({
                    **cached_semantic,
                    **target,
                    "path": str(candidate),
                    "sha256": digest,
                    "duplicate_of": str(cached_semantic.get("path", "")),
                })
                continue
            output_dir = dex_semantic_root / f"dex-{index:04d}-{digest}"
            semantic = disassemble_dex(
                candidate, output_dir, timeout=timeout_per_step,
                deadline_monotonic=pre_ai_deadline,
            )
            result_row = {
                **target,
                "path": str(candidate),
                "sha256": digest,
                **semantic,
            }
            dex_semantic_results.append(result_row)
            semantic_by_hash[digest] = dict(result_row)
        report.metadata["dex_semantic_coverage"] = {
            "targets_expected": len(dex_semantic_results),
            "targets_complete": sum(
                bool(item.get("complete")) for item in dex_semantic_results
            ),
            "target_results": dex_semantic_results,
        }
        checkpoint("dex_semantic", output=dex_semantic_root)
        if dex_semantic_results:
            report.steps_executed.append("dex_semantic_coverage")
        if any(not item.get("complete") for item in dex_semantic_results):
            if report.status == "completed":
                report.status = "partial"
            report.refusal_reasons.append(
                "per-DEX class/method Smali reconciliation is incomplete"
            )
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"dex_semantic_coverage:{exc}")
        report.metadata["dex_semantic_coverage"] = {
            "targets_expected": 0, "targets_complete": 0,
            "target_results": [], "error": type(exc).__name__,
        }
        if report.status == "completed":
            report.status = "partial"
        report.refusal_reasons.append(
            "per-DEX semantic coverage producer failed"
        )

    # JADX is a distinct high-level decompiler witness.  Its findings do not
    # become CONFIRMED merely because another static decoder saw the artifact.
    if run_rules:
        try:
            from src.analysis.jadx_bridge import analyze_apk
            jadx_targets = [("jadx_bridge", apk)]
            jadx_classes = 0
            jadx_target_results: list[dict] = []
            for index, target_info in enumerate(
                report.metadata.get("embedded_code_targets", []), start=1
            ):
                candidate = Path(str(target_info.get("path", "")))
                if candidate.is_file():
                    target_format = str(target_info.get("format", "code"))
                    jadx_targets.append((
                        f"jadx_bridge(embedded-{target_format}-{index})", candidate
                    ))
            for runtime_dex in report.metadata.get("runtime_dex_files", []):
                candidate = Path(runtime_dex)
                if candidate.is_file():
                    jadx_targets.append(("jadx_bridge(runtime-dex)", candidate))
            for module_name, target in jadx_targets:
                jadx_output = None
                if persistent_artifacts is not None:
                    safe_name = module_name.replace("(", "-").replace(")", "")
                    jadx_output = persistent_artifacts / safe_name
                jadx = analyze_apk(
                    target,
                    timeout=timeout_per_step,
                    keep_output=jadx_output,
                    deadline_monotonic=pre_ai_deadline,
                )
                jadx_target_results.append({
                    "module": module_name,
                    "target": str(Path(target).resolve()),
                    "status": jadx.status,
                    "classes_decompiled": jadx.classes_count,
                    "output": str(jadx_output.resolve()) if jadx_output is not None else "",
                    "note": jadx.note,
                })
                if jadx.status in ("success", "partial"):
                    report.steps_executed.append(module_name)
                    jadx_classes += jadx.classes_count
                    for finding in jadx.findings:
                        converted = _audit_from_finding(finding, module_name)
                        converted.verdict = V_LIKELY
                        report.findings.append(converted)
                else:
                    report.steps_skipped.append(f"{module_name}:{jadx.status}:{jadx.note}")
            report.metadata["jadx_coverage"] = {
                "targets": len(jadx_targets),
                "classes_decompiled": jadx_classes,
                "target_results": jadx_target_results,
                "dex_targets_expected": int(
                    report.metadata.get("dex_semantic_coverage", {}).get(
                        "targets_expected", 0
                    )
                ),
                "dex_targets_complete": int(
                    report.metadata.get("dex_semantic_coverage", {}).get(
                        "targets_complete", 0
                    )
                ),
            }
            checkpoint("jadx", output=persistent_artifacts)
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"jadx_bridge:{exc}")

    # A connected-device witness is authoritative for what the installed
    # package manager exposes.  Keep it separate from static manifest claims.
    if try_runtime_extract and package_name and "runtime_surface" not in report.metadata:
        try:
            from src.execution.adb_probe import query_runtime_surface
            runtime_surface = query_runtime_surface(
                package_name,
                serial=device_serial,
                timeout=min(timeout_per_step, 30),
            )
            report.metadata["runtime_surface"] = runtime_surface.as_dict()
            if runtime_surface.status != "ok":
                report.steps_skipped.append(
                    f"adb_runtime_surface:{runtime_surface.status}:{runtime_surface.note}"
                )
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"adb_runtime_surface:{exc}")

    runtime_surface_data = report.metadata.get("runtime_surface", {})
    if runtime_surface_data.get("status") == "ok":
        if "adb_runtime_surface" not in report.steps_executed:
            report.steps_executed.append("adb_runtime_surface")
        static_names = {
            _canonical_android_component(str(component.get("name", "")), package_name)
            for component in static_exported_components if component.get("name")
        }
        runtime_names = {
            _canonical_android_component(name, package_name)
            for key in (
                "exported_activities", "exported_services",
                "exported_receivers", "exported_providers",
            )
            for name in runtime_surface_data.get(key, [])
        }
        runtime_only = sorted(runtime_names - static_names)
        if runtime_only:
            report.findings.append(AuditFinding(
                module="adb_probe", kind="runtime-resolver-surface-delta",
                severity="medium", verdict=V_LIKELY,
                detail=(
                    "dumpsys resolver tables mention components absent from the static "
                    "decoded manifest; active permission-gate probing is required"
                ),
                runtime_corroborated=False, evidence=";".join(runtime_only),
                metadata={"runtime_only": runtime_only},
            ))

    if run_rules:
        try:
            from src.analysis.mtls_tier_classifier import classify_mtls_tier
            mtls = classify_mtls_tier(
                manifest_text=manifest_text,
                source_text=smali_blob,
                apk_path=apk,
            )
            report.metadata["mtls_tier"] = mtls.as_dict()
            report.steps_executed.append("mtls_tier_classifier")
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"mtls_tier_classifier:{exc}")

    # 7) TLS-layered rules (gated)
    if run_rules and tls_layer in ("java", "hybrid"):
        try:
            from src.analysis.cleartext_tls_rule import scan_manifest_text as tls_m
            tls_findings = tls_m(manifest_text) if manifest_text else None
            report.steps_executed.append("cleartext_tls_rule(java)")
            if tls_findings:
                for f in tls_findings.findings:
                    report.findings.append(AuditFinding(
                        module="cleartext_tls_rule", kind=f.get("kind", "tls"),
                        severity=f.get("severity", "medium"),
                        verdict=V_LIKELY if tls_layer == "java" else V_INCONCLUSIVE,
                        detail=f.get("detail", ""),
                    ))
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"cleartext_tls_rule:{exc}")
    elif run_rules:
        report.steps_skipped.append(
            f"cleartext_tls_rule:skipped layer={tls_layer} (Java rules not applicable on rustls/native)")

    # 7a) WebSocket cleartext rules (always run — fintech standard)
    if run_rules:
        try:
            from src.analysis.wss_cleartext_rule import scan_apk as wss_scan_apk
            wss = wss_scan_apk(apk)
            report.steps_executed.append("wss_cleartext_rule")
            for f in wss.findings:
                report.findings.append(AuditFinding(
                    module="wss_cleartext_rule", kind=f.kind,
                    severity=f.severity, verdict=f.verdict,
                    detail=f.detail, evidence=f.evidence,
                ))
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"wss_cleartext_rule:{exc}")

    # 7b) BROWSABLE implicit reachability
    if run_rules and manifest_text:
        try:
            from src.analysis.browsable_implicits import scan_manifest_text as br_scan
            br = br_scan(manifest_text)
            if br.status == "ok" and br.findings:
                report.steps_executed.append("browsable_implicits")
                for f in br.findings:
                    report.findings.append(AuditFinding(
                        module="browsable_implicits", kind=f.kind,
                        severity=f.severity, verdict=f.verdict,
                        detail=f.detail, evidence=f.evidence,
                    ))
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"browsable_implicits:{exc}")

    # 7c) Missing finding-producer wiring — major Android modules live feed.
    # （ ELITE-2 critique: pipeline never invoked logcat/webview/root/secrets
    #  modules; chain templates needed them for live chains. ）
    if run_rules:
        try:
            from src.analysis.dex_reflection_tracker import scan_smali_text as dref_scan
            from src.analysis.logcat_sensitive import scan_source_text as logcat_scan
            from src.analysis.webview_bridge_finder import scan_source_text as wb_scan
            if not smali_blob:
                report.steps_skipped.append(
                    "smali-corpus:unavailable (raw DEX is not valid Smali/source text)"
                )
            if smali_blob:
                from src.analysis.android_root_scanner import (
                    scan_smali_text as root_scan,
                )
                from src.analysis.hardware_keystore_detector import (
                    scan_source_text as ks_scan,
                )
                from src.analysis.http_cache_rule import scan_source_text as cache_scan
                from src.analysis.implicit_intent_finder import (
                    scan_source_text as implicit_scan,
                )
                from src.analysis.shared_prefs_secrets_finder import (
                    scan_source_text as prefs_scan,
                )
                from src.analysis.webview_settings_rule import (
                    scan_source_text as wv_scan,
                )

                producer_modules = (
                    ("logcat_sensitive", logcat_scan),
                    ("webview_bridge_finder", wb_scan),
                    ("dex_reflection_tracker", dref_scan),
                    ("shared_prefs_secrets_finder", prefs_scan),
                    ("http_cache_rule", cache_scan),
                    ("webview_settings_rule", wv_scan),
                    ("hardware_keystore_detector", ks_scan),
                    ("implicit_intent_finder", implicit_scan),
                    ("android_root_scanner", root_scan),
                )
                for mod_name, mod_fn in producer_modules:
                    try:
                        res = mod_fn(smali_blob)
                        for f in getattr(res, "findings", []) or []:
                            report.findings.append(_audit_from_finding(f, mod_name))
                    except Exception as exc:  # noqa: BLE001
                        report.steps_skipped.append(f"{mod_name}:{exc}")
                        continue
                try:
                    from src.analysis.dex_security_rules import (
                        run_security_rules_on_smali,
                    )
                    dex_rules = run_security_rules_on_smali(smali_blob)
                    for finding in dex_rules.get("findings", []):
                        report.findings.append(
                            _audit_from_finding(finding, "dex_security_rules")
                        )
                    report.metadata["dex_security_rule_summary"] = {
                        key: value for key, value in dex_rules.items() if key != "findings"
                    }
                    report.steps_executed.append("dex_security_rules")
                except Exception as exc:  # noqa: BLE001
                    report.steps_skipped.append(f"dex_security_rules:{exc}")
                try:
                    from src.analysis.smali_string_decrypt import decrypt_dex_strings
                    decryption = decrypt_dex_strings(smali_blob)
                    report.metadata["smali_string_decryption"] = decryption
                    report.steps_executed.append("smali_string_decrypt")
                except Exception as exc:  # noqa: BLE001
                    report.steps_skipped.append(f"smali_string_decrypt:{exc}")
            # FileProvider paths.xml read (res/xml/*paths*.xml) — direct config
            # path inspection instead of smali regex (ELITE-1's dead-code note)
            try:
                from src.analysis.file_provider_xml_check import scan_apk as fp_scan_apk
                fp_result = fp_scan_apk(apk)
                for f in getattr(fp_result, "findings", []) or []:
                    report.findings.append(_audit_from_finding(f, "file_provider_xml_check"))
            except Exception as exc:  # noqa: BLE001
                report.steps_skipped.append(f"file_provider_xml_check:{exc}")
            # native .so scans — iterate ALL libraries (alpha-arch holes from `break` were fatal)
            try:
                secrets_scanned_libs: list[str] = []
                anti_scanned_libs: set[str] = set()
                jni_inventory: dict[str, dict] = {}
                constructor_emulation: dict[str, dict] = {}
                from src.analysis.android_binary_inventory import MEMBER_LIMIT
                from src.analysis.jni_boundary_taint import scan_native_strings
                from src.analysis.jni_registration_resolver import (
                    resolve_jni_registration,
                )
                with zipfile.ZipFile(apk) as zf:
                    for info in zf.infolist():
                        name = info.filename
                        if not (name.startswith("lib/") and name.endswith(".so")):
                            continue
                        if info.file_size > MEMBER_LIMIT:
                            report.steps_skipped.append(
                                f"native-library:{name}:exceeds-"
                                f"{MEMBER_LIMIT // (1024 * 1024)}MiB-analysis-budget"
                            )
                            if report.status == "completed":
                                report.status = "partial"
                            report.refusal_reasons.append(
                                f"native library {name} exceeds configured deep-analysis budget"
                            )
                            continue
                        with zf.open(info) as member:
                            blob = member.read(MEMBER_LIMIT + 1)
                        try:
                            from src.analysis.native_secrets_hunter import (
                                scan_so_bytes as secrets_scan,
                            )
                            hops = secrets_scan(blob, source=name)
                            for h in hops:
                                report.findings.append(_audit_from_finding(h, "native_secrets_hunter"))
                            secrets_scanned_libs.append(name)
                        except Exception as exc:  # noqa: BLE001
                            report.steps_skipped.append(
                                f"native_secrets_hunter:{name}:{exc}"
                            )
                        try:
                            from src.analysis.native_anti_tamper_scanner import (
                                scan_so_bytes as at_scan,
                            )
                            at_result = at_scan(blob)
                            for s in getattr(at_result, "sites", []) or []:
                                report.findings.append(AuditFinding(
                                    module="native_anti_tamper_scanner",
                                    kind=s.category, severity=s.severity,
                                    verdict=V_LIKELY, detail=s.pattern,
                                    evidence=f"{name}@{s.offset:x}",
                                    metadata={"offset": s.offset, "uncorroborated": s.uncorroborated},
                                ))
                            anti_scanned_libs.add(name)
                        except Exception as exc:  # noqa: BLE001
                            report.steps_skipped.append(
                                f"native_anti_tamper_scanner:{name}:{exc}"
                            )
                        try:
                            registration = resolve_jni_registration(blob)
                            jni_inventory[name] = {
                                "status": registration.status,
                                "statically_named": registration.statically_named,
                                "dynamically_registered_count": registration.resolved_count,
                                "jni_onload_present": registration.jni_onload_present,
                                "registernatives_imported": registration.registernatives_imported,
                                "note": registration.note,
                            }
                            boundary = scan_native_strings(blob, source_name=name)
                            for finding in boundary.findings:
                                report.findings.append(
                                    _audit_from_finding(finding, "jni_boundary_taint")
                                )
                        except Exception as exc:  # noqa: BLE001
                            report.steps_skipped.append(f"jni-analysis:{name}:{exc}")
                        if packed:
                            try:
                                from src.analysis.constructor_pre_emulator import (
                                    emulate_constructors,
                                )
                                emulation = emulate_constructors(
                                    blob, max_steps=100_000, secrets_scan=True
                                )
                                constructor_emulation[name] = emulation.as_dict()
                            except Exception as exc:  # noqa: BLE001
                                report.steps_skipped.append(
                                    f"constructor_pre_emulator:{name}:{exc}"
                                )
                report.metadata["secrets_libs_scanned"] = secrets_scanned_libs
                report.metadata["anti_tamper_libs_scanned"] = sorted(anti_scanned_libs)
                report.metadata["jni_registration"] = jni_inventory
                report.metadata["constructor_pre_emulation"] = constructor_emulation
                if jni_inventory:
                    report.steps_executed.extend(
                        ["jni_registration_resolver", "jni_boundary_taint"]
                    )
                if constructor_emulation:
                    report.steps_executed.append("constructor_pre_emulator")
            except (zipfile.BadZipFile, OSError, KeyError):
                pass
            # assets_blob_detector
            try:
                from src.analysis.assets_blob_detector import scan_apk_assets
                assets = scan_apk_assets(apk)
                for f in getattr(assets, "candidates", []) or []:
                    report.findings.append(_audit_from_finding(f, "assets_blob_detector"))
            except Exception as exc:  # noqa: BLE001
                report.steps_skipped.append(f"assets_blob_detector:{exc}")
            report.steps_executed.append("missing-producers-wiring")
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"missing-producers-wiring:{exc}")

    # 7d) Cross-APK collusion detection
    if run_rules:
        # Only invoke when caller supplies multiple APKs to correlate;
        # a single-APK call otherwise produces silent no-op theatre.
        try:
            from src.analysis.cross_package_chain_analyzer import analyze_cross_package
            correlation_set = [apk, *(Path(p) for p in (related_apks or []))]
            if len(correlation_set) >= 2:
                r = analyze_cross_package(correlation_set)
                for g in r.groups:
                    for f in g.findings:
                        report.findings.append(_audit_from_finding(f, "cross_package_chain_analyzer"))
                report.steps_executed.append("cross_package_chain_analyzer")
            else:
                report.steps_skipped.append("cross_package_chain_analyzer:needs_multiple_apks")
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"cross_package_chain_analyzer:{exc}")

    # 7e) Optional trusted-upstream comparison supplied by the engagement.
    if run_rules and baseline_path:
        try:
            from src.analysis.upstream_source_differ import (
                diff_against_baseline,
                diff_to_findings,
            )
            source_diff = diff_against_baseline(apk, baseline_path)
            report.metadata["upstream_diff"] = source_diff.as_dict()
            if source_diff.status == "ok":
                report.steps_executed.append("upstream_source_differ")
                for finding in diff_to_findings(source_diff):
                    report.findings.append(
                        _audit_from_finding(finding, "upstream_source_differ")
                    )
            else:
                report.steps_skipped.append(
                    f"upstream_source_differ:{source_diff.status}:{source_diff.note}"
                )
        except Exception as exc:  # noqa: BLE001
            report.steps_skipped.append(f"upstream_source_differ:{exc}")

    # 8) structural/sec sanity (janus only when sdk<23)
    try:
        from src.analysis.janus_signature import check_apk
        j = check_apk(apk)
        if j.suspicious:
            report.steps_executed.append("janus_signature")
            report.findings.append(AuditFinding(
                module="janus_signature", kind="janus",
                severity="critical", verdict=V_CONFIRMED,
                detail=j.note, runtime_corroborated=False,
            ))
        else:
            report.steps_skipped.append("janus_signature:not-applicable")
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"janus_signature:{exc}")

    jadx_coverage = report.metadata.get("jadx_coverage", {})
    dex_gate = _dex_semantic_coverage(mdex, jadx_coverage)
    dex_inventory_complete = bool(dex_gate["inventory_complete"])
    expected_dex_targets = int(dex_gate["targets_expected"])
    complete_dex_targets = int(dex_gate["targets_complete"])
    dex_semantic_complete = bool(dex_gate["complete"])
    static_code_covered = dex_semantic_complete
    runtime_reasons = list(
        report.metadata.get("runtime_escalation", {}).get("reasons", [])
    )
    effective_runtime_reasons = list(runtime_reasons)
    if try_runtime_extract and not effective_runtime_reasons:
        effective_runtime_reasons.append("operator-requested-runtime")
    runtime_semantic_targets = [
        item
        for item in report.metadata.get("dex_semantic_coverage", {}).get(
            "target_results", []
        )
        if item.get("runtime")
    ]
    runtime_semantic_complete = bool(
        runtime_semantic_targets
        and all(item.get("complete") is True for item in runtime_semantic_targets)
    )
    runtime_transport_complete = bool(
        report.metadata.get("runtime_extraction", {})
        .get("runtime_target", {})
        .get("coverage", {})
        .get("complete") is True
    )
    runtime_resolution = {
        reason: bool(
            report.runtime_extract_status == "ok"
            and runtime_transport_complete
            and runtime_semantic_complete
            and reason in {"packer-detected", "operator-requested-runtime"}
        )
        for reason in effective_runtime_reasons
    }
    effective_runtime_required = bool(runtime_required or try_runtime_extract)
    runtime_complete = bool(
        not effective_runtime_required
        or (runtime_resolution and all(runtime_resolution.values()))
    )
    report.metadata["runtime_resolution"] = runtime_resolution
    report.metadata["coverage_gate"] = {
        "manifest_decoded": bool(manifest_text),
        "static_code_covered": static_code_covered,
        "dex_inventory_complete": dex_inventory_complete,
        "dex_semantic_complete": dex_semantic_complete,
        "dex_targets_expected": expected_dex_targets,
        "dex_targets_complete": complete_dex_targets,
        "dex_members": list(report.metadata.get("dex_inventory", {}).get("dex_files", [])),
        "smali_bytes": report.metadata.get("smali_coverage", {}).get("bytes_read", 0),
        "jadx_classes": report.metadata.get("jadx_coverage", {}).get(
            "classes_decompiled", 0
        ),
        "origin_anchored": report.provenance_verdict == "verified",
        "runtime_required": effective_runtime_required,
        "runtime_requested": bool(try_runtime_extract),
        "runtime_complete": runtime_complete,
        "runtime_reasons": effective_runtime_reasons,
        "runtime_resolution": runtime_resolution,
        "runtime_transport_complete": runtime_transport_complete,
        "runtime_semantic_complete": runtime_semantic_complete,
    }
    if run_rules and (not manifest_text or not static_code_covered):
        if report.status == "completed":
            report.status = "partial"
        missing_coverage = []
        if not manifest_text:
            missing_coverage.append("decoded manifest")
        if not static_code_covered:
            missing_coverage.append("Smali/JADX code corpus")
        report.refusal_reasons.append(
            "coverage gate incomplete: " + ", ".join(missing_coverage)
        )

    # 9) refusal policy on packed apps: when runtime DEX extraction was
    # attempted and came back empty/no_process, every STATIC finding from
    # the rule-scanner layer gets downgraded to INCONCLUSIVE.  Structural
    # facts (origin, dex-inventory, packer-id) stay CONFIRMED — they're not
    # security verdicts.
    # (a) When packer DETECTION itself fails (packer_failed=True), refuse to
    # emit positive verdicts on anything non-structural — treat as untrusted.
    # (b) Packed + extraction failed: downgrade still applies.
    runtime_incomplete = effective_runtime_required and not runtime_complete
    if packer_failed or runtime_incomplete:
        if report.status == "completed":
            report.status = "partial"
        downgraded = 0
        for f in report.findings:
            if (not f.runtime_corroborated
                    and f.verdict in (V_LIKELY, V_CONFIRMED)
                    and f.kind not in ("dex-inventory", "origin", "packer-identified")):
                f.verdict = V_INCONCLUSIVE
                downgraded += 1
        reason = (
            "packer-detection failure — all findings treated as untrusted"
            if packer_failed else
            f"runtime escalation with incomplete extraction "
            f"(status={report.runtime_extract_status or 'not-attempted'}) — "
            f"{downgraded} static findings downgraded to INCONCLUSIVE"
        )
        if reason not in report.refusal_reasons:
            report.refusal_reasons.append(reason)

    # 10.5) Double-attest — require 2+ independent witness streams before
    #  any runtime_corroborated upgrade. (ELITE-2 C-2 hardening)
    #
    # Wire real static witnesses into attest() so the 2-witness threshold is
    # meaningfully reachable — not a theatre checkbox:
    #   (a) static anti-tamper sites (native_anti_tamper_scanner static evidence)
    #   (b) static-runtime bridge hook plan (a hook script was actually emitted)
    #   (c) frida_hook_planned via runtime_dex_extractor's instrumentation plan
    try:
        from src.analysis.runtime_attestation import attest
        # Aggregate every distinct anti-tamper evasion class found on the APK.
        # Each category is an independent witness stream; a single finding's
        # kind is one class, but the double-attest bar needs a second class.
        all_tamper_sites: list[dict] = []
        for af in report.findings:
            if af.module == "native_anti_tamper_scanner":
                all_tamper_sites.append({
                    "offset": af.metadata.get("offset", 0),
                    "category": af.kind,
                })
        frida_plan = report.metadata.get("hook_plan_emitted", False)
        # Evidentiary content for the frida runtime witness (ELITE-2 verdict
        # round-5): the anti-tamper categories whose on-device probe observed
        # survival, recorded by the runtime DEX extractor.  An empty list means
        # the hook ran but no probe survived (or the agent has no probe) — the
        # frida witness is then a runtime-availability signal, NOT survival
        # corroboration for the anti-tamper finding.
        frida_cats = report.metadata.get("hook_plan_categories", []) or []
        for f in report.findings:
            narrow_runtime_probe = bool(
                f.module == "native_anti_tamper_scanner" and f.kind in frida_cats
            )
            if f.verdict not in (V_LIKELY, V_CONFIRMED) and not narrow_runtime_probe:
                continue
            # For a native_anti_tamper finding, attest against the full evasion
            # surface (all categories); for other findings, only their own hints.
            if f.module == "native_anti_tamper_scanner":
                static_sites = list(all_tamper_sites)
            else:
                static_sites = list(f.metadata.get("native_elf_hints") or [])

            # witness 2: REAL frida hook plan, emitted when runtime DEX
            # extraction actually wrote a hook script (not theoretical).
            # This is the SINGLE live runtime stream in the current pipeline
            # (stalker_hits and device_available are not wired — see the
            # runtime_attestation module docstring for the honest model).
            # ``frida_witness_categories`` carries the evidentiary content that
            # binds the witness to the specific finding kind it corroborates.
            a = attest(
                finding_module=f.module,
                finding_kind=f.kind,
                static_native_sites=static_sites,
                stalker_hits=[],
                frida_hook_planned=frida_plan,
                frida_witness_categories=frida_cats,
                device_available=False,
            )
            f.metadata["double_attest"] = a.as_dict()
            if a.is_corroborated:
                f.runtime_corroborated = True
                f.metadata["double_attest_upgrade"] = True
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"double-attest:{exc}")

    # 10.6) Build composite chains only after individual findings have passed
    # runtime attestation, so chain verdicts cannot outrun their links.
    try:
        from src.analysis.attack_chain_scorer import build_attack_chains
        chain_res = build_attack_chains(
            report.findings,
            require_entity_binding=True,
        )
        unbound_candidate = False
        if not chain_res.chains:
            # Preserve recall as explicitly INCONCLUSIVE candidates.  They are
            # never promoted to an exploit chain without a shared component,
            # method, path, or other source/sink entity identity.
            chain_res = build_attack_chains(report.findings)
            unbound_candidate = True
        report.steps_executed.append("attack_chain_scorer")
        for chain in chain_res.chains:
            report.findings.append(AuditFinding(
                module="attack_chain_scorer", kind=f"chain:{chain.chain_id}",
                severity=chain.severity,
                verdict=V_INCONCLUSIVE if unbound_candidate else chain.verdict,
                detail=(
                    f"UNBOUND CHAIN CANDIDATE: {chain.name} — {chain.description}"
                    if unbound_candidate else
                    f"ATTACK CHAIN: {chain.name} — {chain.description}"
                ),
                evidence="; ".join(f"{link.module}:{link.kind}" for link in chain.links),
                metadata={
                    "chain_id": chain.chain_id,
                    "links": len(chain.links),
                    "entity_binding": "missing" if unbound_candidate else "verified",
                },
            ))
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"attack_chain_scorer:{exc}")

    # 11) replay-bundle packaging — courtroom-grade audit trail
    try:
        from src.analysis.finding import Finding
        from src.analysis.finding_evidence import build_replay_bundle
        bundles = []
        report.metadata["replay_bundles"] = []  # initialize — must exist even if loop fails
        # Courtroom confidence card: per-finding verdict + module version +
        # evidence-hash so replay can be independently verified.
        report.metadata["confidence_card"] = []
        # Hash the APK ONCE for the whole batch.  build_replay_bundle binds the
        # bundle to apk_sha256 (a signed canonical-payload field), so re-hashing
        # the file per finding is pure waste — on a large APK with tens of
        # thousands of findings it turned the packaging step into an O(N×|APK|)
        # multi-hour CPU stall with no progress output.
        apk_identity_hash = ""
        apk_identity_size = 0
        try:
            with open(apk, "rb") as _apk_stream:
                apk_identity_hash = hashlib.file_digest(
                    _apk_stream, "sha256"
                ).hexdigest()
            apk_identity_size = Path(apk).stat().st_size
        except OSError:
            pass
        for f in report.findings:
            wrapper = Finding(
                module=f.module, kind=f.kind, severity=f.severity,
                verdict=f.verdict, detail=f.detail, evidence=f.evidence,
                runtime_corroborated=f.runtime_corroborated, metadata=f.metadata,
            )
            bundles.append(build_replay_bundle(
                apk_path=apk, finding=wrapper,
                module_version="angerona-android-audit/1.0.0",
                apk_sha256=apk_identity_hash, apk_size=apk_identity_size,
            ))
            report.metadata["confidence_card"].append({
                "module": f.module,
                "kind": f.kind,
                "verdict": f.verdict,
                "severity": f.severity,
                "module_version": "angerona-android-audit/1.0.0",
                "evidence_sha256": __import__("hashlib").sha256(
                    (f.evidence or "").encode("utf-8", "replace")
                ).hexdigest()[:32],
                "runtime_corroborated": f.runtime_corroborated,
            })
        report.metadata["replay_bundles"] = [b.as_dict() for b in bundles]
        report.steps_executed.append("finding_evidence")
        checkpoint("finding_evidence", output=persistent_artifacts)
    except Exception as exc:  # noqa: BLE001
        report.steps_skipped.append(f"finding_evidence:{exc}")

    if decode_workspace is not None:
        decode_workspace.cleanup()
    if binary_payload_workspace is not None:
        binary_payload_workspace.cleanup()
    if dex_semantic_workspace is not None:
        dex_semantic_workspace.cleanup()
    report.duration_s = time.time() - start
    return report
