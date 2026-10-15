"""Build exact DEX/JNI/native graph."""

from __future__ import annotations

import argparse
import json

from ..analysis.cross_layer_graph import build_cross_layer_graph


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smali-root", required=True)
    parser.add_argument("--dex-receipt-root", required=True)
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = build_cross_layer_graph(
        args.smali_root, args.dex_receipt_root, args.audit_root, args.output_dir,
    )
    print(json.dumps({
        key: result[key] for key in (
            "dex_methods", "native_libraries", "invoke_sites", "jni_edges",
            "pending_work_units", "all_invoke_sites_accounted",
            "all_native_declarations_dispositioned", "graph_complete", "manifest_sha256",
        )
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
