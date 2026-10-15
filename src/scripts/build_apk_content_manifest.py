"""Build the authoritative APK content manifest."""

from __future__ import annotations

import argparse
import json

from ..analysis.apk_content_manifest import build_apk_content_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    manifest = build_apk_content_manifest(args.apk, args.output_dir)
    print(json.dumps({
        "apk_sha256": manifest["apk_sha256"],
        "entry_count": manifest["entry_count"],
        "duplicate_name_entries": manifest["duplicate_name_entries"],
        "archive_byte_partition_complete": manifest["archive_byte_partition_complete"],
        "pending_work_units": manifest["pending_work_units"],
        "exhaustive_accounting": manifest["exhaustive_accounting"],
        "manifest_sha256": manifest["manifest_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
