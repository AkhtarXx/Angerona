from __future__ import annotations

import argparse
import json

from src.analysis.audit_lineage import load_audit_epoch
from src.analysis.reverse_knowledge_pack import (
    PINNED_UPSTREAM_COMMIT, import_knowledge_snapshot, knowledge_pack_status,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import/verify a pinned data-only RE methodology pack")
    sub = parser.add_subparsers(dest="command", required=True)
    importer = sub.add_parser("import")
    importer.add_argument("--source-root", required=True)
    importer.add_argument("--output-dir", required=True)
    importer.add_argument("--audit-epoch", required=True)
    importer.add_argument("--expected-commit", default=PINNED_UPSTREAM_COMMIT)
    importer.add_argument("--path", action="append", default=[])
    for name in ("verify", "status"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", required=True)
        command.add_argument("--audit-epoch", required=True)
        command.add_argument("--source-root")
    args = parser.parse_args()
    if args.command == "import":
        result = import_knowledge_snapshot(
            source_root=args.source_root, output_dir=args.output_dir,
            audit_epoch=args.audit_epoch, expected_commit=args.expected_commit,
            paths=args.path or None,
        )
    else:
        epoch = load_audit_epoch(args.audit_epoch)
        manifest = {"path": args.manifest}
        from src.analysis.signed_artifact_io import sha256_bytes
        from pathlib import Path
        manifest["sha256"] = sha256_bytes(Path(args.manifest).resolve(strict=True).read_bytes())
        result = knowledge_pack_status(
            manifest, epoch["trusted_read_roots"], source_root=args.source_root,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
