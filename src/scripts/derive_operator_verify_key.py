from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def _strict(path: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise ValueError(f"path is not absolute: {raw}")
    lexical = Path(os.path.abspath(raw))
    resolved = raw.resolve(strict=raw.exists())
    if lexical != resolved:
        raise ValueError(f"symlinked path is forbidden: {raw}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description="Derive a pinned Ed25519 public verify key")
    parser.add_argument("--signing-seed", required=True)
    parser.add_argument("--output-public-key", required=True)
    parser.add_argument("--forbid-root", action="append", default=[])
    args = parser.parse_args()

    from nacl.signing import SigningKey  # type: ignore

    seed_path = _strict(args.signing_seed)
    output = _strict(args.output_public_key)
    if seed_path == output:
        raise ValueError("signing seed and public verify key paths must differ")
    for value in args.forbid_root:
        root = _strict(value)
        try:
            output.relative_to(root)
        except ValueError:
            continue
        raise ValueError(f"public verify key is inside forbidden audit root: {root}")
    seed = seed_path.read_bytes()
    if len(seed) < 32:
        raise ValueError("Ed25519 signing seed is shorter than 32 bytes")
    public = bytes(SigningKey(seed[:32]).verify_key)
    if output.exists():
        if output.read_bytes() != public:
            raise ValueError("public verify key already exists with different bytes")
        os.chmod(output, 0o400)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, public)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(output, 0o400)
        directory_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    key_id = hashlib.sha256(public).hexdigest()[:16]
    print(json.dumps({
        "schema": "angerona/operator-verify-key/v1",
        "path": str(output),
        "bytes": len(public),
        "sha256": hashlib.sha256(public).hexdigest(),
        "key_id": key_id,
        "mode": oct(output.stat().st_mode & 0o777),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
