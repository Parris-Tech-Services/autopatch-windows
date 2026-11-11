#!/usr/bin/env python3
"""Disposable file-level restore drill; NEVER proof of whole-OS rollback.

Copies a locally available backup file to a temporary directory, confirms the
bytes match the recorded original, and removes the temporary copy. No system
packages, settings, restore points or running services are touched. This cannot
satisfy AutoPatch's separate system-recovery gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import os
import sys

LIMIT = 16 * 1024 * 1024


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(65536)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def drill(original: Path, backup: Path) -> dict:
    out = {"stage": "BLOCKED", "file_restore_tested": False,
           "os_rollback_verified": False, "patch_authorised": False,
           "message": "file recovery was not demonstrated"}
    for p in (original, backup):
        if p.is_symlink() or not p.is_file():
            out["message"] = "source or backup missing or unsafe"
            return out
        try:
            size = p.stat().st_size
        except OSError:
            out["message"] = "source or backup unavailable"
            return out
        if size <= 0 or size > LIMIT:
            out["message"] = "file outside bounded test size"
            return out
    try:
        original_hash = digest(original)
        backup_hash = digest(backup)
        if original_hash != backup_hash:
            out["message"] = "backup checksum differs from original"
            return out
        with tempfile.TemporaryDirectory(prefix="autopatch-file-restore-") as tmp:
            restored = Path(tmp) / "restored.bin"
            shutil.copyfile(backup, restored, follow_symlinks=False)
            if digest(restored) != original_hash:
                out["message"] = "restored bytes differ"
                return out
        return {"stage": "FILE_RESTORE_TEST_PASS_OS_RECOVERY_UNVERIFIED",
                "file_restore_tested": True,
                "os_rollback_verified": False,
                "patch_authorised": False,
                "source_sha256": original_hash, "backup_sha256": backup_hash,
                "size_bytes": original.stat().st_size,
                "message": "test file restored in temporary directory; system-level snapshot or rollback NOT verified"}
    except (OSError, ValueError):
        out["message"] = "file restore check could not complete"
        return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original", required=True, type=Path)
    p.add_argument("--backup", required=True, type=Path)
    p.add_argument("--owned-personal-device", action="store_true",
                   help="Only run against data you own or are authorised to test")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    if not args.owned_personal_device:
        p.error("file restore drill requires explicitly authorised personal device scope")
    result = drill(args.original, args.backup)
    if args.out.is_symlink():
        p.error("report path must not be a symlink")
    mask = os.umask(0o077)
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        args.out.chmod(0o600)
    finally:
        os.umask(mask)
    print(json.dumps({"stage": result["stage"], "patch_authorised": False}))
    return 0 if result["file_restore_tested"] else 2


if __name__ == "__main__":
    sys.exit(main())
