#!/usr/bin/env python3
"""OS update gate: may an OS-NATIVE security update be applied to an enrolled device now? Decision only; applies nothing.

Encodes Josh's rules: native security updates only, never firmware or feature upgrades, never while his work is
running (JoshRS servers, DeepSeek sessions), only inside a maintenance window, only with a backup and a
pre-check, only on an enrolled device. A reboot needs explicit prior approval. Missing information is DENY.
Android and iOS are never gated here: only the vendor updates those (AutoPatch just verifies).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

NATIVE_MECHANISMS = {"windows_update", "softwareupdate", "apt_unattended_upgrades", "dnf_automatic"}
SAFE_KINDS = {"security"}
NEVER_AUTOMATIC = {"firmware", "bios", "feature_upgrade", "kernel_major", "driver"}
BLOCKING_PROCESSES = {"joshrs", "deepseek", "termux-session"}


def check(req: dict) -> dict:
    deny = []
    need = lambda ok, why: None if ok else deny.append(why)
    need(req.get("os") in {"windows", "macos", "linux"}, f"os {req.get('os')!r} is not gated here (Android/iOS update only through their vendor)")
    need(req.get("enrolled") is True, "device is not enrolled")
    need(req.get("mechanism") in NATIVE_MECHANISMS, f"mechanism {req.get('mechanism')!r} is not the OS's own updater")
    kind = req.get("update_kind")
    need(kind not in NEVER_AUTOMATIC, f"{kind} updates are never automatic")
    need(kind in SAFE_KINDS, f"update kind {kind!r} is not a security update")
    need(req.get("in_maintenance_window") is True, "outside the maintenance window")
    need(req.get("backup_taken") is True, "no verified backup or restore point")
    need(req.get("precheck_ok") is True, "pre-check (disk space, battery/power, health) did not pass")
    running = {p.lower() for p in (req.get("running_processes") or [])} & BLOCKING_PROCESSES
    need(not running, f"Josh's work is running: {', '.join(sorted(running))}")
    if req.get("requires_reboot"):
        need(req.get("reboot_approved") is True, "needs a reboot and a reboot was not approved in advance")
    need(req.get("rollback_plan") not in (None, ""), "no rollback plan recorded")
    return {"decision": "DENY" if deny else "ALLOW", "reasons": deny or ["every gate condition holds"], "device": req.get("device")}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", required=True, type=Path)
    a = p.parse_args(argv)
    try:
        r = check(json.loads(a.request.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as exc:
        print(f"BLOCKED: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(r, indent=2))
    return 0 if r["decision"] == "ALLOW" else 1


if __name__ == "__main__":
    sys.exit(main())
