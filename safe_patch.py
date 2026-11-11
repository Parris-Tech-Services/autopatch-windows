#!/usr/bin/env python3
"""Opt-in, local-only Windows/Fedora SINGLE-PACKAGE update with fail-closed gates.

NO service, scheduler, remote access, privilege escalation, firmware, drivers,
Windows OS updates, or automatic reboot. The existing UI remains read-only.
Does NOT claim CVE resolution: package version + fresh scan are separate facts.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import device_status

PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,95}$")
BLOCKED_PREFIXES = ("kernel", "grub", "shim", "fwupd", "systemd", "glibc", "linux-firmware", "nvidia", "akmod")
BLOCKING = ("joshrs", "deepseek", "vboxheadless", "virtualboxvm")
MAX_STATUS_AGE = timedelta(minutes=60)

class Blocked(ValueError): pass

def run(command, timeout=300):
    try:
        r = subprocess.run(command, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=timeout, check=False)
        return r.returncode, r.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""

def stamp(raw):
    try:
        date = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if date.tzinfo is None: raise ValueError()
        return date.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        raise Blocked("missing or invalid timestamp") from None

def gate(policy, status, package, *, approved_inventory=None, system=None, hostname=None, now=None,
         backup_exists=lambda p: Path(p).is_file(), free_gb=None):
    system = system or platform.system().lower()
    hostname = hostname or platform.node()
    now = now or datetime.now(timezone.utc)
    errors = []
    need = lambda cond, reason: None if cond else errors.append(reason)
    need(system in ("windows", "linux"), "unsupported OS")
    need(isinstance(policy, dict), "policy missing")
    if not isinstance(policy, dict):
        return {"decision":"DENY", "reasons":errors}
    need(policy.get("device_class") == system, "OS mismatch")
    need(policy.get("hostname") == hostname, "machine identity mismatch")
    need(policy.get("ownership") == "personal", "not explicitly personal")
    need(policy.get("employer_managed") is False, "work/client management not excluded")
    need(policy.get("patching_enabled") is True, "patching not opted in")
    receipt = approved_inventory if isinstance(approved_inventory, dict) else {}
    need(receipt.get("device_id") == policy.get("device_id")
         and receipt.get("device_class") == system
         and receipt.get("hostname") == hostname, "approved device identity missing")
    need(receipt.get("status") == "enrolled_readonly"
         and receipt.get("permissions") == ["inventory_read"]
         and receipt.get("auto_patch") is False
         and receipt.get("remote_control") is False, "approved inventory is not read-only")
    need(policy.get("auto_restart") is False, "automatic restart is forbidden")
    need(policy.get("reboot_approved") is False, "reboot approval must remain false here")
    need(bool(PKG.fullmatch(package)), "invalid package id")
    need(not package.lower().startswith(BLOCKED_PREFIXES), "core/firmware/driver patch excluded")
    try:
        problems = device_status.validate(status)
        need(not problems, "invalid status document")
        dev = status.get("device") or {}
        need(dev.get("id") == policy.get("device_id") and dev.get("class") == system,
             "status device mismatch")
        need(dev.get("label") == hostname[:40], "status hostname mismatch")
        collected = stamp(status.get("collected_utc"))
        need(timedelta(0) <= now-collected <= MAX_STATUS_AGE, "status stale or future")
        need((status.get("updates") or {}).get("reboot_required") is False,
             "reboot status unknown or pending")
    except (Blocked, TypeError):
        errors.append("status age or structure not proven")
    approved = (policy.get("packages") or {}).get(package)
    need(isinstance(approved, dict), "package not allowlisted")
    if isinstance(approved, dict):
        need(approved.get("update_kind") == "security", "not explicitly classified as security")
        need(bool(PKG.fullmatch(str(approved.get("from_version","")))), "old version missing")
        need(bool(PKG.fullmatch(str(approved.get("to_version","")))), "target version missing")
        need(approved.get("from_version") != approved.get("to_version"), "no version change")
    need((free_gb if free_gb is not None else shutil.disk_usage(Path.home().anchor or "/").free / 2**30) >= 10,
         "insufficient free disk")
    window = policy.get("window") or {}
    try:
        local = now.astimezone(timezone.utc if window["timezone"] == "UTC" else ZoneInfo(window["timezone"]))
        start = window["start"]
        end = window["end"]
        need(re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", start) is not None,
             "invalid start time")
        need(re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", end) is not None,
             "invalid end time")
        # Initial rollout deliberately disallows midnight-spanning windows.
        need(start < end and start <= local.strftime("%H:%M") < end and
             local.weekday() in window["weekdays"], "outside maintenance window")
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError):
        errors.append("invalid maintenance window")
    backup = policy.get("backup") or {}
    try:
        need(backup.get("verified") is True and backup.get("restore_tested") is True,
             "backup or restore not verified")
        need(backup_exists(backup["evidence_file"]), "backup evidence missing")
        need(timedelta(0) <= now-stamp(backup["verified_utc"]) <= timedelta(hours=24),
             "backup evidence stale")
        need(bool(backup.get("rollback_plan")), "rollback plan missing")
    except (KeyError, TypeError, Blocked):
        errors.append("backup evidence invalid")
    return {"decision": "DENY" if errors else "ALLOW", "reasons": errors}

def version(command_runner, system, package):
    if system == "linux":
        rc, out = command_runner(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", package])
        return out.strip() if rc == 0 and re.fullmatch(r"[A-Za-z0-9._+~-]+", out.strip()) else None
    rc, out = command_runner(["winget", "list", "--id", package, "--exact",
                               "--disable-interactivity"])
    if rc != 0: return None
    for line in out.splitlines():
        cols = line.strip().split()
        for index, col in enumerate(cols[:-1]):
            if col.casefold() == package.casefold():
                candidate = cols[index+1]
                if PKG.fullmatch(candidate) and candidate.lower() not in ("version","available"):
                    return candidate
    return None

def apply(policy, status, package, *, approved_inventory=None, apply_change=False, system=None, hostname=None,
          now=None, command_runner=run, backup_exists=lambda p: Path(p).is_file(),
          free_gb=None):
    system = system or platform.system().lower()
    decision = gate(policy, status, package, approved_inventory=approved_inventory, system=system, hostname=hostname,
                    now=now, backup_exists=backup_exists, free_gb=free_gb)
    if decision["decision"] != "ALLOW":
        return {"status": "BLOCKED", "reasons": decision["reasons"], "changed": False}
    # A healthy status document alone is not enough: local processes may be active.
    # Read full command lines, not only process basenames: JoshRS frequently
    # runs under node/java and would otherwise be missed by a "comm" check.
    cmd = (["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine"]
           if system == "windows" else ["ps", "-eo", "args"])
    rc, procs = command_runner(cmd)
    if rc != 0 or any(name in procs.lower() for name in BLOCKING):
        return {"status": "BLOCKED_ACTIVE_OR_UNKNOWN_PROCESSES", "changed": False}
    allow = policy["packages"][package]
    before = version(command_runner, system, package)
    if before != allow["from_version"]:
        return {"status": "BLOCKED_VERSION_MISMATCH", "changed": False}
    if not apply_change:
        return {"status": "READY_DRY_RUN", "package": package,
                "from_version": before, "to_version": allow["to_version"], "changed": False}
    if system == "windows":
        command = ["winget", "upgrade", "--id", package, "--exact",
                   "--version", allow["to_version"], "--silent",
                   "--disable-interactivity", "--accept-package-agreements",
                   "--accept-source-agreements"]
    else:
        command = ["dnf", "upgrade", "--security", "-y",
                   "--setopt=install_weak_deps=False",
                   "--exclude=kernel*", "--exclude=grub*", "--exclude=shim*",
                   "--exclude=linux-firmware*", package]
    rc, _ = command_runner(command)
    after = version(command_runner, system, package)
    if rc != 0 or after != allow["to_version"]:
        return {"status":"BLOCKED_UNVERIFIED_REVIEW_ROLLBACK", "changed": True,
                "package":package, "before_version":before, "after_version":after}
    return {"status":"PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED", "changed": True,
            "package":package, "before_version":before, "after_version":after}

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--status", type=Path, required=True)
    p.add_argument("--approved-inventory", type=Path, required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--apply", action="store_true", help="Explicitly execute the approved local patch")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        pol = json.loads(a.policy.read_text(encoding="utf8"))
        st = json.loads(a.status.read_text(encoding="utf8"))
        receipt = json.loads(a.approved_inventory.read_text(encoding="utf8"))
        outcome = apply(pol, st, a.package, approved_inventory=receipt, apply_change=a.apply)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(outcome, indent=2)+"\n", encoding="utf8")
        a.out.chmod(0o600)
        print(json.dumps(outcome))
        return 0 if outcome["status"] in ("READY_DRY_RUN", "PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED") else 2
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("BLOCKED: "+type(exc).__name__+": "+str(exc), file=sys.stderr)
        return 2
if __name__ == "__main__":
    sys.exit(main())
