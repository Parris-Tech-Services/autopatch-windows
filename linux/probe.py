"""Read-only Linux (Fedora first) posture probe. Every read goes through run(cmd), so it is testable with fakes.
A probe that fails returns None, which becomes `unknown`, never a pass and never an invented failure."""
from __future__ import annotations

import os
import platform
import time
import shutil
import subprocess
from datetime import date

PATCHERS = ("dnf5-automatic.timer", "dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic-install.timer")
MIN_FREE_GB = 10.0


TIMED_OUT = 124
T_SLOW = 180  # dnf may need to refresh package lists over a slow network
T_FAST = 20
T_CACHE = 60


def run_cmd(cmd, timeout=T_FAST):
    """Real runner. A missing tool is 127, a timeout is 124; neither raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout or ""
    except subprocess.TimeoutExpired:
        return TIMED_OUT, ""
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def parse_os_release(text):
    out = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def count_update_lines(text):
    """dnf check-update prints `name.arch  version  repo` per package."""
    n = 0
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and "." in parts[0] and not line.startswith(("Obsoleting", "Security:", " ")):
            n += 1
    return n


def _first_line(rc, out):
    return out.strip().splitlines()[0].strip() if rc == 0 and out.strip() else None


def collect(run=run_cmd, read=read_text, free_gb=None, progress=None, offline=False):
    raw = {"timed_out": []}

    def call(label, cmd, timeout=T_FAST):
        """Run one read-only command, report start and finish, and note a timeout."""
        if progress:
            progress("start", label, cmd, None, None)
        began = time.monotonic()
        rc, out = run(cmd, timeout)
        if rc == TIMED_OUT:
            raw["timed_out"].append(label)
        if progress:
            progress("done", label, cmd, rc, round(time.monotonic() - began, 1))
        return rc, out

    osr = parse_os_release(read("/etc/os-release"))
    raw["os_name"] = osr.get("PRETTY_NAME") or "Linux"
    raw["os_id"] = osr.get("ID")
    raw["support_end"] = osr.get("SUPPORT_END")
    raw["kernel"] = platform.release()
    raw["hostname"] = platform.node()
    raw["is_root"] = hasattr(os, "geteuid") and os.geteuid() == 0

    # Offline first: the system's own package cache answers in seconds. Only if there is no usable cache do we
    # let dnf refresh over the network, which can take minutes on a slow connection.
    rc, out = call("Checking security updates from the local package cache", ["dnf", "-q", "--cacheonly", "check-update", "--security"], T_CACHE)
    raw["has_dnf"] = rc != 127
    raw["updates_source"] = "cache"
    if rc not in (0, 100) and rc != 127 and not offline:
        raw["updates_source"] = "network"
        rc, out = call("Checking for security updates (refreshing package lists over the network)", ["dnf", "-q", "check-update", "--security"], T_SLOW)
    raw["security_updates"] = 0 if rc == 0 else count_update_lines(out) if rc == 100 else None

    rc, out = call("Checking if a restart is needed (dnf)", ["dnf", "needs-restarting", "-r"], T_SLOW)
    raw["reboot_required"] = True if rc == 1 else False if rc == 0 else None

    raw["selinux"] = _first_line(*call("Reading SELinux mode", ["getenforce"]))

    rc, out = call("Checking the firewall", ["systemctl", "is-active", "firewalld"])
    if rc == 127:
        raw["firewall_active"] = None
    elif out.strip() == "active":
        raw["firewall_active"] = True
    else:
        urc, uout = call("Checking ufw", ["ufw", "status"])
        frc, _ = call("Checking firewall-cmd", ["firewall-cmd", "--state"])
        if urc == 0 and "Status: active" in uout:
            raw["firewall_active"] = True
        elif urc == 127 and frc == 127:
            raw["firewall_active"] = None  # no known firewall tool: cannot say it is off
        else:
            raw["firewall_active"] = False

    rc, src = call("Finding the system disk", ["findmnt", "-no", "SOURCE", "/"])
    if rc == 0 and src.strip():
        rc2, types = call("Checking disk encryption", ["lsblk", "-s", "-nro", "TYPE", src.strip().split("[")[0]])
        raw["root_encrypted"] = ("crypt" in types.split()) if rc2 == 0 and types.strip() else None
    else:
        raw["root_encrypted"] = None

    if not os.path.isdir("/sys/firmware/efi"):
        raw["secure_boot"] = "legacy-bios"
    else:
        rc, out = call("Checking Secure Boot", ["mokutil", "--sb-state"])
        if rc == 0 and "enabled" in out.lower():
            raw["secure_boot"] = "on"
        elif rc == 0 and "disabled" in out.lower():
            raw["secure_boot"] = "off"
        else:
            raw["secure_boot"] = None

    enabled = None
    for unit in PATCHERS:
        rc, out = call("Checking automatic updates (%s)" % unit, ["systemctl", "is-enabled", unit])
        if rc == 127:
            break
        if out.strip() == "enabled":
            enabled = True
            break
        enabled = False if enabled is None else enabled
    raw["auto_updates"] = enabled

    try:
        raw["disk_free_gb"] = round((free_gb if free_gb is not None else shutil.disk_usage("/").free / 2**30), 1)
    except OSError:
        raw["disk_free_gb"] = None
    return raw


def _st(value, ok):
    return "unknown" if value is None else ("pass" if ok(value) else "fail")


def to_checks(raw, today=None):
    raw = raw or {}
    today = today or date.today()
    end = raw.get("support_end")
    try:
        eol = date.fromisoformat(end) if end else None
    except ValueError:
        eol = None
    n = raw.get("security_updates")
    sb = raw.get("secure_boot")
    rows = [
        ("os_supported", "high", "unknown" if eol is None else ("pass" if eol >= today else "fail"),
         "Support ends %s" % end if eol else "This release does not say when its support ends"),
        ("security_updates", "high", _st(n, lambda v: v == 0),
         ("%s security updates waiting" % n if n else "No security updates waiting") + (" (from this computer's package cache)" if raw.get("updates_source") == "cache" else "") if n is not None else (
             "dnf not found: only Fedora-family updates are checked for now" if raw.get("has_dnf") is False else
             "timed out after %d s (slow network, or another package tool is running?)" % T_SLOW if any("security updates" in t for t in raw.get("timed_out", [])) else "could not check")),
        ("reboot_ok", "medium", _st(raw.get("reboot_required"), lambda v: not v),
         "could not check" if raw.get("reboot_required") is None else "A restart is needed to finish updates" if raw.get("reboot_required") else "No restart needed"),
        ("firewall_on", "high", _st(raw.get("firewall_active"), bool),
         "No known firewall tool found" if raw.get("firewall_active") is None else "Firewall is running" if raw.get("firewall_active") else "Firewall is installed but not running"),
        ("selinux_on", "medium", _st(raw.get("selinux"), lambda v: v == "Enforcing"),
         "could not read" if raw.get("selinux") is None else "SELinux is %s" % raw.get("selinux")),
        ("disk_encrypted", "medium", _st(raw.get("root_encrypted"), bool),
         "could not read" if raw.get("root_encrypted") is None else "System disk is encrypted" if raw.get("root_encrypted") else "System disk is not encrypted"),
        ("secure_boot", "medium", "unknown" if sb is None else ("pass" if sb == "on" else "fail"),
         {"on": "Secure Boot is on", "off": "Secure Boot is off", "legacy-bios": "Booted in legacy BIOS mode, no Secure Boot"}.get(sb, "could not read")),
        ("auto_updates", "medium", _st(raw.get("auto_updates"), bool),
         "could not read" if raw.get("auto_updates") is None else "Automatic updates are scheduled" if raw.get("auto_updates") else "Automatic updates are not set up"),
        ("disk_space", "low", _st(raw.get("disk_free_gb"), lambda v: v >= MIN_FREE_GB), "could not read" if raw.get("disk_free_gb") is None else "%s GB free" % raw.get("disk_free_gb")),
    ]
    return [{"id": i, "state": s, "severity": sev, "detail": d} for i, sev, s, d in rows]


TITLES = {
    "os_supported": ("Linux release still supported", "Upgrade to a newer Fedora release before this one stops getting security fixes."),
    "security_updates": ("Security updates installed", "Run: sudo dnf upgrade --security   (then restart if asked)."),
    "reboot_ok": ("No restart pending", "Restart the computer to finish installing updates."),
    "firewall_on": ("Firewall", "Run: sudo systemctl enable --now firewalld"),
    "selinux_on": ("SELinux protection", "Run: sudo setenforce 1, and set SELINUX=enforcing in /etc/selinux/config."),
    "disk_encrypted": ("Disk encryption", "Encryption is chosen at install time on Fedora. Back up, then reinstall with encryption, or encrypt a data disk."),
    "secure_boot": ("Secure Boot", "Turn Secure Boot on in the firmware (BIOS/UEFI) settings."),
    "auto_updates": ("Automatic updates", "Run: sudo dnf install dnf5-plugin-automatic, then enable the dnf5-automatic timer. AutoPatch does not switch this on for you."),
    "disk_space": ("Free disk space", "Free up space on the system disk (at least 10 GB)."),
}
UNKNOWN_HINT = "Not verified, so it lowers the score until confirmed. Close this and run it again with sudo to read it."
