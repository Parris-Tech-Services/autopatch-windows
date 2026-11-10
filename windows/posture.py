"""Map the raw Windows posture probe into shared-status checks. Pure parsing; unknown is never a pass."""
from __future__ import annotations

import re

MAX_SIGNATURE_AGE_DAYS = 7


def _state(value, ok):
    if value is None:
        return "unknown"
    return "pass" if ok(value) else "fail"


def _fw(profiles):
    if not isinstance(profiles, list):
        profiles = [profiles] if isinstance(profiles, bool) else None
    return None if not profiles else all(profiles)


WIN10_LAST_BUILD = 19045  # Windows 10 22H2 is the last Windows 10 release; mainstream support ended 14 Oct 2025


def _bitlocker(raw):
    api, shell = raw.get("bitlocker_protection"), raw.get("bitlocker_shell")
    # Get-BitLockerVolume ProtectionStatus: 0 Off, 1 On, 2 Unknown (e.g. a locked drive). Unknown is not a failure.
    if api in (1, "On"):
        return "pass", "BitLocker protection is on"
    if api in (0, "Off"):
        return "fail", "BitLocker protection is off"
    if api is not None:
        return "unknown", "BitLocker reports protection status %s (unknown)" % api
    if shell == 1:
        return "pass", "Drive shows as protected"
    if shell == 2:
        # 2 matched "protection off" on a real ThinkPad (checked with manage-bde as admin), but the value is
        # undocumented, so it stays unknown without an authoritative read.
        return "unknown", "Drive property reads 2, which usually means BitLocker is off; administrator rights are needed to confirm"
    if shell is not None:
        return "unknown", "Drive property reads %s; cannot confirm without administrator rights" % shell
    return "unknown", "could not be read"


def _tpm(raw):
    api, seen_off = raw.get("tpm_present"), raw.get("tpm_seen_not_present") is True
    if api:
        return "pass", "TPM present"
    if api is not None:
        if seen_off:
            return "fail", "This PC has a TPM chip, but it is switched off in the BIOS"
        return "fail", "No TPM reported"
    if raw.get("tpm_pnp_found") is True:
        return "pass", "TPM device found"
    if seen_off:
        # Weak evidence only: stays unknown, but say what was seen.
        return "unknown", "A TPM chip was seen before but is not active now; it may be switched off in the BIOS"
    return "unknown", "Could not confirm a TPM without administrator rights"


def _os_supported(raw):
    """Only Windows 10 on a PC (product type 1) is judged here. Servers have their own, longer lifecycles."""
    build, ptype = raw.get("os_build"), raw.get("os_product_type")
    if build is None:
        return "unknown", "could not read the Windows build"
    if ptype in (2, 3):
        return "unknown", "Windows Server: its support dates are not checked here"
    if build <= WIN10_LAST_BUILD:
        return "fail", "Windows 10 no longer gets regular security updates"
    return "pass", "Windows version is still supported"


_DASHES = re.compile(r"^-{10,}\s*$")
# winget's own result codes when there is nothing to upgrade (same in every language):
# 0x8A15002B "no applicable update", 0x8A150014 "no installed package found".
WINGET_NOTHING = {-1978335189, -1978335212, 0x8A15002B, 0x8A150014}


def winget_outdated(raw, exit_code):
    """Count rows in `winget upgrade` tables without relying on English text. None when it cannot tell."""
    if not isinstance(raw, str):
        return None
    lines = [l.rstrip() for l in re.split(r"\r\n|\n|\r", raw)]
    found, count = False, 0
    for i, line in enumerate(lines):
        if i == 0 or not _DASHES.match(line) or not lines[i - 1].strip():
            continue
        found = True
        header = lines[i - 1]
        last_col = len(header) - len(header.split()[-1])  # start of the last column (Source)
        for row in lines[i + 1:]:
            if row.strip() and len(row) > last_col:  # a footer like "20 upgrades available." is too short
                count += 1
            else:
                break
    if found:
        return count
    if exit_code in WINGET_NOTHING:
        return 0
    return None


def to_checks(raw):
    raw = dict(raw or {})
    if "winget_raw" in raw:
        raw["winget_outdated"] = winget_outdated(raw.get("winget_raw"), raw.get("winget_exit"))
    bl_state, bl_detail = _bitlocker(raw)
    tpm_state, tpm_detail = _tpm(raw)
    age = raw.get("defender_signature_age_days")
    os_state, os_detail = _os_supported(raw)
    rows = [
        ("os_supported", "high", os_state, os_detail),
        ("defender_on", "high", _state(raw.get("defender_enabled"), bool), "Microsoft Defender antivirus enabled"),
        ("defender_realtime", "high", _state(raw.get("defender_realtime"), bool), "Real-time protection on"),
        ("defender_signatures_fresh", "medium", _state(age, lambda a: a <= MAX_SIGNATURE_AGE_DAYS), f"Signature age {age} days"),
        ("firewall_on", "high", _state(_fw(raw.get("firewall_profiles_enabled")), bool), "All firewall profiles enabled"),
        ("bitlocker_on", "medium", bl_state, bl_detail),
        ("secure_boot", "medium", _state(raw.get("secure_boot"), bool), "Secure Boot is on" if raw.get("secure_boot") else "Secure Boot reads as off"),
        ("tpm_present", "low", tpm_state, tpm_detail),
        ("smbv1_off", "high", _state(raw.get("smbv1_enabled"), lambda v: not v), "SMBv1 disabled"),
        ("uac_on", "medium", _state(raw.get("uac_enabled"), lambda v: v == 1), "User Account Control enabled"),
        ("rdp_closed", "medium", _state(raw.get("rdp_denied"), lambda v: v == 1), "Remote Desktop connections denied"),
        ("apps_current", "low", _state(raw.get("winget_outdated"), lambda n: n == 0), f"{raw.get('winget_outdated')} apps outdated (winget)"),
    ]
    return [{"id": i, "state": s, "severity": sev, "detail": d} for i, sev, s, d in rows]
