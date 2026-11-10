"""Map the raw Windows posture probe into shared-status checks. Pure parsing; unknown is never a pass."""
from __future__ import annotations

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
    if shell is not None:
        return "unknown", "Drive property reads %s; cannot confirm without administrator rights" % shell
    return "unknown", "could not be read"


def _tpm(raw):
    api = raw.get("tpm_present")
    if api is not None:
        return ("pass" if api else "fail"), "TPM present" if api else "No TPM reported"
    if raw.get("tpm_pnp_found") is True:
        return "pass", "TPM device found"
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


def to_checks(raw):
    raw = raw or {}
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
