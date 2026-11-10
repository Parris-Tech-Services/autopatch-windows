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


def to_checks(raw):
    raw = raw or {}
    age = raw.get("defender_signature_age_days")
    rows = [
        ("os_supported", "high", _state(raw.get("os_build"), lambda b: b > WIN10_LAST_BUILD), "Windows 10 no longer gets regular security updates"),
        ("defender_on", "high", _state(raw.get("defender_enabled"), bool), "Microsoft Defender antivirus enabled"),
        ("defender_realtime", "high", _state(raw.get("defender_realtime"), bool), "Real-time protection on"),
        ("defender_signatures_fresh", "medium", _state(age, lambda a: a <= MAX_SIGNATURE_AGE_DAYS), f"Signature age {age} days"),
        ("firewall_on", "high", _state(_fw(raw.get("firewall_profiles_enabled")), bool), "All firewall profiles enabled"),
        ("bitlocker_on", "medium", _state(raw.get("bitlocker_protection"), lambda v: v in (1, "On")), "System drive encrypted"),
        ("secure_boot", "medium", _state(raw.get("secure_boot"), bool), "Secure Boot enabled"),
        ("tpm_present", "low", _state(raw.get("tpm_present"), bool), "TPM present"),
        ("smbv1_off", "high", _state(raw.get("smbv1_enabled"), lambda v: not v), "SMBv1 disabled"),
        ("uac_on", "medium", _state(raw.get("uac_enabled"), lambda v: v == 1), "User Account Control enabled"),
        ("rdp_closed", "medium", _state(raw.get("rdp_denied"), lambda v: v == 1), "Remote Desktop connections denied"),
        ("apps_current", "low", _state(raw.get("winget_outdated"), lambda n: n == 0), f"{raw.get('winget_outdated')} apps outdated (winget)"),
    ]
    return [{"id": i, "state": s, "severity": sev, "detail": d if s != "unknown" else "could not be read"} for i, sev, s, d in rows]
