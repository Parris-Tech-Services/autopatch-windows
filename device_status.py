"""Shared device status contract (schema v1) for the Windows, Android and Mac apps and the web interface.

Strict allowlist: unknown fields are rejected so an app cannot smuggle secrets into a status file.
UNKNOWN is never a pass: a score counts only checks that passed, and verify_update() fails closed.
"""
from __future__ import annotations

import re

SCHEMA_VERSION = 1
CLASSES = {"windows", "macos", "linux", "android", "ios"}
STATES = {"pass", "fail", "unknown"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}
DEVICE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
TOP = {"schema_version", "device", "collected_utc", "os", "updates", "checks", "findings", "gate", "agent_version"}
DEVICE = {"id", "class", "label"}
OS = {"name", "version", "patch_level", "end_of_support"}
UPDATES = {"pending_security", "pending_total", "reboot_required", "last_installed_utc"}
CHECK = {"id", "state", "severity", "detail"}
FINDING = {"id", "severity", "title", "evidence", "fix"}
GATE = {"decision", "reasons"}
SECRETISH = re.compile(r"(github_pat_|ghp_|gho_|sk-[A-Za-z0-9]{16}|-----BEGIN|AKIA[0-9A-Z]{16})")


def _extra(obj, allowed, where, errs):
    if not isinstance(obj, dict):
        errs.append(f"{where} must be an object")
        return {}
    for k in obj.keys() - allowed:
        errs.append(f"{where}.{k} is not an allowed field")
    return obj


def validate(doc):
    """Return a list of problems; empty means valid."""
    errs = []
    d = _extra(doc, TOP, "status", errs)
    if d.get("schema_version") != SCHEMA_VERSION:
        errs.append(f"schema_version must be {SCHEMA_VERSION}")
    dev = _extra(d.get("device"), DEVICE, "device", errs)
    if not DEVICE_ID.match(str(dev.get("id", ""))):
        errs.append("device.id invalid")
    if dev.get("class") not in CLASSES:
        errs.append("device.class invalid")
    _extra(d.get("os"), OS, "os", errs)
    _extra(d.get("updates"), UPDATES, "updates", errs)
    for i, c in enumerate(d.get("checks") or []):
        c = _extra(c, CHECK, f"checks[{i}]", errs)
        if c.get("state") not in STATES:
            errs.append(f"checks[{i}].state invalid")
        if c.get("severity") not in SEVERITIES:
            errs.append(f"checks[{i}].severity invalid")
    for i, f in enumerate(d.get("findings") or []):
        f = _extra(f, FINDING, f"findings[{i}]", errs)
        if f.get("severity") not in SEVERITIES:
            errs.append(f"findings[{i}].severity invalid")
    if d.get("gate") is not None:
        g = _extra(d["gate"], GATE, "gate", errs)
        if g.get("decision") not in {"ALLOW", "DENY"}:
            errs.append("gate.decision invalid")
    if SECRETISH.search(repr(doc)):
        errs.append("status contains something that looks like a credential")
    return errs


def score(doc):
    """0-100 over weighted checks. Only a pass earns points; fail and unknown both lose them."""
    checks = [c for c in doc.get("checks") or [] if WEIGHT[c["severity"]]]
    total = sum(WEIGHT[c["severity"]] for c in checks)
    if not total or all(c["state"] == "unknown" for c in checks):
        return None  # nothing measured is neither a perfect score nor a zero
    earned = sum(WEIGHT[c["severity"]] for c in checks if c["state"] == "pass")
    return round(100 * earned / total)


def verify_update(before, after):
    """Did an update really land? Fails closed: needs a newer collection and a lower pending count."""
    b, a = before.get("updates") or {}, after.get("updates") or {}
    if before.get("device", {}).get("id") != after.get("device", {}).get("id"):
        return {"verified": False, "reason": "different device"}
    if not (after.get("collected_utc") or "") > (before.get("collected_utc") or ""):
        return {"verified": False, "reason": "after is not a newer collection"}
    if not all(isinstance(x.get("pending_security"), int) for x in (a, b)):
        return {"verified": False, "reason": "pending count unknown"}
    if a["pending_security"] >= b["pending_security"]:
        return {"verified": False, "reason": "pending security updates did not fall"}
    return {"verified": True, "reason": f"pending {b['pending_security']} -> {a['pending_security']}"}
