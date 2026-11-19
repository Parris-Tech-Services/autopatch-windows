#!/usr/bin/env python3
"""Offline discovery-to-runtime evidence coordinator. NEVER executes a patch.

Receipts are authenticated with per-issuer HMAC keys provisioned out of band.
The policy and its keys are trusted administrator input, NOT evidence supplied by
a patch agent. HMAC provides integrity within that trust domain, not public
non-repudiation or proof that a collector's assertions are true.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys

SCHEMA = "autopatch.verification/1"
STAGES = (
    "discovery", "validation", "patch", "review", "tests", "rollback",
    "approval", "deployment", "runtime", "rescan", "health",
)
BINDINGS = (
    "schema", "run_id", "asset_id", "finding_id", "source_sha",
    "baseline_digest", "candidate_digest",
)
RECEIPT_FIELDS = set(BINDINGS) | {"stage", "issuer", "issued_at", "details", "signature"}
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAX_BYTES = 2 * 1024 * 1024


class Invalid(ValueError):
    """Safe-to-report validation failure; never contains raw input."""


def need(condition, message):
    if not condition:
        raise Invalid(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def timestamp(raw):
    need(isinstance(raw, str), "timestamp missing")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        need(value.tzinfo is not None, "timestamp must include timezone")
        return value.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise Invalid("invalid timestamp") from None


def digest(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def sign_receipt(receipt, key):
    """Collector SDK primitive, not a signing endpoint or evidence trust root."""
    need(digest(key), "invalid issuer key")
    body = {k: v for k, v in receipt.items() if k != "signature"}
    signature = hmac.new(bytes.fromhex(key), canonical(body), hashlib.sha256).hexdigest()
    return dict(body, signature=signature)


def validate_manifest(manifest):
    need(isinstance(manifest, dict) and set(manifest) == set(BINDINGS), "invalid manifest fields")
    need(manifest["schema"] == SCHEMA, "unsupported manifest schema")
    for field in ("run_id", "asset_id", "finding_id"):
        need(isinstance(manifest[field], str) and ID.fullmatch(manifest[field]), "invalid identity")
    need(isinstance(manifest["source_sha"], str) and SHA.fullmatch(manifest["source_sha"]),
         "invalid source revision")
    need(digest(manifest["baseline_digest"]) and digest(manifest["candidate_digest"]),
         "invalid artifact digest")
    need(manifest["baseline_digest"] != manifest["candidate_digest"], "artifact did not change")


def validate_policy(policy, manifest):
    need(isinstance(policy, dict) and policy.get("schema") == SCHEMA, "invalid trusted policy")
    age = policy.get("max_age_seconds")
    need(type(age) is int and 1 <= age <= 86400, "invalid freshness limit")
    assets, issuers = policy.get("assets"), policy.get("issuers")
    need(isinstance(assets, dict) and isinstance(issuers, dict) and bool(issuers), "missing trust roots")
    asset = assets.get(manifest["asset_id"])
    need(isinstance(asset, dict), "asset not authorised")
    need(asset.get("environment") in ("fixture", "test", "production"), "unknown environment")
    if manifest["finding_id"].startswith("FIXTURE-") or manifest["asset_id"] == "synthetic-local-fixture":
        need(asset["environment"] == "fixture", "fixture evidence cannot establish real remediation")
    need(asset.get("ownership") == "personal", "ownership not explicitly personal")
    need(asset.get("enabled") is True, "asset disabled")
    need(asset.get("allow_deploy") is True, "deployment not authorised by trusted policy")
    mechanisms = asset.get("mechanisms")
    need(isinstance(mechanisms, list) and bool(mechanisms)
         and all(isinstance(x, str) and ID.fullmatch(x) for x in mechanisms), "invalid mechanisms")
    observation = asset.get("min_observation_seconds")
    need(type(observation) is int and 1 <= observation <= 86400, "invalid health observation limit")
    seen = set()
    for name, issuer in issuers.items():
        need(isinstance(name, str) and ID.fullmatch(name) and isinstance(issuer, dict),
             "invalid issuer configuration")
        key, roles, scope = issuer.get("key"), issuer.get("roles"), issuer.get("assets")
        need(digest(key) and key not in seen, "issuer keys missing or reused")
        seen.add(key)
        need(isinstance(roles, list) and bool(roles)
             and all(isinstance(x, str) and x in STAGES for x in roles), "invalid issuer roles")
        need(isinstance(scope, list) and bool(scope)
             and all(isinstance(x, str) and ID.fullmatch(x) for x in scope), "invalid issuer scope")
    return asset, issuers, timedelta(seconds=age)


def authenticate(receipt, manifest, issuers, now, max_age):
    need(isinstance(receipt, dict) and set(receipt) == RECEIPT_FIELDS, "invalid receipt fields")
    need(all(receipt.get(k) == manifest[k] for k in BINDINGS), "receipt binding mismatch")
    stage, actor = receipt.get("stage"), receipt.get("issuer")
    need(isinstance(stage, str) and stage in STAGES, "unknown evidence stage")
    need(isinstance(actor, str) and actor in issuers, "untrusted issuer")
    issuer = issuers[actor]
    need(stage in issuer["roles"] and manifest["asset_id"] in issuer["assets"],
         "issuer not authorised for stage or asset")
    supplied = receipt.get("signature")
    need(digest(supplied), "missing receipt authentication")
    expected = sign_receipt(receipt, issuer["key"])["signature"]
    need(hmac.compare_digest(supplied, expected), "receipt authentication failed")
    issued = timestamp(receipt["issued_at"])
    need(timedelta(0) <= now - issued <= max_age, "receipt stale or future")
    need(isinstance(receipt["details"], dict), "invalid stage details")
    return stage, issued


def stage_check(stage, details, manifest, asset, now, max_age):
    """Stage-specific proof obligations. Unknown/missing is never a pass."""
    d = details
    if stage == "discovery":
        need(d.get("affected") is True and d.get("coverage") == "complete", "affected baseline not proven")
        need(isinstance(d.get("baseline_version"), str) and bool(d["baseline_version"])
             and isinstance(d.get("intelligence"), str) and bool(d["intelligence"]),
             "baseline provenance missing")
    elif stage == "validation":
        need(d.get("reproduced") is True and type(d.get("baseline_security_exit")) is int
             and d["baseline_security_exit"] == 1 and digest(d.get("test_digest")),
             "meaningful failing baseline not proven")
    elif stage == "patch":
        need(d.get("minimal") is True and isinstance(d.get("provenance"), str)
             and bool(d["provenance"]), "patch provenance or scope missing")
    elif stage == "review":
        need(d.get("approved") is True and d.get("security_weakened") is False
             and digest(d.get("test_digest")), "independent review did not pass")
    elif stage == "tests":
        need(all(type(d.get(k)) is int and d[k] == 0 for k in ("security_exit", "functional_exit"))
             and digest(d.get("test_digest")), "candidate tests did not pass")
    elif stage == "rollback":
        need(d.get("ready") is True and d.get("restore_tested") is True
             and d.get("baseline_digest") == manifest["baseline_digest"], "rollback not established")
    elif stage == "approval":
        need(all(d.get(k) is True for k in ("approved", "backup_verified", "canary", "maintenance_window")),
             "deployment approval incomplete")
        need(timestamp(d.get("expires_at")) > now, "deployment approval expired")
    elif stage == "deployment":
        need(type(d.get("exit_code")) is int and d["exit_code"] == 0
             and d.get("deployed_digest") == manifest["candidate_digest"]
             and d.get("mechanism") in asset["mechanisms"], "deployment not proven or mechanism denied")
    elif stage == "runtime":
        need(d.get("running_digest") == manifest["candidate_digest"]
             and isinstance(d.get("observed_version"), str) and bool(d["observed_version"])
             and digest(d.get("config_digest")), "running artifact or configuration not proven")
        need(d.get("reboot_required") is False or d.get("reboot_required") is True,
             "runtime reboot status unknown")
    elif stage == "rescan":
        need(d.get("affected") is False and d.get("coverage") == "complete"
             and d.get("subject_digest") == manifest["candidate_digest"], "post-deployment rescan incomplete or affected")
        need(timedelta(0) <= now-timestamp(d.get("intelligence_snapshot")) <= max_age,
             "rescan intelligence stale or future")
    elif stage == "health":
        duration = d.get("observation_seconds")
        need(d.get("healthy") is True and type(duration) is int
             and duration >= asset["min_observation_seconds"], "health observation incomplete")


def cross_checks(by_stage):
    patcher = by_stage.get("patch", {}).get("issuer")
    deployer = by_stage.get("deployment", {}).get("issuer")
    for stage in ("validation", "review", "tests", "rollback", "approval", "runtime", "rescan", "health"):
        if stage in by_stage and patcher:
            need(by_stage[stage]["issuer"] != patcher, "patch agent cannot approve or verify itself")
    for stage in ("runtime", "rescan", "health"):
        if stage in by_stage and deployer:
            need(by_stage[stage]["issuer"] != deployer, "deployer cannot verify itself")
    tests = [by_stage[s]["details"]["test_digest"] for s in ("validation", "review", "tests") if s in by_stage]
    need(len(set(tests)) <= 1, "security regression changed between stages")


def assess(manifest, receipts, policy, *, now=None):
    """Read-only decision. Only administrator-provisioned trust roots confer trust."""
    report = {
        "schema": SCHEMA, "status": "BLOCKED", "verified": False,
        "deployment_permitted": False, "completed_stages": [], "missing_stages": list(STAGES),
        "reasons": [], "execution_performed": False,
    }
    try:
        now = now or datetime.now(timezone.utc)
        need(isinstance(now, datetime) and now.tzinfo is not None, "invalid assessment clock")
        validate_manifest(manifest)
        asset, issuers, max_age = validate_policy(policy, manifest)
        need(isinstance(receipts, list) and len(receipts) <= len(STAGES), "invalid receipt collection")
        by_stage, dates = {}, {}
        for receipt in receipts:
            stage, issued = authenticate(receipt, manifest, issuers, now, max_age)
            need(stage not in by_stage, "duplicate stage evidence")
            stage_check(stage, receipt["details"], manifest, asset, now, max_age)
            by_stage[stage], dates[stage] = receipt, issued
        cross_checks(by_stage)
        present = [s for s in STAGES if s in by_stage]
        need(all(dates[a] <= dates[b] for a, b in zip(present, present[1:])), "stage timestamps out of order")
        # No late-stage receipt can paper over missing prerequisites.
        prefix = []
        for stage in STAGES:
            if stage not in by_stage:
                break
            prefix.append(stage)
        report["completed_stages"] = present
        report["missing_stages"] = [s for s in STAGES if s not in by_stage]
        report["environment"] = asset["environment"]
        report["asset_id"] = manifest["asset_id"]
        report["run_id"] = manifest["run_id"]
        report["deployment_permitted"] = "approval" in prefix
        status = "UNKNOWN"
        for stage, label in (
            ("discovery", "AFFECTED"), ("validation", "VALIDATED"),
            ("patch", "PATCH_PROPOSED"), ("tests", "PATCH_TESTED"),
            ("approval", "READY_FOR_AUTHORISED_DEPLOYMENT"),
            ("deployment", "DEPLOYED_UNVERIFIED"),
        ):
            if stage in prefix:
                status = label
        if "runtime" in prefix and by_stage["runtime"]["details"]["reboot_required"] is True:
            status = "INSTALLED_REBOOT_PENDING"
            report["deployment_permitted"] = False
            report["reasons"].append("installed does not establish running remediation")
        elif len(prefix) == len(STAGES):
            fixture = asset["environment"] == "fixture"
            status = "FIXTURE_VERIFIED" if fixture else "VERIFIED_FIXED"
            report["verified"] = not fixture
        if report["missing_stages"]:
            report["reasons"].append("required evidence is incomplete")
        report["status"] = status
    except (Invalid, TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        # Do not echo attacker-controlled data, signatures, or policy keys.
        report["status"] = "BLOCKED"
        report["verified"] = report["deployment_permitted"] = False
        report["reasons"] = [str(exc) if isinstance(exc, Invalid) else "malformed evidence or policy"]
    return report


def read_json(path):
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    need(len(raw) <= MAX_BYTES, "input exceeds size limit")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    def finite_only(_):
        raise Invalid("non-finite JSON value")

    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=finite_only)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True,
                        help="Private administrator-provisioned policy, never agent-supplied evidence")
    args = parser.parse_args(argv)
    try:
        if os.name != "nt":
            need(args.trust_policy.stat().st_mode & 0o077 == 0, "trust policy must be private (mode 0600)")
        result = assess(read_json(args.manifest), read_json(args.receipts), read_json(args.trust_policy))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result = {"schema": SCHEMA, "status": "BLOCKED", "verified": False,
                  "deployment_permitted": False, "execution_performed": False,
                  "reasons": [str(exc) if isinstance(exc, Invalid) else "cannot read valid private input"]}
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0 if result["status"] in ("VERIFIED_FIXED", "FIXTURE_VERIFIED") else 2


if __name__ == "__main__":
    sys.exit(main())
