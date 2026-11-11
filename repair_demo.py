#!/usr/bin/env python3
"""Actual isolated fixture discovery -> repair -> canary -> runtime verification.

This runs only the synthetic source embedded here. No arbitrary repository,
command, package, network target, endpoint or deployment adapter is accepted.
All authorities are simulated locally: success is FIXTURE_VERIFIED, never proof
of independent production attestation or a newly discovered real vulnerability.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timedelta, timezone
import difflib
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

import verification_pipeline as vp

BASELINE = 'VERSION = "fixture-v1"\n\ndef allowed(role):\n    return role != "guest"\n'
CANDIDATE = 'VERSION = "fixture-v2"\n\ndef allowed(role):\n    return role == "admin"\n'
HARNESS = """\
import hashlib, json, pathlib, runpy, sys
path = pathlib.Path(sys.argv[1])
module = runpy.run_path(str(path))
mode = sys.argv[2]
if mode == "runtime":
    print(json.dumps({"version": module["VERSION"],
                      "digest": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "intruder_allowed": module["allowed"]("intruder")}))
    sys.exit(0)
cases = [("admin", True), ("guest", False)]
if mode == "security":
    cases += [("intruder", False), ("", False), ("ADMIN", False)]
failed = [role for role, expected in cases if module["allowed"](role) is not expected]
print(json.dumps({"mode": mode, "failed_cases": failed}))
sys.exit(1 if failed else 0)
"""


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def discover(source):
    """Deliberately fixture-specific AST scanner, not a general auth analyser."""
    try:
        tree = ast.parse(source)
        functions = [x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "allowed"]
        if len(functions) != 1 or len(functions[0].body) != 1:
            return "UNKNOWN"
        statement = functions[0].body[0]
        if not isinstance(statement, ast.Return):
            return "UNKNOWN"
        expr = statement.value
        if not (isinstance(expr, ast.Compare) and isinstance(expr.left, ast.Name)
                and expr.left.id == "role" and len(expr.ops) == len(expr.comparators) == 1
                and isinstance(expr.comparators[0], ast.Constant)):
            return "UNKNOWN"
        if isinstance(expr.ops[0], ast.NotEq) and expr.comparators[0].value == "guest":
            return "AFFECTED"
        if isinstance(expr.ops[0], ast.Eq) and expr.comparators[0].value == "admin":
            return "NOT_AFFECTED"
    except (SyntaxError, TypeError):
        pass
    return "UNKNOWN"


def run_demo(output):
    output = Path(output)
    # Exclusive creation protects earlier evidence; all execution stays elsewhere.
    output.mkdir(parents=True, exist_ok=False)
    try:
        output.chmod(0o700)
        return _execute(output)
    except Exception:
        # Retain a visible failed-run marker; never silently present partial output as success.
        (output / "FAILED.txt").write_text("Fixture run failed; no verified outcome.\n", encoding="utf-8")
        raise


def _execute(output):
    actors = {
        "fixture-finder": ["discovery"], "fixture-patcher": ["patch"],
        "fixture-checker": ["validation", "tests", "runtime", "rescan", "health", "rollback"],
        "fixture-reviewer": ["review"], "fixture-owner": ["approval"],
        "fixture-deployer": ["deployment"],
    }
    baseline_digest, candidate_digest, test_digest = sha(BASELINE), sha(CANDIDATE), sha(HARNESS)
    manifest = {
        "schema": vp.SCHEMA, "run_id": "fixture-" + secrets.token_hex(8),
        "asset_id": "synthetic-local-fixture", "finding_id": "FIXTURE-AUTH-001",
        # This identifies the embedded fixture, not a fabricated Git commit.
        "source_sha": baseline_digest,
        "baseline_digest": baseline_digest, "candidate_digest": candidate_digest,
    }
    policy = {
        "schema": vp.SCHEMA, "max_age_seconds": 3600,
        "assets": {manifest["asset_id"]: {
            "environment": "fixture", "ownership": "personal", "enabled": True,
            "allow_deploy": True, "mechanisms": ["fixture-copy"], "min_observation_seconds": 1,
        }},
        "issuers": {actor: {"key": secrets.token_hex(32), "roles": roles,
                           "assets": [manifest["asset_id"]]} for actor, roles in actors.items()},
    }
    receipts, commands = [], []

    def emit(stage, details):
        actor = next(a for a, roles in actors.items() if stage in roles)
        receipt = dict(manifest, stage=stage, issuer=actor,
                       issued_at=datetime.now(timezone.utc).isoformat(), details=details)
        receipts.append(vp.sign_receipt(receipt, policy["issuers"][actor]["key"]))

    with tempfile.TemporaryDirectory(prefix="autopatch-fixture-") as temp:
        workspace = Path(temp)
        baseline = workspace / "baseline.py"
        candidate = workspace / "candidate.py"
        harness = workspace / "check.py"
        deployed = workspace / "canary.py"
        backup = workspace / "backup.py"
        baseline.write_text(BASELINE, encoding="utf-8", newline="\n")
        harness.write_text(HARNESS, encoding="utf-8", newline="\n")

        def check(path, mode):
            result = subprocess.run(
                [sys.executable, "-I", str(harness), str(path), mode],
                capture_output=True, text=True, stdin=subprocess.DEVNULL,
                timeout=10, check=False, cwd=workspace,
            )
            commands.append({"subject": path.name, "mode": mode,
                             "exit_code": result.returncode, "stdout": result.stdout.strip()})
            return result

        vp.need(discover(BASELINE) == "AFFECTED", "fixture baseline was not detected")
        emit("discovery", {"affected": True, "coverage": "complete",
                          "baseline_version": "fixture-v1", "intelligence": "synthetic-auth-rule/1"})
        before = check(baseline, "security")
        vp.need(before.returncode == 1 and check(baseline, "functional").returncode == 0,
                "fixture baseline failure was not reproduced")
        emit("validation", {"reproduced": True, "baseline_security_exit": before.returncode,
                            "test_digest": test_digest})

        candidate.write_text(CANDIDATE, encoding="utf-8", newline="\n")
        emit("patch", {"minimal": True, "provenance": "embedded synthetic allowlist root-cause repair"})
        # Separate deterministic review predicate; role identities here are only simulation.
        vp.need(candidate.read_bytes() == CANDIDATE.encode()
                and sha(harness.read_bytes()) == test_digest
                and discover(candidate.read_text(encoding="utf-8")) == "NOT_AFFECTED",
                "fixture review rejected patch or changed test")
        emit("review", {"approved": True, "security_weakened": False, "test_digest": test_digest})
        after, functional = check(candidate, "security"), check(candidate, "functional")
        vp.need(after.returncode == functional.returncode == 0, "fixture candidate tests failed")
        emit("tests", {"security_exit": after.returncode, "functional_exit": functional.returncode,
                       "test_digest": test_digest})

        # Exercise backup/restore in the disposable canary before approval.
        shutil.copyfile(baseline, deployed)
        shutil.copyfile(deployed, backup)
        shutil.copyfile(candidate, deployed)
        shutil.copyfile(backup, deployed)
        vp.need(sha(deployed.read_bytes()) == baseline_digest
                and check(deployed, "functional").returncode == 0, "fixture restore failed")
        emit("rollback", {"ready": True, "restore_tested": True, "baseline_digest": baseline_digest})
        emit("approval", {"approved": True, "backup_verified": True, "canary": True,
                          "maintenance_window": True,
                          "expires_at": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()})
        decision = vp.assess(manifest, receipts, policy)
        vp.need(decision["deployment_permitted"], "fixture deployment gate denied")
        staged = workspace / "staged.py"
        shutil.copyfile(candidate, staged)
        staged.replace(deployed)
        emit("deployment", {"exit_code": 0, "deployed_digest": sha(deployed.read_bytes()),
                            "mechanism": "fixture-copy"})
        probe = check(deployed, "runtime")
        vp.need(probe.returncode == 0, "fixture runtime probe failed")
        runtime = json.loads(probe.stdout)
        vp.need(runtime["intruder_allowed"] is False, "fixture runtime remains vulnerable")
        emit("runtime", {"running_digest": runtime["digest"], "reboot_required": False,
                         "observed_version": runtime["version"], "config_digest": sha("fixture-default-config")})
        scan = discover(deployed.read_text(encoding="utf-8"))
        vp.need(scan == "NOT_AFFECTED", "fixture post-deployment rescan did not clear finding")
        emit("rescan", {"affected": False, "coverage": "complete",
                        "subject_digest": sha(deployed.read_bytes()),
                        "intelligence_snapshot": datetime.now(timezone.utc).isoformat()})
        start = time.monotonic()
        samples = 0
        while time.monotonic()-start < 1:
            vp.need(check(deployed, "functional").returncode == 0, "fixture health check failed")
            samples += 1
        duration = int(time.monotonic()-start)
        emit("health", {"healthy": True, "observation_seconds": duration})
        result = vp.assess(manifest, receipts, policy)
        vp.need(result["status"] == "FIXTURE_VERIFIED", "fixture evidence chain rejected")
        report = {
            "schema": vp.SCHEMA, "scope": "synthetic-local-fixture",
            "assessment": result, "baseline_security_exit": before.returncode,
            "candidate_security_exit": after.returncode, "candidate_digest": candidate_digest,
            "runtime_digest": runtime["digest"], "rollback_exercised": True,
            "health_samples": samples, "health_observation_seconds": duration,
            "fixture_execution_performed": True, "production_changes_performed": False,
            "independent_production_attestation": False, "commands": commands,
            "not_verified": [
                "Real CVE discovery or remediation", "External repository scanning",
                "Independent production signing authorities", "Live device or service deployment",
                "Windows/Fedora package updates", "Unattended scheduling",
            ],
        }

    # Private demo keys are ephemeral and intentionally never saved or printed.
    for name, payload in (("manifest.json", manifest), ("receipts.json", receipts), ("report.json", report)):
        (output / name).write_text(json.dumps(payload, indent=2)+"\n", encoding="utf-8")
    (output / "candidate.patch").write_text(
        "".join(difflib.unified_diff(BASELINE.splitlines(True), CANDIDATE.splitlines(True),
                                     fromfile="a/fixture.py", tofile="b/fixture.py")), encoding="utf-8")
    (output / "security-check.py").write_text(HARNESS, encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New directory; existing evidence is never overwritten")
    args = parser.parse_args(argv)
    try:
        report = run_demo(args.out)
    except (OSError, ValueError, subprocess.SubprocessError, KeyError):
        print(json.dumps({"status": "BLOCKED", "reason": "fixture failed or output already exists"}))
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
