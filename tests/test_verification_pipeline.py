"""Offline gate tests. No package manager, device, cloud or network access."""
from datetime import datetime, timezone, timedelta
import unittest

import verification_pipeline as vp


NOW = datetime(2026, 11, 11, 2, 0, tzinfo=timezone.utc)


def case(environment="test"):
    manifest = {
        "schema": vp.SCHEMA, "run_id": "fixture-run-1", "asset_id": "test-asset",
        "finding_id": "TEST-AUTH-001", "source_sha": "a" * 40,
        "baseline_digest": "b" * 64, "candidate_digest": "c" * 64,
    }
    actors = {
        "finder": ["discovery"], "patcher": ["patch"],
        "checker": ["validation", "tests", "runtime", "rescan", "health", "rollback"],
        "reviewer": ["review"], "owner": ["approval"], "deployer": ["deployment"],
    }
    policy = {
        "schema": vp.SCHEMA, "max_age_seconds": 3600,
        "assets": {"test-asset": {
            "environment": environment, "ownership": "personal",
            "enabled": True, "allow_deploy": True,
            "mechanisms": ["fixture-copy"], "min_observation_seconds": 1,
        }},
        "issuers": {actor: {
            "key": format(i + 1, "064x"), "roles": roles, "assets": ["test-asset"],
        } for i, (actor, roles) in enumerate(actors.items())},
    }
    details = {
        "discovery": {"affected": True, "coverage": "complete",
                      "baseline_version": "fixture-v1", "intelligence": "synthetic-fixture"},
        "validation": {"reproduced": True, "baseline_security_exit": 1, "test_digest": "d" * 64},
        "patch": {"minimal": True, "provenance": "synthetic-root-cause-fix"},
        "review": {"approved": True, "security_weakened": False, "test_digest": "d" * 64},
        "tests": {"security_exit": 0, "functional_exit": 0, "test_digest": "d" * 64},
        "rollback": {"ready": True, "restore_tested": True, "baseline_digest": "b" * 64},
        "approval": {"approved": True, "backup_verified": True, "canary": True,
                     "maintenance_window": True, "expires_at": (NOW + timedelta(minutes=5)).isoformat()},
        "deployment": {"exit_code": 0, "deployed_digest": "c" * 64, "mechanism": "fixture-copy"},
        "runtime": {"running_digest": "c" * 64, "reboot_required": False,
                    "observed_version": "fixture-v2", "config_digest": "e" * 64},
        "rescan": {"affected": False, "coverage": "complete", "subject_digest": "c" * 64,
                   "intelligence_snapshot": (NOW - timedelta(seconds=1)).isoformat()},
        "health": {"healthy": True, "observation_seconds": 1},
    }
    receipts = []
    for index, stage in enumerate(vp.STAGES):
        actor = next(a for a, roles in actors.items() if stage in roles)
        receipt = dict(manifest, stage=stage, issuer=actor,
                       issued_at=(NOW - timedelta(seconds=30-index)).isoformat(),
                       details=details[stage])
        receipts.append(vp.sign_receipt(receipt, policy["issuers"][actor]["key"]))
    return manifest, policy, receipts


def resign(policy, receipt):
    return vp.sign_receipt(receipt, policy["issuers"][receipt["issuer"]]["key"])


class PipelineTests(unittest.TestCase):
    def assess(self, manifest, policy, receipts):
        return vp.assess(manifest, receipts, policy, now=NOW)

    def test_complete_trusted_chain(self):
        result = self.assess(*case())
        self.assertEqual(result["status"], "VERIFIED_FIXED")
        self.assertTrue(result["verified"])

    def test_fixture_never_claims_real_remediation(self):
        result = self.assess(*case("fixture"))
        self.assertEqual(result["status"], "FIXTURE_VERIFIED")
        self.assertFalse(result["verified"])

    def test_fixture_identity_cannot_be_promoted_by_environment_change(self):
        m, p, r = case()
        m["finding_id"] = "FIXTURE-AUTH-001"
        for item in r:
            item["finding_id"] = m["finding_id"]
            item.update(resign(p, item))
        result = self.assess(m, p, r)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("fixture", result["reasons"][0])

    def test_missing_receipts_never_pass(self):
        m, p, _ = case()
        result = self.assess(m, p, [])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["deployment_permitted"])

    def test_each_missing_stage_prevents_completion(self):
        m, p, receipts = case()
        for stage in vp.STAGES:
            with self.subTest(stage=stage):
                result = self.assess(m, p, [r for r in receipts if r["stage"] != stage])
                self.assertFalse(result["verified"])

    def test_tested_is_not_deployed(self):
        m, p, r = case()
        result = self.assess(m, p, r[:5])
        self.assertEqual(result["status"], "PATCH_TESTED")
        self.assertFalse(result["deployment_permitted"])

    def test_approved_prefix_is_ready_not_verified(self):
        m, p, r = case()
        result = self.assess(m, p, r[:7])
        self.assertEqual(result["status"], "READY_FOR_AUTHORISED_DEPLOYMENT")
        self.assertTrue(result["deployment_permitted"])
        self.assertFalse(result["verified"])

    def test_tampering_and_forgery_fail(self):
        m, p, r = case()
        r[-1]["details"]["healthy"] = False
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")
        m, p, r = case()
        r[-1]["signature"] = "0" * 64
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_untrusted_issuer_cannot_supply_its_own_key(self):
        m, p, r = case()
        r[-1]["issuer"] = "attacker"
        r[-1] = vp.sign_receipt(r[-1], "f" * 64)
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_unbound_fields_are_rejected(self):
        for field in ("run_id", "asset_id", "finding_id", "source_sha",
                      "baseline_digest", "candidate_digest"):
            m, p, r = case()
            r[-1][field] = "different"
            r[-1] = resign(p, r[-1])
            with self.subTest(field=field):
                self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_stale_future_and_reordered_receipts_fail(self):
        for age in (timedelta(hours=2), timedelta(seconds=-1)):
            m, p, r = case()
            r[-1]["issued_at"] = (NOW-age).isoformat()
            r[-1] = resign(p, r[-1])
            self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")
        m, p, r = case()
        r[-1]["issued_at"] = (NOW-timedelta(seconds=50)).isoformat()
        r[-1] = resign(p, r[-1])
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_duplicate_receipt_and_unknown_stage_fail(self):
        m, p, r = case()
        self.assertEqual(self.assess(m, p, r + [r[-1]])["status"], "BLOCKED")
        r[-1]["stage"] = "declare-success"
        r[-1] = resign(p, r[-1])
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_patch_agent_cannot_review_test_or_verify_itself(self):
        for stage in ("review", "tests", "runtime", "rescan", "health", "validation"):
            m, p, r = case()
            p["issuers"]["patcher"]["roles"].append(stage)
            item = next(x for x in r if x["stage"] == stage)
            item["issuer"] = "patcher"
            item.update(resign(p, item))
            with self.subTest(stage=stage):
                self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_reused_identity_key_does_not_prove_independence(self):
        m, p, r = case()
        p["issuers"]["reviewer"]["key"] = p["issuers"]["patcher"]["key"]
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_deployer_cannot_verify_running_state(self):
        m, p, r = case()
        p["issuers"]["deployer"]["roles"].append("runtime")
        item = next(x for x in r if x["stage"] == "runtime")
        item["issuer"] = "deployer"
        item.update(resign(p, item))
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_mismatched_security_test_fails(self):
        m, p, r = case()
        item = next(x for x in r if x["stage"] == "tests")
        item["details"]["test_digest"] = "f" * 64
        item.update(resign(p, item))
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_negative_or_unknown_check_results_fail(self):
        for stage, field, value in (
            ("discovery", "affected", None), ("discovery", "coverage", "partial"),
            ("tests", "security_exit", 1), ("tests", "functional_exit", False),
            ("review", "approved", False), ("rescan", "affected", True),
            ("rescan", "coverage", "unknown"), ("health", "healthy", None),
            ("rollback", "restore_tested", False), ("approval", "backup_verified", False),
            ("runtime", "running_digest", "f" * 64),
            ("deployment", "mechanism", "unrestricted-shell"),
        ):
            m, p, r = case()
            item = next(x for x in r if x["stage"] == stage)
            item["details"][field] = value
            item.update(resign(p, item))
            with self.subTest(stage=stage, field=field):
                self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_reboot_pending_never_verified(self):
        m, p, r = case()
        item = next(x for x in r if x["stage"] == "runtime")
        item["details"]["reboot_required"] = True
        item.update(resign(p, item))
        self.assertEqual(self.assess(m, p, r)["status"], "INSTALLED_REBOOT_PENDING")

    def test_expired_approval_cannot_authorise_new_deployment(self):
        m, p, r = case()
        item = next(x for x in r if x["stage"] == "approval")
        item["details"]["expires_at"] = (NOW-timedelta(seconds=1)).isoformat()
        item.update(resign(p, item))
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_disabled_work_unknown_assets_fail_closed(self):
        for field, value in (("enabled", False), ("ownership", "work"), ("allow_deploy", False)):
            m, p, r = case()
            p["assets"]["test-asset"][field] = value
            self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")
        m, p, r = case()
        p["assets"].clear()
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_malformed_inputs_return_blocked_not_crash(self):
        m, p, r = case()
        for bad in (None, [], "string", {"schema": vp.SCHEMA}):
            self.assertEqual(self.assess(bad, p, r)["status"], "BLOCKED")
            self.assertEqual(self.assess(m, bad, r)["status"], "BLOCKED")
        for bad in (None, {}, ["bad"], [None], [dict(r[0], details=[])]):
            self.assertEqual(self.assess(m, p, bad)["status"], "BLOCKED")

    def test_unchanged_artifact_is_not_a_repair(self):
        m, p, r = case()
        m["candidate_digest"] = m["baseline_digest"]
        self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")

    def test_reports_do_not_leak_keys_or_receipt_details(self):
        import json
        m, p, r = case()
        serialized = json.dumps(self.assess(m, p, r))
        for issuer in p["issuers"].values():
            self.assertNotIn(issuer["key"], serialized)
        self.assertNotIn("synthetic-root-cause-fix", serialized)

    def test_json_parser_rejects_duplicate_keys_and_nonfinite_values(self):
        from pathlib import Path
        import tempfile
        for raw in ('{"stage":"tests","stage":"health"}', '{"value":NaN}', '{"value":Infinity}'):
            with tempfile.TemporaryDirectory() as root:
                path = Path(root) / "input.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises(ValueError):
                    vp.read_json(path)

    def test_cli_requires_private_trust_file(self):
        import json
        import os
        from pathlib import Path
        import subprocess
        import sys
        import tempfile
        if os.name == "nt":
            self.skipTest("POSIX permissions; Windows policy ACLs are administrator-managed")
        m, p, r = case()
        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root) / x for x in ("manifest.json", "policy.json", "receipts.json")]
            for path, data in zip(paths, (m, p, r)):
                path.write_text(json.dumps(data), encoding="utf-8")
            paths[1].chmod(0o644)
            result = subprocess.run(
                [sys.executable, "verification_pipeline.py", "--manifest", str(paths[0]),
                 "--receipts", str(paths[2]), "--trust-policy", str(paths[1])],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")
            self.assertIn("0600", result.stdout)

    def test_raw_package_success_is_not_a_trusted_receipt(self):
        m, p, _ = case()
        raw = {"status": "PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED",
               "changed": True, "after_version": "fixture-v2"}
        self.assertEqual(self.assess(m, p, [raw])["status"], "BLOCKED")

    def test_advisory_freshness_health_duration_and_unknown_reboot(self):
        for stage, field, value in (
            ("rescan", "intelligence_snapshot", (NOW-timedelta(days=2)).isoformat()),
            ("health", "observation_seconds", 0),
            ("runtime", "reboot_required", None),
        ):
            m, p, r = case()
            item = next(x for x in r if x["stage"] == stage)
            item["details"][field] = value
            item.update(resign(p, item))
            self.assertEqual(self.assess(m, p, r)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
