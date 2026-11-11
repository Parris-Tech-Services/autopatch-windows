"""Mocked Windows and Fedora patch-plan tests. No OS package is changed."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import safe_patch

NOW = datetime(2026, 11, 11, 21, 30, tzinfo=timezone.utc)
def settings(system="linux"):
    pkg = "openssl" if system == "linux" else "Git.Git"
    old = "1.0-1" if system == "linux" else "1.0"
    new = "1.1-1" if system == "linux" else "1.1"
    policy = {
        "device_id": "owned-disposable-01", "device_class": system,
        "hostname": "disposable-host", "ownership": "personal",
        "employer_managed": False, "patching_enabled": True,
        "auto_restart": False, "reboot_approved": False,
        "packages": {pkg: {"update_kind":"security","from_version":old,"to_version":new}},
        "window": {"timezone":"UTC","weekdays":[2],"start":"20:00","end":"23:00"},
        "backup": {"verified": True, "restore_tested": True, "evidence_file":"/safe/private/receipt",
                   "verified_utc":(NOW-timedelta(minutes=10)).isoformat(),
                   "rollback_plan":"Restore disposable snapshot"},
    }
    status = {"schema_version":1, "device":{"id":"owned-disposable-01","class":system,
                                              "label":"disposable-host"},
              "collected_utc":(NOW-timedelta(minutes=1)).isoformat(),
              "os":{"name":system, "version":"1"},
              "updates":{"pending_security":1,"reboot_required":False},
              "checks":[{"id":"update", "state":"fail","severity":"high","detail":"pending"}],
              "findings":[],"gate":{"decision":"DENY","reasons":["read-only app"]},
              "agent_version":"test"}
    return policy,status,pkg,old,new

def approved(system):
    return {"device_id":"owned-disposable-01", "device_class":system,
            "hostname":"disposable-host", "status":"enrolled_readonly",
            "permissions":["inventory_read"], "auto_patch":False, "remote_control":False}

def run_case(system, success=True):
    pol, st, pkg, old, new = settings(system)
    events = []
    def mock_run(cmd):
        events.append(cmd)
        if cmd[0] in ("ps","powershell"): return 0, "normal-process"
        if cmd[0] in ("rpm","winget") and (cmd[0]=="rpm" or cmd[1]=="list"):
            latest = any(c[0]=="dnf" or (c[0]=="winget" and c[1]=="upgrade") for c in events[:-1])
            actual = (new if success else old) if latest else old
            return 0, actual if system=="linux" else f"Name Id Version Available Source\nGit {pkg} {actual} winget\n"
        if cmd[0] == "dnf" or (cmd[0]=="winget" and cmd[1]=="upgrade"):
            return 0, "transaction"
        return 127, ""
    return safe_patch.apply(pol, st, pkg, approved_inventory=approved(system), apply_change=True, system=system,
                            hostname="disposable-host",now=NOW,
                            backup_exists=lambda _:True,free_gb=20,
                            command_runner=mock_run),events

class PatchCycleTests(unittest.TestCase):
    def test_fedora_exact_single_package_and_post_version(self):
        report, commands = run_case("linux")
        self.assertEqual(report["status"],"PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED")
        self.assertEqual(report["after_version"],"1.1-1")
        self.assertEqual(len([x for x in commands if x[0]=="dnf"]),1)
        self.assertIn("--security",next(x for x in commands if x[0]=="dnf"))
    def test_windows_exact_package_no_reboot_flag(self):
        report, commands = run_case("windows")
        self.assertEqual(report["status"],"PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED")
        patch = next(x for x in commands if x[0]=="winget" and x[1]=="upgrade")
        self.assertIn("--exact",patch)
        self.assertNotIn("--allow-reboot",patch)
    def test_failed_post_check_not_verified(self):
        report, _ = run_case("linux", False)
        self.assertEqual(report["status"],"BLOCKED_UNVERIFIED_REVIEW_ROLLBACK")
    def test_default_dry_run(self):
        pol, st, pkg, old, new = settings()
        def fake(cmd):
            return (0,"normal") if cmd[0]=="ps" else (0,old)
        result = safe_patch.apply(pol, st, pkg, approved_inventory=approved("linux"), system="linux",hostname="disposable-host",
                                  now=NOW, backup_exists=lambda _:True,free_gb=20,
                                  command_runner=fake)
        self.assertEqual(result["status"],"READY_DRY_RUN")
    def test_denied_without_approved_receipt(self):
        pol, st, pkg, _, _ = settings()
        dec = safe_patch.gate(pol,st,pkg,system="linux",hostname="disposable-host",
                              now=NOW, backup_exists=lambda _:True, free_gb=20)
        self.assertEqual(dec["decision"],"DENY")

    def test_denied_on_work_device(self):
        pol, st, pkg, _, _ = settings()
        pol["employer_managed"] = True
        decision = safe_patch.gate(pol,st,pkg,approved_inventory=approved("linux"),system="linux",hostname="disposable-host",
                                  now=NOW,backup_exists=lambda _:True,free_gb=20)
        self.assertEqual(decision["decision"],"DENY")
    def test_denied_outside_window(self):
        pol, st, pkg, _, _ = settings()
        decision = safe_patch.gate(pol,st,pkg,approved_inventory=approved("linux"),system="linux",hostname="disposable-host",
                                  now=NOW+timedelta(hours=3),
                                  backup_exists=lambda _:True,free_gb=20)
        self.assertEqual(decision["decision"],"DENY")
    def test_denied_missing_backup_and_device_mismatch(self):
        pol, st, pkg, _, _ = settings()
        a = safe_patch.gate(pol,st,pkg,approved_inventory=approved("linux"),system="linux",hostname="wrong",now=NOW,
                            backup_exists=lambda _:False,free_gb=20)
        self.assertIn("machine identity mismatch",a["reasons"])
        self.assertIn("backup evidence missing",a["reasons"])
    def test_denied_firmware_and_kernel(self):
        pol, st, pkg, _, _ = settings()
        for bad in ("kernel", "fwupd", "grub2", "systemd"):
            with self.subTest(bad=bad):
                d = safe_patch.gate(pol,st,bad,approved_inventory=approved("linux"),system="linux",hostname="disposable-host",
                                    now=NOW,backup_exists=lambda _:True,free_gb=20)
                self.assertEqual(d["decision"],"DENY")
    def test_denied_stale_scan(self):
        pol, st, pkg, _, _ = settings()
        st["collected_utc"]=(NOW-timedelta(days=1)).isoformat()
        d=safe_patch.gate(pol,st,pkg,approved_inventory=approved("linux"),system="linux",hostname="disposable-host",
                           now=NOW,backup_exists=lambda _:True,free_gb=20)
        self.assertEqual(d["decision"],"DENY")
    def test_active_process_stops_patch(self):
        pol, st, pkg, _, _ = settings()
        r=safe_patch.apply(pol,st,pkg,approved_inventory=approved("linux"),system="linux",hostname="disposable-host",now=NOW,
                           backup_exists=lambda _:True,free_gb=20,
                           command_runner=lambda cmd:(0,"DeepSeek running"),apply_change=True)
        self.assertEqual(r["status"],"BLOCKED_ACTIVE_OR_UNKNOWN_PROCESSES")

if __name__ == "__main__": unittest.main()
