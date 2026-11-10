from pathlib import Path
import sys
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "windows"))
import app

INV = {"hostname": "PC", "os": "Windows 11", "disk_free_gb": 50, "reboot_required": False,
       "patch_level": "KB1", "security_updates_pending": 1}


def fake(stdout="", code=0):
    return lambda cmd: types.SimpleNamespace(returncode=code, stdout=stdout, stderr="boom")


class WindowsAppTests(unittest.TestCase):
    def test_fresh_install_never_allows(self):
        g = app.assess(INV, [])["gate"]
        self.assertEqual(g["decision"], "DENY")
        self.assertTrue(any("not enrolled" in r for r in g["reasons"]))

    def test_low_disk_fails_precheck(self):
        g = app.assess(dict(INV, disk_free_gb=2), [])["gate"]
        self.assertTrue(any("pre-check" in r for r in g["reasons"]))

    def test_all_conditions_allow(self):
        ctx = {"enrolled": True, "in_maintenance_window": True, "backup_taken": True, "rollback_plan": "restore point"}
        self.assertEqual(app.assess(INV, [], ctx)["gate"]["decision"], "ALLOW")

    def test_josh_work_running_blocks(self):
        procs = app.running_processes(fake("deepseek.exe,1\n"))
        ctx = {"enrolled": True, "in_maintenance_window": True, "backup_taken": True, "rollback_plan": "x"}
        self.assertEqual(app.assess(INV, procs, ctx)["gate"]["decision"], "DENY")

    def test_agent_failure_is_error_not_pass(self):
        with self.assertRaises(RuntimeError):
            app.collect_inventory("windows-ab12cd34", fake(code=1))

    def test_page_never_interpolates_device_data(self):
        import ui
        v = ui.view({"checks": [], "updates": {}}, None, {"hostname": "<script>"}, {"decision": "DENY", "reasons": []})
        self.assertEqual(v["host"], "<script>")  # carried as data; the page writes it with textContent
        self.assertIn("textContent", ui.PAGE)
        self.assertNotIn("innerHTML", ui.PAGE)


if __name__ == "__main__":
    unittest.main()


class PostureTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import device_status, posture
        self.ds, self.posture = device_status, posture

    def test_empty_probe_is_all_unknown_and_unscored(self):
        checks = self.posture.to_checks({})
        self.assertTrue(all(c["state"] == "unknown" for c in checks))
        status = app.build_status(INV, {}, {"decision": "DENY", "reasons": ["x"]}, "windows-ab12cd34", "2026-11-10T10:00:00Z")
        self.assertEqual(self.ds.validate(status), [])
        self.assertIsNone(self.ds.score(status))

    def test_bad_values_fail(self):
        raw = {"defender_enabled": False, "smbv1_enabled": True, "firewall_profiles_enabled": [True, False],
               "defender_signature_age_days": 30, "bitlocker_protection": 0, "winget_outdated": 3}
        st = {c["id"]: c["state"] for c in self.posture.to_checks(raw)}
        for k in ("defender_on", "smbv1_off", "firewall_on", "defender_signatures_fresh", "bitlocker_on", "apps_current"):
            self.assertEqual(st[k], "fail", k)

    def test_good_values_pass(self):
        raw = {"defender_enabled": True, "defender_realtime": True, "defender_signature_age_days": 1,
               "firewall_profiles_enabled": [True, True, True], "bitlocker_protection": 1, "secure_boot": True,
               "tpm_present": True, "smbv1_enabled": False, "uac_enabled": 1, "rdp_denied": 1, "winget_outdated": 0, "os_build": 22631}
        status = app.build_status(INV, raw, {"decision": "DENY", "reasons": []}, "windows-ab12cd34", "2026-11-10T10:00:00Z")
        self.assertEqual(self.ds.score(status), 100)

    def test_failed_probe_degrades_to_unknown(self):
        self.assertEqual(app.collect_posture(fake(code=1)), {})
        self.assertEqual(app.collect_posture(fake("not json")), {})




class FrozenPathTests(unittest.TestCase):
    def test_frozen_paths_use_bundle_dir(self):
        sys._MEIPASS = "/tmp/bundle"
        try:
            self.assertEqual(app.resource("posture.ps1", Path("/src/p.ps1")), Path("/tmp/bundle") / "posture.ps1")
        finally:
            del sys._MEIPASS
        self.assertEqual(app.resource("posture.ps1", Path("/src/p.ps1")), Path("/src/p.ps1"))


class ScanTests(unittest.TestCase):
    def test_scan_survives_inventory_failure(self):
        calls = []
        def run(cmd):
            calls.append(cmd[0])
            if "agent-windows.ps1" in " ".join(map(str, cmd)):
                return types.SimpleNamespace(returncode=1, stdout="", stderr="update service busy")
            if "posture.ps1" in " ".join(map(str, cmd)):
                return types.SimpleNamespace(returncode=0, stdout='{"os_build": 19045, "defender_enabled": true}', stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        scan = app.Scan("windows-ab12cd34", run)
        scan.work()
        st = scan.state()
        self.assertIsNone(st["error"])
        self.assertTrue(st["warnings"])
        titles = {c["title"]: c["state"] for c in st["view"]["checks"]}
        self.assertEqual(titles["Windows version still supported"], "fail")
        self.assertEqual(st["view"]["pending"], None)

    def test_unexpected_crash_is_shown_not_silent(self):
        def run(cmd):
            raise ValueError("boom")
        scan = app.Scan("windows-ab12cd34", run)
        scan.work()
        self.assertIn("boom", scan.state()["error"])

    def test_servers_are_not_judged_as_windows_10(self):
        import posture
        st = {c["id"]: c["state"] for c in posture.to_checks({"os_build": 17763, "os_product_type": 3})}
        self.assertEqual(st["os_supported"], "unknown")
        st = {c["id"]: c["state"] for c in posture.to_checks({"os_build": 19045, "os_product_type": 1})}
        self.assertEqual(st["os_supported"], "fail")

    def test_page_script_has_no_python_escape_warnings(self):
        import ui, warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(open(ui.__file__, encoding="utf-8").read(), ui.__file__, "exec")

    def test_windows10_build_flagged(self):
        import posture
        st = {c["id"]: c["state"] for c in posture.to_checks({"os_build": 19045})}
        self.assertEqual(st["os_supported"], "fail")
        st = {c["id"]: c["state"] for c in posture.to_checks({"os_build": 22631})}
        self.assertEqual(st["os_supported"], "pass")


class VersionTests(unittest.TestCase):
    def test_state_reports_version_and_page_shows_it(self):
        import ui
        scan = app.Scan("windows-ab12cd34", lambda cmd: types.SimpleNamespace(returncode=1, stdout="", stderr="x"))
        self.assertIn(app.BASE_VERSION, scan.state()["version"])
        self.assertIn('id="ver"', ui.PAGE)


class FallbackHonestyTests(unittest.TestCase):
    def states(self, raw):
        import posture
        return {c["id"]: c["state"] for c in posture.to_checks(raw)}

    def test_weak_fallbacks_never_invent_a_failure(self):
        st = self.states({"bitlocker_shell": 0, "tpm_pnp_found": False})
        self.assertEqual(st["bitlocker_on"], "unknown")
        self.assertEqual(st["tpm_present"], "unknown")

    def checks(self, raw):
        import posture
        return {c["id"]: c for c in posture.to_checks(raw)}

    def test_thinkpad_tpm_switched_off_in_bios(self):
        # Real ThinkPad: Get-Tpm (admin) said TpmPresent False, but PnP lists a non-present "TPM 2.0" device.
        admin = self.checks({"tpm_present": False, "tpm_seen_not_present": True})["tpm_present"]
        self.assertEqual(admin["state"], "fail")
        self.assertIn("switched off in the BIOS", admin["detail"])
        nonadmin = self.checks({"tpm_pnp_found": False, "tpm_seen_not_present": True})["tpm_present"]
        self.assertEqual(nonadmin["state"], "unknown")
        self.assertIn("BIOS", nonadmin["detail"])
        self.assertEqual(self.checks({"tpm_present": True, "tpm_seen_not_present": True})["tpm_present"]["state"], "pass")

    def test_bitlocker_shell_2_stays_unknown_but_says_probably_off(self):
        c = self.checks({"bitlocker_shell": 2})["bitlocker_on"]
        self.assertEqual(c["state"], "unknown")
        self.assertIn("usually means BitLocker is off", c["detail"])

    def test_bitlocker_status_unknown_is_not_a_failure(self):
        self.assertEqual(self.states({"bitlocker_protection": 2})["bitlocker_on"], "unknown")
        self.assertEqual(self.states({"bitlocker_protection": "Unknown"})["bitlocker_on"], "unknown")

    def test_authoritative_reads_still_pass_or_fail(self):
        self.assertEqual(self.states({"bitlocker_protection": 0})["bitlocker_on"], "fail")
        self.assertEqual(self.states({"tpm_present": False})["tpm_present"], "fail")
        self.assertEqual(self.states({"bitlocker_shell": 1})["bitlocker_on"], "pass")
        self.assertEqual(self.states({"tpm_pnp_found": True})["tpm_present"], "pass")
        self.assertEqual(self.states({"secure_boot": False})["secure_boot"], "fail")


class ElevationTests(unittest.TestCase):
    def test_only_own_page_can_request_elevation(self):
        ok = {"Host": "127.0.0.1:8765", "Sec-Fetch-Site": "same-origin"}
        self.assertTrue(app.same_origin(ok, 8765))
        self.assertFalse(app.same_origin({"Host": "127.0.0.1:8765", "Sec-Fetch-Site": "cross-site"}, 8765))
        self.assertFalse(app.same_origin({"Host": "evil.example", "Sec-Fetch-Site": "same-origin"}, 8765))

    def test_relaunch_uses_next_port(self):
        self.assertEqual(app.elevation_command(True, "C:/a.exe", "x.py", 8765), ("C:/a.exe", "--port 8766"))
        prog, params = app.elevation_command(False, "python", "/x/app.py", 8765)
        self.assertIn("--port 8766", params)
