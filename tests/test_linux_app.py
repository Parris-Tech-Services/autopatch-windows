from pathlib import Path
import sys
import unittest
from datetime import date

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "linux", ROOT, ROOT / "windows"):
    sys.path.insert(0, str(p))
import autopatch_linux as linux_app  # noqa: E402
import probe  # noqa: E402

DNF_OUT = """kernel.x86_64          6.17.1-300.fc43   updates
openssl-libs.x86_64    1:3.2.6-2.fc43    updates
Obsoleting packages
foo.x86_64   1.0   updates
"""


def runner(table):
    def run(cmd, timeout=0):
        for key, val in table.items():
            if cmd[: len(key)] == list(key):
                return val
        return 127, ""
    return run


FEDORA = {
    ("dnf", "-q", "check-update", "--security"): (100, DNF_OUT),
    ("dnf", "needs-restarting", "-r"): (1, ""),
    ("getenforce",): (0, "Enforcing\n"),
    ("systemctl", "is-active", "firewalld"): (0, "active\n"),
    ("findmnt", "-no", "SOURCE", "/"): (0, "/dev/mapper/luks-abc\n"),
    ("lsblk", "-s", "-nro", "TYPE"): (0, "lvm\ncrypt\npart\ndisk\n"),
    ("mokutil", "--sb-state"): (0, "SecureBoot enabled\n"),
    ("systemctl", "is-enabled", "dnf5-automatic.timer"): (0, "enabled\n"),
    ("ps", "-eo", "comm"): (0, "systemd\nbash\n"),
}
OSREL = 'PRETTY_NAME="Fedora Linux 43"\nID=fedora\nSUPPORT_END=2026-12-02\n'


def read(path):
    return OSREL if path == "/etc/os-release" else None


class ProbeTests(unittest.TestCase):
    def test_counts_only_package_lines(self):
        self.assertEqual(probe.count_update_lines(DNF_OUT), 3)

    def test_fedora_all_good_except_updates_and_reboot(self):
        raw = probe.collect(runner(FEDORA), read, free_gb=50)
        st = {c["id"]: c["state"] for c in probe.to_checks(raw, today=date(2026, 11, 10))}
        self.assertEqual(st["os_supported"], "pass")
        self.assertEqual(st["security_updates"], "fail")
        self.assertEqual(st["reboot_ok"], "fail")
        for good in ("firewall_on", "selinux_on", "disk_encrypted", "auto_updates", "disk_space"):
            self.assertEqual(st[good], "pass", good)

    def test_end_of_support_passed(self):
        raw = probe.collect(runner(FEDORA), read, free_gb=50)
        st = {c["id"]: c["state"] for c in probe.to_checks(raw, today=date(2027, 1, 1))}
        self.assertEqual(st["os_supported"], "fail")

    def test_missing_tools_are_unknown_never_a_pass_or_invented_fail(self):
        raw = probe.collect(runner({}), lambda p: None, free_gb=50)
        checks = {c["id"]: c for c in probe.to_checks(raw)}
        for cid in ("os_supported", "security_updates", "reboot_ok", "firewall_on", "selinux_on", "disk_encrypted", "auto_updates"):
            self.assertEqual(checks[cid]["state"], "unknown", cid)
        self.assertIn("dnf not found", checks["security_updates"]["detail"])
        self.assertNotIn("None", " ".join(c["detail"] for c in checks.values()))

    def test_no_updates_is_a_pass(self):
        table = dict(FEDORA)
        table[("dnf", "-q", "check-update", "--security")] = (0, "")
        raw = probe.collect(runner(table), read, free_gb=50)
        self.assertEqual({c["id"]: c["state"] for c in probe.to_checks(raw)}["security_updates"], "pass")


class ScanTests(unittest.TestCase):
    def test_scan_produces_valid_shared_status_and_denies_by_default(self):
        scan = linux_app.Scan("linux-ab12cd34", runner(FEDORA), read)
        scan.work()
        st = scan.state()
        self.assertIsNone(st["error"])
        self.assertEqual(st["view"]["gate"]["decision"], "DENY")
        self.assertFalse(st["can_elevate"])
        self.assertEqual(scan.status["device"]["class"], "linux")

    def test_blocking_work_is_seen(self):
        table = dict(FEDORA)
        table[("ps", "-eo", "comm")] = (0, "deepseek\n")
        scan = linux_app.Scan("linux-ab12cd34", runner(table), read)
        scan.work()
        self.assertTrue(any("work is running" in r for r in scan.state()["view"]["gate"]["reasons"]))

    def test_crash_is_reported_not_silent(self):
        def boom(cmd, timeout=0):
            raise ValueError("boom")
        scan = linux_app.Scan("linux-ab12cd34", boom, read)
        scan.work()
        self.assertIn("boom", scan.state()["error"])


class PackagingTests(unittest.TestCase):
    def test_pyz_builds_and_contains_every_module(self):
        import subprocess, tempfile, zipfile
        out = Path(tempfile.mkdtemp()) / "a.pyz"
        subprocess.run([sys.executable, str(ROOT / "tools" / "build_pyz.py"), str(out)], check=True, capture_output=True)
        names = set(zipfile.ZipFile(out).namelist())
        for n in ("__main__.py", "autopatch_linux.py", "probe.py", "server.py", "ui.py", "device_status.py", "os_update_gate.py"):
            self.assertIn(n, names)


if __name__ == "__main__":
    unittest.main()


class SharedPageWordingTests(unittest.TestCase):
    def test_linux_page_never_says_windows(self):
        import ui
        page = ui.page("dnf")
        self.assertNotIn("Windows Update", page)
        self.assertNotIn('["Windows",v', page)
        self.assertIn("dnf does the patching", page)
        self.assertNotIn("{{PATCHER}}", page)
