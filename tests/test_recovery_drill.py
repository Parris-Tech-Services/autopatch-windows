"""Disposable restore drill: no OS changes, no false recovery claims."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery_drill
import safe_patch
from test_safe_patch import run_case


class FileRestoreTests(unittest.TestCase):
    def test_really_restores_bytes_but_never_grants_os_patching(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            src, backup = p / "original", p / "backup"
            src.write_bytes(b"Disposable application fixture, not a real system image")
            backup.write_bytes(src.read_bytes())
            r = recovery_drill.drill(src, backup)
            self.assertEqual(r["stage"], "FILE_RESTORE_TEST_PASS_OS_RECOVERY_UNVERIFIED")
            self.assertTrue(r["file_restore_tested"])
            self.assertFalse(r["os_rollback_verified"])
            self.assertFalse(r["patch_authorised"])
            self.assertEqual(r["source_sha256"], r["backup_sha256"])

    def test_corrupted_backup_does_not_pass(self):
        with tempfile.TemporaryDirectory() as t:
            src, backup = Path(t)/"original", Path(t)/"backup"
            src.write_bytes(b"before")
            backup.write_bytes(b"corrupted")
            self.assertEqual(recovery_drill.drill(src, backup)["stage"], "BLOCKED")

    def test_missing_or_empty_backups_are_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            src, backup = Path(t)/"original", Path(t)/"backup"
            src.write_bytes(b"content")
            self.assertEqual(recovery_drill.drill(src, backup)["stage"], "BLOCKED")
            backup.write_bytes(b"")
            self.assertEqual(recovery_drill.drill(src, backup)["stage"], "BLOCKED")

    def test_symlink_backup_is_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            src, link = p/"original", p/"alias"
            src.write_bytes(b"content")
            link.symlink_to(src)
            self.assertEqual(recovery_drill.drill(src, link)["stage"], "BLOCKED")

    def test_larger_than_limit_not_copied(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            src, backup = p/"original", p/"backup"
            src.write_bytes(b"x" * (recovery_drill.LIMIT + 1))
            backup.write_bytes(b"x")
            self.assertEqual(recovery_drill.drill(src, backup)["stage"], "BLOCKED")

    def test_approval_flag_required_for_cli(self):
        with mock.patch.object(recovery_drill, "drill") as drill:
            with self.assertRaises(SystemExit) as e:
                recovery_drill.main(["--original", "x", "--backup", "y", "--out", "z"])
            self.assertEqual(e.exception.code, 2)
            drill.assert_not_called()

    def test_checked_file_restore_does_not_become_os_gate_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            src, backup = p/"a", p/"b"
            src.write_bytes(b"just a file")
            backup.write_bytes(src.read_bytes())
            report = recovery_drill.drill(src, backup)
            self.assertFalse(report["os_rollback_verified"])
            self.assertFalse(report["patch_authorised"])

    def test_winget_is_pinned_to_exact_version(self):
        report, commands = run_case("windows")
        command = next(x for x in commands if x[0] == "winget" and x[1] == "upgrade")
        self.assertEqual(command[command.index("--version") + 1], "1.1")
        self.assertEqual(report["status"], "PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
