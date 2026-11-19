"""Exercise real temporary files and Python subprocesses, never a live target."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import repair_demo


class DemoTests(unittest.TestCase):
    def test_complete_fixture_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "evidence"
            report = repair_demo.run_demo(out)
            self.assertEqual(report["assessment"]["status"], "FIXTURE_VERIFIED")
            self.assertFalse(report["assessment"]["verified"])
            self.assertEqual(report["baseline_security_exit"], 1)
            self.assertEqual(report["candidate_security_exit"], 0)
            self.assertTrue(report["rollback_exercised"])
            self.assertEqual(report["runtime_digest"], report["candidate_digest"])
            self.assertEqual(len(report["assessment"]["completed_stages"]), 11)
            self.assertTrue((out / "candidate.patch").is_file())
            self.assertTrue((out / "receipts.json").is_file())
            self.assertTrue((out / "report.json").is_file())
            self.assertFalse(any("key" in p.name for p in out.rglob("*")))
            self.assertEqual(json.loads((out / "report.json").read_text())["scope"], "synthetic-local-fixture")

    def test_does_not_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileExistsError):
                repair_demo.run_demo(Path(root))

    def test_scanner_is_fixture_specific_and_unknown_is_not_clean(self):
        self.assertEqual(repair_demo.discover(repair_demo.BASELINE), "AFFECTED")
        self.assertEqual(repair_demo.discover(repair_demo.CANDIDATE), "NOT_AFFECTED")
        self.assertEqual(repair_demo.discover("def allowed(role): return bool(role)"), "UNKNOWN")
        self.assertEqual(repair_demo.discover("not valid python!"), "UNKNOWN")

    def test_cli_reports_fixture_not_production(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [sys.executable, "repair_demo.py", "--out", str(Path(root) / "evidence")],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["assessment"]["status"], "FIXTURE_VERIFIED")


if __name__ == "__main__":
    unittest.main()
