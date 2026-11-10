import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_status as ds


def doc(pending=2, when="2026-11-10T10:00:00Z", checks=None):
    return {"schema_version": 1, "device": {"id": "windows-ab12cd34", "class": "windows", "label": "PC"},
            "collected_utc": when, "os": {"name": "Windows 11"}, "updates": {"pending_security": pending},
            "checks": checks if checks is not None else [], "findings": []}


class StatusTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ds.validate(doc()), [])

    def test_unknown_field_rejected(self):
        d = doc(); d["extra"] = 1; d["device"]["password"] = "x"
        self.assertEqual(len(ds.validate(d)), 2)

    def test_credential_rejected(self):
        d = doc(); d["findings"] = [{"id": "x", "severity": "low", "evidence": "github_pat_abcdef"}]
        self.assertTrue(any("credential" in e for e in ds.validate(d)))

    def test_bad_enums(self):
        d = doc(checks=[{"id": "fw", "state": "maybe", "severity": "huge"}])
        self.assertEqual(len(ds.validate(d)), 2)

    def test_unknown_is_not_pass_and_empty_is_not_perfect(self):
        cs = [{"id": "a", "state": "pass", "severity": "high"}, {"id": "b", "state": "unknown", "severity": "high"}]
        self.assertEqual(ds.score(doc(checks=cs)), 50)
        self.assertIsNone(ds.score(doc()))

    def test_verify_update(self):
        before, after = doc(2), doc(0, "2026-11-10T12:00:00Z")
        self.assertTrue(ds.verify_update(before, after)["verified"])
        self.assertFalse(ds.verify_update(before, doc(2, "2026-11-10T12:00:00Z"))["verified"])
        self.assertFalse(ds.verify_update(before, doc(0))["verified"])  # not newer
        self.assertFalse(ds.verify_update(before, doc("unknown", "2026-11-10T12:00:00Z"))["verified"])


if __name__ == "__main__":
    unittest.main()
