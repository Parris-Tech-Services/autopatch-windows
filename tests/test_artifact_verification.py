import unittest

from artifact_verification import assess_artifact, inventory_digest


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.files = {"index.html": "a" * 64, "assets/app.js": "b" * 64}
        self.digest = inventory_digest(self.files)

    def assess(self, observed, expected=None, digest=None):
        return assess_artifact(self.files if expected is None else expected,
                               observed, self.digest if digest is None else digest)

    def test_match_is_never_security_or_deployment_authority(self):
        result = self.assess(dict(self.files))
        self.assertTrue(result["artifact_bytes_match"])
        self.assertFalse(result["verified_fixed"])
        self.assertFalse(result["deployment_permitted"])
        self.assertFalse(result["execution_performed"])

    def test_changed_bytes_rejected(self):
        self.assertFalse(self.assess(dict(self.files, **{"index.html": "c" * 64}))["artifact_bytes_match"])

    def test_missing_file_rejected(self):
        self.assertFalse(self.assess({"index.html": "a" * 64})["artifact_bytes_match"])

    def test_extra_file_rejected(self):
        self.assertFalse(self.assess(dict(self.files, extra="c" * 64))["artifact_bytes_match"])

    def test_changed_build_inventory_rejected(self):
        self.assertFalse(self.assess(self.files, digest="0" * 64)["artifact_bytes_match"])

    def test_no_trust_digest_never_passes(self):
        self.assertFalse(self.assess(self.files, digest="")["artifact_bytes_match"])

    def test_order_does_not_change_identity(self):
        self.assertEqual(self.digest, inventory_digest(dict(reversed(list(self.files.items())))))

    def test_ambiguous_paths_never_pass(self):
        for name in ("../app", "/app", "a/../b", "a//b", "./app",
                     "a\\b", "a%2fb", "a?x", "a#x", "C:app", "a\x00b"):
            with self.subTest(name=repr(name)):
                result = self.assess({name: "a" * 64}, expected={name: "a" * 64})
                self.assertFalse(result["artifact_bytes_match"])

    def test_malformed_and_empty_maps_never_pass(self):
        for value in ({}, [], None, {"a": True}, {"a": "not-a-digest"}):
            with self.subTest(value=value):
                self.assertFalse(self.assess(value)["artifact_bytes_match"])


if __name__ == "__main__":
    unittest.main()
