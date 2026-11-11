import unittest
import dependency_discovery as dd


def record(events=None, **extra):
    return dict({
        "id": "GHSA-fixture", "aliases": ["CVE-FIXTURE-001"],
        "affected": [{"package": {"ecosystem": "npm", "name": "fixture"},
                      "ranges": [{"type": "SEMVER", "events": events or [
                          {"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
    }, **extra)


class DiscoveryTests(unittest.TestCase):
    def test_empty_success_and_missing_vulns_are_unknown(self):
        for cache in ({"query_status": "ok"}, {"query_status": "ok", "vulns": []}, None):
            self.assertEqual(dd.assess_package("fixture", "1.0.0", cache)["status"], "UNKNOWN")

    def test_unversioned_prerelease_and_git_spec_are_unknown(self):
        for value in (None, "git+https://example.invalid", "^1.0.0", "1.2.3-beta.1"):
            self.assertEqual(dd.assess_package("fixture", value, {})["status"], "UNKNOWN")

    def test_positive_and_fixed_boundary(self):
        cached = {"query_status": "ok", "vulns": [record()]}
        self.assertEqual(dd.assess_package("fixture", "1.2.2", cached)["status"], "AFFECTED")
        self.assertEqual(dd.assess_package("fixture", "1.2.3", cached)["status"],
                         "NOT_AFFECTED_BY_RETRIEVED_ADVISORIES")

    def test_withdrawn_not_active(self):
        result = dd.assess_package("fixture", "1.0.0", {
            "query_status": "ok", "vulns": [record(withdrawn="2026-01-01T00:00:00Z")]})
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["withdrawn"], ["GHSA-fixture"])

    def test_batch_ids_without_full_record_remain_unknown(self):
        result = dd.assess_package("fixture", "1.0.0", {"query_status": "ok", "vulns": [{"id": "GHSA-fixture"}]})
        self.assertEqual(result["status"], "UNKNOWN")

    def test_partial_fetch_failure_does_not_prove_negative(self):
        result = dd.assess_package("fixture", "2.0.0", {
            "query_status": "ok", "vulns": [record(), {"id": "unfetched"}]})
        self.assertEqual(result["status"], "UNKNOWN")

    def test_last_affected_and_multiple_intervals(self):
        self.assertTrue(dd.interval_match((1, 0, 0), [{"introduced": "0"}, {"last_affected": "1.0.0"}]))
        self.assertFalse(dd.interval_match((1, 0, 1), [{"introduced": "0"}, {"last_affected": "1.0.0"}]))
        events = [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}]
        self.assertFalse(dd.interval_match((1, 5, 0), events))
        self.assertTrue(dd.interval_match((2, 1, 0), events))

    def test_malformed_ranges_unknown(self):
        for events in ([], [{"fixed": "1.0.0"}], [{"introduced": "bogus"}],
                       [{"introduced": "2.0.0"}, {"fixed": "1.0.0"}]):
            self.assertIsNone(dd.interval_match((1, 0, 0), events))

    def test_other_package_is_not_negative_proof(self):
        self.assertIsNone(dd.advisory_match("unrelated", "1.0.0", record()))

    def test_unsupported_range_type_unknown(self):
        item = record()
        item["affected"][0]["ranges"][0]["type"] = "ECOSYSTEM"
        self.assertIsNone(dd.advisory_match("fixture", "1.0.0", item))

    def test_malformed_version_list_is_not_negative_proof(self):
        item = record()
        item["affected"][0].update(ranges=[], versions=[{"invalid": "1.0.0"}])
        self.assertIsNone(dd.advisory_match("fixture", "2.0.0", item))

    def test_exact_version_list(self):
        item = record()
        item["affected"][0].update(ranges=[], versions=["1.0.0"])
        self.assertTrue(dd.advisory_match("fixture", "1.0.0", item))
        self.assertFalse(dd.advisory_match("fixture", "1.0.1", item))
        self.assertTrue(dd.advisory_match("fixture", "1.0.0+build", item))

    def test_lockfile_counts_and_dev_flags(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"devDependencies": {"fixture": "1.0.0"}},
            "node_modules/fixture": {"version": "1.0.0", "dev": True},
            "node_modules/parent/node_modules/fixture": {"version": "1.0.0"},
            "node_modules/unknown": {"version": "2.0.0"},
        }}
        result = dd.scan(lock, {"fixture@1.0.0": {"query_status": "ok", "vulns": [record()]}})
        self.assertEqual(result["counts"]["AFFECTED"], 2)
        self.assertEqual(result["counts"]["UNKNOWN"], 1)
        self.assertEqual(result["unique_package_versions"], 2)
        self.assertEqual(result["findings"][0]["scope"], "development")
        self.assertTrue(result["findings"][0]["root_direct"])
        self.assertFalse(result["findings"][1]["root_direct"])
        self.assertEqual(len(result["advisory_alias_groups"]), 1)

    def test_alias_dedup_transitive(self):
        findings = [{"advisories": [
            {"id": "A", "aliases": ["B"]}, {"id": "C", "aliases": ["D"]},
            {"id": "B", "aliases": ["C"]},
        ]}]
        self.assertEqual(dd.alias_groups(findings), [["A", "B", "C", "D"]])

    def test_unsupported_lockfile_fails_closed(self):
        with self.assertRaises(ValueError):
            dd.scan({"lockfileVersion": 1}, {})

    def test_linked_package_is_not_assumed_to_be_registry_version(self):
        lock = {"lockfileVersion": 3, "packages": {
            "node_modules/fixture": {"link": True, "version": "2.0.0"},
        }}
        result = dd.scan(lock, {"fixture@2.0.0": {"query_status": "ok", "vulns": [record()]}})
        self.assertEqual(result["findings"][0]["status"], "UNKNOWN")
        self.assertEqual(result["findings"][0]["scope"], "unknown")


if __name__ == "__main__":
    unittest.main()
