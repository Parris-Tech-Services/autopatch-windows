#!/usr/bin/env python3
"""Offline artifact-identity comparison. Never fetches, deploys, signs or executes.

The expected digest must come from a separately trusted build record. Observations
must come from a separately authorised collector of every first-party deployed
file. Matching agent-supplied maps is NOT independent attestation.
"""
import argparse
import hashlib
import hmac
import json

from verification_pipeline import Invalid, canonical, digest, need, read_json

MAX_FILES = 4096


def validate_files(files):
    need(isinstance(files, dict) and 0 < len(files) <= MAX_FILES,
         "artifact inventory missing or exceeds limit")
    for name, value in files.items():
        need(isinstance(name, str) and 0 < len(name) <= 512, "invalid artifact path")
        need(not any(c in name for c in "\\%?#:\x00") and not name.startswith("/"),
             "ambiguous or absolute artifact path")
        need(all(part not in ("", ".", "..") for part in name.split("/")),
             "non-canonical artifact path")
        need(digest(value), "invalid file digest")
    return files


def inventory_digest(files):
    """Stable digest of the complete first-party path-to-SHA256 inventory."""
    return hashlib.sha256(canonical(validate_files(files))).hexdigest()


def assess_artifact(expected, observed, expected_digest):
    """Compare read-only inputs. This result can never declare VERIFIED_FIXED."""
    report = {
        "schema": "autopatch.artifact-comparison/1", "status": "NOT_VERIFIED",
        "artifact_bytes_match": False, "verified_fixed": False,
        "deployment_permitted": False, "execution_performed": False, "reasons": [],
    }
    try:
        need(digest(expected_digest), "trusted build digest missing")
        actual = inventory_digest(expected)
        need(hmac.compare_digest(actual, expected_digest), "build inventory digest mismatch")
        validate_files(observed)
        need(set(expected) == set(observed), "observed inventory missing or has extra files")
        need(all(hmac.compare_digest(expected[k], observed[k]) for k in expected),
             "deployed file bytes differ")
        report.update(status="ARTIFACT_BYTES_MATCH", artifact_bytes_match=True,
                      file_count=len(expected), inventory_digest=actual)
    except (Invalid, TypeError, ValueError, RecursionError):
        report["reasons"] = ["artifact comparison incomplete, malformed or mismatched"]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--observed", required=True)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args(argv)
    try:
        result = assess_artifact(read_json(args.expected), read_json(args.observed),
                                 args.expected_digest)
    except (OSError, ValueError, TypeError, RecursionError):
        result = assess_artifact(None, None, None)
    print(json.dumps(result, indent=2))
    return 0 if result["artifact_bytes_match"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
