#!/usr/bin/env python3
"""Read-only npm lockfile / cached full OSV record assessment.

No HTTP requests, package installation or source execution. Stable three-part
npm SEMVER intervals and exact version lists are supported. Prerelease and
unsupported range forms remain UNKNOWN rather than guessing.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

import verification_pipeline as vp

VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\+[0-9A-Za-z.-]+)?$")


def version(value):
    match = VERSION.fullmatch(value) if isinstance(value, str) else None
    return tuple(int(x) for x in match.groups()) if match else None


def interval_match(installed, events):
    if not isinstance(events, list) or not events:
        return None
    start, matches, previous = None, False, None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        kind, raw = next(iter(event.items()))
        boundary = (0, 0, 0) if kind == "introduced" and raw == "0" else version(raw)
        if boundary is None or (previous is not None and boundary < previous):
            return None
        previous = boundary
        if kind == "introduced":
            if start is not None:
                return None
            start = boundary
        elif kind in ("fixed", "last_affected", "limit"):
            if start is None:
                return None
            matches |= start <= installed and (installed <= boundary if kind == "last_affected" else installed < boundary)
            start = None
        else:
            return None
    return matches or (start is not None and installed >= start)


def advisory_match(name, installed, record):
    if not isinstance(record, dict) or not isinstance(record.get("id"), str):
        return None
    affected = record.get("affected")
    if not isinstance(affected, list):
        return None
    results = []
    for entry in affected:
        if not isinstance(entry, dict):
            return None
        package = entry.get("package")
        if not isinstance(package, dict):
            return None
        if package.get("ecosystem") != "npm" or package.get("name") != name:
            continue
        versions, ranges = entry.get("versions", []), entry.get("ranges", [])
        if not isinstance(versions, list) or not isinstance(ranges, list):
            return None
        parsed = version(installed)
        if installed in versions or (parsed is not None and any(
                version(item) == parsed for item in versions if version(item) is not None)):
            return True
        values = []
        for span in ranges:
            if not isinstance(span, dict) or span.get("type") != "SEMVER" or parsed is None:
                values.append(None)
            else:
                values.append(interval_match(parsed, span.get("events")))
        if any(x is True for x in values):
            return True
        if any(x is None for x in values) or (not ranges and not versions):
            results.append(None)
        else:
            results.append(False)
    if not results or any(x is None for x in results):
        return None
    return False


def assess_package(name, installed, cached):
    result = {"status": "UNKNOWN", "advisories": [], "unknown_advisories": [], "withdrawn": []}
    if version(installed) is None:
        result["reason"] = "unsupported or missing exact stable npm version"
        return result
    if not isinstance(cached, dict) or cached.get("query_status") != "ok":
        result["reason"] = "cached lookup missing or unsuccessful"
        return result
    records = cached.get("vulns", [])
    if not isinstance(records, list) or not records:
        result["reason"] = "no matching OSV records; Goal C unknown"
        return result
    negatives = 0
    for record in records:
        if isinstance(record, dict) and record.get("withdrawn"):
            result["withdrawn"].append(record.get("id", "unknown"))
            continue
        matched = advisory_match(name, installed, record)
        identity = record.get("id", "unknown") if isinstance(record, dict) else "unknown"
        if matched is True:
            aliases = record.get("aliases", [])
            if not isinstance(aliases, list) or not all(isinstance(x, str) for x in aliases):
                aliases = []
            result["advisories"].append({"id": identity, "aliases": aliases})
        elif matched is None:
            result["unknown_advisories"].append(identity)
        else:
            negatives += 1
    if result["advisories"]:
        result["status"] = "AFFECTED"
    elif negatives and not result["unknown_advisories"]:
        result["status"] = "NOT_AFFECTED_BY_RETRIEVED_ADVISORIES"
    else:
        result["reason"] = "active advisory assessment incomplete"
    return result


def alias_groups(findings):
    groups = []
    for finding in findings:
        for advisory in finding["advisories"]:
            names = {advisory["id"], *advisory["aliases"]}
            overlap = [group for group in groups if group & names]
            for group in overlap:
                groups.remove(group)
                names |= group
            groups.append(names)
    return sorted([sorted(group) for group in groups])


def scan(lockfile, cache):
    vp.need(isinstance(lockfile, dict) and lockfile.get("lockfileVersion") in (2, 3),
            "only npm lockfile v2/v3 supported")
    packages = lockfile.get("packages")
    vp.need(isinstance(packages, dict) and isinstance(cache, dict), "invalid lockfile or cache")
    root = packages.get("", {})
    vp.need(isinstance(root, dict), "invalid root package")
    declared = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        values = root.get(field, {})
        vp.need(isinstance(values, dict), "invalid root dependency declarations")
        declared.update(values)
    findings = []
    for path, entry in packages.items():
        if path == "":
            continue
        vp.need(isinstance(path, str) and isinstance(entry, dict), "invalid package entry")
        if "node_modules/" not in path:
            # Workspace source entries are not assumed to be registry packages.
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        installed = entry.get("version")
        lookup = cache.get(f"{name}@{installed}") if isinstance(installed, str) else None
        result = assess_package(name, installed, lookup)
        if entry.get("link"):
            result = {"status": "UNKNOWN", "advisories": [], "unknown_advisories": [],
                      "withdrawn": [], "reason": "linked package requires source/workspace assessment"}
        result.update({
            "path": path, "package": name, "version": installed,
            "scope": "unknown" if entry.get("devOptional") or entry.get("link")
            or ("dev" in entry and type(entry["dev"]) is not bool) else (
                "development" if entry.get("dev") is True else "production"),
            "root_direct": path == "node_modules/" + name and name in declared,
        })
        findings.append(result)
    counts = {state: sum(x["status"] == state for x in findings)
              for state in ("AFFECTED", "UNKNOWN", "NOT_AFFECTED_BY_RETRIEVED_ADVISORIES")}
    return {
        "schema": "autopatch.dependency-discovery/1",
        "scope": "npm-registry-entries-in-one-lockfile; cached OSV only",
        "comparison": "Dependabot comparison unavailable", "counts": counts,
        "package_occurrences": len(findings),
        "unique_package_versions": len({(x["package"], x["version"]) for x in findings}),
        "advisory_alias_groups": alias_groups(findings),
        "findings": findings, "runtime_coverage": "NOT_VERIFIED",
        "not_verified": ["Workspace source packages", "Other ecosystems", "Running deployed versions",
                         "Advisory freshness", "Reachability or exploitability"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--osv-cache", type=Path, required=True,
                        help='Object keyed by name@version, containing query_status and full vulns records')
    args = parser.parse_args(argv)
    try:
        result = scan(vp.read_json(args.lockfile), vp.read_json(args.osv_cache))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({"status": "UNKNOWN", "reason": "invalid or unsupported scan input"}))
        return 2
    print(json.dumps(result, indent=2))
    # A successful parse/lookup is not a clean bill of health.
    return 0 if result["package_occurrences"] and not result["counts"]["AFFECTED"] and not result["counts"]["UNKNOWN"] else 2


if __name__ == "__main__":
    sys.exit(main())
