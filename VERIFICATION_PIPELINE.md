# Discovery-to-deployment verification

## Artifact identity collection

`artifact_verification.py` compares a complete first-party file-hash inventory
with collected deployed-file hashes and an expected inventory digest from a
separately trusted build record. It rejects changed, missing, extra and ambiguous
paths, malformed hashes and mismatched build inventories. JSON reads retain the
existing size and duplicate-field limits.

```sh
python artifact_verification.py --expected expected-files.json \
  --observed observed-files.json --expected-digest <trusted-build-inventory-sha256>
```

Maps contain canonical relative paths and SHA-256 digests. Include HTML and all
first-party executable scripts, styles and assets; do not fingerprint only a
release marker. A detached inventory cannot include its own hash. External
scripts, mutable backends, runtime configuration and collector authenticity need
separate evidence. This helper performs no network access and grants no signing,
deployment or update authority. Even a match has `verified_fixed: false`.
Its output is collector input, not a replacement for authenticated stage receipts.

## Scope and current status

The existing Windows/Fedora posture UI remains read-only. The new tools are
separate, standard-library Python CLIs, available from this source checkout;
they are not added to the downloadable UI executable or Linux zipapp.
Neither the evidence assessor nor the dependency scanner executes updates.
The demonstration executes only its own embedded synthetic Python fixture
inside a disposable temporary directory.

Implemented:

- Cached npm lockfile/OSV discovery with conservative unknown handling.
- A deterministic, authenticated discovery-to-runtime evidence gate.
- A real local fixture run: reproduce a security failure, apply a minimal
  allowlist repair, run the unchanged test, exercise restore, approve a
  disposable canary, copy the candidate, execute it in a new Python process,
  rescan, and observe health.
- Regression tests integrated with the repository's existing unittest discovery.

Not implemented or established by this change:

- General autonomous discovery of unknown vulnerabilities, a cloud model
  integration, live OSV fetching, or complete asset/runtime inventory.
- Independent production signing services, a production deployment adapter,
  replay-resistant deployment execution, or enrollment cryptographic authority.
- A changed scheduler, live device patch, actual CVE remediation, production
  canary, or production rollout approval.

Status: **PARTIALLY COMPLETE** for the broader AutoPatch goal. A fixture result
is **FIXTURE_VERIFIED**, with `verified: false`; it cannot claim real remediation.
The same program simulates all fixture authorities, so separate actor names in
that demo do not establish organisational or process independence.

## Run the entire local fixture

```sh
python -m unittest discover -s tests -v
python repair_demo.py --out _work/verification-demo-01
```

Use a new output directory for each run. Existing evidence is never overwritten.
The ignored `_work/` directory keeps local evidence out of public commits.
The command needs no credentials, paid model, internet access, package install,
privilege, server, or real target. It does not accept arbitrary source or shell
commands.

Expected measurements:

- The security test exits 1 before and 0 after the repair.
- Functional checks pass; the immutable test digest matches across stages.
- Restoring the saved baseline reproduces its exact digest.
- A new process executes the candidate on the disposable canary and observes
  the same candidate digest and corrected authorisation behaviour.
- A fixture-specific AST rescan and at least one second of functional health
  observations pass.
- All eleven evidence stages pass, but the result remains `FIXTURE_VERIFIED`.

Outputs are `manifest.json`, `receipts.json`, `report.json`, `candidate.patch`,
and `security-check.py`. A failed run retains a failure marker where possible.
Demo HMAC keys exist only in memory and are destroyed when the process exits;
saved demo receipts therefore cannot later be authenticated with a retained
demo trust store. The report records what ran, not independent attestation.

The synthetic rule is “only admin is authorised.” A deny-only-guest baseline
incorrectly permits other roles. This is a deliberately known fixture, not a
newly discovered vulnerability or a CVE claim.

## Scan cached dependency intelligence

```sh
python dependency_discovery.py \
  --lockfile path/to/package-lock.json \
  --osv-cache path/to/cached-records.json
```

This reads npm lockfile v2/v3 registry entries. Supply a cache object keyed by
exact `name@version`, for example:

```json
{
  "example@1.0.0": {
    "query_status": "ok",
    "vulns": []
  }
}
```

An empty successful result, including an omitted `vulns` key, stays `UNKNOWN`
under Goal C. A batch list containing advisory IDs without complete records is
insufficient. Missing lookups and partial record failures do not become clean
results. Withdrawn records are retained separately and excluded from active
findings.

With full records, the scanner supports exact affected version lists and
stable three-component npm `SEMVER` event intervals, including introduced,
fixed, last-affected, and limit boundaries. Unsupported specifications,
prereleases, range types, linked workspace packages, or malformed data remain
unknown. This intentionally limited matcher is not a complete npm semver
implementation.

`NOT_AFFECTED_BY_RETRIEVED_ADVISORIES` is narrower than “safe.” Inventory scope,
cache age, reachability, other ecosystems, workspace source, and actual running
applications remain unverified. Production/dev flags describe lockfile
metadata, not runtime exposure. `root_direct` does not infer all workspace
dependency paths.

The report separates occurrences, unique package/version pairs, alias groups,
withdrawn records, and unknown advisory assessments. A package can be known
affected while another advisory for it remains unknown. The command exits 2
for affected/unknown results, invalid inputs, or no registry packages; exit 0
means only that parsed entries are outside the retrieved advisory ranges.

## Evidence contract and trust model

The assessor is a read-only decision tool:

```sh
python verification_pipeline.py \
  --manifest private/run-manifest.json \
  --receipts private/receipts.json \
  --trust-policy private/collector-policy.json
```

It prints a public-safe decision summary, never raw keys or receipt details.
Input files are size-limited. On POSIX the trust policy must have no group or
other permissions; use mode 0600 and a trusted, access-controlled directory.
Windows administrators must apply equivalent ACLs. Do not commit trust files.

The **trust policy is an administrator-provisioned input**, not something the
patch agent may author or include in an evidence bundle. Replacing that policy
replaces the trust boundary. An operator who accepts an attacker's keys has
not established independent verification.

### Manifest

The exact manifest fields are:

| Field | Meaning |
| --- | --- |
| `schema` | `autopatch.verification/1` |
| `run_id` | Unique assessment/deployment attempt identity |
| `asset_id` | Explicitly enrolled target identity |
| `finding_id` | Advisory or validated source-finding identity |
| `source_sha` | 40/64-character source revision; the fixture uses its content digest |
| `baseline_digest` | SHA-256 of the original artifact |
| `candidate_digest` | Different SHA-256 of the tested repair |

Every receipt includes these bindings, plus `stage`, `issuer`, `issued_at`,
`details`, and `signature`. The signature authenticates canonical JSON without
the signature field. Collectors can use `sign_receipt()` as an SDK primitive;
there is deliberately no public signing HTTP endpoint or unrestricted signing
CLI.

### Trusted policy

Configure the following outside agent-controlled artifacts:

- `schema` and `max_age_seconds` (1 to 86,400).
- `assets`: keyed by target identity, with `environment` (`fixture`, `test`, or
  `production`), `ownership: personal`, `enabled: true`, `allow_deploy: true`,
  allowlisted `mechanisms`, and `min_observation_seconds`.
- `issuers`: independently provisioned identities, each with a random
  32-byte hexadecimal `key`, allowed `roles`, and allowed `assets`.

Use different secrets per identity and restrict each collector to the stages
and assets it actually observes. A production collector must not hold a patch
agent's secret, and the patch agent must not hold verifier secrets.

HMAC is symmetric: the assessor has the verification keys and can therefore
forge signatures if compromised. This is a bounded shared-secret trust model,
not public non-repudiation. A production system should use approved workload
identity/asymmetric attestation if the existing coordinator provides it.
Authenticating a collector does not prove its assertions are true or its
tests are comprehensive.

### Stages and decisive obligations

| Stage | Required evidence |
| --- | --- |
| `discovery` | Affected exact baseline, complete scoped coverage, version and intelligence provenance |
| `validation` | Reproduced baseline security-test failure, exit 1, immutable test digest |
| `patch` | Minimal candidate and fix provenance |
| `review` | Separate approval, no security weakening, same test digest |
| `tests` | Security and functional exit 0, same test digest |
| `rollback` | Restore exercised and exact baseline bound |
| `approval` | Explicit, unexpired approval, backup, canary and maintenance-window assertions |
| `deployment` | Successful allowlisted mechanism and exact candidate digest |
| `runtime` | Observed running candidate, version, configuration digest and known reboot state |
| `rescan` | Complete scoped post-deployment negative result on the same artifact with fresh intelligence |
| `health` | Positive observation meeting the target's minimum duration |

All receipts must be fresh and chronologically consistent. Missing stages
prevent later receipts from advancing past the incomplete prefix. Duplicate
stages, invalid signatures, unknown issuers, reused keys, changed test hashes,
different assets/runs/revisions/digests, failed checks, or unknown required
values fail closed.

The patch issuer cannot validate, review, test, approve, or verify its own
repair. The deployer cannot supply runtime, rescan, or health verification.
These identity checks only hold when credentials and collector execution are
actually separated. Signing an agent-written report is not independent
measurement.

An approved prefix may return `READY_FOR_AUTHORISED_DEPLOYMENT`; this is a
decision only, not execution authority or a command runner. Complete
authenticated test/production evidence can return `VERIFIED_FIXED` under the
configured trust assumptions. A pending reboot returns
`INSTALLED_REBOOT_PENDING`, never verified.

The assessor can evaluate the same bundle repeatedly. It does **not** consume
one-time approvals or maintain an execution ledger. Any future deployment
adapter must enforce single-use attempts, freshness at execution, target
locking, and maintenance windows again. Do not connect its decision directly
to privileged commands.

## Production integration still required

1. Inspect and reuse the private coordinator's actual inventory, receipt
   verifier, scheduler and update gates. This repository's `device_status.py`,
   `safe_patch.py`, and `os_update_gate.py` are intentionally unchanged.
2. Implement protected collectors that bind actual findings, tests and
   runtime observations to this contract, or adapt to the coordinator's
   stronger existing format. Do not create competing trust stores.
3. Run real npm advisory records through the cached scanner and review its
   limited semver coverage before enabling any live intelligence adapter.
4. Use protected CI for immutable regression checks and separate review.
   Bind receipts to the exact candidate artifact, not just a PR number.
5. Add a separately approved deployment adapter for one owned test target,
   using the existing policy gate, supported update channel, execution ledger,
   backup and tested recovery. Do not weaken gates or reinterpret read-only
   enrollment as patch permission.
6. Obtain actual target-side running-version, configuration, rescan and health
   evidence. An installed version is not automatically the running version.
7. Exercise denial, stale evidence, partial failure, rollback and pending
   reboot paths before expanding or modifying a recurring task.

No paid model integration, automatic merge, production update, reboot, firmware
change, or employer-managed device action is authorised by running these tools.
