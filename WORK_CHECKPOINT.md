# Verification workflow checkpoint

Date: 11 November 2026. Classification: PUBLIC, implementation summary only.

## Implemented on this branch

- Read-only cached npm/OSV discovery with Goal C unknown semantics, conservative
  interval matching, withdrawn-record handling, and alias deduplication.
- An offline authenticated evidence coordinator with exact artifact/target/run
  binding, freshness checks, identity separation, protected-policy assumptions,
  and distinct tested/deployed-unverified/reboot-pending/verified states.
- An executable embedded-fixture workflow covering discovery, failing security
  reproduction, minimal repair, deterministic review, unchanged regression,
  restore rehearsal, approved local canary, runtime observation, rescan, health,
  and evidence artifacts.
- Documentation explaining trust assumptions, fixture limitations, and remaining
  production integration work.

## Local evidence

- Baseline: 69 existing tests passed before edits.
- Current: 116 tests passed with `python -m unittest discover -s tests -q`.
- Python compilation and `git diff --check` passed.
- Original `device_status.py`, `safe_patch.py`, `os_update_gate.py`, UI/apps, and
  release workflow are unchanged.
- The local fixture security check failed before the patch and passed after;
  restored baseline and observed candidate digests matched their expected values.
- Existing tests emit resource warnings on the local Python version; these were
  also present in the baseline run and were not suppressed or reclassified.
- Review reproduced a malformed OSV version-list negative-classification defect
  with a failing test; the matcher now returns unknown for that malformed input.

## Honest limits

Overall status is PARTIALLY COMPLETE. This branch does not establish real CVE
remediation, independent production collectors, live inventory coverage, a
deployment adapter, or unattended execution. Fixture actors and their ephemeral
keys are simulated in one local process and cannot establish production trust.

No production system, live device, package manager, scheduled maintenance task,
enrollment authority, merge rule, or OS gate was changed. The source-only tools
are not bundled into the current UI downloads.

## Next safe action

Review this implementation and its CI, then inspect the existing private
coordinator before connecting production collectors or adding another receipt
format. Obtain explicit approval for one owned test target, establish
independently provisioned collectors and a replay-resistant deployment adapter,
and exercise the full failure/rollback path before enabling real deployment.

See [VERIFICATION_PIPELINE.md](VERIFICATION_PIPELINE.md) for commands, the trust
contract, and detailed integration requirements. Existing cloud-enrollment work
is separate; registration is not deployment authority.

## Real public-app canary and artifact comparison

11 November 2026: added the source-only `artifact_verification.py` helper and nine
offline negative/positive tests. It checks full first-party file inventories
against a separate expected inventory digest, rejects changed/missing/extra files
and ambiguous paths, and never declares a vulnerability fixed or allows deployment.
Full local suite: **125 tests passed**. Existing read-only apps, device status and
update gates remain unchanged.

Alternative public canary: `Parris-Tech-Services/Midnight-Line`. Real esbuild CORS
regression fails on 0.21.5 and passes unchanged on 0.25.12. Root-lockfile npm audit
reports six affected package nodes before and zero findings after; production
dependency versions and application source are unchanged. Candidate browser
matrix: 36/36 desktop/emulated-mobile journeys pass. Separate hosted preview
loads, completes six stations and restarts; JS/CSS hashes match.

This does not establish trusted independent actors, source-vulnerability discovery,
whole-repository security, production remediation or an unattended deployment loop.
Hosted artifact identity and rollback evidence must remain distinct from a
post-deployment vulnerability rescan of an actual running backend.
