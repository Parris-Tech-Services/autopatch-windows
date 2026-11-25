# Local device health evidence: Windows battery and storage

This is documentation of a reusable operator-side observation pattern, not a new scanner feature, enrolment permission, automatic patch action or remote agent.

## Battery and disk checks

- The Windows battery report supports XML output: powercfg /batteryreport /xml /output <private-local-path>. Treat an unavailable/invalid capacity as UNKNOWN, not 0% or pass.
- Parse the installed Battery element namespace-independently; validate positive DesignCapacity and FullChargeCapacity, then compute 100 * full / design. Keep capacity units (mWh) and cycles separate from instantaneous charge level. Capacity estimates fluctuate, so review trends and practical runtime rather than one reading.
- A local CSV can hold date, free GiB, battery health percentage and design/full capacity. The report and log remain private; do not transmit without separate approval.
- If an owner installs a local alert task, use a limited interactive principal, a bounded schedule, no network access, no deletion, no device update or reboot. Distinguish task registration from a witnessed successful run: inspect LastTaskResult and a fresh populated log row. A popup condition is not proof the popup was seen.
- Storage thresholds and battery warning thresholds are operator preferences, not guarantees or automatic replacement rules. Report low space without deleting user data.

## CPU and firmware observations

Do not infer physical boost limits from one clock reading. Virtualisation can affect reporting, WMI counters may be unavailable, and frequency/benchmark/version/workload differences matter. Record matched benchmark versions, settings, scores, load, named effective clocks, temperatures and power. A benchmark timeout is not a completed score; an idle clock is not a load clock. Missing firmware event records are not proof of no throttling.

Keep Memory Integrity, virtualisation-based security, thermal protections and normal firmware settings intact. Read-only diagnostics may continue without disrupting work; shutdown, firmware reset, UEFI diagnostics and driver installation require a separate owner-approved maintenance window.

## Integration boundary

Existing public scanner remains read-only; this document adds no telemetry or task to the application. Personal health records, reports, identifiers and repair history belong in a private device evidence store. Local observation is not signed central enrolment, independent recovery proof or verified patch authority.
