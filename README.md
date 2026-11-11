# AutoPatch for Windows

Security posture scan for a Windows PC, with an optional **one-click cloud registration button**. The scanner does not change Windows settings, install updates or restart. The button connects to your Cloudflare-hosted read-only registration service and stores a private device credential in your Windows user profile. Everything listens on this PC only.

**Download (no sign-in):** https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-windows.exe

Double-click it. SmartScreen will warn about an unknown publisher (the exe is unsigned): click **More info**, then **Run anyway**. Your browser opens at `http://127.0.0.1:8765` with a posture score, the checks (Defender, firewall, BitLocker, Secure Boot, TPM, SMBv1, UAC, Remote Desktop, outdated apps) and whether an auto-apply would be allowed. Close the console window to stop it.

Some checks need administrator rights and show "could not be read" otherwise. Unknown is never counted as a pass.

## One-click cloud enrolment (Windows v0.5)

1. [Download AutoPatch Windows](https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-windows.exe) and open it on **a personal PC you own and are authorised to manage**.
2. Click **Enrol this PC**. That's it. No phone, Termux, manual command, or file.
3. AutoPatch connects to [AutoPatch Cloud](https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev/) over HTTPS and saves a unique, randomly generated device credential under your user profile.

The device becomes **cloud-registered, but not owner-verified**. It sends only the machine's device ID, hostname and Windows device class during enrolment. Credentials are hashed by the cloud service; the original credential stays local. The registration is not a patching, command execution, remote control, background monitoring, or restart permission. The app remains read-only.

**Important:** An authenticated fleet dashboard is **not yet enabled**, because Cloudflare Access is not configured on this account. Registration is not a claim that any central operator has approved the PC or that unattended patching has begun. Work/school/customer computers should only be enrolled with their administrator's authorisation. The legacy phone approval workflow is deprecated, not required for this button.

The [short enrolment guide](PATCH_ENROLMENT.md) explains the one-click flow and current limits.

## Personal-device patch safety progress (11 November 2026)

The existing opt-in, local-only `safe_patch.py` command now **pins winget upgrades to the exact approved version**, rather than accepting an unbounded latest-version install. It still has no service, scheduler, remote patch endpoint or automatic OS restart; Windows Update itself remains read-only in the app. A successful package-version update is **not** proof that a CVE has been fixed.

A new `recovery_drill.py` can restore a **small disposable file** from an existing backup into a temporary folder, verify matching SHA-256 and discard the restored copy. This is useful evidence of one file's restorability but **does not prove a Windows restore point, Fedora snapshot or whole-device rollback works**, and it never enables patching. Example on an explicitly authorised personal device:

```sh
python recovery_drill.py --owned-personal-device --original path/to/safe-test-file --backup path/to/backup-copy --out private-restore-report.json
```

**Do not enable unattended patching yet:** Current Cloudflare registration remains owner-unverified; no personally owned machine has a tested system rollback and independently verified post-patch CVE scan. Before any household pilot, require owner-approved enrolment, actual system recovery/restore test, bounded package allowlist and maintenance window, independent running-version/advisory verification, and no changes to work, school or client PCs. The private `JoshDashboard4/security/autopatch-ai/` repository owns the end-to-end evidence lifecycle; this public app must not create a competing controller or expose private device data.

## Fedora / Linux

Read-only check for a Fedora-family computer. Needs only the python3 that Fedora already has. One line in a terminal:

```
curl -fsSL https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-linux.pyz -o autopatch-linux.pyz && python3 autopatch-linux.pyz
```

It opens a page at `http://127.0.0.1:8765` with a score and the checks: security updates waiting (`dnf check-update --security`), restart needed, firewall, SELinux, disk encryption, Secure Boot, automatic updates, free space, and whether your Fedora release is still supported. It changes nothing; dnf stays the only thing that patches. Run it again with `sudo` to read items that need root. Other distributions are not checked yet (it says so).
