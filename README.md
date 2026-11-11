# AutoPatch for Windows

Security posture scan for a Windows PC, with an optional owner-controlled **read-only enrolment wizard**. The scanner does not change Windows settings, install updates or restart. The optional wizard saves a locally imported approval record in the user's Windows profile. Everything listens on this PC only.

**Download (no sign-in):** https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-windows.exe

Double-click it. SmartScreen will warn about an unknown publisher (the exe is unsigned): click **More info**, then **Run anyway**. Your browser opens at `http://127.0.0.1:8765` with a posture score, the checks (Defender, firewall, BitLocker, Secure Boot, TPM, SMBv1, UAC, Remote Desktop, outdated apps) and whether an auto-apply would be allowed. Close the console window to stop it.

Some checks need administrator rights and show "could not be read" otherwise. Unknown is never counted as a pass.

## Discovery-to-deployment verification tools

The source checkout also includes an [offline verification pipeline](VERIFICATION_PIPELINE.md): cached npm/OSV discovery, authenticated fail-closed evidence assessment, and a disposable local repair/canary demonstration. Run `python repair_demo.py --out _work/verification-demo-01` to exercise the fixture without network access, credentials, package installation or live-device changes.

These are separate developer tools, not new capabilities in the downloaded UI app. A successful fixture reports `FIXTURE_VERIFIED`, not a real CVE fix. Production collectors, independently provisioned trust, an approved deployment adapter and actual runtime evidence are still required; the existing app, enrollment and OS-update boundaries remain unchanged.

## Enrol this personal PC — built into the app (v0.4)

After opening `autopatch-windows.exe`, choose **Enrol this PC**, or open
[the local enrolment wizard](http://127.0.0.1:8765/#enrol) while the app runs.

1. Tick the confirmation that **you personally own this PC** (not work, school or client managed), then click **Download enrolment file**. The app collects the existing read-only inventory and downloads a JSON file. No Windows configuration is changed.
2. Follow the wizard's phone commands. On your trusted Android/Termux AutoPatch installation, create the matching one-time invitation, privately transfer the inventory, approve it there and export `approved-device.json`. Do **not** share invitation tokens or the private phone key.
3. Move `approved-device.json` back to this computer and use **Import approval**. The wizard checks the device ID and hostname and saves a minimal local record under the Windows user's AutoPatch folder.

**This is deliberately not zero-trust one-click cloud enrolment.** The phone remains the authority. A returned JSON receipt cannot be cryptographically verified by this version of the Windows app; its status explicitly says so. Importing it **does not** enable automatic patching, remote control, scheduled tasks or elevated privileges. A future signed-approval or secure local-pairing service is needed for fully hands-off verified enrolment.

The [full enrolment guide](PATCH_ENROLMENT.md) describes the same workflow and the separate optional package patch runner. Never enrol work/customer devices without the relevant administrator's approval.

## Fedora / Linux

Read-only check for a Fedora-family computer. Needs only the python3 that Fedora already has. One line in a terminal:

```
curl -fsSL https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-linux.pyz -o autopatch-linux.pyz && python3 autopatch-linux.pyz
```

It opens a page at `http://127.0.0.1:8765` with a score and the checks: security updates waiting (`dnf check-update --security`), restart needed, firewall, SELinux, disk encryption, Secure Boot, automatic updates, free space, and whether your Fedora release is still supported. It changes nothing; dnf stays the only thing that patches. Run it again with `sudo` to read items that need root. Other distributions are not checked yet (it says so).
