# Enrol personal devices for AutoPatch (Windows / Fedora)

**Deploy status:** no device is automatically enrolled by installing or running the
AutoPatch app. Your live scanner remains read-only. The separate `safe_patch.py`
script is *disabled unless explicitly opted in with your own policy and backup
evidence*; the phone's enrolment only grants `inventory_read`.

**Never enrol a work, employer, school, client or shared machine without its
administrator's explicit authorisation.** Your work ThinkPad must stay out of
AutoPatch's automatic patching scope even if Windows says it is not domain joined.

## A. One-time read-only enrolment (private)

1. On the trusted phone where the private `JoshDashboard4/security/autopatch-ai`
   code and authority live, run:
   
   ```sh
   python3 devices/enroll.py init
   python3 devices/enroll.py invite --device-id home-fedora-01 --device-class linux --owner joshualparris
   ```
   
   For a *personal* Windows device, choose `--device-id home-windows-01`
   and `--device-class windows`. **Never share the one-time invitation token
   in chat, logs, or Git.**
2. On the **personal device you physically control**, use the existing
   `devices/agent-linux.sh` or `devices/agent-windows.ps1` agent from the
   private repository (the public AutoPatch project also bundles the Windows
   agent). It runs locally and writes a JSON inventory. Example on Fedora:
   
   ```sh
   AUTOPATCH_DEVICE_ID=home-fedora-01 sh devices/agent-linux.sh ./inventory.json
   ```
   
   Example on personal Windows, from a trusted local checkout:
   
   ```powershell
   .\devices\agent-windows.ps1 -DeviceId home-windows-01 -OutFile .\inventory.json
   ```
3. Copy *only that inventory file* privately to the trusted phone and approve
   with its local invitation token:
   
   ```sh
   python3 devices/enroll.py approve --token '<one-time-token>' --inventory ./inventory.json
   python3 devices/enroll.py export --device-id home-fedora-01 --out ./approved-device.json
   ```
   
   Export is minimal: device ID/class, hostname, approval metadata and
   read-only permission. **It is not a cryptographic patch authorisation.**
   Transfer it back to that same personal device privately. Never distribute
   the phone's HMAC key or complete multi-device registry.
4. Start the normal local status app with **the exact enrolled device ID**
   (otherwise it will generate a different ID and ingestion will block).
   On Fedora, from a source checkout:
   
   ```sh
   python3 linux/autopatch_linux.py --device-id home-fedora-01
   ```
   
   On personal Windows from a PowerShell terminal where the released exe lives:
   
   ```powershell
   .\autopatch-windows.exe --device-id home-windows-01
   ```
   
   While it runs, save **on that same device** its local status file:
   
   ```sh
   curl -fsS http://127.0.0.1:8765/status.json > ./status.json
   ```
   
   PowerShell:
   
   ```powershell
   Invoke-WebRequest http://127.0.0.1:8765/status.json -OutFile .\status.json
   ```
   
   The status must have the same device ID and hostname and be under an hour
   old for the patch runner. Upload it privately to the trusted phone if you
   want fleet ingestion:
   
   ```sh
   python3 fleet_ingest.py --registry ~/.local/share/autopatch-ai/devices.json --status ./status.json --out ~/.local/share/autopatch-ai/fleet
   ```
   
   This checks read-only inventory. It does not enable updates.

## B. Future local package patching (separate explicit opt-in)

The public repo provides `patch-policy.example.json`, intended to be copied
**outside Git** onto the personal device. Update device ID, hostname, OS, target
package/version, maintenance window, rollback plan and private backup evidence.
Defaults are `patching_enabled: false` and `backup.verified: false`: a fresh
file can never patch. A tested recoverable backup must really exist.

The standalone local patch executor is NOT bundled in the read-only
`autopatch-windows.exe`; run it from an authorised checkout with Python 3.11+:

```sh
python3 safe_patch.py --policy /private/policy.json --approved-inventory /private/approved-device.json --status /private/status.json --package PACKAGE_ID --out /private/dry-run.json
```

Dry-run is default. `--apply` is the separate local opt-in to invoke
`dnf upgrade --security -y ... PACKAGE` on Fedora or
`winget upgrade --id PACKAGE --exact --silent ...` on Windows, **only if every
gate passes**. There is no scheduled patch timer or automatic restart, and
no attempt to elevate privileges. Do not schedule `--apply` until an owned
disposable OS test plus rollback has been proven for your chosen package.

A successful upgrade is only
`PACKAGE_VERSION_VERIFIED_CVE_NOT_VERIFIED`. It proves the installed package
version changed to the explicitly approved target; it does **not** prove a
specific Windows/Fedora CVE is resolved. OS/vendor/CVE verification remains a
separate task, and OS updates or drivers/firmware are excluded from this runner.
A failed postcheck returns `BLOCKED_UNVERIFIED_REVIEW_ROLLBACK` and requires
manual recovery (there is no automatic OS rollback).

This project is not an MDM or unattended fleet patch manager. No hidden
remote shell, LAN crawling, email, self-approval or automatic enrolment.
