# Enrol a personal Windows PC — one click

**Install:** [AutoPatch for Windows](https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-windows.exe)

1. Open AutoPatch on a **personally owned Windows computer**.
2. Click **Enrol this PC** in the app.
3. Look for **Cloud registered · Owner not verified**.

That's it. The app sends a minimal device identity over HTTPS to
[AutoPatch Cloud](https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev/).
No phone, terminal commands, invitation tokens or JSON files.

## What this enables

Cloud-side read-only device registration, with a private randomly generated
credential saved in your Windows profile. The service stores a SHA-256 digest of
that credential and the device ID, hostname, class and registration timestamps.

This is **not yet a verified owner fleet enrolment**. There is no private fleet
dashboard sign-in yet, no unattended monitoring service and no automatic
patching. The service does not expose a public device list or any endpoint
that performs patches, commands, remote control, BIOS changes or restarts.

**Don't enrol an employer, school or customer device without written
authorisation from its administrator.** A domain-free work PC is still a
work-managed device. If you click on a work device by mistake, its read-only
cloud registration does not grant patch privileges, but contact the owner
about removing the registration.

## If enrolment fails

Check your internet connection and press the button again. Failed or
interrupted requests are safe to retry: the device reuses its same local random
credential. The app will never claim a confirmed registration unless the
cloud responds with the restricted read-only result.

Cloud availability is checked at
[the health endpoint](https://autopatch-cloud-enrolment.parris-neathaustralia.workers.dev/healthz).

## What's next

Cloudflare Access owner sign-in is currently **not enabled on this Cloudflare
account**. It must be configured before a private shared device dashboard can
show approved fleet devices or issue patch policies.

OS updates, winget, Fedora dnf and vendor CVE verification must still
pass explicit safety gates and tests. The separate `safe_patch.py` tool
remains deny-by-default, local-only and opt-in; it is not scheduled and is not
part of the one-click enrolment operation.
