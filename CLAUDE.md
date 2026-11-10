# AutoPatch for Windows: context for coding agents

## What this is
A read-only patch and security posture checker for a Windows PC the owner controls. It is one part of a larger "AutoPatch" project whose goal is: every device the owner has (Windows, Mac, Linux, Android, iPhone, websites, GitHub repos) kept as safe as possible, automatically, with AI helping find vulnerabilities. Android (Kotlin) and Mac apps and a web dashboard come later and share the status contract in `device_status.py`.

Today the app only LOOKS and DECIDES. It installs nothing and changes nothing. Windows Update stays the only thing that patches. Turning on any real patching is a later, separate phase.

## Who you are working for, and how
- The owner is not a developer by trade and wants minimal setup. One-click everything, plain language, no jargon, no homework you could do yourself. Do not ask the owner to do something you can do.
- Report honestly: "implemented" is not "verified". Say what ran on real hardware and what only ran in tests. Never claim an update or fix succeeded without checking.
- The owner shares screenshots of the page after each build. Treat them as the real test result.

## Hard rules (do not weaken to make a test pass)
- READ-ONLY. No installs, no setting changes, no firmware/BIOS changes, no remote control, no listening on anything but 127.0.0.1.
- UNKNOWN IS NEVER A PASS. A check that could not be read must say `unknown`. A weak fallback (anything that cannot prove the answer) must return unknown, never invent a `fail`. Only an authoritative read may pass or fail.
- Scoring (`device_status.score`): only a pass earns points; if every check is unknown the score is "not measured", never 0 or 100.
- Elevation: only the page's own button may ask for administrator rights (`same_origin()` check). Never auto-elevate. Never add a code path that runs something elevated that is not a read.
- Never put credentials, tokens, PC names, emails, or personal details in this repo: it is PUBLIC.
- The auto-apply gate (`os_update_gate.py`) must deny when anything is missing: not enrolled, outside maintenance window, no verified restore point, no rollback plan, or the owner's own work is running.

## Layout
- `windows/app.py`: entry point. `Scan` runs the scan in a background thread; HTTP server on 127.0.0.1:8765 (`/`, `/api/state`, `/status.json`, POST `/api/elevate`). `BASE_VERSION` is the version; the build adds the commit and time (`windows/_version.py`, written by CI, gitignored).
- `windows/ui.py`: the whole page (static HTML + JS that polls `/api/state`; device data is written with textContent, never innerHTML) and the display labels/fix text for each check.
- `windows/posture.ps1`: read-only probe, prints one JSON object. Anything it cannot read is null.
- `windows/posture.py`: maps that JSON to checks (`id`, `state`, `severity`, `detail`).
- `devices/agent-windows.ps1`: inventory (OS, patch level, pending security updates via the Windows Update COM API, reboot flag, disk). This is the slow step (1 to 3 minutes).
- `linux/probe.py`, `linux/autopatch_linux.py`: the Fedora/Linux app (same page, same shared status). Packaged as one file by `tools/build_pyz.py` (zipapp) and attached to the same `latest` release as `autopatch-linux.pyz`. CI runs it on a real Fedora container (`tests/smoke_linux.py`, real dnf) before anything is published.
- `server.py`: the loopback web server shared by both apps (`windows/ui.py` is the shared page).
- `device_status.py`: the shared status contract (strict field allowlist, `validate`, `score`, `verify_update`). Other apps depend on it; change it only deliberately.
- `os_update_gate.py`: decision-only update gate.
- `tests/`: `python -m unittest discover -s tests`. `tests/smoke_exe.py` runs the BUILT exe end to end on real Windows (CI only).
- `.github/workflows/release.yml`: on push to main: run tests, build with PyInstaller (scripts bundled via --add-data and verified inside the exe), smoke test, publish the exe as the `latest` release. Download link (no sign-in): https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-windows.exe

## Real-hardware results so far (one Windows 10 Pro Education 22H2 laptop, build 19045)
- Fine without admin: Defender on, real-time on, definitions fresh, firewall on, SMBv1 off, UAC on, Remote Desktop off, winget outdated apps (28), pending security updates (1), patch level (a KB number; an earlier bug printed `KBKB...`, fixed).
- Windows 10 is past end of support (14 Oct 2025): flagged as a high finding (`os_supported`, build <= 19045).
- Secure Boot: registry read says OFF (authoritative on UEFI), unconfirmed against firmware.
- BitLocker: the shell property `System.Volume.BitLockerProtection` read `2`. Probably "off" but its meaning is unconfirmed, so it is reported unknown. Needs admin `Get-BitLockerVolume` / `manage-bde -status` to settle.
- TPM: not confirmable without admin (the non-admin PnP lookup found nothing; a laptop of this class almost certainly has one). Needs admin `Get-Tpm`.

## Ground truth from a second laptop (Lenovo ThinkPad, Windows 10 22H2 build 19045, UEFI, admin terminal)
- BitLocker: `Get-BitLockerVolume` ProtectionStatus Off (0), `manage-bde -status` "Protection Off, Fully Decrypted, no key protectors". Shell `System.Volume.BitLockerProtection` read `2` on the same drive, so 2 = off here too. Still reported unknown (undocumented value) but the detail now says "usually means off".
- Secure Boot: `Confirm-SecureBootUEFI` False and registry `UEFISecureBootEnabled` 0 agree. The registry fallback is right on this machine.
- TPM: `Get-Tpm` TpmPresent False even as admin, but PnP lists a non-present "Trusted Platform Module 2.0" device, so the chip exists and is switched off in the BIOS. The probe now reports `tpm_seen_not_present`, and the detail says so.
- A locally built exe (PyInstaller, same flags as CI) was run as a real standard user (launched through `explorer.exe` from an admin shell, which de-elevates; `/api/state` showed admin false). Results: BitLocker unknown, TPM unknown with the BIOS hint, Secure Boot fail, score 67. Every check matched the admin commands.
- "Re-check with administrator rights" was clicked on that page on real hardware: UAC prompt, the elevated copy came up on port 8766 with admin true, and BitLocker/TPM/Secure Boot all read authoritatively (fail, matching the admin commands). A cross-site POST to `/api/elevate` was refused with 403. Open work item 2 is done for Windows 10.
- Tip for agents: to get a true non-admin run from an admin terminal, run `explorer.exe <path-to-exe>`. It needs no password.

## Open work, roughly in order
1. Ground truth on real Windows: with an administrator terminal, run `Get-Tpm`, `Get-BitLockerVolume`, `Confirm-SecureBootUEFI`, `manage-bde -status` and compare with the app's admin run. Fix `posture.ps1`/`posture.py` where they disagree. Settle what shell BitLockerProtection values mean.
2. DONE on a real ThinkPad (Windows 10 22H2): the "Re-check with administrator rights" button relaunched the exe elevated on port+1 after the UAC prompt. Still worth checking once on Windows 11.
3. Windows Update scan time: add a time limit and a friendlier progress message; keep partial results if it times out.
4. Check winget output parsing across Windows builds and locales.
5. ESU (extended security updates) detection for Windows 10, so the end-of-support finding is not wrong for a PC that has ESU.
6. Real patching phase (later, needs the owner's decision): restore-point verification, maintenance window, rollback plan, then only Windows-native security updates, never drivers/firmware/feature upgrades, and a post-update `verify_update`.

## How to work
- Branch and open a PR; CI must be green. (The first commit was pushed straight to main because the repo was empty.) Merging to main republishes the download, so do not merge broken builds.
- Bump `BASE_VERSION` when behaviour changes. Add a test that fails on the original bug. Do not skip tests or loosen the contract to get green.
- A private repo (JoshDashboard4, `security/autopatch-ai/windows`) holds an older copy; this repo is the live one.
- Be careful with PowerShell run non-interactively: avoid anything that prompts.
