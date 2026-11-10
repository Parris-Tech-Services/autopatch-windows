# AutoPatch for Windows

Read-only patch and security posture check for a Windows PC you own. It changes nothing and listens on this PC only.

**Download (no sign-in):** https://github.com/Parris-Tech-Services/autopatch-windows/releases/latest/download/autopatch-windows.exe

Double-click it. SmartScreen will warn about an unknown publisher (the exe is unsigned): click **More info**, then **Run anyway**. Your browser opens at `http://127.0.0.1:8765` with a posture score, the checks (Defender, firewall, BitLocker, Secure Boot, TPM, SMBv1, UAC, Remote Desktop, outdated apps) and whether an auto-apply would be allowed. Close the console window to stop it.

Some checks need administrator rights and show "could not be read" otherwise. Unknown is never counted as a pass.
