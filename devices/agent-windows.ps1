#requires -Version 5.1
<#
AutoPatch read-only inventory agent (Windows PowerShell).
Reads CIM data only. It does not install updates, change policy, open a listener,
or accept remote commands. Run on a device you own after creating an invitation.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9][a-z0-9-]{2,63}$')][string]$DeviceId,
  [string]$OutFile = "autopatch-inventory.json"
)
$ErrorActionPreference = "Stop"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$hotfix = Get-CimInstance Win32_QuickFixEngineering |
  Sort-Object InstalledOn -Descending | Select-Object -First 1
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$pending = "unknown"; $pendingTotal = "unknown"
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $found = $session.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'").Updates
  $pendingTotal = $found.Count
  # Only updates Windows Update itself classifies as security count as security updates.
  $securityCategory = "0fa1201d-4330-4fa8-8ae9-b877473b6441"
  $pending = @($found | Where-Object { ($_.Categories | ForEach-Object { $_.CategoryID.ToLower() }) -contains $securityCategory -or $_.MsrcSeverity }).Count
} catch { }
# Win32_OperatingSystem has no reboot property; read the signals Windows Update and servicing set. null = could not read.
$reboot = $null
try { $reboot = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch { }
if ($reboot -ne $true) {
  try {
    $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
              "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
    if (@($keys | Where-Object { Test-Path -LiteralPath $_ }).Count) { $reboot = $true }
  } catch { }
}
$inventory = [ordered]@{
  device_id                = $DeviceId
  device_class             = "windows"
  collected_utc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  hostname                 = $cs.Name
  os                       = "$($os.Caption) $($os.Version)"
  kernel                   = $os.BuildNumber
  patch_level              = if ($hotfix) { ("KB" + ($hotfix.HotFixID -replace "^KB","")) } else { "unknown" }
  packages_total           = 0
  security_updates_pending = $pending
  updates_pending_total    = $pendingTotal
  reboot_required          = $reboot
  disk_free_gb             = if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { 0 }
  agent_version            = "1.0"
}
$inventory | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Output "Read-only inventory written to $OutFile (no updates installed)"
