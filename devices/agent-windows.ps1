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
$pending = 0
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  # Only updates in Microsoft's "Security Updates" classification (GUID, so it works in every language).
  $result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $pending = @($result.Updates | Where-Object { @($_.Categories | ForEach-Object { $_.CategoryID }) -contains '0fa1201d-4330-4fa8-8ae9-b877473b6441' }).Count
} catch { $pending = "unknown" }
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
  reboot_required          = [bool]$os.RebootRequired
  disk_free_gb             = if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { 0 }
  agent_version            = "1.0"
}
$inventory | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Output "Read-only inventory written to $OutFile (no updates installed)"
