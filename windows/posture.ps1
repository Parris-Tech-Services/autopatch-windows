#requires -Version 5.1
# Read-only Windows posture probe. Emits ONE JSON object; every probe that fails yields null (reported as unknown).
$ErrorActionPreference = "SilentlyContinue"
function Try-Get([scriptblock]$b) { try { & $b } catch { $null } }
$mp  = Try-Get { Get-MpComputerStatus }
$fw  = Try-Get { Get-NetFirewallProfile | ForEach-Object { [bool]$_.Enabled } }
$bl  = Try-Get { (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus }
$bl_shell = $null
if ($null -eq $bl) { $bl_shell = Try-Get { $v = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty("System.Volume.BitLockerProtection"); if ($null -ne $v) { [int]$v } } }
$sb  = Try-Get { Confirm-SecureBootUEFI }
if ($null -eq $sb) { $sb = Try-Get { $r = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -ErrorAction Stop).UEFISecureBootEnabled; if ($null -ne $r) { [bool]$r } } }
$tpm = Try-Get { (Get-Tpm).TpmPresent }
$tpm_pnp = $null
if ($null -eq $tpm) { $tpm_pnp = Try-Get { [bool](Get-PnpDevice -Class SecurityDevices -PresentOnly | Where-Object { $_.FriendlyName -like "*Trusted Platform Module*" }) } }
# A TPM Windows has seen before but that is not present now usually means it was switched off in the BIOS (seen on a real ThinkPad).
$tpm_seen_not_present = Try-Get { [bool](Get-PnpDevice -Class SecurityDevices | Where-Object { $_.FriendlyName -like "*Trusted Platform Module*" -and -not $_.Present }) }
$build = Try-Get { [int](Get-CimInstance Win32_OperatingSystem).BuildNumber }
$ptype = Try-Get { [int](Get-CimInstance Win32_OperatingSystem).ProductType }
$smb = Try-Get { (Get-SmbServerConfiguration).EnableSMB1Protocol }
$uac = Try-Get { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA }
$rdp = Try-Get { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections }
$wg_raw = $null; $wg_exit = $null
if (Get-Command winget -ErrorAction SilentlyContinue) {
  # Counted in posture.py (tested there). Non-ASCII is replaced 1:1 so columns stay aligned and stdout stays decodable.
  $wg_raw = (winget upgrade --include-unknown --disable-interactivity 2>$null | Out-String) -replace '[^\x20-\x7E\r\n]', '?'
  $wg_exit = $LASTEXITCODE
  if ($wg_raw.Length -gt 30000) { $wg_raw = $wg_raw.Substring(0, 30000) }
}
[ordered]@{
  defender_enabled = if ($mp) { [bool]$mp.AntivirusEnabled } else { $null }
  defender_realtime = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
  defender_signature_age_days = if ($mp) { [int]$mp.AntivirusSignatureAge } else { $null }
  firewall_profiles_enabled = $fw
  bitlocker_protection = $bl
  bitlocker_shell = $bl_shell
  secure_boot = $sb
  tpm_present = $tpm
  tpm_pnp_found = $tpm_pnp
  tpm_seen_not_present = $tpm_seen_not_present
  smbv1_enabled = $smb
  uac_enabled = $uac
  rdp_denied = $rdp
  os_build = $build
  os_product_type = $ptype
  winget_raw = $wg_raw
  winget_exit = $wg_exit
} | ConvertTo-Json -Compress
