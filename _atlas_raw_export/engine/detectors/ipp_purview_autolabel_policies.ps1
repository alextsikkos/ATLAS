param(
  [Parameter(Mandatory=$true)]
  [string]$TenantDomain,

  [string]$AppId,
  [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement
# Fast-fail: if the cmdlet isn't available locally, don't pay the EXO/IPP connect cost.
if (-not (Get-Command Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue)) {
  @{
    ok = $false
    connected = $false
    missingCmdlet = "Get-AutoSensitivityLabelPolicy"
    policyCount = $null
    policies = @()
    reason = "Cmdlet missing in installed ExchangeOnlineManagement module"
  } | ConvertTo-Json -Depth 6
  exit 0
}

try {
  # Connect to EXO (required before Connect-IPPSSession in many environments)
  if (-not ($AppId -and $CertThumbprint)) {
    @{
        ok = $false
        error = "App-only authentication is required for Purview detectors (AppId + CertThumbprint missing). Interactive login is intentionally blocked."
    } | ConvertTo-Json -Depth 4
    exit 1
}

Connect-ExchangeOnline `
    -AppId $AppId `
    -CertificateThumbprint $CertThumbprint `
    -Organization $TenantDomain `
    -ShowBanner:$false `
    -ErrorAction Stop | Out-Null


  # Connect to Security & Compliance (IPPSSession)
    if ($AppId -and $CertThumbprint) {
    Connect-IPPSSession `
        -AppId $AppId `
        -CertificateThumbprint $CertThumbprint `
        -Organization $TenantDomain `
        -ErrorAction Stop | Out-Null
    } else {
    Connect-IPPSSession -ErrorAction Stop | Out-Null
    }


  $policies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)

  $out = @{
    ok = $true
    policyCount = $policies.Count
    policies = @(
      $policies | Select-Object Name, Guid, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation
    )
  }

  $out | ConvertTo-Json -Depth 10
}
catch {
  @{
    ok = $false
    error = $_.Exception.Message
  } | ConvertTo-Json -Depth 6
}
finally {
  try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
}
