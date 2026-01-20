param(
  [Parameter(Mandatory=$true)]
  [string]$TenantDomain,

  [string]$AppId,
  [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement

function New-FailSection($missingCmdlet, $reason) {
  return @{
    ok = $false
    connected = $false
    missingCmdlet = $missingCmdlet
    reason = $reason
  }
}

# Fast-fail if app-only auth params missing (interactive is forbidden by design)
if (-not ($AppId -and $CertThumbprint)) {
  @{
    ok = $false
    connected = $false
    error = "App-only authentication is required for Purview detectors (AppId/CertThumbprint missing). Interactive login is intentionally blocked."
  } | ConvertTo-Json -Depth 6
  exit 0
}

# Cmdlet availability checks BEFORE connect (keeps runs fast on machines missing modules)
$hasAuto = [bool](Get-Command Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue)
$hasLabel = [bool](Get-Command Get-Label -ErrorAction SilentlyContinue)

$autoSection = $null
$scopeSection = $null

if (-not $hasAuto) {
  $autoSection = New-FailSection "Get-AutoSensitivityLabelPolicy" "Cmdlet missing in installed ExchangeOnlineManagement module"
}
if (-not $hasLabel) {
  $scopeSection = New-FailSection "Get-Label" "Cmdlet missing in installed ExchangeOnlineManagement module"
}

# If BOTH cmdlets are missing, no reason to connect
if (-not $hasAuto -and -not $hasLabel) {
  @{
    ok = $true
    connected = $false
    autoLabeling = $autoSection
    dataMapScope = $scopeSection
  } | ConvertTo-Json -Depth 10
  exit 0
}

try {
  Connect-ExchangeOnline `
    -AppId $AppId `
    -CertificateThumbprint $CertThumbprint `
    -Organization $TenantDomain `
    -ShowBanner:$false `
    -ErrorAction Stop | Out-Null

  if ($hasAuto) {
    $policies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
    $autoSection = @{
      ok = $true
      policyCount = $policies.Count
      policies = @(
        $policies | Select-Object Name, Guid, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation
      )
    }
  }

  if ($hasLabel) {
    $labels = @(Get-Label -ErrorAction Stop)
    # Keep payload small but useful
    $proj = @($labels | Select-Object DisplayName, Name, Guid, ContentType, LabelActions, Settings)
    $scopeSection = @{
      ok = $true
      labelCount = $labels.Count
      labels = $proj
    }
  }

  @{
    ok = $true
    connected = $true
    autoLabeling = $autoSection
    dataMapScope = $scopeSection
  } | ConvertTo-Json -Depth 10
}
catch {
  @{
    ok = $false
    connected = $false
    error = $_.Exception.Message
  } | ConvertTo-Json -Depth 6
}
finally {
  try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
}
