param(
  [Parameter(Mandatory=$true)]
  [string]$TenantDomain,

  [string]$AppId,
  [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement
# Fast-fail: if the cmdlet isn't available locally, don't pay the EXO/IPP connect cost.
if (-not (Get-Command Get-Label -ErrorAction SilentlyContinue)) {
  @{
    ok = $false
    connected = $false
    missingCmdlet = "Get-Label"
    labelCount = $null
    labels = @()
    reason = "Cmdlet missing in installed ExchangeOnlineManagement module"
  } | ConvertTo-Json -Depth 6
  exit 0
}

try {
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


  if ($AppId -and $CertThumbprint) {
  Connect-IPPSSession `
    -AppId $AppId `
    -CertificateThumbprint $CertThumbprint `
    -Organization $TenantDomain `
    -ErrorAction Stop | Out-Null
} else {
  Connect-IPPSSession -ErrorAction Stop | Out-Null
}


  $labels = @(Get-Label -ErrorAction Stop)

  # We do NOT assume a specific property name for the "Files & other data assets" scope.
  # We return a conservative summary so Python can decide whether it can evaluate.
  $proj = @()
  foreach ($l in $labels) {
    $proj += [pscustomobject]@{
      DisplayName = $l.DisplayName
      Name        = $l.Name
      Guid        = $l.Guid
      ImmutableId = $l.ImmutableId
      ContentType = $l.ContentType
      Properties  = @($l | Get-Member -MemberType Property,NoteProperty | Select-Object -ExpandProperty Name)
    }
  }

  @{
    ok = $true
    labelCount = $labels.Count
    labels = $proj
  } | ConvertTo-Json -Depth 10
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
