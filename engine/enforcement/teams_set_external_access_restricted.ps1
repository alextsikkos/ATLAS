param(
  [Parameter(Mandatory=$true)] [string]$TenantId,
  [Parameter(Mandatory=$true)] [string]$AppId,
  [Parameter(Mandatory=$true)] [string]$CertificateThumbprint,
  [Parameter(Mandatory=$true)] [string]$Mode
)

$ErrorActionPreference = "Stop"

$WarningPreference = "SilentlyContinue"

$result = @{
  ok = $false
  applied = $false
  changed = @()
  before = $null
  after = $null
  verify = @{ ok = $false; expected = @{}; actual = @{} }
  error = $null
}

try {
  if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
    throw "MicrosoftTeams PowerShell module is not installed. Install-Module MicrosoftTeams"
  }

  Import-Module MicrosoftTeams -ErrorAction Stop

  Connect-MicrosoftTeams -TenantId $TenantId -ApplicationId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

  $pol = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
  $result.before = @{
    Identity = "$($pol.Identity)"
    EnableFederationAccess = $pol.EnableFederationAccess
    EnableTeamsConsumerAccess = $pol.EnableTeamsConsumerAccess
    EnableTeamsConsumerInbound = $pol.EnableTeamsConsumerInbound
  }
  if ($null -ne $pol.EnablePublicCloudAccess) {
    $result.before.EnablePublicCloudAccess = $pol.EnablePublicCloudAccess
  }


  $expected = @{
    EnableFederationAccess = $false
    EnableTeamsConsumerAccess = $false
    EnableTeamsConsumerInbound = $false
  }
  if ($null -ne $pol.EnablePublicCloudAccess) {
    $expected.EnablePublicCloudAccess = $false
  }


  if ($Mode -in @("report-only","detect-only")) {
    # no changes
  } else {
    # apply only if needed
    if ($pol.EnableFederationAccess -ne $false) { $result.changed += "EnableFederationAccess" }
    if ($null -ne $pol.EnablePublicCloudAccess -and $pol.EnablePublicCloudAccess -ne $false) {
      $result.changed += "EnablePublicCloudAccess"
    }

    if ($pol.EnableTeamsConsumerAccess -ne $false) { $result.changed += "EnableTeamsConsumerAccess" }
    if ($pol.EnableTeamsConsumerInbound -ne $false) { $result.changed += "EnableTeamsConsumerInbound" }

    if ($result.changed.Count -gt 0) {
      $cmd = Get-Command Set-CsExternalAccessPolicy
      $ps = @{ Identity = "Global" }

      if ($cmd.Parameters.ContainsKey("EnableFederationAccess"))     { $ps.EnableFederationAccess     = $false }
      if ($cmd.Parameters.ContainsKey("EnableTeamsConsumerAccess"))  { $ps.EnableTeamsConsumerAccess  = $false }
      if ($cmd.Parameters.ContainsKey("EnableTeamsConsumerInbound")) { $ps.EnableTeamsConsumerInbound = $false }

      # Only set if the module supports it (this is the one breaking your run)
      if ($cmd.Parameters.ContainsKey("EnablePublicCloudAccess"))    { $ps.EnablePublicCloudAccess    = $false }

      Set-CsExternalAccessPolicy @ps 3>$null
      $result.applied = ($result.changed.Count -gt 0)

    }
  }

  # verify
  $after = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
  $result.after = @{
    Identity = "$($after.Identity)"
    EnableFederationAccess = $after.EnableFederationAccess
    EnableTeamsConsumerAccess = $after.EnableTeamsConsumerAccess
    EnableTeamsConsumerInbound = $after.EnableTeamsConsumerInbound
  }
  if ($null -ne $after.EnablePublicCloudAccess) {
    $result.after.EnablePublicCloudAccess = $after.EnablePublicCloudAccess
  }


  $result.verify.expected = $expected
  $result.verify.actual = $result.after
  $publicOk = $true
  if ($null -ne $after.EnablePublicCloudAccess) {
    $publicOk = ($after.EnablePublicCloudAccess -eq $false)
  }

  $result.verify.ok = (
    $after.EnableFederationAccess -eq $false -and
    $publicOk -and
    $after.EnableTeamsConsumerAccess -eq $false -and
    $after.EnableTeamsConsumerInbound -eq $false
  )


  $result.ok = $true
}
catch {
  $result.ok = $false
  $result.error = $_.Exception.Message
}
finally {
  try { Disconnect-MicrosoftTeams | Out-Null } catch {}
}

$result | ConvertTo-Json -Depth 20
