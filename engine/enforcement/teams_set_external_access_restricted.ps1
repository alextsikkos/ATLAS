param(
  [Parameter(Mandatory=$true)] [string]$TenantId,
  [Parameter(Mandatory=$true)] [string]$AppId,
  [Parameter(Mandatory=$true)] [string]$CertificateThumbprint,
  [Parameter(Mandatory=$true)] [string]$Mode
)

$ErrorActionPreference = "Stop"

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
    EnablePublicCloudAccess = $pol.EnablePublicCloudAccess
    EnableTeamsConsumerAccess = $pol.EnableTeamsConsumerAccess
    EnableTeamsConsumerInbound = $pol.EnableTeamsConsumerInbound
  }

  $expected = @{
    EnableFederationAccess = $false
    EnablePublicCloudAccess = $false
    EnableTeamsConsumerAccess = $false
    EnableTeamsConsumerInbound = $false
  }

  if ($Mode -in @("report-only","detect-only")) {
    # no changes
  } else {
    # apply only if needed
    if ($pol.EnableFederationAccess -ne $false) { $result.changed += "EnableFederationAccess" }
    if ($pol.EnablePublicCloudAccess -ne $false) { $result.changed += "EnablePublicCloudAccess" }
    if ($pol.EnableTeamsConsumerAccess -ne $false) { $result.changed += "EnableTeamsConsumerAccess" }
    if ($pol.EnableTeamsConsumerInbound -ne $false) { $result.changed += "EnableTeamsConsumerInbound" }

    if ($result.changed.Count -gt 0) {
      Set-CsExternalAccessPolicy -Identity Global `
        -EnableFederationAccess:$false `
        -EnablePublicCloudAccess:$false `
        -EnableTeamsConsumerAccess:$false `
        -EnableTeamsConsumerInbound:$false `
        -ErrorAction Stop | Out-Null

      $result.applied = $true
    }
  }

  # verify
  $after = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
  $result.after = @{
    Identity = "$($after.Identity)"
    EnableFederationAccess = $after.EnableFederationAccess
    EnablePublicCloudAccess = $after.EnablePublicCloudAccess
    EnableTeamsConsumerAccess = $after.EnableTeamsConsumerAccess
    EnableTeamsConsumerInbound = $after.EnableTeamsConsumerInbound
  }

  $result.verify.expected = $expected
  $result.verify.actual = $result.after
  $result.verify.ok = (
    $after.EnableFederationAccess -eq $false -and
    $after.EnablePublicCloudAccess -eq $false -and
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
