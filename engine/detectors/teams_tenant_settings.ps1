param(
  [Parameter(Mandatory=$true)] [string]$TenantId,
  [Parameter(Mandatory=$true)] [string]$AppId,
  [Parameter(Mandatory=$true)] [string]$CertificateThumbprint
)

$ErrorActionPreference = "Stop"

$result = @{
  ok = $false
  tenant = @{}
}

try {
  # Require MicrosoftTeams module
  if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
    throw "MicrosoftTeams PowerShell module is not installed. Install-Module MicrosoftTeams"
  }

  Import-Module MicrosoftTeams -ErrorAction Stop

  # App-only connect
  Connect-MicrosoftTeams -TenantId $TenantId -ApplicationId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

  # Best-effort pulls (different tenants/modules may have different cmdlet availability)
  $fed = $null
  $ext = $null
  $extError = $null


  try { $fed = Get-CsTenantFederationConfiguration } catch { $fed = $null }
  try { 
    $ext = Get-CsExternalAccessPolicy -Identity Global
  } catch { 
    $ext = $null
    $extError = $_.Exception.Message
  }
  # External access policy is best-effort; do not fail the whole detector if it can't be read
  $result.ok = ($fed -ne $null)



  $result.tenant = @{
    Federation = $fed
    ExternalAccessPolicy = $ext
    ExternalAccessPolicyError = $extError
  }


} catch {
  $result.ok = $false
  $result.error = $_.Exception.Message
} finally {
  try { Disconnect-MicrosoftTeams | Out-Null } catch {}
}

# Convert to JSON in a way Python can parse
$result | ConvertTo-Json -Depth 20
