param(
  [Parameter(Mandatory=$true)][string]$TenantDomain,
  [Parameter(Mandatory=$false)][string]$AppId,
  [Parameter(Mandatory=$false)][string]$CertThumbprint
)

$ErrorActionPreference = "Stop"

Import-Module ExchangeOnlineManagement

try {
  # Connect (App-only if provided; otherwise interactive fallback)
  if ($AppId -and $CertThumbprint) {
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
  } else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
  }

  # Sanity: ensure connected
  $conn = Get-ConnectionInformation | Select-Object -First 1
  if (-not $conn) { throw "Not connected to Exchange Online (Get-ConnectionInformation returned nothing)" }

  # Pull policies + rules
  $policies = @(Get-SafeLinksPolicy -ErrorAction Stop | Select-Object Name, EnableSafeLinksForEmail, EnableSafeLinksForOffice, EnableSafeLinksForTeams, IsBuiltInProtection, RecommendedPolicyType, IsValid)
  $rules    = @(Get-SafeLinksRule   -ErrorAction Stop | Select-Object Name, State, SafeLinksPolicy, Priority)

  # Output JSON for Python to parse
  $result = @{
    connected = $true
    connection = $conn
    policyCount = $policies.Count
    ruleCount   = $rules.Count
    policies = $policies
    rules    = $rules
  }

  $result | ConvertTo-Json -Depth 8
}
catch {
  $err = $_.Exception.Message
  $result = @{
    connected = $false
    error = $err
  }
  $result | ConvertTo-Json -Depth 8

  # Ensure non-zero exit so Python flags it
  exit 1
}
finally {
  try { Disconnect-ExchangeOnline -Confirm:$false } catch {}
}
