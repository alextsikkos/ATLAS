param(
  [Parameter(Mandatory=$true)][string]$TenantDomain,
  [Parameter(Mandatory=$false)][string]$AppId,
  [Parameter(Mandatory=$false)][string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement

try {
  if ($AppId -and $CertThumbprint) {
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
  } else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop
  }

  $conn = Get-ConnectionInformation | Select-Object -First 1
  if (-not $conn) { throw "Not connected to Exchange Online (Get-ConnectionInformation returned nothing)" }

  $policies = @(
    Get-AntiPhishPolicy -ErrorAction Stop |
      Select-Object Name, Enabled, IsBuiltInProtection, IsValid
  )

  $rules = @(
    Get-AntiPhishRule -ErrorAction Stop |
      Select-Object Name, State, AntiPhishPolicy, Priority
  )

  $result = @{
    connected   = $true
    connection  = $conn
    policyCount = $policies.Count
    ruleCount   = $rules.Count
    policies    = $policies
    rules       = $rules
  }

  $result | ConvertTo-Json -Depth 8
}
catch {
  $result = @{
    connected = $false
    error     = $_.Exception.Message
  }
  $result | ConvertTo-Json -Depth 8
  exit 1
}
finally {
  try { Disconnect-ExchangeOnline -Confirm:$false } catch {}
}
