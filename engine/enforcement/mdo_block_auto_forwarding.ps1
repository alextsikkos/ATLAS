param(
  [Parameter(Mandatory=$true)][string]$TenantDomain
)

$ErrorActionPreference = "Stop"

Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -AppOnly -Organization $TenantDomain -ShowBanner:$false | Out-Null

$before = Get-RemoteDomain -Identity "Default" | Select-Object Identity, AutoForwardEnabled

Set-RemoteDomain -Identity "Default" -AutoForwardEnabled $false

$after = Get-RemoteDomain -Identity "Default" | Select-Object Identity, AutoForwardEnabled

$result = @{
  ok = $true
  before = $before
  desired = @{ Identity = "Default"; AutoForwardEnabled = $false }
  after = $after
}

$result | ConvertTo-Json -Depth 6
