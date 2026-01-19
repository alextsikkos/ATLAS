param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [string]$AppId,
    [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"

Import-Module ExchangeOnlineManagement

if ($AppId -and $CertThumbprint) {
    Connect-ExchangeOnline `
        -AppId $AppId `
        -CertificateThumbprint $CertThumbprint `
        -Organization $TenantDomain `
        -ShowBanner:$false
} else {
    throw "App-only certificate auth required"
}

$policies = Get-HostedContentFilterPolicy | Select-Object Name, IsDefault
$rules    = Get-HostedContentFilterRule  | Select-Object Name, Priority, State

Disconnect-ExchangeOnline -Confirm:$false

@{
    policies = $policies
    rules    = $rules
} | ConvertTo-Json -Depth 4
