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

# Rules for preset security policies:
# - EOPProtectionPolicyRule: default email protections for cloud mailboxes
# - ATPProtectionPolicyRule: Defender for Office 365 protections
$eopRules = Get-EOPProtectionPolicyRule | Select-Object Name,State
$atpRules = Get-ATPProtectionPolicyRule | Select-Object Name,State

Disconnect-ExchangeOnline -Confirm:$false

@{
    eopRules = $eopRules
    atpRules = $atpRules
} | ConvertTo-Json -Depth 4
