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

# Accepted domains (exclude onmicrosoft)
$accepted = Get-AcceptedDomain | Select-Object DomainName
$customDomains = @()
foreach ($d in $accepted) {
    if ($d.DomainName -and ($d.DomainName -notlike "*.onmicrosoft.com")) {
        $customDomains += $d.DomainName
    }
}

# DKIM signing config (one per domain where it exists)
$dkim = @()
foreach ($domain in $customDomains) {
    try {
        $cfg = Get-DkimSigningConfig -Identity $domain
        $dkim += ($cfg | Select-Object Domain, Enabled, Selector1CNAME, Selector2CNAME)
    } catch {
        # No DKIM config object found for that domain
        $dkim += [pscustomobject]@{
            Domain = $domain
            Enabled = $false
            Selector1CNAME = $null
            Selector2CNAME = $null
        }
    }
}

Disconnect-ExchangeOnline -Confirm:$false

@{
    customDomains = $customDomains
    dkim = $dkim
} | ConvertTo-Json -Depth 6
