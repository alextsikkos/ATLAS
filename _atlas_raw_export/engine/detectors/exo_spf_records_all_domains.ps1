param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,
    [string]$AppId,
    [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement

# Track cmdlets used (matches your existing audit conventions)
$cmdletsUsed = @()
$errors = @{}

# Connect (app-only if provided)
if ($AppId -and $CertThumbprint) {
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
}
else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
}

try {
    # Get accepted domains (do NOT do DNS here; Python handles TXT lookups with timeouts/parallelism)
    $cmdletsUsed += "Get-AcceptedDomain"
    $accepted = @(Get-AcceptedDomain -ErrorAction Stop)
    # Normalize accepted domains to strings
    $customDomains = @(
        $accepted |
        Where-Object { $_ -and $_.DomainName } |
        ForEach-Object { [string]$_.DomainName }
    )

    $maxDomains = 250
    $domainsOut = @($customDomains | Where-Object { $_ } | Select-Object -First $maxDomains)
    $domainsTruncated = (@($customDomains).Count -gt $maxDomains)

    @{
        connected            = $true
        cmdletsUsed          = @("Get-AcceptedDomain")
        domainCount          = @($customDomains).Count
        domainsReturnedCount = @($domainsOut).Count
        domainsTruncated     = $domainsTruncated
        domains              = $domainsOut
        errors               = @{}
    } | ConvertTo-Json -Depth 10

}
catch {
    @{
        connected = $false
        error     = $_.Exception.Message
    } | ConvertTo-Json -Depth 6
}
finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
