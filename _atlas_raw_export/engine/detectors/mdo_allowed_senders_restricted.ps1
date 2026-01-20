param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,
    [string]$AppId,
    [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement

if ($AppId -and $CertThumbprint) {
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
}
else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
}

try {
    $errors = @{}
    $cmdletsUsed = @("Get-HostedContentFilterPolicy")

    $pol = $null
    try { $pol = Get-HostedContentFilterPolicy -ErrorAction Stop } catch { $errors["Get-HostedContentFilterPolicy"] = $_.Exception.Message }

    $rows = @()
    if ($pol) {
        foreach ($p in @($pol)) {
            $allowedSenders = @($p.AllowedSenders)
            $allowedDomains = @($p.AllowedSenderDomains)
            $rows += @{
                identity = "$($p.Identity)"
                allowedSendersCount = @($allowedSenders).Count
                allowedDomainsCount = @($allowedDomains).Count
            }
        }
    }

    @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policyCount = if ($pol) { @($pol).Count } else { 0 }
        policies = @($rows | Select-Object -First 25)
        errors = $errors
    } | ConvertTo-Json -Depth 8
}
catch {
    @{
        connected = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Depth 6
}

finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
