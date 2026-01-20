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
    $cmdletsUsed = @()

    $cmdletsUsed += "Get-SharingPolicy"
    $policies = $null
    try { $policies = Get-SharingPolicy -ErrorAction Stop } catch { $errors["Get-SharingPolicy"] = $_.Exception.Message }

    $policyCount = if ($policies) { @($policies).Count } else { 0 }

    $enabled = @()
    $missingDomains = @()

    if ($policies) {
        foreach ($p in @($policies)) {
            if ($p.PSObject.Properties.Name -contains "Domains") {
                $domains = @($p.Domains)
                $joined = ($domains | ForEach-Object { "$_" }) -join ";"
                # Conservative: treat Anonymous:* or wildcard as "external sharing available"
                if ($joined -match "Anonymous:" -or $joined -match "\*") {
                    $enabled += "$($p.Identity)"
                }
            } else {
                $missingDomains += "$($p.Identity)"
            }
        }
    }

    @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policyCount = $policyCount
        enabledPolicyCount = @($enabled).Count
        enabledPolicies = @($enabled | Select-Object -First 10)
        missingDomainsPropertyCount = @($missingDomains).Count
        missingDomainsPropertyPolicies = @($missingDomains | Select-Object -First 10)
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
