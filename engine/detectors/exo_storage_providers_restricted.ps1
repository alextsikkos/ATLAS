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
} else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
}

try {
    $errors = @{}
    $cmdletsUsed = @()

    $cmdletsUsed += "Get-OwaMailboxPolicy"
    $policies = Get-OwaMailboxPolicy -ErrorAction Stop

    $missingPropPolicies = @()
    $enabledPolicies = @()

    foreach ($p in @($policies)) {
        if ($p.PSObject.Properties.Name -contains "AdditionalStorageProvidersAvailable") {
            if ($p.AdditionalStorageProvidersAvailable -eq $true) {
                $enabledPolicies += $p.Identity
            }
        } else {
            $missingPropPolicies += $p.Identity
        }
    }

    $out = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policyCount = @($policies).Count
        enabledPolicyCount = @($enabledPolicies).Count
        enabledPolicies = @($enabledPolicies | Select-Object -First 10)
        missingPropertyCount = @($missingPropPolicies).Count
        missingPropertyPolicies = @($missingPropPolicies | Select-Object -First 10)
        errors = $errors
    }

    $out | ConvertTo-Json -Depth 6
}
catch {
    @{
        connected = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Depth 4
}
finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
