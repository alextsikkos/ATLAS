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

    $cmdletsUsed += "Get-OrganizationConfig"
    $org = $null
    try { $org = Get-OrganizationConfig -ErrorAction Stop } catch { $errors["Get-OrganizationConfig"] = $_.Exception.Message }

    $candidates = @("OutlookAddInsEnabled","OutlookAddinsEnabled","AppsForOfficeEnabled")
    $values = @{}
    foreach ($k in $candidates) {
        if ($org -and ($org.PSObject.Properties.Name -contains $k)) { $values[$k] = $org.$k } else { $values[$k] = $null }
    }

    @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        candidates = $values
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
