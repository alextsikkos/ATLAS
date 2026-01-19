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
    $cmdletsUsed += "Get-HostedContentFilterPolicy"
    $items = $null
    try { $items = Get-HostedContentFilterPolicy -ErrorAction Stop } catch { $errors["Get-HostedContentFilterPolicy"] = $_.Exception.Message }
    $availableProperties = @()
    if ($items -and @($items).Count -gt 0) {
        $availableProperties = @(@($items)[0].PSObject.Properties.Name)
    }

    $rows = @()
    if ($items) {
        foreach ($p in @($items)) {
            $row = @{
            identity = "$($p.Identity)"
            presentKeys = @($p.PSObject.Properties.Name)
        }
        foreach ($k in @("EnableEndUserSpamNotifications","EnableEndUserSpamNotificationsForSpam","EnableEndUserSpamNotificationsForPhish","EndUserSpamNotificationFrequency","EndUserSpamNotificationCustomFromAddress")) {

                if ($p.PSObject.Properties.Name -contains $k) {
                    $row[$k] = $p.$k
                } else {
                    $row[$k] = $null
                }
            }
            $rows += $row
        }
    }

    @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policiesCount = if ($items) { @($items).Count } else { 0 }
        availableProperties = $availableProperties
        policies = @($rows | Select-Object -First 25)
        errors = $errors
    } | ConvertTo-Json -Depth 10

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
