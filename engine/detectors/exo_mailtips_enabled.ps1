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

    $cmdletsUsed += "Get-OrganizationConfig"
    $org = Get-OrganizationConfig -ErrorAction Stop

    # MailTips settings are org-level. We avoid guessing: if properties missing, return nulls.
    $props = @(
        "MailTipsAllTipsEnabled",
        "MailTipsExternalRecipientsTipsEnabled",
        "MailTipsGroupMetricsEnabled",
        "MailTipsMailboxSourcedTipsEnabled",
        "MailTipsLargeAudienceThreshold"
    )

    $out = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        errors = $errors
        CustomerLockBoxEnabled = $org.CustomerLockBoxEnabled
    }

    foreach ($p in $props) {
        if ($org.PSObject.Properties.Name -contains $p) {
            $out[$p] = $org.$p
        } else {
            $out[$p] = $null
            $errors["MissingProperty:$p"] = "Property not present on Get-OrganizationConfig output"
        }
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
