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
        -ShowBanner:$false `
        -ErrorAction Stop | Out-Null
}
else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
}

try {
    $cfg = Get-AdminAuditLogConfig -ErrorAction Stop

    $result = @{
        connected = $true
        unifiedAuditLogIngestionEnabled = $cfg.UnifiedAuditLogIngestionEnabled
        adminAuditLogEnabled = $cfg.AdminAuditLogEnabled
    }

    $result | ConvertTo-Json -Depth 6
}
catch {
    $err = $_.Exception.Message
    $fail = @{
        connected = $false
        error = $err
    }
    $fail | ConvertTo-Json -Depth 6
}
finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
