param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [string]$AppId,
    [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement

try {
    # Connect (App-only if provided; otherwise interactive fallback)
    if ($AppId -and $CertThumbprint) {
        Connect-ExchangeOnline `
            -AppId $AppId `
            -CertificateThumbprint $CertThumbprint `
            -Organization $TenantDomain `
            -ShowBanner:$false `
            -ErrorAction Stop | Out-Null
    } else {
        Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
    }

    $errors = @{}
    $cmdletsUsed = @()

    $cmdletsUsed += "Get-OrganizationConfig"
    $org = Get-OrganizationConfig -ErrorAction Stop

    $out = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        errors = $errors
    }

    if ($org.PSObject.Properties.Name -contains "CustomerLockBoxEnabled") {
        $out["CustomerLockBoxEnabled"] = $org.CustomerLockBoxEnabled
    } else {
        $out["CustomerLockBoxEnabled"] = $null
    }

    $out | ConvertTo-Json -Depth 6
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
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
}
