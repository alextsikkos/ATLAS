param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [string]$AppId,
    [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
$WarningPreference = "SilentlyContinue"

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
    $errors = @{}
    $cmdletsUsed = @()

    # Org-level signal (may not exist in some tenants / module versions)
    $auditDisabled = $null
    try {
        $cmdletsUsed += "Get-OrganizationConfig"
        $org = Get-OrganizationConfig -ErrorAction Stop
        if ($org.PSObject.Properties.Name -contains "AuditDisabled") {
            $auditDisabled = [bool]$org.AuditDisabled
        }
        else {
            $errors["Get-OrganizationConfig.AuditDisabledMissing"] = "AuditDisabled property not present on Get-OrganizationConfig output"
        }
    }
    catch {
        $errors["Get-OrganizationConfig"] = $_.Exception.Message
    }

    # Per-mailbox signal (AuditEnabled may be missing depending on mailbox auditing model)
    $mailboxesAuditingDisabledCount = $null
    $mailboxesAuditingDisabledSamples = @()

    try {
        $cmdletsUsed += "Get-EXOMailbox(PropertySets=Audit)"
        $mbxs = Get-EXOMailbox -ResultSize Unlimited -PropertySets Audit -WarningAction SilentlyContinue -RecipientTypeDetails UserMailbox,SharedMailbox -ErrorAction Stop

        if ($null -eq $mbxs) {
            $mailboxesAuditingDisabledCount = 0
        }
        else {
            $first = $mbxs | Select-Object -First 1
            if ($first -and ($first.PSObject.Properties.Name -contains "AuditEnabled")) {
                $disabled = @($mbxs | Where-Object { $_.AuditEnabled -eq $false })
                $mailboxesAuditingDisabledCount = $disabled.Count
                $mailboxesAuditingDisabledSamples = @($disabled | Select-Object -First 10 | ForEach-Object { $_.UserPrincipalName })
            }
            else {
                $errors["Get-EXOMailbox.AuditEnabledMissing"] = "AuditEnabled property not present on Get-EXOMailbox output (PropertySets Audit)"
            }
        }
    }
    catch {
        $errors["Get-EXOMailbox"] = $_.Exception.Message
    }

    # Optional: mailbox audit bypass associations (info-only)
    $bypassAssociationsCount = $null
    $bypassAssociationsSamples = @()

    try {
        $cmdletsUsed += "Get-MailboxAuditBypassAssociation"
        $bypass = Get-MailboxAuditBypassAssociation -ErrorAction Stop
        $bypassAssociationsCount = @($bypass).Count
        $bypassAssociationsSamples = @($bypass | Select-Object -First 10 | ForEach-Object { $_.Identity })
    }
    catch {
        # Non-fatal: cmdlet may not exist/available
        $errors["Get-MailboxAuditBypassAssociation"] = $_.Exception.Message
    }

    $result = @{
        connected = $true
        auditDisabled = $auditDisabled
        mailboxesAuditingDisabledCount = $mailboxesAuditingDisabledCount
        mailboxesAuditingDisabledSamples = $mailboxesAuditingDisabledSamples
        bypassAssociationsCount = $bypassAssociationsCount
        bypassAssociationsSamples = $bypassAssociationsSamples
        cmdletsUsed = $cmdletsUsed
        errors = $errors
    }

    $result | ConvertTo-Json -Depth 8
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
