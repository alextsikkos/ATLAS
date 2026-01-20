param(
    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [string]$AppId,
    [string]$CertThumbprint
)

$ErrorActionPreference = "Stop"
Import-Module ExchangeOnlineManagement

# App-only certificate auth required
if (-not ($AppId -and $CertThumbprint)) {
    @{
        connected = $false
        error = "App-only certificate auth required (AppId + CertThumbprint)"
        scripts = @{}
    } | ConvertTo-Json -Depth 10
    exit 1
}

$connected = $false
$errors = @{}
$scripts = @{}

try {
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
    $connected = $true

    # 1) exo_audit_log_search_enabled.ps1
    try {
        $cfg = Get-AdminAuditLogConfig -ErrorAction Stop
        $scripts["exo_audit_log_search_enabled.ps1"] = @{
            connected = $true
            unifiedAuditLogIngestionEnabled = $cfg.UnifiedAuditLogIngestionEnabled
            adminAuditLogEnabled = $cfg.AdminAuditLogEnabled
        }
    } catch {
        $scripts["exo_audit_log_search_enabled.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 2) exo_mailtips_enabled.ps1
    try {
        $org = Get-OrganizationConfig -ErrorAction Stop
        $scripts["exo_mailtips_enabled.ps1"] = @{
            connected = $true
            MailTipsAllTipsEnabled = $org.MailTipsAllTipsEnabled
            MailTipsExternalRecipientsTipsEnabled = $org.MailTipsExternalRecipientsTipsEnabled
            MailTipsGroupMetricsEnabled = $org.MailTipsGroupMetricsEnabled
            MailTipsMailboxSourcedTipsEnabled = $org.MailTipsMailboxSourcedTipsEnabled
            MailTipsLargeAudienceThreshold = $org.MailTipsLargeAudienceThreshold
        }
    } catch {
        $scripts["exo_mailtips_enabled.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 3) exo_customer_lockbox_enabled.ps1
    try {
        if (-not $org) {
           $org = Get-OrganizationConfig -ErrorAction Stop
        }

        
$scripts["exo_customer_lockbox_enabled.ps1"] = @{
    connected = $true
    CustomerLockBoxEnabled = $org.CustomerLockBoxEnabled
}

# Also: exo_outlook_addins_blocked.ps1 (uses same Get-OrganizationConfig result)
$cmdletsUsed2 = @("Get-OrganizationConfig")
$candidates = @("OutlookAddInsEnabled","OutlookAddinsEnabled","AppsForOfficeEnabled")
$values = @{}
foreach ($k in $candidates) {
    if ($org -and ($org.PSObject.Properties.Name -contains $k)) { $values[$k] = $org.$k } else { $values[$k] = $null }
}
$scripts["exo_outlook_addins_blocked.ps1"] = @{
    connected = $true
    cmdletsUsed = $cmdletsUsed2
    candidates = $values
    errors = @{}
}

    } catch {
        
$scripts["exo_customer_lockbox_enabled.ps1"] = @{
    connected = $false
    error = $_.Exception.Message
}
$scripts["exo_outlook_addins_blocked.ps1"] = @{
    connected = $false
    error = $_.Exception.Message
}}


# 3b) exo_calendar_external_sharing_disabled.ps1
try {
    $errors2 = @{}
    $cmdletsUsed2 = @()
    $cmdletsUsed2 += "Get-SharingPolicy"
    $policies = $null
    try { $policies = Get-SharingPolicy -ErrorAction Stop } catch { $errors2["Get-SharingPolicy"] = $_.Exception.Message }

    $enabled = @()
    $missingDomains = @()
    $policyCount = if ($policies) { @($policies).Count } else { 0 }

    if ($policies) {
        foreach ($p in @($policies)) {
            if ($p.PSObject.Properties.Name -contains "Domains") {
                $domains = @($p.Domains)
                if ($domains -and ($domains -match "\*")) {
                    $enabled += "$($p.Identity)"
                } else {
                    $missingDomains += "$($p.Identity)"
                }
            } else {
                $missingDomains += "$($p.Identity)"
            }
        }
    }

    $scripts["exo_calendar_external_sharing_disabled.ps1"] = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed2
        policyCount = $policyCount
        enabledPolicyCount = @($enabled).Count
        enabledPolicies = @($enabled | Select-Object -First 10)
        missingDomainsPropertyCount = @($missingDomains).Count
        missingDomainsPropertyPolicies = @($missingDomains | Select-Object -First 10)
        errors = $errors2
    }
} catch {
    $scripts["exo_calendar_external_sharing_disabled.ps1"] = @{
        connected = $false
        error = $_.Exception.Message
    }
}

    # 4) exo_storage_providers_restricted.ps1
    try {
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

        $scripts["exo_storage_providers_restricted.ps1"] = @{
            connected = $true
            policyCount = @($policies).Count
            enabledPolicyCount = @($enabledPolicies).Count
            enabledPolicies = @($enabledPolicies | Select-Object -First 10)
            missingPropertyCount = @($missingPropPolicies).Count
            missingPropertyPolicies = @($missingPropPolicies | Select-Object -First 10)
        }
    } catch {
        $scripts["exo_storage_providers_restricted.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 5) exo_safe_links.ps1
    try {
        $policies = Get-SafeLinksPolicy | Select-Object Name, IsEnabled, IsDefault
        $rules    = Get-SafeLinksRule  | Select-Object Name, Priority, State
        $scripts["exo_safe_links.ps1"] = @{
            connected = $true
            policyCount = $policies.Count
            ruleCount = $rules.Count
            policies = $policies
            rules = $rules
        }
    } catch {
        $scripts["exo_safe_links.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 6) exo_safe_attachments.ps1
    try {
        $policies = Get-SafeAttachmentPolicy | Select-Object Name, IsEnabled, IsDefault
        $rules    = Get-SafeAttachmentRule  | Select-Object Name, Priority, State
        $scripts["exo_safe_attachments.ps1"] = @{
            connected = $true
            policyCount = $policies.Count
            ruleCount = $rules.Count
            policies = $policies
            rules = $rules
        }
    } catch {
        $scripts["exo_safe_attachments.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 7) exo_anti_phish.ps1
    try {
        $policies = Get-AntiPhishPolicy | Select-Object Name, IsDefault
        $rules    = Get-AntiPhishRule  | Select-Object Name, Priority, State
        $scripts["exo_anti_phish.ps1"] = @{
            connected = $true
            policies = $policies
            rules = $rules
        }
    } catch {
        $scripts["exo_anti_phish.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 8) exo_anti_spam.ps1
    try {
        $policies = Get-HostedContentFilterPolicy | Select-Object Name, IsDefault
        $rules    = Get-HostedContentFilterRule  | Select-Object Name, Priority, State
        $scripts["exo_anti_spam.ps1"] = @{
            connected = $true
            policies = $policies
            rules = $rules
        }
    } catch {
        $scripts["exo_anti_spam.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 9) exo_anti_malware.ps1
    try {
        $policies = Get-MalwareFilterPolicy | Select-Object Name, IsDefault
        $rules    = Get-MalwareFilterRule  | Select-Object Name, Priority, State
        $scripts["exo_anti_malware.ps1"] = @{
            connected = $true
            policies = $policies
            rules = $rules
        }
    } catch {
        $scripts["exo_anti_malware.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 10) exo_preset_security_policies.ps1
    try {
        $eopRules = Get-EOPProtectionPolicyRule | Select-Object Name, State
        $atpRules = Get-ATPProtectionPolicyRule | Select-Object Name, State
        $scripts["exo_preset_security_policies.ps1"] = @{
            connected = $true
            eopRules = $eopRules
            atpRules = $atpRules
        }
    } catch {
        $scripts["exo_preset_security_policies.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 11) exo_dkim.ps1
    try {
        $accepted = Get-AcceptedDomain | Where-Object { $_.DomainType -eq "Authoritative" -and $_.Default -ne $true } | Select-Object -ExpandProperty DomainName
        $customDomains = @($accepted)
        $dkim = @()
        foreach ($domain in $customDomains) {
            try {
                $cfg = Get-DkimSigningConfig -Identity $domain -ErrorAction Stop
                $dkim += @{
                    Domain = $domain
                    Enabled = [bool]$cfg.Enabled
                    Selector1CNAME = $cfg.Selector1CNAME
                    Selector2CNAME = $cfg.Selector2CNAME
                }
            } catch {
                $dkim += @{
                    Domain = $domain
                    Enabled = $false
                    Selector1CNAME = $null
                    Selector2CNAME = $null
                }
            }
        }

        $scripts["exo_dkim.ps1"] = @{
            connected = $true
            customDomains = $customDomains
            dkim = $dkim
        }
    } catch {
        $scripts["exo_dkim.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

    # 12) exo_mailbox_auditing_enabled.ps1 (expensive but only once)
    try {
        $cmdletsUsed = @()
        $errors2 = @{}

        $cmdletsUsed += "Get-OrganizationConfig"
        $org = Get-OrganizationConfig -ErrorAction Stop
        $auditDisabled = $org.AuditDisabled

        $cmdletsUsed += "Get-EXOMailbox"
        # Using Get-EXOMailbox for speed; fall back to Get-Mailbox if needed.
        $mbx = @()
        try {
            $mbx = Get-EXOMailbox -ResultSize Unlimited -PropertySets Audit -ErrorAction Stop
        } catch {
            $errors2["Get-EXOMailbox"] = $_.Exception.Message
            $cmdletsUsed += "Get-Mailbox"
            $mbx = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        }

        $disabled = @()
        foreach ($m in @($mbx)) {
            try {
                if ($m.PSObject.Properties.Name -contains "AuditEnabled") {
                    if ($m.AuditEnabled -eq $false) { $disabled += $m.Identity }
                }
            } catch {}
        }

        $mailboxesAuditingDisabledCount = @($disabled).Count
        $mailboxesAuditingDisabledSamples = @($disabled | Select-Object -First 10)

        $bypass_cnt = 0
        $bypass_samp = @()
        try {
            $cmdletsUsed += "Get-MailboxAuditBypassAssociation"
            $assoc = Get-MailboxAuditBypassAssociation -ErrorAction Stop
            $bypass_cnt = @($assoc).Count
            $bypass_samp = @(@($assoc) | Select-Object -First 10 | ForEach-Object { $_.Identity })
        } catch {
            $errors2["Get-MailboxAuditBypassAssociation"] = $_.Exception.Message
        }

        $scripts["exo_mailbox_auditing_enabled.ps1"] = @{
            connected = $true
            auditDisabled = $auditDisabled
            mailboxesAuditingDisabledCount = $mailboxesAuditingDisabledCount
            mailboxesAuditingDisabledSamples = $mailboxesAuditingDisabledSamples
            bypassAssociationsCount = $bypass_cnt
            bypassAssociationsSamples = $bypass_samp
            cmdletsUsed = $cmdletsUsed
            errors = $errors2
        }
    } catch {
        $scripts["exo_mailbox_auditing_enabled.ps1"] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }

# === MDO (Exchange Online cmdlets) ===
# We intentionally fetch once per cmdlet family and then shape per-script payloads.

# HostedContentFilterPolicy-based scripts
try {
    $cmdletsUsed += "Get-HostedContentFilterPolicy"
    $hcfItems = Get-HostedContentFilterPolicy -ErrorAction Stop
    $hcfRows = @()
    foreach ($p in @($hcfItems)) {
        $hcfRows += @{
            identity = "$($p.Identity)"
            BulkSpamAction = if ($p.PSObject.Properties.Name -contains "BulkSpamAction") { $p.BulkSpamAction } else { $null }
            HighConfidenceSpamAction = if ($p.PSObject.Properties.Name -contains "HighConfidenceSpamAction") { $p.HighConfidenceSpamAction } else { $null }
            PhishSpamAction = if ($p.PSObject.Properties.Name -contains "PhishSpamAction") { $p.PhishSpamAction } else { $null }
            PhishingAction = if ($p.PSObject.Properties.Name -contains "PhishingAction") { $p.PhishingAction } else { $null }
            EnableEndUserSpamNotifications = if ($p.PSObject.Properties.Name -contains "EnableEndUserSpamNotifications") { $p.EnableEndUserSpamNotifications } else { $null }
        }
    }

    foreach ($scriptKey in @(
        "mdo_bulk_spam_action.ps1",
        "mdo_high_confidence_spam_action.ps1",
        "mdo_phishing_action.ps1",
        "mdo_spam_notifications_admins_only.ps1"
    )) {
        $scripts[$scriptKey] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($hcfItems) { @($hcfItems).Count } else { 0 }
            policies = @($hcfRows | Select-Object -First 25)
            errors = $errors
        }
    }
} catch {
    foreach ($scriptKey in @(
        "mdo_bulk_spam_action.ps1",
        "mdo_high_confidence_spam_action.ps1",
        "mdo_phishing_action.ps1",
        "mdo_spam_notifications_admins_only.ps1"
    )) {
        $scripts[$scriptKey] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }
}

# AntiPhishPolicy-based scripts
try {
    $cmdletsUsed += "Get-AntiPhishPolicy"
    $apItems = Get-AntiPhishPolicy -ErrorAction Stop
    $apRows = @()
    foreach ($p in @($apItems)) {
        $apRows += @{
            identity = "$($p.Identity)"
            PhishThresholdLevel = if ($p.PSObject.Properties.Name -contains "PhishThresholdLevel") { $p.PhishThresholdLevel } else { $null }
            EnableMailboxIntelligenceProtection = if ($p.PSObject.Properties.Name -contains "EnableMailboxIntelligenceProtection") { $p.EnableMailboxIntelligenceProtection } else { $null }
            EnableFirstContactSafetyTips = if ($p.PSObject.Properties.Name -contains "EnableFirstContactSafetyTips") { $p.EnableFirstContactSafetyTips } else { $null }
            EnableSimilarDomainsSafetyTips = if ($p.PSObject.Properties.Name -contains "EnableSimilarDomainsSafetyTips") { $p.EnableSimilarDomainsSafetyTips } else { $null }
            EnableSimilarUsersSafetyTips = if ($p.PSObject.Properties.Name -contains "EnableSimilarUsersSafetyTips") { $p.EnableSimilarUsersSafetyTips } else { $null }
            EnableSuspiciousSafetyTip = if ($p.PSObject.Properties.Name -contains "EnableSuspiciousSafetyTip") { $p.EnableSuspiciousSafetyTip } else { $null }
            EnableUnusualCharactersSafetyTips = if ($p.PSObject.Properties.Name -contains "EnableUnusualCharactersSafetyTips") { $p.EnableUnusualCharactersSafetyTips } else { $null }
            EnableTargetedUserProtection = if ($p.PSObject.Properties.Name -contains "EnableTargetedUserProtection") { $p.EnableTargetedUserProtection } else { $null }
            EnableTargetedDomainsProtection = if ($p.PSObject.Properties.Name -contains "EnableTargetedDomainsProtection") { $p.EnableTargetedDomainsProtection } else { $null }
            TargetedUserProtectionAction = if ($p.PSObject.Properties.Name -contains "TargetedUserProtectionAction") { $p.TargetedUserProtectionAction } else { $null }
            TargetedDomainProtectionAction = if ($p.PSObject.Properties.Name -contains "TargetedDomainProtectionAction") { $p.TargetedDomainProtectionAction } else { $null }
        }
    }

    foreach ($scriptKey in @(
        "mdo_phish_threshold_level.ps1",
        "mdo_mailbox_intelligence_protection.ps1",
        "mdo_safety_tips_enabled.ps1"
        "mdo_targeted_user_protection_action.ps1"
        "mdo_targeted_domain_protection_action.ps1"
    )) {
        $scripts[$scriptKey] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($apItems) { @($apItems).Count } else { 0 }
            policies = @($apRows | Select-Object -First 25)
            errors = $errors
        }
    }
} catch {
    foreach ($scriptKey in @(
        "mdo_phish_threshold_level.ps1",
        "mdo_mailbox_intelligence_protection.ps1",
        "mdo_safety_tips_enabled.ps1"
        "mdo_targeted_user_protection_action.ps1"
        "mdo_targeted_domain_protection_action.ps1"
    )) {
        $scripts[$scriptKey] = @{
            connected = $false
            error = $_.Exception.Message
        }
    }
}

# SafeLinksPolicy-based scripts
try {
    $cmdletsUsed += "Get-SafeLinksPolicy"
    $slItems = Get-SafeLinksPolicy -ErrorAction Stop
    $slRows = @()
    foreach ($p in @($slItems)) {
        $slRows += @{
            identity = "$($p.Identity)"
            EnableSafeLinksForOffice = if ($p.PSObject.Properties.Name -contains "EnableSafeLinksForOffice") { $p.EnableSafeLinksForOffice } else { $null }
            TrackClicks = if ($p.PSObject.Properties.Name -contains "TrackClicks") { $p.TrackClicks } else { $null }
            AllowClickThrough = if ($p.PSObject.Properties.Name -contains "AllowClickThrough") { $p.AllowClickThrough } else { $null }
            ScanUrls = if ($p.PSObject.Properties.Name -contains "ScanUrls") { $p.ScanUrls } else { $null }
        }
    }

    $scripts["mdo_safe_links_office_apps.ps1"] = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policiesCount = if ($slItems) { @($slItems).Count } else { 0 }
        policies = @($slRows | Select-Object -First 25)
        errors = $errors
    }
} catch {
    $scripts["mdo_safe_links_office_apps.ps1"] = @{
        connected = $false
        error = $_.Exception.Message
    }
}
    # --- Bulk MDO policy signals (speed-up for multiple controls) ---
    # These scripts are called by multiple MDO controls and were costing ~6–7s EACH. :contentReference[oaicite:1]{index=1}
    # By emitting their payloads from the snapshot, engine.detectors.mdo._run_exo_ps() will cache them and skip per-control EXO calls.

    # A) Hosted Content Filter Policies bundle (Get-HostedContentFilterPolicy)
    try {
        $cmdletsUsed = @()
        $errors2 = @{}

        $cmdletsUsed += "Get-HostedContentFilterPolicy"
        $pol = $null
        try { $pol = Get-HostedContentFilterPolicy -ErrorAction Stop } catch { $errors2["Get-HostedContentFilterPolicy"] = $_.Exception.Message }

        # 1) mdo_bulk_spam_action.ps1
        $rows = @()
        if ($pol) {
            foreach ($p in @($pol)) {
                $row = @{ identity = "$($p.Identity)" }
                foreach ($k in @("BulkComplaintLevelThreshold","BulkSpamAction","BulkThreshold","ThresholdReachedAction")) {
                    if ($p.PSObject.Properties.Name -contains $k) { $row[$k] = $p.$k } else { $row[$k] = $null }
                }
                $rows += $row
            }
        }
        $scripts["mdo_bulk_spam_action.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 25)
            errors = $errors2
        }

        # 2) mdo_bulk_complaint_level_threshold.ps1 (same dataset/shape)
        $scripts["mdo_bulk_complaint_level_threshold.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 25)
            errors = $errors2
        }

        # 3) mdo_phishing_action.ps1
        $rows = @()
        if ($pol) {
            foreach ($p in @($pol)) {
                $row = @{ identity = "$($p.Identity)" }
                foreach ($k in @("PhishSpamAction","PhishingAction")) {
                    if ($p.PSObject.Properties.Name -contains $k) { $row[$k] = $p.$k } else { $row[$k] = $null }
                }
                $rows += $row
            }
        }
        $scripts["mdo_phishing_action.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 25)
            errors = $errors2
        }

        # 4) mdo_spam_notifications_admins_only.ps1
        $rows = @()
        if ($pol) {
            foreach ($p in @($pol)) {
                $row = @{ identity = "$($p.Identity)" }
                foreach ($k in @(
                    "EnableEndUserSpamNotifications",
                    "EnableEndUserSpamNotificationsForSpam",
                    "EnableEndUserSpamNotificationsForPhish",
                    "EndUserSpamNotificationFrequency",
                    "EndUserSpamNotificationCustomFromAddress"
                )) {
                    if ($p.PSObject.Properties.Name -contains $k) { $row[$k] = $p.$k } else { $row[$k] = $null }
                }
                $rows += $row
            }
        }
        $scripts["mdo_spam_notifications_admins_only.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 25)
            errors = $errors2
        }

        # 5) mdo_allowed_senders_restricted.ps1
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
        $scripts["mdo_allowed_senders_restricted.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policyCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 25)
            errors = $errors2
        }
    }
    catch {
        # If this bundle fails, mark each dependent script as failed so the engine won't keep re-snapshotting.
        foreach ($k in @(
            "mdo_bulk_spam_action.ps1",
            "mdo_bulk_complaint_level_threshold.ps1",
            "mdo_phishing_action.ps1",
            "mdo_spam_notifications_admins_only.ps1",
            "mdo_allowed_senders_restricted.ps1"
        )) {
            $scripts[$k] = @{ connected = $false; error = $_.Exception.Message }
        }
    }

    # B) Threshold reached action (Hosted Outbound Spam Filter Policy)
    try {
        $cmdletsUsed = @()
        $errors2 = @{}

        $cmdletsUsed += "Get-HostedOutboundSpamFilterPolicy"
        $pol = $null
        try { $pol = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop } catch { $errors2["Get-HostedOutboundSpamFilterPolicy"] = $_.Exception.Message }

        $rows = @()
        if ($pol) {
            foreach ($p in @($pol)) {
                $rows += @{
                    identity = "$($p.Identity)"
                    ActionWhenThresholdReached = if ($p.PSObject.Properties.Name -contains "ActionWhenThresholdReached") { $p.ActionWhenThresholdReached } else { $null }
                    ThresholdReachedAction     = if ($p.PSObject.Properties.Name -contains "ThresholdReachedAction")     { $p.ThresholdReachedAction }     else { $null }
                }
            }
        }

        $scripts["mdo_threshold_reached_action.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 10)
            errors = $errors2
        }
    }
    catch {
        $scripts["mdo_threshold_reached_action.ps1"] = @{ connected = $false; error = $_.Exception.Message }
    }

    # C) Mailbox intelligence protection (AntiPhish policy)
    try {
        $cmdletsUsed = @()
        $errors2 = @{}

        $cmdletsUsed += "Get-AntiPhishPolicy"
        $pol = $null
        try { $pol = Get-AntiPhishPolicy -ErrorAction Stop } catch { $errors2["Get-AntiPhishPolicy"] = $_.Exception.Message }

        $rows = @()
        if ($pol) {
            foreach ($p in @($pol)) {
                $row = @{ identity = "$($p.Identity)" }
                foreach ($k in @("EnableMailboxIntelligenceProtection")) {
                    if ($p.PSObject.Properties.Name -contains $k) { $row[$k] = $p.$k } else { $row[$k] = $null }
                }
                $rows += $row
            }
        }

        $scripts["mdo_mailbox_intelligence_protection.ps1"] = @{
            connected = $true
            cmdletsUsed = $cmdletsUsed
            policiesCount = if ($pol) { @($pol).Count } else { 0 }
            policies = @($rows | Select-Object -First 25)
            errors = $errors2
        }
    }
    catch {
        $scripts["mdo_mailbox_intelligence_protection.ps1"] = @{ connected = $false; error = $_.Exception.Message }
    }

# AtpPolicyForO365-based scripts (Safe Documents)
try {
    $cmdletsUsed += "Get-AtpPolicyForO365"
    $sdItems = Get-AtpPolicyForO365 -ErrorAction Stop
    $sdRows = @()
    foreach ($p in @($sdItems)) {
        $sdRows += @{
            identity = "$($p.Identity)"
            EnableSafeDocs = if ($p.PSObject.Properties.Name -contains "EnableSafeDocs") { $p.EnableSafeDocs } else { $null }
            EnableSafeDocsForClients = if ($p.PSObject.Properties.Name -contains "EnableSafeDocsForClients") { $p.EnableSafeDocsForClients } else { $null }
            AllowSafeDocsOpen = if ($p.PSObject.Properties.Name -contains "AllowSafeDocsOpen") { $p.AllowSafeDocsOpen } else { $null }
            TrackSafeDocs = if ($p.PSObject.Properties.Name -contains "TrackSafeDocs") { $p.TrackSafeDocs } else { $null }
            EnableATPForSPOTeamsODB = if ($p.PSObject.Properties.Name -contains "EnableATPForSPOTeamsODB") { $p.EnableATPForSPOTeamsODB } else { $null }
            EnableATPForSharePoint = if ($p.PSObject.Properties.Name -contains "EnableATPForSharePoint") { $p.EnableATPForSharePoint } else { $null }
            EnableSafeLinksForO365Clients = if ($p.PSObject.Properties.Name -contains "EnableSafeLinksForO365Clients") { $p.EnableSafeLinksForO365Clients } else { $null }
        }
    }

    $scripts["mdo_safe_documents_enabled.ps1"] = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policiesCount = if ($sdItems) { @($sdItems).Count } else { 0 }
        policies = @($sdRows | Select-Object -First 25)
        errors = $errors
    }

$scripts["mdo_turn_on_mdo_for_spood_teams.ps1"] = @{
    connected = $true
    cmdletsUsed = $cmdletsUsed
    policiesCount = if ($sdItems) { @($sdItems).Count } else { 0 }
    policies = @($sdRows | Select-Object -First 25)
    errors = $errors
}
} catch {
    $scripts["mdo_safe_documents_enabled.ps1"] = @{
        connected = $false
        error = $_.Exception.Message
    }
    $scripts["mdo_turn_on_mdo_for_spood_teams.ps1"] = @{ connected = $false; error = $_.Exception.Message }
}

# QuarantinePolicy-based scripts
try {
    $cmdletsUsed += "Get-QuarantinePolicy"
    $qItems = Get-QuarantinePolicy -ErrorAction Stop
    $qRows = @()
    foreach ($p in @($qItems)) {
        $qRows += @{
            identity = "$($p.Identity)"
            QuarantineRetentionDays = if ($p.PSObject.Properties.Name -contains "QuarantineRetentionDays") { $p.QuarantineRetentionDays } else { $null }
            EndUserQuarantinePermissions = if ($p.PSObject.Properties.Name -contains "EndUserQuarantinePermissions") { $p.EndUserQuarantinePermissions } else { $null }
            ESNEnabled = if ($p.PSObject.Properties.Name -contains "ESNEnabled") { $p.ESNEnabled } else { $null }
        }
    }

    $scripts["mdo_quarantine_retention_period.ps1"] = @{
        connected = $true
        cmdletsUsed = $cmdletsUsed
        policiesCount = if ($qItems) { @($qItems).Count } else { 0 }
        policies = @($qRows | Select-Object -First 25)
        errors = $errors
    }
} catch {
    $scripts["mdo_quarantine_retention_period.ps1"] = @{
        connected = $false
        error = $_.Exception.Message
    }
}

    @{
        connected = $true
        scripts = $scripts
    } | ConvertTo-Json -Depth 10
}
catch {
    @{
        connected = $false
        error = $_.Exception.Message
        scripts = $scripts
    } | ConvertTo-Json -Depth 10
    exit 1
}
finally {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
