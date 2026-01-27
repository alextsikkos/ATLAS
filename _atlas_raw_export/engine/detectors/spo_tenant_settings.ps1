param(
  [Parameter(Mandatory=$true)][string]$AdminUrl,
  [string]$ClientId,
  [string]$TenantId,
  [string]$CertificateThumbprint,
  [string]$CertificatePath,
  [string]$CertificatePassword
)

$ErrorActionPreference = "Stop"

$result = @{
  ok = $false
  error = $null
  adminUrl = $AdminUrl
  tenant = $null
}

try {
  if (-not $AdminUrl) {
    throw "AdminUrl is required (e.g. https://contoso-admin.sharepoint.com)"
  }

  Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue

  # --- Connect: app-only if configured; interactive only if no app-only args passed ---
  $hasAppOnlyArgs = ($ClientId -and $TenantId -and ( $CertificateThumbprint -or $CertificatePath ))

  if ($hasAppOnlyArgs) {
    if ($CertificateThumbprint) {
      $tp = $CertificateThumbprint -replace "\s",""
      $certPath = "Cert:\CurrentUser\My\$tp"
      $cert = Get-ChildItem $certPath -ErrorAction Stop
      if (-not $cert.HasPrivateKey) { throw "Certificate found but has no private key: $certPath" }

      Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -Certificate $cert -ErrorAction Stop
    }
    else {
      # CertificatePath mode
      if (-not $CertificatePath) { throw "CertificatePath is required when using CertificatePath auth" }
      if (-not $CertificatePassword) { throw "CertificatePassword is required when using CertificatePath auth" }

      $secPwd = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force

      spo = tenant.get("spoAppAuth") or {}
      cmd = [
        "pwsh", "-NoProfile", "-NonInteractive",
        "-File", SPO_SCRIPT_PATH,
        "-AdminUrl", admin_url,
      ]

      if spo.get("clientId") and spo.get("tenantId") and spo.get("certificateThumbprint"):
          cmd += ["-ClientId", spo["clientId"], "-TenantId", spo["tenantId"], "-CertificateThumbprint", spo["certificateThumbprint"]]
      elif spo.get("clientId") and spo.get("tenantId") and spo.get("certificatePath") and spo.get("certificatePassword"):
          cmd += ["-ClientId", spo["clientId"], "-TenantId", spo["tenantId"], "-CertificatePath", spo["certificatePath"], "-CertificatePassword", spo["certificatePassword"]]
      else:
          raise RuntimeError("spoAppAuth missing required fields for app-only auth")

    }

  }
  else {
    throw "Interactive SPO auth is disabled. Configure spoAppAuth (clientId/tenantId/certificateThumbprint) in the tenant JSON."
  }

  # --- end connect ---

  $t = Get-SPOTenant
  # Sync client restriction (OneDrive/SharePoint sync restrictions)
  $sync = $null
  try {
    $sync = Get-SPOTenantSyncClientRestriction
  } catch {
    $sync = $null
  }

  # Idle session sign-out (SharePoint/OneDrive browser idle timeout)
  $idle = $null
  try {
    $idle = Get-SPOBrowserIdleSignOut
  } catch {
    $idle = $null
  }


  $result.ok = $true
  $result.tenant = @{
    TenantSyncClientRestriction = $(if ($sync) {
    @{
      TenantRestrictionEnabled = $sync.TenantRestrictionEnabled
      AllowedDomainList        = $sync.AllowedDomainList
      BlockMacSync             = $sync.BlockMacSync
      GrooveBlockOption        = $sync.GrooveBlockOption
    }
  } else { $null })

  SyncClientRestrictionEnabled = $t.SyncClientRestrictionEnabled
  AllowedDomainGuids           = $t.AllowedDomainGuids

  # SharePoint sharing posture
  SharingCapability = $t.SharingCapability
  SharingDomainRestrictionMode = $t.SharingDomainRestrictionMode
  SharingAllowedDomainList = $t.SharingAllowedDomainList
  SharingBlockedDomainList = $t.SharingBlockedDomainList

  # Default link controls
  DefaultSharingLinkType = $t.DefaultSharingLinkType
  DefaultLinkPermission = $t.DefaultLinkPermission
  
  # Legacy auth protocols (modern auth requirement)
  LegacyAuthProtocolsEnabled = $t.LegacyAuthProtocolsEnabled
  RequireAnonymousLinksExpireInDays = $t.RequireAnonymousLinksExpireInDays


  # Idle session sign-out
  IdleSessionSignOutEnabled = $(if ($idle) { [bool]$idle.Enabled } else { $null })
  IdleSessionSignOutWarnAfterSeconds = $(if ($idle -and $idle.WarnAfter) { [int]$idle.WarnAfter.TotalSeconds } else { $null })
  IdleSessionSignOutAfterSeconds = $(if ($idle -and $idle.SignOutAfter) { [int]$idle.SignOutAfter.TotalSeconds } else { $null })

  # Guest re-share control
  PreventExternalUsersFromResharing = $t.PreventExternalUsersFromResharing

  # OneDrive-specific sharing posture (some tenants expose this separately)
  OneDriveSharingCapability = $t.OneDriveSharingCapability

}

} catch {
  $result.ok = $false
  $result.error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 6