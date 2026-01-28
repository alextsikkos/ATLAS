param(
    [Parameter(Mandatory)]
    [string] $AdminUrl,

    [string] $ClientId,
    [string] $TenantId,
    [string] $CertificateThumbprint,
    [string] $CertificatePath,
    [string] $CertificatePassword
)
function Get-AtlasSpoCertificate {
  param(
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [string]$CertificatePassword
  )

  # Prefer CertificatePath (+ password) if provided
  if ($CertificatePath -and $CertificatePath.Trim().Length -gt 0) {
    if (-not (Test-Path -LiteralPath $CertificatePath)) {
      throw "CertificatePath not found: $CertificatePath"
    }
    if (-not ($CertificatePassword -and $CertificatePassword.Trim().Length -gt 0)) {
      throw "CertificatePassword is required when using CertificatePath auth."
    }

    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
           -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($CertificatePath, $CertificatePassword, $flags)

    if (-not $cert) { throw "Failed to load certificate from path: $CertificatePath" }
    if (-not $cert.HasPrivateKey) { throw "Certificate loaded from path but has no private key: $CertificatePath" }

    return $cert
  }

  # Otherwise resolve by thumbprint in both stores
  if ($CertificateThumbprint -and $CertificateThumbprint.Trim().Length -gt 0) {
    $tp = $CertificateThumbprint -replace "\s",""

    $cert = Get-ChildItem "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
    if (-not $cert) {
      $cert = Get-ChildItem "Cert:\LocalMachine\My\$tp" -ErrorAction SilentlyContinue
    }

    if (-not $cert) {
      throw "Certificate not found in CurrentUser or LocalMachine store. Thumbprint=$tp"
    }

    if ($cert -is [object[]]) { $cert = $cert[0] }

    if (-not $cert.HasPrivateKey) {
      throw "Certificate found but has no private key. Thumbprint=$tp"
    }

    return $cert
  }

  throw "No certificate auth provided. Supply CertificatePath+CertificatePassword or CertificateThumbprint."
}



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
    $cert = Get-AtlasSpoCertificate -CertificateThumbprint $CertificateThumbprint -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword
    Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -Certificate $cert -ErrorAction Stop
  }
  else {
    throw "Interactive SPO auth is disabled. Set ATLAS_SPO_* environment variables and pass them into this script."
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