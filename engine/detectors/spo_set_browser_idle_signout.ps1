param(
  [Parameter(Mandatory=$true)]
  [string]$AdminUrl,

  [Parameter(Mandatory=$true)]
  [bool]$Enabled,

  [Parameter(Mandatory=$true)]
  [int]$WarnAfterSeconds,

  [Parameter(Mandatory=$true)]
  [int]$SignOutAfterSeconds,

  [Parameter(Mandatory=$true)]
  [string]$ClientId,

  [Parameter(Mandatory=$true)]
  [string]$TenantId,

  [string]$CertificateThumbprint,
  [string]$CertificatePath,
  [string]$CertificatePassword
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

try {
  $EnabledBool = [System.Convert]::ToBoolean($Enabled)
}
catch {
  throw "Invalid value for Enabled: '$Enabled'. Must be true/false or 1/0."
}



$ErrorActionPreference = "Stop"

$result = @{
  ok = $false
  error = $null
  adminUrl = $AdminUrl
  idle = $null
}

try {
  Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue

  # --- Connect app-only (no interactive fallback) ---
  if (-not ($ClientId -and $TenantId -and (($CertificateThumbprint -and $CertificateThumbprint.Trim()) -or ($CertificatePath -and $CertificatePath.Trim())))) {
    throw "App-only auth parameters missing; refusing to fall back to interactive auth."
  }

  $cert = Get-AtlasSpoCertificate -CertificateThumbprint $CertificateThumbprint -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword

  Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -Certificate $cert -ErrorAction Stop
  # --- end connect ---


  # Build timespans only if provided
  $warnTs = $null
  $signoutTs = $null
  if ($WarnAfterSeconds -gt 0) { $warnTs = New-TimeSpan -Seconds $WarnAfterSeconds }
  if ($SignOutAfterSeconds -gt 0) { $signoutTs = New-TimeSpan -Seconds $SignOutAfterSeconds }

  if ($EnabledBool -and ($WarnAfterSeconds -le 0 -or $SignOutAfterSeconds -le 0)) {
    throw "When Enabled=true, WarnAfterSeconds and SignOutAfterSeconds must both be > 0."
  }
  if ($EnabledBool -and ($WarnAfterSeconds -ge $SignOutAfterSeconds)) {
    throw "WarnAfterSeconds must be less than SignOutAfterSeconds."
  }

  if ($EnabledBool) {
    Set-SPOBrowserIdleSignOut -Enabled:$true -WarnAfter $warnTs -SignOutAfter $signoutTs -ErrorAction Stop
  }
  else {
    Set-SPOBrowserIdleSignOut -Enabled:$false -ErrorAction Stop
  }

  $idle = Get-SPOBrowserIdleSignOut -ErrorAction Stop

  $result.ok = $true
  $result.idle = @{
    Enabled = [bool]$idle.Enabled
    WarnAfterSeconds = $(if ($idle.WarnAfter) { [int]$idle.WarnAfter.TotalSeconds } else { $null })
    SignOutAfterSeconds = $(if ($idle.SignOutAfter) { [int]$idle.SignOutAfter.TotalSeconds } else { $null })
  }
}
catch {
  $result.ok = $false
  $result.error = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 6
