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

  # --- Connect app-only ---
  if (-not ($ClientId -and $TenantId -and (($CertificateThumbprint -and $CertificateThumbprint.Trim()) -or ($CertificatePath -and $CertificatePath.Trim())))) {
    throw "App-only auth parameters missing; refusing to fall back to interactive auth."
  }

  if ($CertificateThumbprint -and $CertificateThumbprint.Trim().Length -gt 0) {
    Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
  }
  elseif ($CertificatePath -and $CertificatePath.Trim().Length -gt 0) {
    if ($CertificatePassword -and $CertificatePassword.Trim().Length -gt 0) {
      $sec = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force
      Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificatePath $CertificatePath -CertificatePassword $sec -ErrorAction Stop
    }
    else {
      throw "CertificatePassword is required when using CertificatePath auth."
    }
  }
  else {
    throw "No certificate auth provided. Supply -CertificateThumbprint or (-CertificatePath and -CertificatePassword)."
  }
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
