param(
  [Parameter(Mandatory=$true)]
  [string]$AdminUrl,

  # Expect: "AllowList" or "BlockList"
  [Parameter(Mandatory=$true)]
  [string]$Mode,

  # Optional but required depending on Mode
  [string]$AllowedDomains,
  [string]$BlockedDomains,

  [string]$AccountId,
  [string]$ClientId,
  [string]$TenantId,
  [string]$CertificateThumbprint,
  [string]$CertificatePath,
  [string]$CertificatePassword
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
# Connect to SPO admin
if ($ClientId -and $TenantId -and (($CertificateThumbprint -and $CertificateThumbprint.Trim().Length -gt 0) -or ($CertificatePath -and $CertificatePath.Trim().Length -gt 0))) {

  if ($CertificateThumbprint -and $CertificateThumbprint.Trim().Length -gt 0) {
    Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
  }
  elseif ($CertificatePath -and $CertificatePath.Trim().Length -gt 0) {
    if ($CertificatePassword -and $CertificatePassword.Trim().Length -gt 0) {
      $sec = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force
      Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificatePath $CertificatePath -CertificatePassword $sec -ErrorAction Stop
    }
    else {
      Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificatePath $CertificatePath -ErrorAction Stop
    }
  }

}
else {
  if ($AccountId -and $AccountId.Trim().Length -gt 0) {
    try {
      Connect-SPOService -Url $AdminUrl -AccountId $AccountId -ErrorAction Stop
    } catch {
      Connect-SPOService -Url $AdminUrl -ErrorAction Stop
    }
  }
  else {
    Connect-SPOService -Url $AdminUrl -ErrorAction Stop
  }
}

# Build parameters conservatively
if ($Mode -eq "AllowList") {
  if (-not $AllowedDomains -or $AllowedDomains.Trim().Length -eq 0) { throw "AllowedDomains is required when Mode=AllowList" }
  Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList $AllowedDomains
}
elseif ($Mode -eq "BlockList") {
  if (-not $BlockedDomains -or $BlockedDomains.Trim().Length -eq 0) { throw "BlockedDomains is required when Mode=BlockList" }
  Set-SPOTenant -SharingDomainRestrictionMode BlockList -SharingBlockedDomainList $BlockedDomains
}
else {
  throw "Unsupported Mode. Expected AllowList or BlockList."
}

Write-Output "OK"
exit 0
