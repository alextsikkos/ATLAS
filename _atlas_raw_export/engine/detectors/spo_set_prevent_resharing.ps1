param(
  [Parameter(Mandatory=$true)]
  [string]$AdminUrl,

  [Parameter(Mandatory=$true)]
  [string]$Enabled,

  [Parameter(Mandatory=$true)]
  [string]$ClientId,

  [Parameter(Mandatory=$true)]
  [string]$TenantId,

  [Parameter(Mandatory=$false)]
  [string]$CertificateThumbprint,

  [Parameter(Mandatory=$false)]
  [string]$CertificatePath,

  [Parameter(Mandatory=$false)]
  [string]$CertificatePassword
)
# Coerce Enabled to boolean (ATLAS passes "$true"/"$false" as strings)
$EnabledBool = ($Enabled -as [string]).Trim().ToLower() -in @("true","$true","1","yes","y")


$ErrorActionPreference = "Stop"

Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
# Connect to SPO admin
if ($ClientId -and $TenantId -and (($CertificateThumbprint -and $CertificateThumbprint.Trim().Length -gt 0) -or ($CertificatePath -and $CertificatePath.Trim().Length -gt 0))) {

  if ($CertificateThumbprint -and $CertificateThumbprint.Trim().Length -gt 0) {
    if ($CertificateThumbprint) {
      Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificateThumbprint $CertificateThumbprint
    }
    elseif ($CertificatePath -and $CertificatePassword) {
      $sec = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
      Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -CertificatePath $CertificatePath -CertificatePassword $sec
    }
    else {
      throw "No certificate auth provided. Supply -CertificateThumbprint or (-CertificatePath and -CertificatePassword)."
    }


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


if ($Enabled -eq '$true') {
  Set-SPOTenant -PreventExternalUsersFromResharing $EnabledBool
} else {
  Set-SPOTenant -PreventExternalUsersFromResharing $EnabledBool
}

Write-Output "OK"
exit 0
