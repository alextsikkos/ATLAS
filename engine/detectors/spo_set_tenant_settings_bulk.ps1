param(
  [Parameter(Mandatory=$true)]
  [string]$AdminUrl,

  [Parameter(Mandatory=$true)]
  [string]$SettingsJson,

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

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

# Connect to SPO admin (app-only). Auth args are validated in Python and passed explicitly.
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
  else {
    throw "No certificate auth provided. Supply -CertificateThumbprint or (-CertificatePath and -CertificatePassword)."
  }

}
else {
  throw "App-only auth parameters missing; refusing to fall back to interactive auth."
}

# Convert JSON -> hashtable for splatting
$obj = $SettingsJson | ConvertFrom-Json
$ht = @{}
foreach ($p in $obj.PSObject.Properties) {
  $ht[$p.Name] = $p.Value
}

Set-SPOTenant @ht

Write-Output "OK"
exit 0
