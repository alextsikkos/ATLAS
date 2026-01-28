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

Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null

# Connect to SPO admin (app-only). No interactive fallback.
if (-not ($ClientId -and $TenantId -and (($CertificateThumbprint -and $CertificateThumbprint.Trim()) -or ($CertificatePath -and $CertificatePath.Trim())))) {
  throw "App-only auth parameters missing; refusing to fall back to interactive auth."
}

$cert = Get-AtlasSpoCertificate -CertificateThumbprint $CertificateThumbprint -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword

Connect-SPOService -Url $AdminUrl -ClientId $ClientId -Tenant $TenantId -Certificate $cert -ErrorAction Stop

# Convert JSON -> hashtable for splatting
$obj = $SettingsJson | ConvertFrom-Json
$ht = @{}
foreach ($p in $obj.PSObject.Properties) {
  $ht[$p.Name] = $p.Value
}

Set-SPOTenant @ht

Write-Output "OK"
exit 0
