param(
  [Parameter(Mandatory=$true)][string]$TenantDomain,
  [string]$AppId,
  [string]$CertThumbprint
)

$ErrorActionPreference="Stop"
Import-Module ExchangeOnlineManagement

if($AppId -and $CertThumbprint){
  Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false | Out-Null
}else{
  Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false | Out-Null
}

try{
  $errors=@{}
  $cmdletsUsed=@("Get-AntiPhishPolicy")

  $pol=$null
  try{ $pol = Get-AntiPhishPolicy -ErrorAction Stop } catch { $errors["Get-AntiPhishPolicy"]=$_.Exception.Message }

  $rows=@()
  if($pol){
    foreach($p in @($pol)){
      $rows += @{
        identity = "$($p.Identity)"
        presentKeys = @($p.PSObject.Properties.Name)

        # Actual safety tips flags exposed on AntiPhishPolicy
        EnableSimilarUsersSafetyTips        = if($p.PSObject.Properties.Name -contains "EnableSimilarUsersSafetyTips"){ $p.EnableSimilarUsersSafetyTips } else { $null }
        EnableSimilarDomainsSafetyTips      = if($p.PSObject.Properties.Name -contains "EnableSimilarDomainsSafetyTips"){ $p.EnableSimilarDomainsSafetyTips } else { $null }
        EnableUnusualCharactersSafetyTips   = if($p.PSObject.Properties.Name -contains "EnableUnusualCharactersSafetyTips"){ $p.EnableUnusualCharactersSafetyTips } else { $null }

        # Optional extras (good to include, but not required for evaluation)
        EnableFirstContactSafetyTips        = if($p.PSObject.Properties.Name -contains "EnableFirstContactSafetyTips"){ $p.EnableFirstContactSafetyTips } else { $null }
        EnableSuspiciousSafetyTip           = if($p.PSObject.Properties.Name -contains "EnableSuspiciousSafetyTip"){ $p.EnableSuspiciousSafetyTip } else { $null }
        }


    }
  }

  @{
    connected = $true
    cmdletsUsed = $cmdletsUsed
    policiesCount = if($pol){ @($pol).Count } else { 0 }
    policies = @($rows | Select-Object -First 25)
    errors = $errors
  } | ConvertTo-Json -Depth 8
}
catch{
  @{connected=$false;error=$_.Exception.Message} | ConvertTo-Json -Depth 4
}
finally{
  try{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
