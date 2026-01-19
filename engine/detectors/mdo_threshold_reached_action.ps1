param([Parameter(Mandatory=$true)][string]$TenantDomain,[string]$AppId,[string]$CertThumbprint)

$ErrorActionPreference="Stop"
Import-Module ExchangeOnlineManagement

if($AppId -and $CertThumbprint){
  Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertThumbprint -Organization $TenantDomain -ShowBanner:$false | Out-Null
}else{
  Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false | Out-Null
}

try{
  $errors=@{}
  $cmdletsUsed=@("Get-HostedOutboundSpamFilterPolicy")
  $pol=$null
  try{ $pol = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop } catch { $errors["Get-HostedOutboundSpamFilterPolicy"]=$_.Exception.Message }

  $rows=@()
  if($pol){
    foreach($p in @($pol)){
      # Different tenants/modules use different names; return both.
      $rows+=@{
        identity="$($p.Identity)"
        ActionWhenThresholdReached = if($p.PSObject.Properties.Name -contains "ActionWhenThresholdReached"){ $p.ActionWhenThresholdReached } else { $null }
        ThresholdReachedAction     = if($p.PSObject.Properties.Name -contains "ThresholdReachedAction"){ $p.ThresholdReachedAction } else { $null }
      }
    }
  }

  @{connected=$true;cmdletsUsed=$cmdletsUsed;policiesCount=if($pol){@($pol).Count}else{0};policies=($rows|Select-Object -First 10);errors=$errors} | ConvertTo-Json -Depth 6
}
catch{
  @{connected=$false;error=$_.Exception.Message} | ConvertTo-Json -Depth 4
}
finally{
  try{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
