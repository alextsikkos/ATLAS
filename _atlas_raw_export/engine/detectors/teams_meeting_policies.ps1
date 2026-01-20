param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$AppId,
  [Parameter(Mandatory=$true)][string]$CertificateThumbprint
)

$ErrorActionPreference = "Stop"

try {
  Import-Module MicrosoftTeams -ErrorAction Stop

  Connect-MicrosoftTeams -TenantId $TenantId -ApplicationId $AppId -CertificateThumbprint $CertificateThumbprint | Out-Null

  $policies = @(Get-CsTeamsMeetingPolicy -Identity Global)

  $selected = @()
  foreach ($p in $policies) {
    $obj = [ordered]@{
      Identity                               = $p.Identity
      AutoAdmittedUsers                      = $p.AutoAdmittedUsers
      DesignatedPresenterRoleMode            = $p.DesignatedPresenterRoleMode
      AllowExternalParticipantGiveRequestControl = $p.AllowExternalParticipantGiveRequestControl
      AllowAnonymousUsersToJoinMeeting        = $p.AllowAnonymousUsersToJoinMeeting
      AllowAnonymousUsersToStartMeeting       = $p.AllowAnonymousUsersToStartMeeting
      AllowPSTNUsersToBypassLobby             = $p.AllowPSTNUsersToBypassLobby
    }
    $selected += [pscustomobject]$obj
  }

  $presentKeys = @()
  if ($selected.Count -gt 0) {
    $presentKeys = $selected[0].PSObject.Properties.Name
  }

  $out = [ordered]@{
    ok = $true
    policies = $selected
    presentKeys = $presentKeys
  }

  $out | ConvertTo-Json -Depth 6 -Compress
}
catch {
  $err = $_.Exception.Message
  $out = [ordered]@{
    ok = $false
    error = $err
  }
  $out | ConvertTo-Json -Depth 4 -Compress
  exit 1
}
finally {
  try { Disconnect-MicrosoftTeams | Out-Null } catch {}
}
