param(
  [Parameter(Mandatory=$true)]
  [string]$TenantPath,

  [string]$Message = "Auto-push before ATLAS run",

  # Comma-separated list of ATLAS control IDs to run (e.g. "AdminOwnedAppsRestricted,IntegratedAppsRestricted")
  [string]$OnlyControls = "",

  # Comma-separated list of ATLAS control IDs to skip
  [string]$SkipControls = ""
)

Set-Location (Split-Path $PSScriptRoot)

Write-Host "=== Git status ==="
git status

Write-Host "=== Staging changes ==="
git add -A

$staged = git diff --cached --name-only
if ($staged) {
  git commit -m $Message
} else {
  Write-Host "No changes to commit."
}

Write-Host "=== Pushing ==="
git push

Write-Host "=== Running ATLAS at commit ==="
git rev-parse --short HEAD

# ---- Control filtering support (engine/main.py reads these env vars) ----
# Save previous values so we don't permanently pollute your shell session
$prevOnly = $env:ATLAS_ONLY_CONTROLS
$prevSkip = $env:ATLAS_SKIP_CONTROLS

try {
  if ($OnlyControls.Trim()) {
    $env:ATLAS_ONLY_CONTROLS = $OnlyControls
    Write-Host "=== ATLAS_ONLY_CONTROLS set to: $OnlyControls ==="
  } else {
    Remove-Item Env:\ATLAS_ONLY_CONTROLS -ErrorAction SilentlyContinue
  }

  if ($SkipControls.Trim()) {
    $env:ATLAS_SKIP_CONTROLS = $SkipControls
    Write-Host "=== ATLAS_SKIP_CONTROLS set to: $SkipControls ==="
  } else {
    Remove-Item Env:\ATLAS_SKIP_CONTROLS -ErrorAction SilentlyContinue
  }

  Write-Host "=== Running ATLAS ==="
  python -m engine.main --tenant $TenantPath
}
finally {
  # Restore prior env var values
  if ($null -ne $prevOnly) { $env:ATLAS_ONLY_CONTROLS = $prevOnly } else { Remove-Item Env:\ATLAS_ONLY_CONTROLS -ErrorAction SilentlyContinue }
  if ($null -ne $prevSkip) { $env:ATLAS_SKIP_CONTROLS = $prevSkip } else { Remove-Item Env:\ATLAS_SKIP_CONTROLS -ErrorAction SilentlyContinue }
}
