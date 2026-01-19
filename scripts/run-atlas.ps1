param(
    [Parameter(Mandatory=$true)]
    [string]$TenantPath,

    [string]$Message = "Auto-push before ATLAS run"
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

Write-Host "=== Running ATLAS ==="
python -m engine.main --tenant $TenantPath
