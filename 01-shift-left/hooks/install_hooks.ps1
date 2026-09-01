# ==============================================================================
# Script de Instalación Automatizada de Git Hooks (Windows PowerShell)
# ==============================================================================

$repoRoot = (git rev-parse --show-toplevel 2>$null)
if (-not $repoRoot) {
    Write-Host "[!] Error: No estás dentro de un repositorio Git." -ForegroundColor Red
    exit 1
}

$hooksDir = Join-Path $repoRoot ".git\hooks"
$sourceHook = Join-Path $repoRoot "01-shift-left\hooks\pre-commit"
$targetHook = Join-Path $hooksDir "pre-commit"

if (-not (Test-Path $hooksDir)) {
    New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
}

Copy-Item -Path $sourceHook -Destination $targetHook -Force

Write-Host "[+] Git Pre-commit Hook instalado exitosamente en:" -ForegroundColor Green
Write-Host "    $targetHook" -ForegroundColor Cyan
Write-Host "[+] Todo 'git commit' ahora será escaneado automáticamente con Gitleaks." -ForegroundColor Green
