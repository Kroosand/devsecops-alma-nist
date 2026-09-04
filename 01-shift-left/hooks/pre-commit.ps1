# ==============================================================================
# Proyecto: DevSecOps NIST CSF v2.0 - Alma Industria Creativa E.I.R.L.
# Control: SOP-02 - Control Preventivo Shift-Left en PowerShell con Notificación SOAR
# ==============================================================================

Write-Host "[DevSecOps - Shift Left] Validando código preparado en Staging..." -ForegroundColor Cyan

# Determinar la raíz del repositorio dinámicamente
$repoRoot = (git rev-parse --show-toplevel 2>$null)
if (-not $repoRoot) {
    $repoRoot = (Get-Location).Path
}

$configPath = Join-Path $repoRoot "01-shift-left\.gitleaks.toml"
$dispatcherScript = Join-Path $repoRoot "04-soar-n8n-testing\trigger_alert.py"

# Verificar existencia de gitleaks
$gitleaksCmd = Get-Command gitleaks -ErrorAction SilentlyContinue
if (-not $gitleaksCmd) {
    Write-Host "[!] ADVERTENCIA: Gitleaks no está en el PATH del sistema." -ForegroundColor Yellow
    Write-Host "Ejecuta: winget install Gitleaks.Gitleaks" -ForegroundColor Yellow
    exit 1
}

if (Test-Path $configPath) {
    & gitleaks protect --staged --verbose --redact --config $configPath
} else {
    & gitleaks protect --staged --verbose --redact
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n===================================================================" -ForegroundColor Red
    Write-Host "[BLOQUEO SHIFT-LEFT] Se detectaron secretos o tokens en el commit!" -ForegroundColor Red
    Write-Host "===================================================================" -ForegroundColor Red
    Write-Host "Acción Correctiva:" -ForegroundColor Yellow
    Write-Host "1. Remueve las credenciales y trasládalas a la bóveda (Vault/Bitwarden)."
    Write-Host "2. Usa variables de entorno (.env) que no se suban al repositorio."
    Write-Host "3. Vuelve a ejecutar 'git add <archivo>' y realiza el commit nuevamente.`n"
    
    # Notificación automática SOAR hacia n8n / Telegram en segundo plano
    if (Test-Path $dispatcherScript) {
        Start-Process -FilePath "python" -ArgumentList "`"$dispatcherScript`" 1" -WindowStyle Hidden
    }

    exit 1
}

Write-Host "[PASS] Código limpio de secretos. Commit autorizado." -ForegroundColor Green
exit 0
