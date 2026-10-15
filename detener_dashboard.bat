@echo off
title Detener Dashboard DevSecOps
echo ==============================================================================
echo  DETENIENDO SERVICIO DEL DASHBOARD DEVSECOPS (PUERTO 5000)
echo  Empresa: Alma Industria Creativa E.I.R.L.
echo ==============================================================================
echo.

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5000" ^| findstr "LISTENING"') do (
    echo [+] Proceso detectado con PID: %%a. Terminando proceso...
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo [OK] Servidor detenido con exito. Puerto 5000 liberado.
timeout /t 3 >nul
