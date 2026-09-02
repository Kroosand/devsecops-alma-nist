@echo off
title DevSecOps SOAR Center - Alma Industria Creativa
echo ==============================================================================
echo  INICIANDO CENTRO DE CONTROL DEVSECOPS & SOAR - NIST CSF v2.0
echo  Empresa: Alma Industria Creativa E.I.R.L. ^| SENATI
echo ==============================================================================
echo.
echo [1] Abriendo navegador en: http://127.0.0.1:5000 ...
start http://127.0.0.1:5000
echo.
echo [2] Ejecutando servidor Flask en segundo plano...
python dashboard\app.py
pause
