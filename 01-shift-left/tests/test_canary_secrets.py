#!/usr/bin/env python3
"""
==============================================================================
Script de Validación y Simulación de Fuga de Secretos (Canary Token Test)
Proyecto: DevSecOps NIST CSF v2.0 - Alma Industria Creativa E.I.R.L.
Autor: Sergio Incacutipa (SENATI)
Control: SOP-02 (PR.PS-01 / DE.CM-01)
==============================================================================
"""

import os
import subprocess
import sys

CANARY_FILE = "temp_canary_leak_test.php"

SAMPLE_LEAKS = """<?php
// ARCHIVO DE PRUEBA CONTROLADA - SIMULACIÓN DE FUGA DE CREDENCIALES
$telegram_bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789";
$aws_access_key = "AKIAIOSFODNN7EXAMPLE";
$aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
define('DB_PASSWORD', 'super_secret_db_pass_12345');
$n8n_api_key = "n8n_api_key_alma_growth_secret_998877665544";
?>"""

def run_command(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def main():
    print("=" * 70)
    print("[*] TEST AUTOMATIZADO SHIFT-LEFT: SIMULACIÓN DE INTENTO DE COMMIT CON SECRETOS")
    print("=" * 70)

    # 1. Crear archivo con secretos simulados
    print(f"\n[1] Creando archivo temporal con credenciales: {CANARY_FILE}...")
    with open(CANARY_FILE, "w") as f:
        f.write(SAMPLE_LEAKS)

    # 2. Agregar archivo a staging
    print("[2] Agregando archivo a Staging (git add)...")
    run_command(f"git add {CANARY_FILE}")

    # 3. Intentar realizar el commit
    print("[3] Ejecutando 'git commit' (Se espera intercepción y bloqueo)...")
    commit_res = run_command('git commit -m "test: intento de subir secretos hardcodeados"')

    # 4. Analizar resultado
    blocked = (commit_res.returncode != 0)
    
    print("\n--- SALIDA DEL ESCANEO ---")
    print(commit_res.stdout)
    if commit_res.stderr:
        print(commit_res.stderr)
    print("--------------------------")

    # 5. Limpieza (Deshacer staging y eliminar archivo temporal)
    print("[5] Limpiando entorno de prueba...")
    run_command(f"git reset HEAD {CANARY_FILE}")
    if os.path.exists(CANARY_FILE):
        os.remove(CANARY_FILE)

    # 6. Conclusión y reporte
    print("\n" + "=" * 70)
    if blocked:
        print("[RESULTADO: EXITOSO - CONTROL OPERATIVO SOP-02 FUNCIONANDO]")
        print(" -> El Pre-commit Hook detectó los secretos y BLOQUEÓ el commit.")
        print(" -> Código de salida retornado: 1 (Fallo forzado de seguridad).")
        print(" -> Cumplimiento NIST CSF v2.0: PR.PS-01 (Platform Security) VALIDADO.")
        print("=" * 70)
        sys.exit(0)
    else:
        print("[RESULTADO: FALLIDO - EL COMMIT NO FUE BLOQUEADO]")
        print(" -> Revisa la instalación del hook en .git/hooks/pre-commit.")
        print("=" * 70)
        sys.exit(1)

if __name__ == "__main__":
    main()
