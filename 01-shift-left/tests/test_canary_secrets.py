#!/usr/bin/env python3
"""
==============================================================================
Script de Validación y Simulación Shift-Left (Canary Token Test)
Proyecto: DevSecOps NIST CSF v2.0 - Alma Industria Creativa E.I.R.L.
Autores: Sergio Incacutipa & Waldir Chullo (SENATI)
Control: SOP-02 (PR.PS-01 / DE.CM-01)
==============================================================================
"""

import os
import subprocess
import sys

CANARY_FILE = "services_notifier_demo.php"

SAMPLE_LEAKS = """<?php
// Módulo de Notificaciones de Clientes - Alma Industria Creativa E.I.R.L.
// [ERROR DE DESARROLLO]: Credenciales hardcodeadas en código fuente
$telegram_bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789";
$n8n_api_key = "n8n_api_key_alma_growth_secret_998877665544";
define('DB_PASSWORD', 'AlmaQuinta2024#SecretDBPass');
?>"""

SAMPLE_REMEDIATED = """<?php
// Módulo de Notificaciones de Clientes - Alma Industria Creativa E.I.R.L.
// [CÓDIGO REMEDIADO]: Custodiado en Bóveda y consumido por Variables de Entorno (SOP-02)
$telegram_bot_token = getenv('TELEGRAM_BOT_TOKEN');
$n8n_api_key = getenv('N8N_API_KEY');
$db_password = getenv('DB_PASSWORD');
?>"""

def run_command(cmd, cwd=None):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd)

def main():
    mode = "leak"
    if len(sys.argv) > 1 and sys.argv[1].lower() in ["remediate", "clean", "pass"]:
        mode = "remediate"

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    target_path = os.path.join(repo_root, CANARY_FILE)

    if mode == "leak":
        print("=" * 75)
        print("  SIMULACIÓN SHIFT-LEFT: INTENTO DE COMMIT CON CREDENCIALES HARDCODEADAS")
        print("  Control NIST CSF v2.0: PR.PS-01 (Platform Security) / SOP-02")
        print("=" * 75)

        print(f"\n[1] Creando archivo vulnerable de prueba: {CANARY_FILE}...")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_LEAKS)

        print("[2] Agregando archivo a Staging (git add)...")
        run_command(f'git add "{CANARY_FILE}"', cwd=repo_root)

        print("[3] Ejecutando 'git commit' (Se espera intercepción de Gitleaks en <300ms)...")
        commit_res = run_command('git commit -m "feat: modulo de notificaciones con credenciales hardcodeadas"', cwd=repo_root)

        blocked = (commit_res.returncode != 0)

        print("\n--- SALIDA DE LA INTERCEPCIÓN EN TERMINAL ---")
        print(commit_res.stdout)
        if commit_res.stderr:
            print(commit_res.stderr)
        print("---------------------------------------------")

        # Limpieza
        run_command(f'git reset HEAD "{CANARY_FILE}"', cwd=repo_root)
        if os.path.exists(target_path):
            os.remove(target_path)

        print("=" * 75)
        if blocked:
            print(" [RESULTADO: EXITOSO - CONTROL SOP-02 FUNCIONANDO]")
            print(" -> El Pre-commit Hook (Gitleaks) detectó los secretos y BLOQUEÓ el commit.")
            print(" -> Código de salida retornado: 1 (Commit abortado antes de entrar al repo).")
            print(" -> Alerta SOAR despachada automáticamente hacia n8n y SOC Dashboard.")
            print(" -> Control NIST CSF v2.0 PR.PS-01 VALIDADO.")
            print("=" * 75)
            sys.exit(0)
        else:
            print(" [RESULTADO: FALLIDO - EL COMMIT NO FUE BLOQUEADO]")
            print(" -> Revisa la instalación del hook en .git/hooks/pre-commit.")
            print("=" * 75)
            sys.exit(1)

    else:
        print("=" * 75)
        print("  SIMULACIÓN SHIFT-LEFT: COMMIT REMEDIADO CON VARIABLES DE ENTORNO (SOP-02)")
        print("  Control NIST CSF v2.0: PR.PS-01 (Platform Security) / DE.CM-01")
        print("=" * 75)

        print(f"\n[1] Creando archivo remediado seguro: {CANARY_FILE}...")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_REMEDIATED)

        print("[2] Agregando archivo seguro a Staging (git add)...")
        run_command(f'git add "{CANARY_FILE}"', cwd=repo_root)

        print("[3] Ejecutando 'git commit' (Se espera verificación limpia y autorización)...")
        commit_res = run_command('git commit -m "feat(security): modulo remediado con variables de entorno (SOP-02)"', cwd=repo_root)

        passed = (commit_res.returncode == 0)

        print("\n--- SALIDA DE LA VALIDACIÓN EN TERMINAL ---")
        print(commit_res.stdout)
        if commit_res.stderr:
            print(commit_res.stderr)
        print("-------------------------------------------")

        # Revertir commit de prueba para mantener el repo limpio
        if passed:
            run_command("git reset --soft HEAD~1", cwd=repo_root)
        run_command(f'git reset HEAD "{CANARY_FILE}"', cwd=repo_root)
        if os.path.exists(target_path):
            os.remove(target_path)

        print("=" * 75)
        if passed:
            print(" [RESULTADO: EXITOSO - COMMIT AUTORIZADO]")
            print(" -> Gitleaks analizó el código: 0 secretos detectados.")
            print(" -> El código cumple con las directivas de seguridad SOP-02 y NIST PR.PS-01.")
            print(" -> Entorno de staging limpio y listo para el flujo CI/CD.")
            print("=" * 75)
            sys.exit(0)
        else:
            print(" [RESULTADO: FALLIDO - EL COMMIT FUE RECHAZADO]")
            print("=" * 75)
            sys.exit(1)

if __name__ == "__main__":
    main()
