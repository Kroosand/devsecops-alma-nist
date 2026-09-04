#!/usr/bin/env python3
"""
==============================================================================
Benchmark Comparativo Ilustrativo de MTTR (Simulación de Rangos Esperados)
==============================================================================
NOTA METODOLÓGICA (SECCIÓN 4.4 TESIS SENATI):
Este script es un modelo de SIMULACIÓN ILUSTRATIVA basado en rangos teóricos
esperados (Monte Carlo con random.uniform) con fines comparativos y conceptuales.

Para consultar el reporte con mediciones EMPÍRICAS REALES registradas en el
repositorio y Webhooks de n8n, ejecute:
  python 04-soar-n8n-testing/generate_mttr_report.py
==============================================================================
Empresa: Alma Industria Creativa E.I.R.L.
Autores: Sergio Incacutipa & Waldir Chullo
Control: SOP-04 (RS.AN-01 / RS.MI-01)
==============================================================================
"""

import random
import statistics

def simulate_incidents(num_samples=30):
    print("=" * 80)
    print("  SIMULACIÓN ILUSTRATIVA DE MTTR: SITUACIÓN ACTUAL VS PROPUESTA MEJORADA")
    print("  [NOTA: Modelo de simulación de rangos teóricos - No datos empíricos]")
    print("=" * 80)

    # Situación Actual (Manual: Detección tardía, comunicación por chat plano, triage manual)
    # Tiempos en minutos: Detección (30-180m) + Triage (20-60m) + Contención (30-120m)
    current_mttr = []
    for _ in range(num_samples):
        detection = random.uniform(45.0, 180.0)
        triage = random.uniform(20.0, 60.0)
        containment = random.uniform(30.0, 90.0)
        total = detection + triage + containment
        current_mttr.append(total)

    # Situación Mejorada (DevSecOps + SOAR n8n + Webhooks + Pre-commit Shift-Left)
    # Tiempos en minutos: Detección (< 1 min) + Triage Automatizado (< 2 min) + Contención (< 10 min)
    improved_mttr = []
    for _ in range(num_samples):
        detection = random.uniform(0.1, 1.0)
        triage = random.uniform(0.5, 2.0)
        containment = random.uniform(3.0, 10.0)
        total = detection + triage + containment
        improved_mttr.append(total)

    avg_curr = statistics.mean(current_mttr)
    std_curr = statistics.stdev(current_mttr)
    avg_imp = statistics.mean(improved_mttr)
    std_imp = statistics.stdev(improved_mttr)

    reduction_pct = ((avg_curr - avg_imp) / avg_curr) * 100

    print(f"\n[+] Muestras evaluadas: {num_samples} incidentes simulados\n")
    print(f"{'Métrica':<35} | {'Situación Actual (Manual)':<22} | {'Situación Mejorada (SOAR/DevSecOps)':<25}")
    print("-" * 90)
    print(f"{'MTTR Promedio (Minutos)':<35} | {avg_curr:>20.2f} m | {avg_imp:>23.2f} m")
    print(f"{'Desviación Estándar':<35} | {std_curr:>20.2f} m | {std_imp:>23.2f} m")
    print(f"{'Tiempo Máximo Registrado':<35} | {max(current_mttr):>20.2f} m | {max(improved_mttr):>23.2f} m")
    print(f"{'Tiempo Mínimo Registrado':<35} | {min(current_mttr):>20.2f} m | {min(improved_mttr):>23.2f} m")
    print("-" * 90)
    print(f"\n[RESULTADO DE LA SIMULACIÓN ILUSTRATIVA]:")
    print(f" -> Reducción porcentual estimada: {reduction_pct:.2f}%")
    print(f" -> Cumplimiento de meta SENATI (< 15 minutos): {'CUMPLE (APROBADO)' if avg_imp < 15.0 else 'NO CUMPLE'}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    simulate_incidents()
