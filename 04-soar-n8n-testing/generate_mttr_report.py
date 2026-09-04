#!/usr/bin/env python3
"""
==============================================================================
Generador de Reporte Estadístico de MTTR Basado en Mediciones Empíricas Reales
Empresa: Alma Industria Creativa E.I.R.L.
Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
Autores: Sergio Incacutipa & Waldir Chullo
Control: SOP-04 (RS.AN-01 / RS.MI-01 / DE.AE-01)
==============================================================================
"""

import os
import sys

# Permitir importación del módulo metrics_logger
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from metrics_logger import get_metrics_summary, load_metrics, METRICS_FILE

def print_mttr_report():
    print("=" * 85)
    print("  REPORTE ESTADÍSTICO DE MTTR (DATOS EMPÍRICOS MEDIDOS EN TIEMPO REAL)")
    print("  Empresa: Alma Industria Creativa E.I.R.L. | SENATI Ciberseguridad")
    print("=" * 85)
    
    summary = get_metrics_summary()
    
    if summary.get("status") == "insufficient_data":
        print("\n[!] ESTADO: DATOS INSUFICIENTES")
        print(f" -> {summary.get('message')}")
        print(f" -> Ubicación esperada: {METRICS_FILE}")
        print("\nPara generar métricas reales, ejecuta una de las siguientes opciones:")
        print(" 1. Corre el Canary Test: python 01-shift-left/tests/test_canary_secrets.py")
        print(" 2. Ejecuta el disparador: python 04-soar-n8n-testing/trigger_alert.py [1-4]")
        print(" 3. Realiza auditorías web desde el Dashboard en http://127.0.0.1:5000\n")
        print("=" * 85)
        return

    samples = summary["total_samples"]
    successful = summary["successful_samples"]
    rate = summary["success_rate_pct"]
    lat = summary["latency_ms"]
    comp = summary["mttr_comparison_min"]
    
    manual_total = comp["manual_baseline_total"]
    auto_total = comp["automated_soar_total"]
    red_pct = summary["reduction_pct"]
    sla_ok = summary["sla_compliance_15min"]

    det_str = f"{comp['automated_breakdown']['detection']:.4f} min"
    tri_str = f"{comp['automated_breakdown']['triage']:.4f} min"
    not_str = f"{comp['automated_breakdown']['notification']:.4f} min"
    con_str = f"{comp['automated_breakdown']['containment']:.2f} min"
    man_tot_str = f"{manual_total:.2f} min"
    aut_tot_str = f"{auto_total:.2f} min"

    print(f"\n[+] Total de Eventos e Incidentes Reales Registrados: {samples}")
    print(f"[+] Eventos Entregados Exitosamente: {successful} ({rate}%)")
    print(f"[+] Latencia de Red Promedio (SOAR Webhook): {lat['mean']} ms (StdDev: +/-{lat['stdev']} ms)")
    print(f"[+] Latencia Mínima: {lat['min']} ms | Latencia Máxima: {lat['max']} ms\n")

    print("-" * 85)
    print(f"{'Fase del Incidente':<32} | {'Situación Actual (Manual)':<24} | {'Propuesta Mejorada (SOAR)':<22}")
    print("-" * 85)
    print(f"{'1. Detección de Amenaza':<32} | {'120.00 min':>24} | {det_str:>22}")
    print(f"{'2. Triage & Clasificación':<32} | {'45.00 min':>24} | {tri_str:>22}")
    print(f"{'3. Notificación al Equipo':<32} | {'30.00 min':>24} | {not_str:>22}")
    print(f"{'4. Contención & Aislamiento':<32} | {'60.00 min':>24} | {con_str:>22}")
    print("-" * 85)
    print(f"{'MTTR TOTAL ESTIMADO':<32} | {man_tot_str:>24} | {aut_tot_str:>22}")
    print("-" * 85)

    print(f"\n[EVALUACIÓN DE IMPACTO Y RESULTADOS REALES]:")
    print(f" -> Reducción porcentual de MTTR: {red_pct}")
    print(f" -> Meta SENATI (< 15 minutos):   {'CUMPLE (APROBADO)' if sla_ok else 'NO CUMPLE'}")
    print(f" -> Fuente de Datos:              Empírica ({METRICS_FILE})")
    print("=" * 85 + "\n")

if __name__ == "__main__":
    print_mttr_report()
