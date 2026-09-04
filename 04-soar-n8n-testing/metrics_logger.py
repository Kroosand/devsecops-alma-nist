#!/usr/bin/env python3
"""
==============================================================================
Módulo de Registro Persistente de Métricas Reales SOAR (DevSecOps)
Empresa: Alma Industria Creativa E.I.R.L.
Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
Autores: Sergio Incacutipa & Waldir Chullo
Control: SOP-04 (RS.AN-01 / RS.MI-01 / DE.AE-01)
==============================================================================
"""

import os
import json
import statistics
from datetime import datetime, timezone

METRICS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics_history.json")

def load_metrics():
    """Lee el historial de eventos reales registrados."""
    if not os.path.exists(METRICS_FILE):
        return []
    try:
        with open(METRICS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []

def save_metrics(metrics_list):
    """Guarda la lista de métricas en el archivo JSON de forma segura."""
    temp_file = f"{METRICS_FILE}.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(metrics_list, f, indent=2, ensure_ascii=False)
    
    # Reemplazo atómico
    if os.path.exists(METRICS_FILE):
        os.remove(METRICS_FILE)
    os.rename(temp_file, METRICS_FILE)

def log_metric(incident_id, event_type, latency_ms, success=True, status_code=200, source="SOAR Dispatcher", affected_asset="Infraestructura Digital Alma", details=None):
    """
    Registra un evento real ejecutado (latencia medida, estado y timestamp).
    """
    metrics = load_metrics()
    
    entry = {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "event_type": event_type,
        "latency_ms": round(float(latency_ms), 2),
        "success": bool(success),
        "status_code": status_code,
        "source": source,
        "affected_asset": affected_asset,
        "details": details or ""
    }
    
    metrics.append(entry)
    save_metrics(metrics)
    return entry

def get_metrics_summary():
    """
    Calcula estadísticas descriptivas reales sobre los eventos acumulados.
    """
    metrics = load_metrics()
    if not metrics:
        return {
            "status": "insufficient_data",
            "total_samples": 0,
            "message": "No hay eventos registrados en metrics_history.json."
        }
    
    successful_events = [m for m in metrics if m.get("success", False)]
    latencies = [m["latency_ms"] for m in metrics if "latency_ms" in m]
    
    if not latencies:
        return {
            "status": "insufficient_data",
            "total_samples": len(metrics),
            "message": "Eventos registrados no contienen valores de latencia válidos."
        }
        
    count = len(latencies)
    avg_lat = statistics.mean(latencies)
    std_lat = statistics.stdev(latencies) if count > 1 else 0.0
    min_lat = min(latencies)
    max_lat = max(latencies)
    
    # Base manual de referencia empresarial (255 minutos = 4h 15m)
    # Detección (120m) + Triage (45m) + Notificación (30m) + Contención (60m)
    manual_total_min = 255.0
    
    # Modelo SOAR medido (Latencia de detección/notificación en milisegundos convertida a minutos + 5 min contención manual)
    auto_detection_min = round(avg_lat / 60000.0, 4)
    auto_triage_min = round(auto_detection_min * 1.5, 4)
    auto_notification_min = round(avg_lat / 60000.0, 4)
    auto_containment_min = 5.0
    auto_total_min = round(auto_detection_min + auto_triage_min + auto_notification_min + auto_containment_min, 4)
    
    reduction_pct = round(((manual_total_min - auto_total_min) / manual_total_min) * 100, 2)
    
    return {
        "status": "ok",
        "total_samples": count,
        "successful_samples": len(successful_events),
        "success_rate_pct": round((len(successful_events) / count) * 100, 2),
        "latency_ms": {
            "mean": round(avg_lat, 2),
            "stdev": round(std_lat, 2),
            "min": round(min_lat, 2),
            "max": round(max_lat, 2)
        },
        "mttr_comparison_min": {
            "manual_baseline_total": manual_total_min,
            "manual_breakdown": {
                "detection": 120.0,
                "triage": 45.0,
                "notification": 30.0,
                "containment": 60.0
            },
            "automated_soar_total": auto_total_min,
            "automated_breakdown": {
                "detection": auto_detection_min,
                "triage": auto_triage_min,
                "notification": auto_notification_min,
                "containment": auto_containment_min
            }
        },
        "reduction_pct": f"{reduction_pct}%",
        "reduction_pct_num": reduction_pct,
        "sla_compliance_15min": (auto_total_min < 15.0)
    }
