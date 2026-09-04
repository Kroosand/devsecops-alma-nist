#!/usr/bin/env python3
"""
==============================================================================
Centro de Control y Dashboard DevSecOps SOAR - Alma Industria Creativa E.I.R.L.
Proyecto de Titulación SENATI: Framework NIST CSF v2.0 & Ciclo PHVA
Autores: Sergio Saul Incacutipa Mamani & Waldir Rivaldo Chullo Chuma
==============================================================================
"""

import os
import sys
import json
import time
import uuid
import subprocess
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify

# Rutas del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

SOAR_DIR = os.path.join(PROJECT_ROOT, "04-soar-n8n-testing")
if SOAR_DIR not in sys.path:
    sys.path.insert(0, SOAR_DIR)
import metrics_logger

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))

DEFAULT_WEBHOOK_URL = "https://n8n.almaquinta.com/webhook/devsecops-alert"

# Memoria de incidentes en sesión
INCIDENT_HISTORY = []

EVENT_PRESETS = {
    "1": {
        "event_type": "Exposicion de Secretos en Pre-Commit",
        "severity": "CRITICAL",
        "risk_score": "9.5",
        "source": "Shift-Left / Gitleaks Pre-commit Hook",
        "details": "Intento de commit interceptado y bloqueado localmente. Se detectaron secretos hardcodeados en el archivo preparado.",
        "affected_asset": "Repositorio: Kroosand/devsecops-alma-nist (Rama: main)",
        "attacker_ip": "192.168.1.15",
        "user_involved": "Sergio Incacutipa (DevSecOps Lead)",
        "nist_control": "PR.PS-01 (Platform Security) / DE.CM-01 (Continuous Monitoring)",
        "phva_phase": "Hacer (Do) a Verificar (Check)",
        "sop_reference": "SOP-02: Control Preventivo Shift-Left en Codigo",
        "file_endpoint": "config_test_leak.php",
        "suggested_action": "1. Verificar revocacion de credencial. 2. Custodiar en Vaultwarden. 3. Ejecutar git reset en estacion local."
    },
    "2": {
        "event_type": "Intento de Enumeracion de Usuarios REST API",
        "severity": "HIGH",
        "risk_score": "8.0",
        "source": "Hardening Web (.htaccess / WAF)",
        "details": "Peticion HTTP anonima interceptada y bloqueada con codigo 403 Forbidden en el endpoint sensible de usuarios.",
        "affected_asset": "CMS WordPress - Produccion (almaindustriacreativa.com)",
        "attacker_ip": "185.220.101.5",
        "user_involved": "Anonimo / Scanner Externo",
        "nist_control": "PR.IR-01 (Infrastructure Protection) / DE.AE-01 (Anomaly Detection)",
        "phva_phase": "Hacer (Do) a Detectar (Check)",
        "sop_reference": "SOP-03: Bastionado Web y Control de Dependencias",
        "file_endpoint": "/wp-json/wp/v2/users",
        "suggested_action": "1. Mantener regla de bloqueo 403 activa. 2. Evaluar baneo de subred en WAF si la tasa supera 100 req/min."
    },
    "3": {
        "event_type": "Rastreador OpenGraph en Whitelist",
        "severity": "INFO",
        "risk_score": "2.1",
        "source": "Servidor Web LiteSpeed / Nginx",
        "details": "Rastreador de redes sociales procesando metadatos OpenGraph. Trafico admitido por Whitelist (Evitado error HTTP 429).",
        "affected_asset": "Landing Page / Campana Growth Alma",
        "attacker_ip": "31.13.127.1 (Meta Platforms Inc.)",
        "user_involved": "Meta OpenGraph Crawler",
        "nist_control": "PR.PT-01 (Technology Protection) / RS.MI-01 (Incident Mitigation)",
        "phva_phase": "Hacer (Do) a Verificar (Check)",
        "sop_reference": "SOP-03: Calibracion de Rate Limiting y Whitelist OpenGraph",
        "file_endpoint": "https://almaindustriacreativa.com/",
        "suggested_action": "Mantener User-Agent en la lista blanca para garantizar previsualizacion de enlaces en redes sociales."
    },
    "4": {
        "event_type": "Intento de Fuerza Bruta en Login CMS",
        "severity": "CRITICAL",
        "risk_score": "9.8",
        "source": "WAF Perimetral / Monitor de Autenticacion",
        "details": "Mas de 60 peticiones POST fallidas consecutivas contra wp-login.php en una ventana de 30 segundos.",
        "affected_asset": "Panel de Administracion CMS (wp-login.php)",
        "attacker_ip": "45.145.67.89",
        "user_involved": "admin / root (Diccionario de Fuerza Bruta)",
        "nist_control": "PR.AA-01 (Identity Management) / RS.MI-01 (Incident Mitigation)",
        "phva_phase": "Detectar (Check) a Responder (Act)",
        "sop_reference": "SOP-04: Triage Automatizado y Despacho de Incidentes con n8n",
        "file_endpoint": "/wp-login.php",
        "suggested_action": "1. Baneo temporal de IP por 24 horas. 2. Verificar doble factor de autenticacion (2FA) en usuarios admin."
    }
}

def dispatch_to_n8n(webhook_url, payload):
    data = json.dumps(payload, indent=2).encode('utf-8')
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Alma-DevSecOps-Engine/2.0 (SENATI Thesis)',
            'X-Incident-Source': 'DevSecOps-NIST-SOAR'
        }
    )
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            latency = (time.time() - start_time) * 1000
            status_code = response.getcode()
            response_body = response.read().decode('utf-8', errors='ignore')
            try:
                metrics_logger.log_metric(
                    incident_id=payload.get("incident_id", "ALMA-SEC-UNKNOWN"),
                    event_type=payload.get("event_type", "Incidente Desconocido"),
                    latency_ms=latency,
                    success=True,
                    status_code=status_code,
                    source=payload.get("source", "Dashboard Dispatcher"),
                    affected_asset=payload.get("affected_asset", "Infraestructura Alma"),
                    details=payload.get("details", "")
                )
            except Exception:
                pass
            return True, status_code, latency, response_body
    except urllib.error.HTTPError as e:
        latency = (time.time() - start_time) * 1000
        err_body = e.read().decode('utf-8', errors='ignore') if e.fp else str(e)
        try:
            metrics_logger.log_metric(
                incident_id=payload.get("incident_id", "ALMA-SEC-UNKNOWN"),
                event_type=payload.get("event_type", "Incidente Desconocido"),
                latency_ms=latency,
                success=False,
                status_code=e.code,
                source=payload.get("source", "Dashboard Dispatcher"),
                affected_asset=payload.get("affected_asset", "Infraestructura Alma"),
                details=err_body
            )
        except Exception:
            pass
        return False, e.code, latency, err_body
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        try:
            metrics_logger.log_metric(
                incident_id=payload.get("incident_id", "ALMA-SEC-UNKNOWN"),
                event_type=payload.get("event_type", "Incidente Desconocido"),
                latency_ms=latency,
                success=False,
                status_code=500,
                source=payload.get("source", "Dashboard Dispatcher"),
                affected_asset=payload.get("affected_asset", "Infraestructura Alma"),
                details=str(e)
            )
        except Exception:
            pass
        return False, 500, latency, str(e)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status", methods=["GET"])
def get_status():
    summary = metrics_logger.get_metrics_summary()
    total_logged = summary.get("total_samples", len(INCIDENT_HISTORY))
    mttr_red = summary.get("reduction_pct", "98.02%") if summary.get("status") == "ok" else "Sin datos"
    return jsonify({
        "system": "DevSecOps NIST CSF v2.0 SOC Center",
        "company": "Alma Industria Creativa E.I.R.L.",
        "status": "OPERATIONAL",
        "nist_rating": "Tier 3 (Repeatable & Automated)",
        "active_controls": 6,
        "gitleaks_version": "8.30.1",
        "webhook_target": DEFAULT_WEBHOOK_URL,
        "total_incidents_logged": total_logged,
        "mttr_reduction_pct": mttr_red
    })

@app.route("/api/trigger-alert", methods=["POST"])
def trigger_alert_api():
    data = request.json or {}
    preset_id = str(data.get("preset_id", "1"))
    webhook_url = data.get("webhook_url", DEFAULT_WEBHOOK_URL)
    
    if preset_id in EVENT_PRESETS:
        event = EVENT_PRESETS[preset_id].copy()
    else:
        event = {
            "event_type": data.get("event_type", "INCIDENTE_PERSONALIZADO"),
            "severity": data.get("severity", "MEDIUM"),
            "risk_score": str(data.get("risk_score", "5.0")),
            "source": data.get("source", "Dashboard Manual Dispatcher"),
            "details": data.get("details", "Alerta de prueba manual disparada desde el Dashboard."),
            "affected_asset": data.get("affected_asset", "Infraestructura Digital Alma"),
            "attacker_ip": data.get("attacker_ip", "192.168.1.100"),
            "user_involved": data.get("user_involved", "Operador SOC"),
            "nist_control": "DE.AE-01 (Anomaly Detection)",
            "phva_phase": "Detectar (Check) a Responder (Act)",
            "sop_reference": "SOP-04: Triage Automatizado",
            "file_endpoint": "/custom-endpoint",
            "suggested_action": "Revisar logs del sistema y verificar origen de la peticion."
        }

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    incident_id = f"ALMA-SEC-{uuid.uuid4().hex[:8].upper()}"

    payload = {
        "incident_id": incident_id,
        "id_incidente": incident_id,
        "company": "Alma Industria Creativa E.I.R.L.",
        "empresa": "Alma Industria Creativa E.I.R.L.",
        "project": "DevSecOps NIST CSF v2.0",
        "proyecto": "DevSecOps NIST CSF v2.0",
        "timestamp": now_utc,
        "fecha_hora": now_utc,
        "severity": event["severity"],
        "severidad": event["severity"],
        "risk_score": event["risk_score"],
        "score": event["risk_score"],
        "nivel": event["severity"],
        "event_type": event["event_type"],
        "incidente": event["event_type"],
        "tipo_incidente": event["event_type"],
        "tipo_evento": event["event_type"],
        "evento": event["event_type"],
        "nombre_incidente": event["event_type"],
        "titulo": event["event_type"],
        "affected_asset": event["affected_asset"],
        "activo_afectado": event["affected_asset"],
        "activo": event["affected_asset"],
        "nist_control": event["nist_control"],
        "framework_nist": event["nist_control"],
        "control_nist": event["nist_control"],
        "source": event["source"],
        "origen": event["source"],
        "fuente": event["source"],
        "archivo_endpoint": event["file_endpoint"],
        "archivo": event["file_endpoint"],
        "endpoint": event["file_endpoint"],
        "regla": event["sop_reference"],
        "responsable_ip": f"{event['user_involved']} ({event['attacker_ip']})",
        "responsable": event["user_involved"],
        "usuario": event["user_involved"],
        "ip": event["attacker_ip"],
        "details": event["details"],
        "detalles": event["details"],
        "detalles_tecnicos": event["details"],
        "suggested_action": event["suggested_action"],
        "accion_recomendada": event["suggested_action"],
        "accion": event["suggested_action"]
    }

    success, status_code, latency, response_body = dispatch_to_n8n(webhook_url, payload)

    history_entry = {
        "incident_id": incident_id,
        "timestamp": now_utc,
        "event_type": event["event_type"],
        "severity": event["severity"],
        "status_code": status_code,
        "latency_ms": round(latency, 2),
        "success": success,
        "response_body": response_body
    }
    INCIDENT_HISTORY.insert(0, history_entry)

    return jsonify({
        "success": success,
        "status_code": status_code,
        "latency_ms": round(latency, 2),
        "incident_id": incident_id,
        "payload": payload,
        "response_body": response_body
    })

@app.route("/api/run-canary-test", methods=["POST"])
def run_canary_test():
    test_script = os.path.join(PROJECT_ROOT, "01-shift-left", "tests", "test_canary_secrets.py")
    res = subprocess.run([sys.executable, test_script], cwd=PROJECT_ROOT, capture_output=True, text=True)
    return jsonify({
        "return_code": res.returncode,
        "blocked": (res.returncode == 0 or "BLOQUEO" in res.stdout or "leaks found" in res.stdout),
        "stdout": res.stdout,
        "stderr": res.stderr
    })

@app.route("/api/audit-url", methods=["POST"])
def audit_url():
    data = request.json or {}
    target_url = data.get("target_url", "https://almaindustriacreativa.com")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    results = {}
    
    # 1. Test Endpoint REST Users
    rest_url = f"{target_url.rstrip('/')}/wp-json/wp/v2/users"
    try:
        req = urllib.request.Request(rest_url, headers={'User-Agent': 'Alma-Security-Auditor/1.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            results["rest_users_code"] = resp.getcode()
            results["rest_users_protected"] = False
    except urllib.error.HTTPError as e:
        results["rest_users_code"] = e.code
        results["rest_users_protected"] = (e.code in [401, 403, 404])
    except Exception as e:
        results["rest_users_code"] = "ERROR"
        results["rest_users_protected"] = True
        results["rest_users_err"] = str(e)

    # 2. Test Security Headers
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            headers = dict(resp.headers)
            results["headers"] = {
                "X-Frame-Options": headers.get("X-Frame-Options", "FALTANTE"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "FALTANTE"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "FALTANTE"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "FALTANTE"),
                "Referrer-Policy": headers.get("Referrer-Policy", "FALTANTE")
            }
    except Exception as e:
        results["headers"] = {"error": str(e)}

    # 3. Test OpenGraph Whitelist (facebookexternalhit)
    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'})
        with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
            results["opengraph_code"] = resp.getcode()
            results["opengraph_ok"] = (resp.getcode() == 200)
    except urllib.error.HTTPError as e:
        results["opengraph_code"] = e.code
        results["opengraph_ok"] = (e.code == 200)
    except Exception as e:
        results["opengraph_code"] = "ERROR"
        results["opengraph_ok"] = False

    # 4. Si se detecta vulnerabilidad (HTTP 200 en endpoint sensible), disparar alerta SOAR automáticamente
    alert_dispatched = False
    incident_id = None
    if not results.get("rest_users_protected", True):
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        incident_id = f"ALMA-SEC-{uuid.uuid4().hex[:8].upper()}"
        
        payload = {
            "incident_id": incident_id,
            "id_incidente": incident_id,
            "company": "Alma Industria Creativa E.I.R.L.",
            "empresa": "Alma Industria Creativa E.I.R.L.",
            "project": "DevSecOps NIST CSF v2.0",
            "proyecto": "DevSecOps NIST CSF v2.0",
            "timestamp": now_utc,
            "fecha_hora": now_utc,
            "severity": "HIGH",
            "severidad": "HIGH",
            "risk_score": "8.5",
            "score": "8.5",
            "nivel": "HIGH",
            "event_type": "Vulnerabilidad en Auditoria Web",
            "incidente": "Vulnerabilidad en Auditoria Web",
            "tipo_incidente": "Vulnerabilidad en Auditoria Web",
            "tipo_evento": "Vulnerabilidad en Auditoria Web",
            "evento": "Vulnerabilidad en Auditoria Web",
            "nombre_incidente": "Vulnerabilidad en Auditoria Web",
            "titulo": "Vulnerabilidad en Auditoria Web",
            "affected_asset": target_url,
            "activo_afectado": target_url,
            "activo": target_url,
            "recurso": target_url,
            "nist_control": "PR.IR-01 (Infrastructure Protection) / DE.AE-01 (Anomaly Detection)",
            "framework_nist": "PR.IR-01 (Infrastructure Protection) / DE.AE-01 (Anomaly Detection)",
            "control_nist": "PR.IR-01 (Infrastructure Protection)",
            "source": "Auditor Perimetral Web / Pentesting Engine",
            "origen": "Auditor Perimetral Web / Pentesting Engine",
            "fuente": "Auditor Perimetral Web / Pentesting Engine",
            "archivo_endpoint": f"{target_url.rstrip('/')}/wp-json/wp/v2/users",
            "archivo_o_endpoint": f"{target_url.rstrip('/')}/wp-json/wp/v2/users",
            "archivo": "/wp-json/wp/v2/users",
            "endpoint": "/wp-json/wp/v2/users",
            "ruta": "/wp-json/wp/v2/users",
            "regla": "SOP-03: Bastionado Web y Control de Dependencias",
            "regla_seguridad": "SOP-03: Bastionado Web y Control de Dependencias",
            "sop": "SOP-03: Bastionado Web y Control de Dependencias",
            "sop_reference": "SOP-03: Bastionado Web y Control de Dependencias",
            "responsable_ip": "Escaneo de Diagnostico (Auditor Web)",
            "usuario_ip": "Escaneo de Diagnostico (Auditor Web)",
            "responsable": "Sergio Incacutipa (DevSecOps Lead)",
            "usuario": "Sergio Incacutipa",
            "ip": "Auditoria Remota",
            "attacker_ip": "Auditoria Remota",
            "details": f"Se audito el objetivo {target_url} y se detecto el endpoint sensible /wp-json/wp/v2/users expuesto publicamente (HTTP 200) permitiendo enumeracion de administradores.",
            "detalles": f"Se audito el objetivo {target_url} y se detecto el endpoint sensible /wp-json/wp/v2/users expuesto publicamente (HTTP 200) permitiendo enumeracion de administradores.",
            "detalles_tecnicos": f"Se audito el objetivo {target_url} y se detecto el endpoint sensible /wp-json/wp/v2/users expuesto publicamente (HTTP 200).",
            "suggested_action": "1. Inyectar directivas de bastionado .htaccess en el servidor. 2. Instalar wp-hardening-plugin.php para restringir la REST API.",
            "accion_recomendada": "1. Inyectar directivas de bastionado .htaccess en el servidor. 2. Instalar wp-hardening-plugin.php para restringir la REST API.",
            "accion": "1. Inyectar directivas de bastionado .htaccess en el servidor. 2. Instalar wp-hardening-plugin.php para restringir la REST API."
        }
        
        ok, code, lat, resp_b = dispatch_to_n8n(DEFAULT_WEBHOOK_URL, payload)
        alert_dispatched = ok
        
        INCIDENT_HISTORY.insert(0, {
            "incident_id": incident_id,
            "timestamp": now_utc,
            "event_type": "Vulnerabilidad en Auditoria Web",
            "severity": "HIGH",
            "status_code": code,
            "latency_ms": round(lat, 2),
            "success": ok,
            "response_body": resp_b
        })

    return jsonify({
        "target_url": target_url,
        "results": results,
        "alert_dispatched": alert_dispatched,
        "incident_id": incident_id
    })

@app.route("/api/incident-history", methods=["GET"])
def get_incident_history():
    return jsonify(INCIDENT_HISTORY[:25])

@app.route("/api/benchmark-data", methods=["GET"])
def get_benchmark_data():
    summary = metrics_logger.get_metrics_summary()
    if summary.get("status") == "insufficient_data":
        return jsonify({
            "status": "insufficient_data",
            "total_samples": summary.get("total_samples", 0),
            "message": summary.get("message", "Datos insuficientes: ejecuta alertas reales o auditorías para registrar mediciones empíricas.")
        })
    
    comp = summary["mttr_comparison_min"]
    return jsonify({
        "status": "ok",
        "categories": ["Detección Inicial", "Triage y Análisis", "Notificación al Equipo", "Contención y Cierre", "MTTR Total"],
        "manual_times_min": [
            comp["manual_breakdown"]["detection"],
            comp["manual_breakdown"]["triage"],
            comp["manual_breakdown"]["notification"],
            comp["manual_breakdown"]["containment"],
            comp["manual_baseline_total"]
        ],
        "automated_times_min": [
            comp["automated_breakdown"]["detection"],
            comp["automated_breakdown"]["triage"],
            comp["automated_breakdown"]["notification"],
            comp["automated_breakdown"]["containment"],
            comp["automated_soar_total"]
        ],
        "reduction_pct": summary["reduction_pct"],
        "total_samples": summary["total_samples"],
        "latency_ms": summary["latency_ms"],
        "sla_compliance_15min": summary["sla_compliance_15min"]
    })

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print(" [*] INICIANDO DASHBOARD DEVSECOPS - ALMA INDUSTRIA CREATIVA E.I.R.L.")
    print(" [+] URL Local: http://127.0.0.1:5000")
    print("=" * 70 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
