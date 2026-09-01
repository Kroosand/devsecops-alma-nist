#!/usr/bin/env python3
"""
==============================================================================
Disparador de Eventos e Incidentes hacia Webhook de n8n (SOAR)
Empresa: Alma Industria Creativa E.I.R.L.
Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
Autores: Sergio Incacutipa & Waldir Chullo
Control: SOP-04 (DE.AE-01 / RS.AN-01 / RS.MI-01)
==============================================================================
"""

import json
import sys
import time
import uuid
from datetime import datetime, timezone
import urllib.request
import urllib.error
import ssl

# URL oficial del Webhook de n8n de Waldir
DEFAULT_WEBHOOK_URL = "https://n8n.almaquinta.com/webhook/devsecops-alert"

EVENT_PRESETS = {
    "1": {
        "event_type": "EXPOSICION_DE_SECRETOS_PRECOMMIT",
        "severity": "CRITICAL",
        "risk_score": "9.5/10",
        "source": "Shift-Left / Gitleaks Pre-commit Hook",
        "details": "Intento de commit interceptado y bloqueado localmente. Se detectaron secretos hardcodeados en el archivo preparado.",
        "affected_asset": "Repositorio: Kroosand/devsecops-alma-nist (Rama: main)",
        "attacker_ip": "192.168.1.15",
        "user_involved": "s_incacutipa (DevSecOps Lead)",
        "nist_control": "PR.PS-01 (Platform Security) / DE.CM-01 (Continuous Monitoring)",
        "phva_phase": "Hacer (Do) a Verificar (Check)",
        "sop_reference": "SOP-02: Control Preventivo Shift-Left en Codigo",
        "file_endpoint": "config_test_leak.php",
        "suggested_action": "1. Verificar revocacion de credencial. 2. Custodiar en Vaultwarden. 3. Ejecutar git reset en estacion local."
    },
    "2": {
        "event_type": "INTENTO_ENUMERACION_USUARIOS_REST_API",
        "severity": "HIGH",
        "risk_score": "8.0/10",
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
        "event_type": "DETECCION_RASTREADOR_OPENGRAPH_WHITELISTED",
        "severity": "INFO",
        "risk_score": "2.1/10",
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
        "event_type": "INTENTO_FUERZA_BRUTA_WP_LOGIN",
        "severity": "CRITICAL",
        "risk_score": "9.8/10",
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

def send_alert(webhook_url, payload):
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
            return True, status_code, latency, response_body
    except urllib.error.HTTPError as e:
        latency = (time.time() - start_time) * 1000
        err_body = e.read().decode('utf-8', errors='ignore') if e.fp else str(e)
        return False, e.code, latency, err_body
    except urllib.error.URLError as e:
        latency = (time.time() - start_time) * 1000
        return False, 'NET_ERROR', latency, str(e.reason)
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        return False, 'ERROR', latency, str(e)

def main():
    print("=" * 80)
    print("  DEVSECOPS SOAR DISPATCHER: EMISION DE INCIDENTES HACIA n8n")
    print("  Empresa: Alma Industria Creativa E.I.R.L. | SENATI")
    print("=" * 80)

    target_url = DEFAULT_WEBHOOK_URL
    event_choice = "1"
    
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        target_url = sys.argv[1]
        if len(sys.argv) > 2 and sys.argv[2] in EVENT_PRESETS:
            event_choice = sys.argv[2]
    elif len(sys.argv) > 1 and sys.argv[1] in EVENT_PRESETS:
        event_choice = sys.argv[1]

    print(f"\n[+] URL de Webhook Configurada: {target_url}\n")
    print("Seleccione el evento de seguridad a simular:")
    for k, v in EVENT_PRESETS.items():
        print(f" [{k}] {v['event_type']} (Severidad: {v['severity']} | Riesgo: {v['risk_score']})")

    if len(sys.argv) == 1:
        try:
            user_input = input("\nIngrese opcion [1-4] (Presione Enter para opcion 1): ").strip()
            if user_input in EVENT_PRESETS:
                event_choice = user_input
        except EOFError:
            event_choice = "1"

    selected_event = EVENT_PRESETS[event_choice].copy()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    incident_id = f"ALMA-SEC-{uuid.uuid4().hex[:8].upper()}"

    # Construir payload 100% TEXTO PLANO (Sin etiquetas HTML ni caracteres < o >)
    payload = {
        # Metadatos del Proyecto
        "incident_id": incident_id,
        "id_incidente": incident_id,
        "company": "Alma Industria Creativa E.I.R.L.",
        "empresa": "Alma Industria Creativa E.I.R.L.",
        "project": "DevSecOps NIST CSF v2.0",
        "proyecto": "DevSecOps NIST CSF v2.0",
        "timestamp": now_utc,
        "fecha_hora": now_utc,
        
        # Severidad y Score
        "severity": selected_event["severity"],
        "severidad": selected_event["severity"],
        "risk_score": selected_event["risk_score"],
        "score": selected_event["risk_score"],
        "nivel": selected_event["severity"],
        
        # Tipo de Incidente
        "event_type": selected_event["event_type"],
        "incidente": selected_event["event_type"],
        "tipo_incidente": selected_event["event_type"],
        "tipo_evento": selected_event["event_type"],
        "evento": selected_event["event_type"],
        "nombre_incidente": selected_event["event_type"],
        "titulo": selected_event["event_type"],
        
        # Activo Afectado
        "affected_asset": selected_event["affected_asset"],
        "activo_afectado": selected_event["affected_asset"],
        "activo": selected_event["affected_asset"],
        "recurso": selected_event["affected_asset"],
        
        # Framework NIST
        "nist_control": selected_event["nist_control"],
        "framework_nist": selected_event["nist_control"],
        "control_nist": selected_event["nist_control"],
        "nist": selected_event["nist_control"],
        "control": selected_event["nist_control"],
        "norma_nist": selected_event["nist_control"],
        "phva_phase": selected_event["phva_phase"],
        "fase_phva": selected_event["phva_phase"],
        
        # Origen / Fuente
        "source": selected_event["source"],
        "origen": selected_event["source"],
        "fuente": selected_event["source"],
        "modulo": selected_event["source"],
        
        # Archivo / Endpoint
        "archivo_endpoint": selected_event["file_endpoint"],
        "archivo_o_endpoint": selected_event["file_endpoint"],
        "archivo": selected_event["file_endpoint"],
        "endpoint": selected_event["file_endpoint"],
        "ruta": selected_event["file_endpoint"],
        
        # Regla / SOP
        "regla": selected_event["sop_reference"],
        "regla_seguridad": selected_event["sop_reference"],
        "politica": selected_event["sop_reference"],
        "sop": selected_event["sop_reference"],
        "sop_reference": selected_event["sop_reference"],
        
        # Responsable / IP
        "responsable_ip": f"{selected_event['user_involved']} ({selected_event['attacker_ip']})",
        "usuario_ip": f"{selected_event['user_involved']} ({selected_event['attacker_ip']})",
        "responsable": selected_event["user_involved"],
        "usuario": selected_event["user_involved"],
        "ip": selected_event["attacker_ip"],
        "attacker_ip": selected_event["attacker_ip"],
        
        # Detalles Técnicos
        "details": selected_event["details"],
        "detalles": selected_event["details"],
        "detalles_tecnicos": selected_event["details"],
        "descripcion": selected_event["details"],
        
        # Acción Recomendada
        "suggested_action": selected_event["suggested_action"],
        "accion_recomendada": selected_event["suggested_action"],
        "accion": selected_event["suggested_action"],
        "recomendacion": selected_event["suggested_action"]
    }

    print(f"\n[*] Despachando incidente [{incident_id}]: {payload['event_type']}...")
    print(f"[*] Enviando payload JSON en TEXTO PLANO a: {target_url} ...")
    
    success, status_code, latency, response_body = send_alert(target_url, payload)

    print("\n" + "=" * 80)
    print("  RESULTADO DEL ENVIO AL WEBHOOK DE n8n")
    print("=" * 80)
    print(f" Codigo de Respuesta HTTP: {status_code}")
    print(f" Latencia de Red:          {latency:.2f} ms")
    
    if success:
        print(" Estado de Entrega:        [EXITOSO] - Webhook de n8n proceso el evento")
        print(f" Respuesta del Servidor:   {response_body if response_body else '(Sin cuerpo de retorno / 200 OK)'}")
        print("\n [!] Notificacion enviada con texto plano limpio. Verifica en Telegram.")
    else:
        print(" Estado de Entrega:        [ERROR DE COMUNICACION]")
        print(f" Detalle del Error:        {response_body}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
