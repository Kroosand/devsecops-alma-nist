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
        "risk_score": 9.5,
        "source": "Shift-Left / Gitleaks Pre-commit Hook",
        "details": "Intento de confirmación (commit) interceptado y bloqueado localmente. Se detectó una AWS Secret Key y un Telegram Bot Token en el archivo de configuración.",
        "affected_asset": "Repositorio: Kroosand/devsecops-alma-nist (Rama: main)",
        "attacker_ip": "192.168.1.15 (Estación de Desarrollo)",
        "user_involved": "s_incacutipa (DevSecOps Lead)",
        "nist_control": "PR.PS-01 (Platform Security) / DE.CM-01 (Continuous Monitoring)",
        "phva_phase": "Hacer (Do) -> Verificar (Check)",
        "sop_reference": "SOP-02: Control Preventivo Shift-Left en Código",
        "suggested_action": "1. Verificar revocación de credencial.\n2. Custodiar en Vaultwarden.\n3. Ejecutar git reset en estación local."
    },
    "2": {
        "event_type": "INTENTO_ENUMERACION_USUARIOS_REST_API",
        "severity": "HIGH",
        "risk_score": 8.0,
        "source": "Hardening Web (.htaccess / WAF)",
        "details": "Petición HTTP anónima interceptada y bloqueada con código 403 Forbidden en el endpoint sensible /wp-json/wp/v2/users.",
        "affected_asset": "CMS WordPress - Producción (almaindustriacreativa.com)",
        "attacker_ip": "185.220.101.5 (Nodo Tor / Scanner Externo)",
        "user_involved": "Anónimo / Crawler Malicioso",
        "nist_control": "PR.IR-01 (Infrastructure Protection) / DE.AE-01 (Anomaly Detection)",
        "phva_phase": "Hacer (Do) -> Detectar (Check)",
        "sop_reference": "SOP-03: Bastionado Web y Control de Dependencias",
        "suggested_action": "1. Mantener regla de bloqueo 403 activa.\n2. Evaluar baneo de subred en Cloudflare/WAF si la tasa supera 100 req/min."
    },
    "3": {
        "event_type": "DETECCION_RASTREADOR_OPENGRAPH_WHITELISTED",
        "severity": "INFO",
        "risk_score": 2.1,
        "source": "Servidor Web LiteSpeed / Nginx",
        "details": "Rastreador de redes sociales (facebookexternalhit/1.1) procesando metadatos OpenGraph. Tráfico admitido por Whitelist (Evitado error HTTP 429).",
        "affected_asset": "Landing Page / Campaña Growth Alma",
        "attacker_ip": "31.13.127.1 (Meta Platforms Inc.)",
        "user_involved": "Meta OpenGraph Crawler",
        "nist_control": "PR.PT-01 (Technology Protection) / RS.MI-01 (Incident Mitigation)",
        "phva_phase": "Hacer (Do) -> Verificar (Check)",
        "sop_reference": "SOP-03: Calibración de Rate Limiting y Whitelist OpenGraph",
        "suggested_action": "Mantener User-Agent en la lista blanca para garantizar previsualización de enlaces en redes sociales."
    },
    "4": {
        "event_type": "INTENTO_FUERZA_BRUTA_WP_LOGIN",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "source": "WAF Perimetral / Monitor de Autenticación",
        "details": "Más de 60 peticiones POST fallidas consecutivas contra wp-login.php en una ventana de 30 segundos.",
        "affected_asset": "Panel de Administración CMS (wp-login.php)",
        "attacker_ip": "45.145.67.89 (IP sospechosa / Botnet)",
        "user_involved": "admin / root / tester (Diccionario de Fuerza Bruta)",
        "nist_control": "PR.AA-01 (Identity Management) / RS.MI-01 (Incident Mitigation)",
        "phva_phase": "Detectar (Check) -> Responder (Act)",
        "sop_reference": "SOP-04: Triage Automatizado y Despacho de Incidentes con n8n",
        "suggested_action": "1. Baneo temporal de IP por 24 horas.\n2. Verificar doble factor de autenticación (2FA) en usuarios admin."
    }
}

def send_alert(webhook_url, payload):
    data = json.dumps(payload, indent=2).encode('utf-8')
    
    # Contexto SSL seguro pero tolerante
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

def format_telegram_message(event):
    """Genera una plantilla en formato Markdown compatible con el bot de Telegram."""
    emoji_map = {
        "CRITICAL": "🚨 <b>[ALERTA CRÍTICA]</b>",
        "HIGH": "⚠️ <b>[ALERTA ALTA]</b>",
        "MEDIUM": "🟡 <b>[ALERTA MEDIA]</b>",
        "LOW": "ℹ️ <b>[ALERTA BAJA]</b>",
        "INFO": "🟢 <b>[INFORMACIÓN]</b>"
    }
    header = emoji_map.get(event.get("severity"), "🔔 <b>[ALERTA DE SEGURIDAD]</b>")
    
    msg = (
        f"{header}\n"
        f"<b>Evento:</b> {event.get('event_type')}\n"
        f"<b>Severidad:</b> {event.get('severity')} | <b>Score CVSS:</b> {event.get('risk_score')}/10\n"
        f"<b>Origen:</b> {event.get('source')}\n"
        f"<b>Activo Afectado:</b> {event.get('affected_asset')}\n"
        f"<b>IP Detectada:</b> <code>{event.get('attacker_ip')}</code>\n"
        f"<b>Control NIST:</b> {event.get('nist_control')}\n"
        f"<b>Detalle:</b> {event.get('details')}\n\n"
        f"🛠️ <b>Acción Recomendada:</b>\n{event.get('suggested_action')}\n\n"
        f"⏱️ <i>Timestamp: {event.get('timestamp')} | ID: {event.get('incident_id')}</i>"
    )
    return msg

def main():
    print("=" * 80)
    print("  DEVSECOPS SOAR DISPATCHER: EMISIÓN DE INCIDENTES HACIA n8n")
    print("  Empresa: Alma Industria Creativa E.I.R.L. | SENATI")
    print("=" * 80)

    # Evaluar argumentos CLI
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

    # Si se ejecuta sin interacción o con argumento
    if len(sys.argv) == 1:
        try:
            user_input = input("\nIngrese opción [1-4] (Presione Enter para opción 1): ").strip()
            if user_input in EVENT_PRESETS:
                event_choice = user_input
        except EOFError:
            event_choice = "1"

    selected_event = EVENT_PRESETS[event_choice].copy()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    incident_id = f"ALMA-SEC-{uuid.uuid4().hex[:8].upper()}"

    # Construir payload enriquecido
    payload = {
        "incident_id": incident_id,
        "company": "Alma Industria Creativa E.I.R.L.",
        "project": "DevSecOps NIST CSF v2.0",
        "timestamp": now_utc,
        "event_type": selected_event["event_type"],
        "severity": selected_event["severity"],
        "risk_score": selected_event["risk_score"],
        "source": selected_event["source"],
        "affected_asset": selected_event["affected_asset"],
        "attacker_ip": selected_event["attacker_ip"],
        "user_involved": selected_event["user_involved"],
        "nist_control": selected_event["nist_control"],
        "phva_phase": selected_event["phva_phase"],
        "sop_reference": selected_event["sop_reference"],
        "details": selected_event["details"],
        "suggested_action": selected_event["suggested_action"],
        "telegram_formatted_text": format_telegram_message({**selected_event, "timestamp": now_utc, "incident_id": incident_id})
    }

    print(f"\n[*] Despachando incidente [{incident_id}]: {payload['event_type']}...")
    print(f"[*] Enviando payload JSON a: {target_url} ...")
    
    success, status_code, latency, response_body = send_alert(target_url, payload)

    print("\n" + "=" * 80)
    print("  RESULTADO DEL ENVÍO AL WEBHOOK DE n8n")
    print("=" * 80)
    print(f" Código de Respuesta HTTP: {status_code}")
    print(f" Latencia de Red:          {latency:.2f} ms")
    
    if success:
        print(" Estado de Entrega:        [EXITOSO] - Webhook de n8n proceso el evento")
        print(f" Respuesta del Servidor:   {response_body if response_body else '(Sin cuerpo de retorno / 200 OK)'}")
        print("\n [!] Verifica en el canal/bot de Telegram de Waldir para confirmar la alerta recibida.")
    else:
        print(" Estado de Entrega:        [ERROR DE COMUNICACION]")
        print(f" Detalle del Error:        {response_body}")
        print("\n [!] Posibles causas:")
        print("     1. El flujo de n8n no está en modo 'Active' o 'Listening for test event'.")
        print("     2. La ruta '/webhook/devsecops-alert' difiere del nodo Webhook configurado.")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
