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
from datetime import datetime
import urllib.request
import urllib.error

# URL por defecto del Webhook de n8n de Waldir (o variable de entorno)
DEFAULT_WEBHOOK_URL = "http://localhost:5678/webhook/security-incident-alert"

EVENT_PRESETS = {
    "1": {
        "event_type": "EXPOSICION_DE_SECRETOS_PRECOMMIT",
        "severity": "HIGH",
        "risk_score": 8.5,
        "source": "Shift-Left / Gitleaks Pre-commit Hook",
        "details": "Intento de confirmación bloqueado en Git conteniendo AWS Secret Key y Telegram Bot Token.",
        "affected_asset": "Repositorio: devsecops-alma-nist",
        "attacker_ip": "192.168.1.15",
        "suggested_action": "Rotar credenciales expuestas en la bóveda y notificar al líder técnico."
    },
    "2": {
        "event_type": "INTENTO_ENUMERACION_USUARIOS_REST_API",
        "severity": "MEDIUM",
        "risk_score": 6.8,
        "source": "Hardening Web (.htaccess / WAF)",
        "details": "Petición anónima interceptada y bloqueada en /wp-json/wp/v2/users.",
        "affected_asset": "CMS WordPress - Producción",
        "attacker_ip": "185.220.101.5",
        "suggested_action": "Verificar si la IP persiste en el log para baneo temporal en WAF."
    },
    "3": {
        "event_type": "ANOMALIA_RATE_LIMITING_OPENGRAPH",
        "severity": "LOW",
        "risk_score": 3.2,
        "source": "Servidor Web LiteSpeed / Nginx",
        "details": "Rastreador de redes sociales (facebookexternalhit) detectado en umbral alto pero exonerado.",
        "affected_asset": "Landing Page / Meta Tags",
        "attacker_ip": "31.13.127.1",
        "suggested_action": "Mantener en whitelist para evitar error HTTP 429."
    },
    "4": {
        "event_type": "INTENTO_FUERZA_BRUTA_WP_LOGIN",
        "severity": "CRITICAL",
        "risk_score": 9.2,
        "source": "WAF / Rate Limiter",
        "details": "Más de 50 intentos fallidos de login en wp-login.php en 60 segundos.",
        "affected_asset": "CMS WordPress - Administración",
        "attacker_ip": "45.145.67.89",
        "suggested_action": "Baneo de IP automático por 24 horas y alerta inmediata a Telegram."
    }
}

def send_alert(webhook_url, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={'Content-Type': 'application/json', 'User-Agent': 'Alma-Security-Dispatcher/1.0'}
    )
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            latency = (time.time() - start_time) * 1000
            status_code = response.getcode()
            response_body = response.read().decode('utf-8')
            return True, status_code, latency, response_body
    except urllib.error.URLError as e:
        latency = (time.time() - start_time) * 1000
        return False, getattr(e, 'code', 'ERROR'), latency, str(e)

def main():
    print("=" * 70)
    print("[*] EMISOR DE ALERTAS DE CIBERSEGURIDAD HACIA SOAR (n8n)")
    print("=" * 70)
    
    webhook_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_WEBHOOK_URL
    print(f"[+] Webhook Destino: {webhook_url}")
    print("\nSeleccione el tipo de incidente simulado:")
    for k, v in EVENT_PRESETS.items():
        print(f" [{k}] {v['event_type']} (Severidad: {v['severity']})")

    choice = input("\nIngrese opción [1-4] (por defecto: 1): ").strip()
    if choice not in EVENT_PRESETS:
        choice = "1"

    selected_event = EVENT_PRESETS[choice].copy()
    selected_event["timestamp"] = datetime.utcnow().isoformat() + "Z"
    selected_event["dispatcher"] = "Alma DevSecOps NIST Engine"

    print(f"\n[*] Despachando incidente [{selected_event['event_type']}]...")
    success, code, latency, body = send_alert(webhook_url, selected_event)

    print("\n--- RESULTADO DE LA COMUNICACIÓN CON n8n ---")
    print(f"Estado HTTP: {code}")
    print(f"Latencia:    {latency:.2f} ms")
    if success:
        print("[+] ALERTA RECIBIDA EXITOSAMENTE POR EL FLUJO n8n.")
        print(f"Respuesta:   {body}")
    else:
        print(f"[-] AVISO: No se pudo contactar al Webhook de n8n ({body}).")
        print("    (Asegúrate de que n8n esté ejecutándose y el Webhook activo).")
    print("--------------------------------------------\n")

if __name__ == "__main__":
    main()
