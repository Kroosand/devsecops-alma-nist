#!/usr/bin/env python3
"""
==============================================================================
Script de Pentesting y Auditoría de Endpoints WordPress
Empresa: Alma Industria Creativa E.I.R.L.
Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
Control: SOP-03 (PR.IR-01 / PR.PT-01 / DE.AE-01)
==============================================================================
"""

import sys
import os
import uuid
from datetime import datetime, timezone
import urllib.request
import urllib.error
import ssl

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
import trigger_alert

DEFAULT_TARGET = "https://radiosanmartin.pe"

def make_request(url, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url,
        headers={'User-Agent': user_agent}
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=6) as response:
            return response.getcode(), response.headers, response.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return None, {}, str(e)

def audit_target(base_url):
    print("=" * 75)
    print(f"[*] AUDITANDO BASTIONADO EN OBJETIVO: {base_url}")
    print("=" * 75)

    # 1. Prueba de Endpoint REST API (/wp-json/wp/v2/users)
    print("\n[TEST 1] Enumeración de usuarios anónima vía REST API (/wp-json/wp/v2/users)...")
    url_rest = f"{base_url.rstrip('/')}/wp-json/wp/v2/users"
    code, headers, body = make_request(url_rest)
    
    if code in [401, 403, 404]:
        print(f" -> [PASS] HTTP {code}: Endpoint protegido contra enumeración pública.")
    elif code == 200:
        print(f" -> [FAIL] HTTP 200: VULNERABILIDAD - Endpoint expone datos de usuarios.")
        # Mostrar resumen de usuarios filtrados si existen
        if "slug" in body or "name" in body:
            print(" -> [!] ALERTA CRÍTICA: Se expusieron nombres de cuentas en formato JSON.")
        
        # Disparo automático hacia SOAR n8n
        print("\n [!] Sensor de Pentesting: Disparando alerta automática hacia SOAR n8n...")
        try:
            local_ip = trigger_alert.get_local_ip()
            incident_id = f"ALMA-SEC-{uuid.uuid4().hex[:8].upper()}"
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            payload = {
                "incident_id": incident_id,
                "id_incidente": incident_id,
                "event_type": "Intento de Enumeracion de Usuarios REST API",
                "tipo_evento": "Intento de Enumeracion de Usuarios REST API",
                "severity": "HIGH",
                "severidad": "HIGH",
                "risk_score": 8.0,
                "source": "Pentesting Engine / Waldir Red Team",
                "origen": "Pentesting Engine / Waldir Red Team",
                "affected_asset": base_url,
                "activo_afectado": base_url,
                "file_endpoint": url_rest,
                "attacker_ip": local_ip,
                "ip": local_ip,
                "responsable_ip": f"Waldir Chullo / Estación Atacante ({local_ip})",
                "nist_control": "PR.IR-01 / DE.AE-01",
                "control_nist": "PR.IR-01 / DE.AE-01",
                "sop_reference": "SOP-03: Bastionado Web y Control de Dependencias",
                "details": f"Se audito el objetivo {base_url} y se detecto el endpoint sensible /wp-json/wp/v2/users expuesto publicamente (HTTP 200) permitiendo enumeracion de administradores.",
                "detalles": f"Se audito el objetivo {base_url} y se detecto el endpoint sensible /wp-json/wp/v2/users expuesto publicamente (HTTP 200) permitiendo enumeracion de administradores.",
                "suggested_action": f"Bloquear IP {local_ip} en .htaccess y restringir el endpoint sensible.",
                "accion_recomendada": f"Bloquear IP {local_ip} en .htaccess y restringir el endpoint sensible."
            }
            
            ok, status, lat, resp_body = trigger_alert.send_alert(trigger_alert.DEFAULT_WEBHOOK_URL, payload)
            if ok:
                print(f" [+] Alerta enviada con éxito al SOAR (HTTP {status} - Latencia: {lat:.1f}ms).")
                print(" [!] Revisa Telegram: La IA está analizando el hallazgo en vivo.")
            else:
                print(f" [!] Error en respuesta del SOAR: {status} - {resp_body}")
        except Exception as e:
            print(f" [!] Error despachando alerta: {e}")
    else:
        print(f" -> [INFO] Respuesta HTTP {code} recibida.")

    # 2. Prueba de Enumeración por Query String (/?author=1)
    print("\n[TEST 2] Enumeración de usuario administrador vía Query String (/?author=1)...")
    url_author = f"{base_url}/?author=1"
    code, headers, body = make_request(url_author)
    if code in [403, 404]:
        print(f" -> [PASS] HTTP {code}: Redirección de autor bloqueada.")
    else:
        print(f" -> [INFO] HTTP {code}: Verificar si hubo redirección a /author/username/.")

    # 3. Verificación de Security Headers
    print("\n[TEST 3] Verificación de Cabeceras HTTP de Seguridad (Security Headers)...")
    code, headers, body = make_request(base_url)
    expected_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Content-Security-Policy"
    ]
    for h in expected_headers:
        val = headers.get(h)
        if val:
            print(f" -> [OK] {h}: {val[:50]}...")
        else:
            print(f" -> [MISSING] Cabecera '{h}' no presente en la respuesta.")

    print("\n" + "=" * 75)
    print("[*] FIN DE AUDITORÍA TÉCNICA.")
    print("=" * 75 + "\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    audit_target(target)
