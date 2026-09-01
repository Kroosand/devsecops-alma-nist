#!/usr/bin/env python3
"""
==============================================================================
Script de Pentesting y Auditoría de Endpoints WordPress
Empresa: Alma Industria Creativa E.I.R.L.
Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
Control: SOP-03 (PR.IR-01 / PR.PT-01)
==============================================================================
"""

import sys
import urllib.request
import urllib.error
import ssl

DEFAULT_TARGET = "http://localhost:8088"

def make_request(url, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url,
        headers={'User-Agent': user_agent}
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
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
    url_rest = f"{base_url}/wp-json/wp/v2/users"
    code, headers, body = make_request(url_rest)
    
    if code in [401, 403, 404]:
        print(f" -> [PASS] HTTP {code}: Endpoint protegido contra enumeración pública.")
    elif code == 200:
        print(f" -> [FAIL] HTTP 200: VULNERABILIDAD - Endpoint expone datos de usuarios.")
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

    # 4. Prueba de Rastreo OpenGraph (Whitelist de Bots)
    print("\n[TEST 4] Simulación de Bot de Redes Sociales (facebookexternalhit)...")
    code_fb, _, _ = make_request(base_url, user_agent="facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)")
    if code_fb == 200:
        print(f" -> [PASS] HTTP {code_fb}: Bot OpenGraph recibido con éxito (Sin error HTTP 429).")
    elif code_fb == 429:
        print(f" -> [FAIL] HTTP 429: El bot fue bloqueado por Rate Limiting.")
    else:
        print(f" -> [INFO] HTTP {code_fb}: Estado recibido.")

    print("\n" + "=" * 75)
    print("[*] FIN DE AUDITORÍA TÉCNICA.")
    print("=" * 75 + "\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    audit_target(target)
