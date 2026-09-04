#!/usr/bin/env python3
"""
==============================================================================
Módulo de Triage Inteligente Asistido por IA (SOP-07)
Empresa: Alma Industria Creativa E.I.R.L.
Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
Autores: Sergio Incacutipa & Waldir Chullo
Control: SOP-07 / NIST CSF v2.0: RS.AN-01 (Incident Analysis)
==============================================================================
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
import ssl

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-6"

def get_api_key():
    """
    Obtiene la API key de Anthropic desde variables de entorno o archivos .env locales.
    """
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if key:
        return key
    
    # Buscar en archivos .env locales si no está en os.environ
    search_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "03-secrets-management", ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    ]
    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ANTHROPIC_API_KEY=") and not line.startswith("#"):
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val and val != "CHANGE_ME":
                                return val
            except Exception:
                pass
    return ""

def sanitize_plain_text(text):
    """
    Limpia etiquetas HTML y caracteres problemáticos para Telegram (<, >).
    """
    if not text:
        return ""
    cleaned = str(text).replace("<", "[").replace(">", "]")
    return cleaned.strip()

def analyze_incident_with_ai(incident_payload, timeout_sec=5.0):
    """
    Envía el payload del incidente a Claude (Anthropic API) para generar:
    1. Severidad reevaluada
    2. Resumen en lenguaje natural (español, 2-3 frases)
    3. Remediación específica accionable
    
    Retorna (success: bool, result_dict: dict)
    """
    api_key = get_api_key()
    if not api_key:
        return False, {
            "error": "ANTHROPIC_API_KEY no configurada",
            "fallback": True
        }

    system_prompt = (
        "Eres un analista experto de SOC y DevSecOps (NIST CSF v2.0) para la empresa "
        "Alma Industria Creativa E.I.R.L. Tu tarea es realizar un triage técnico rápido sobre "
        "el incidente reportado. Debes responder EXCLUSIVAMENTE un objeto JSON válido sin texto "
        "introductorio, sin comentarios y sin formato de bloques de código markdown. El JSON debe contener:\n"
        "{\n"
        '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '  "ai_summary": "Resumen conciso en español de 2 a 3 frases explicando qué ocurrió, causa raíz e impacto.",\n'
        '  "suggested_action": "Acciones de remediación técnica específicas y accionables numeradas (1. ..., 2. ...) en texto plano puro sin etiquetas HTML"\n'
        "}"
    )

    incident_context = {
        "event_type": incident_payload.get("event_type", "Incidente Desconocido"),
        "initial_severity": incident_payload.get("severity", "HIGH"),
        "risk_score": incident_payload.get("risk_score", "7.0"),
        "affected_asset": incident_payload.get("affected_asset", "Infraestructura Alma"),
        "source": incident_payload.get("source", "Monitor Perimetral"),
        "details": incident_payload.get("details", ""),
        "file_endpoint": incident_payload.get("archivo_endpoint", incident_payload.get("file_endpoint", "N/A")),
        "nist_control": incident_payload.get("nist_control", "RS.AN-01")
    }

    req_body = {
        "model": DEFAULT_MODEL,
        "max_tokens": 450,
        "temperature": 0.2,
        "system": system_prompt,
        "messages": [
            {
                "role": "user",
                "content": f"Realiza el triage del siguiente incidente de ciberseguridad:\n{json.dumps(incident_context, ensure_ascii=False)}"
            }
        ]
    }

    data = json.dumps(req_body).encode("utf-8")
    ctx = ssl.create_default_context()
    
    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=data,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "User-Agent": "Alma-DevSecOps-AI-Triage/1.0 (SENATI Thesis)"
        }
    )

    start_t = time.time()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout_sec) as resp:
            latency_ms = (time.time() - start_t) * 1000
            resp_bytes = resp.read()
            resp_json = json.loads(resp_bytes.decode("utf-8"))
            
            # Extraer contenido de la respuesta de Claude
            content_blocks = resp_json.get("content", [])
            text_response = ""
            for block in content_blocks:
                if block.get("type") == "text":
                    text_response += block.get("text", "")
            
            text_response = text_response.strip()
            # Limpiar posibles bloques markdown ```json ... ``` si el modelo los incluyera
            if text_response.startswith("```"):
                lines = text_response.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                text_response = "\n".join(lines).strip()
            
            parsed = json.loads(text_response)
            
            severity = parsed.get("severity", incident_payload.get("severity", "HIGH")).upper()
            ai_summary = sanitize_plain_text(parsed.get("ai_summary", ""))
            suggested_action = sanitize_plain_text(parsed.get("suggested_action", incident_payload.get("suggested_action", "")))

            return True, {
                "severity": severity,
                "ai_summary": ai_summary,
                "suggested_action": suggested_action,
                "latency_ms": round(latency_ms, 2),
                "model": DEFAULT_MODEL,
                "triage_source": f"Triage IA Asistido (Anthropic {DEFAULT_MODEL})"
            }

    except Exception as e:
        return False, {
            "error": str(e),
            "fallback": True
        }

def enhance_payload_with_ai(payload):
    """
    Función de integración principal: enriquece el payload con el triage IA.
    Si la API de IA no está disponible o falla, realiza fallback silencioso
    garantizando que la alerta SOAR no se interrumpa.
    """
    ok, ai_result = analyze_incident_with_ai(payload)
    
    if ok and ai_result.get("ai_summary"):
        payload["severity"] = ai_result.get("severity", payload.get("severity", "HIGH"))
        payload["severidad"] = payload["severity"]
        payload["nivel"] = payload["severity"]
        
        payload["ai_summary"] = ai_result["ai_summary"]
        payload["resumen_ia"] = ai_result["ai_summary"]
        payload["analisis_ia"] = ai_result["ai_summary"]
        
        if ai_result.get("suggested_action"):
            payload["suggested_action"] = ai_result["suggested_action"]
            payload["accion_recomendada"] = ai_result["suggested_action"]
            payload["accion"] = ai_result["suggested_action"]
            payload["recomendacion"] = ai_result["suggested_action"]
            
        payload["triage_source"] = ai_result.get("triage_source", "Triage IA Asistido")
        payload["triage_origen"] = payload["triage_source"]
    else:
        # Fallback estático transparente (SOP-04)
        default_summary = (
            f"Evento clasificado bajo reglas estáticas SOP-04: {payload.get('event_type', 'Alerta de Seguridad')}. "
            f"Activo afectado: {payload.get('affected_asset', 'Infraestructura')}."
        )
        payload["ai_summary"] = default_summary
        payload["resumen_ia"] = default_summary
        payload["analisis_ia"] = default_summary
        payload["triage_source"] = "Reglas Deterministas SOP-04 (Fallback Local)"
        payload["triage_origen"] = payload["triage_source"]
        
    return payload

if __name__ == "__main__":
    print("=" * 70)
    print("  TEST DE TRIAGE ASISTIDO POR IA (SOP-07 / RS.AN-01)")
    print("=" * 70)
    
    test_sample = {
        "event_type": "Exposicion de Secretos en Pre-Commit",
        "severity": "CRITICAL",
        "risk_score": "9.5",
        "affected_asset": "Repositorio: Kroosand/devsecops-alma-nist (Rama: main)",
        "source": "Shift-Left / Gitleaks Pre-commit Hook",
        "details": "Intento de commit interceptado con un token de Telegram y llave de API de AWS hardcodeados en config_test_leak.php.",
        "archivo_endpoint": "config_test_leak.php",
        "suggested_action": "Texto estático original: 1. Revocar credencial."
    }
    
    print("\n[1] Payload Original (Antes de Triage IA):")
    print(json.dumps(test_sample, indent=2, ensure_ascii=False))
    
    print("\n[2] Ejecutando análisis con Claude AI...")
    enhanced = enhance_payload_with_ai(test_sample.copy())
    
    print("\n[3] Payload Enriquecido (Después de Triage IA):")
    print(json.dumps(enhanced, indent=2, ensure_ascii=False))
    print("\n" + "=" * 70)
