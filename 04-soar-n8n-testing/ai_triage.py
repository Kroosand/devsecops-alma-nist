#!/usr/bin/env python3
"""
==============================================================================
Módulo de Triage Inteligente Asistido por IA (SOP-07)
Multi-Proveedor: Google Gemini API & Anthropic Claude API
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

# Endpoints oficiales
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
GEMINI_FALLBACK_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"

def read_env_file_key(key_name):
    """Busca una variable en archivos .env locales si no está en os.environ."""
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
                        if line.startswith(f"{key_name}=") and not line.startswith("#"):
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val and val != "CHANGE_ME":
                                return val
            except Exception:
                pass
    return ""

def get_gemini_api_key():
    """Obtiene la API key de Google Gemini."""
    return os.environ.get("GEMINI_API_KEY", "").strip() or \
           os.environ.get("GOOGLE_API_KEY", "").strip() or \
           read_env_file_key("GEMINI_API_KEY") or \
           read_env_file_key("GOOGLE_API_KEY")

def get_anthropic_api_key():
    """Obtiene la API key de Anthropic Claude."""
    return os.environ.get("ANTHROPIC_API_KEY", "").strip() or \
           read_env_file_key("ANTHROPIC_API_KEY")

def sanitize_plain_text(text):
    """Limpia etiquetas HTML y caracteres problemáticos para Telegram (<, >)."""
    if not text:
        return ""
    cleaned = str(text).replace("<", "[").replace(">", "]")
    return cleaned.strip()

def _call_gemini_api(incident_context, api_key, timeout_sec=5.0):
    """Ejecuta el triage usando la API REST de Google Gemini."""
    url = f"{GEMINI_API_URL}?key={api_key}"
    
    system_instruction = (
        "Eres un analista experto de SOC y DevSecOps (NIST CSF v2.0) para la empresa "
        "Alma Industria Creativa E.I.R.L. Tu tarea es realizar un triage técnico rápido sobre "
        "el incidente reportado. Debes responder EXCLUSIVAMENTE un objeto JSON estructurado con las siguientes claves:\n"
        "{\n"
        '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '  "ai_summary": "Resumen conciso en español de 2 a 3 frases explicando qué ocurrió, causa raíz e impacto potencial.",\n'
        '  "suggested_action": "Acciones de remediación técnica específicas y accionables numeradas (1. ..., 2. ...) en texto plano puro sin etiquetas HTML"\n'
        "}"
    )

    req_body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": f"Realiza el triage del siguiente incidente de ciberseguridad:\n{json.dumps(incident_context, ensure_ascii=False)}"
                    }
                ]
            }
        ],
        "systemInstruction": {
            "parts": [
                {
                    "text": system_instruction
                }
            ]
        },
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 600,
            "responseMimeType": "application/json"
        }
    }

    data = json.dumps(req_body).encode("utf-8")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Alma-DevSecOps-Gemini-Triage/2.0 (SENATI Thesis)"
        }
    )

    start_t = time.time()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout_sec) as resp:
        latency_ms = (time.time() - start_t) * 1000
        resp_data = json.loads(resp.read().decode("utf-8"))
        
        # Extraer JSON de candidatos de Gemini
        text_response = resp_data["candidates"][0]["content"]["parts"][0]["text"].strip()
        parsed = json.loads(text_response)
        
        return {
            "severity": parsed.get("severity", incident_context.get("initial_severity", "HIGH")).upper(),
            "ai_summary": sanitize_plain_text(parsed.get("ai_summary", "")),
            "suggested_action": sanitize_plain_text(parsed.get("suggested_action", "")),
            "latency_ms": round(latency_ms, 2),
            "model": DEFAULT_GEMINI_MODEL,
            "provider": "Google Gemini",
            "triage_source": f"Triage IA Asistido (Google {DEFAULT_GEMINI_MODEL})"
        }

def _call_anthropic_api(incident_context, api_key, timeout_sec=5.0):
    """Ejecuta el triage usando la API REST de Anthropic Claude."""
    system_prompt = (
        "Eres un analista experto de SOC y DevSecOps (NIST CSF v2.0) para la empresa "
        "Alma Industria Creativa E.I.R.L. Tu tarea es realizar un triage técnico rápido sobre "
        "el incidente reportado. Debes responder EXCLUSIVAMENTE un objeto JSON válido sin texto "
        "introductorio, sin comentarios y sin bloques de código markdown. El JSON debe contener:\n"
        "{\n"
        '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '  "ai_summary": "Resumen conciso en español de 2 a 3 frases explicando qué ocurrió, causa raíz e impacto.",\n'
        '  "suggested_action": "Acciones de remediación técnica específicas y accionables numeradas (1. ..., 2. ...) en texto plano puro sin etiquetas HTML"\n'
        "}"
    )

    req_body = {
        "model": DEFAULT_ANTHROPIC_MODEL,
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
            "User-Agent": "Alma-DevSecOps-Claude-Triage/2.0 (SENATI Thesis)"
        }
    )

    start_t = time.time()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout_sec) as resp:
        latency_ms = (time.time() - start_t) * 1000
        resp_json = json.loads(resp.read().decode("utf-8"))
        
        content_blocks = resp_json.get("content", [])
        text_response = ""
        for block in content_blocks:
            if block.get("type") == "text":
                text_response += block.get("text", "")
        
        text_response = text_response.strip()
        if text_response.startswith("```"):
            lines = text_response.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text_response = "\n".join(lines).strip()
        
        parsed = json.loads(text_response)
        
        return {
            "severity": parsed.get("severity", incident_context.get("initial_severity", "HIGH")).upper(),
            "ai_summary": sanitize_plain_text(parsed.get("ai_summary", "")),
            "suggested_action": sanitize_plain_text(parsed.get("suggested_action", "")),
            "latency_ms": round(latency_ms, 2),
            "model": DEFAULT_ANTHROPIC_MODEL,
            "provider": "Anthropic Claude",
            "triage_source": f"Triage IA Asistido (Anthropic {DEFAULT_ANTHROPIC_MODEL})"
        }

def analyze_incident_with_ai(incident_payload, timeout_sec=5.0):
    """
    Motor unificado de Triage IA: Intenta Google Gemini o Anthropic Claude
    según la disponibilidad de credenciales, con fallback automático.
    """
    gemini_key = get_gemini_api_key()
    anthropic_key = get_anthropic_api_key()
    preferred_provider = os.environ.get("AI_PROVIDER", "gemini").lower()

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

    # Intentar Gemini primero si está preferido o disponible
    if (preferred_provider == "gemini" and gemini_key) or (gemini_key and not anthropic_key):
        try:
            res = _call_gemini_api(incident_context, gemini_key, timeout_sec=timeout_sec)
            return True, res
        except Exception as e:
            # Si falla Gemini y existe Anthropic, intentar Claude
            if anthropic_key:
                try:
                    res = _call_anthropic_api(incident_context, anthropic_key, timeout_sec=timeout_sec)
                    return True, res
                except Exception:
                    pass
            return False, {"error": f"Gemini error: {str(e)}", "fallback": True}

    # Intentar Claude si está preferido o disponible
    if anthropic_key:
        try:
            res = _call_anthropic_api(incident_context, anthropic_key, timeout_sec=timeout_sec)
            return True, res
        except Exception as e:
            if gemini_key:
                try:
                    res = _call_gemini_api(incident_context, gemini_key, timeout_sec=timeout_sec)
                    return True, res
                except Exception:
                    pass
            return False, {"error": f"Anthropic error: {str(e)}", "fallback": True}

    return False, {"error": "Sin API key configurada (GEMINI_API_KEY / ANTHROPIC_API_KEY)", "fallback": True}

def enhance_payload_with_ai(payload):
    """
    Enriquece el payload del incidente con el Triage IA.
    Si la IA no está disponible o falla, aplica fallback silencioso a SOP-04.
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
        payload["ai_provider"] = ai_result.get("provider", "IA Generativa")
    else:
        # Fallback determinista local
        default_summary = (
            f"Evento clasificado bajo reglas estáticas SOP-04: {payload.get('event_type', 'Alerta de Seguridad')}. "
            f"Activo afectado: {payload.get('affected_asset', 'Infraestructura')}."
        )
        payload["ai_summary"] = default_summary
        payload["resumen_ia"] = default_summary
        payload["analisis_ia"] = default_summary
        payload["triage_source"] = "Reglas Deterministas SOP-04 (Fallback Local)"
        payload["triage_origen"] = payload["triage_source"]
        payload["ai_provider"] = "Reglas Estáticas (Local)"
        
    return payload

if __name__ == "__main__":
    print("=" * 75)
    print("  TEST DE TRIAGE MULTI-PROVEEDOR IA (GOOGLE GEMINI & ANTHROPIC CLAUDE)")
    print("=" * 75)
    
    test_sample = {
        "event_type": "Exposicion de Secretos en Pre-Commit",
        "severity": "CRITICAL",
        "risk_score": "9.5",
        "affected_asset": "Repositorio: Kroosand/devsecops-alma-nist (Rama: main)",
        "source": "Shift-Left / Gitleaks Pre-commit Hook",
        "details": "Intento de commit interceptado con credenciales hardcodeadas en config_test_leak.php.",
        "archivo_endpoint": "config_test_leak.php",
        "suggested_action": "1. Revocar credencial estática."
    }
    
    print(f"\n[+] Estado de Credenciales:")
    print(f" -> GEMINI_API_KEY:    {'CONFIGURADA' if get_gemini_api_key() else 'NO CONFIGURADA'}")
    print(f" -> ANTHROPIC_API_KEY: {'CONFIGURADA' if get_anthropic_api_key() else 'NO CONFIGURADA'}")
    
    print("\n[+] Ejecutando Triage IA...")
    enhanced = enhance_payload_with_ai(test_sample.copy())
    
    print(f"\n[+] Proveedor Utilizado: {enhanced.get('triage_source')}")
    print(f" -> Resumen IA: {enhanced.get('ai_summary')}")
    print(f" -> Acciones:   {enhanced.get('suggested_action')}")
    print("\n" + "=" * 75)
