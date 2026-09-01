# SOP-06: Guía Estándar de Desarrollo Seguro y Cumplimiento Normativo

* **Empresa:** Alma Industria Creativa E.I.R.L.
* **Proyecto:** DevSecOps NIST CSF v2.0
* **Marco Legal:** Ley N° 29733 (Ley de Protección de Datos Personales del Perú)
* **Control NIST CSF v2.0:** GV.OC-01 / GV.RM-01 / PR.PS-01
* **Fase PHVA:** Actuar (Act)

---

## 1. Principio Fundamental: Shift-Left Security
La seguridad es una responsabilidad transversal de todo el equipo de ingeniería y Growth. Toda vulnerabilidad detectada en etapas tempranas (local/pre-commit) representa un ahorro del **85% en costos de remediación** frente a la detección en producción.

---

## 2. Reglas Obligatorias para Desarrolladores

### Regla 1: Cero Secretos en Repositorios (Zero Hardcoded Credentials)
1. **Queda terminantemente prohibido** incluir API Keys, JWTs, tokens de Telegram, credenciales de base de datos o claves privadas en el código fuente.
2. Todo secreto debe alojarse exclusivamente en:
   * La bóveda central (**Vaultwarden / Vault**).
   * Archivos locales `.env` que se encuentren declarados en el `.gitignore`.
3. Es obligatorio tener activo el **Git Pre-commit Hook** local provisto en el proyecto (`01-shift-left/hooks/`).

### Regla 2: Gestión de Endpoints y APIs del CMS
1. Ningún endpoint que retorne metadatos de usuarios administradores o clientes debe ser accesible de forma anónima.
2. Todo nuevo endpoint personalizado debe implementar validación de capacidades:
   ```php
   'permission_callback' => function() {
       return current_user_can('manage_options');
   }
   ```

### Regla 3: Cumplimiento de la Ley N° 29733 (Perú)
1. Los formularios web de captación y landing pages deben incluir casilla de consentimiento explícito e informada.
2. Los datos personales almacenados en bases de datos deben contar con cifrado en reposo y en tránsito (TLS 1.3 / HSTS).
3. No registrar información sensible (PII) en los logs de depuración o consola del servidor.

---

## 3. Protocolo de Incorporación (Onboarding)
1. Asignación de rol y usuario en la bóveda Vaultwarden según perfil (Frontend, Backend, QA).
2. Clonación del repositorio y ejecución obligatoria del script de hooks:
   ```powershell
   .\01-shift-left\hooks\install_hooks.ps1
   ```
3. Firma del compromiso de confidencialidad y buenas prácticas de seguridad.
