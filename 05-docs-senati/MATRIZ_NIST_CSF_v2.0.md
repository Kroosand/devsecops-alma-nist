# Matriz de Trazabilidad Técnica: NIST Cybersecurity Framework (CSF v2.0)

**Proyecto:** Implementación de un Sistema de DevSecOps mediante el ciclo PHVA y framework NIST CSF v2.0 en la Empresa Alma Industria Creativa E.I.R.L.  
**Autores:** Sergio Saul Incacutipa Mamani & Waldir Rivaldo Chullo Chuma  
**Institución:** SENATI — Dirección Zonal Arequipa - Puno

---

| Función NIST v2.0 | Categoría / Subcategoría | Control Técnico Implementado | Procedimiento (SOP) | Archivos / Componentes en Repositorio |
| :--- | :--- | :--- | :--- | :--- |
| **GOBERNAR (GV)** | **GV.OC-01 / GV.RM-01** | Definición de políticas de desarrollo seguro, roles RBAC y lineamientos de la Ley N° 29733. | **SOP-06** | `05-docs-senati/GUIA_DESARROLLO_SEGURO.md`<br>`03-secrets-management/rbac-policies/` |
| **IDENTIFICAR (ID)** | **ID.AM-01 / ID.RA-01** | Mapeo de repositorios, inventario de credenciales y modelado de superficie de ataque en endpoints. | **Fase 1 PHVA** | `04-soar-n8n-testing/test_wp_enumeration.py` |
| **PROTEGER (PR)** | **PR.AA-01 / PR.DS-01** | Custodia centralizada de secretos, eliminación de credenciales en canales planos y control RBAC. | **SOP-01** | `03-secrets-management/docker-compose.yml`<br>`03-secrets-management/rbac-policies/` |
| **PROTEGER (PR)** | **PR.PS-01 / PR.IR-01** | Bloqueo preventivo Shift-Left en Git con Gitleaks y TruffleHog (intercepción de staged files). | **SOP-02** | `01-shift-left/hooks/pre-commit`<br>`01-shift-left/.gitleaks.toml` |
| **PROTEGER (PR)** | **PR.IR-01 / PR.PT-01** | Bastionado perimetral (.htaccess/WAF), bloqueo de `/wp-json/wp/v2/users` y whitelist OpenGraph. | **SOP-03** | `02-hardening-web/.htaccess`<br>`02-hardening-web/wp-hardening-plugin.php` |
| **DETECTAR (DE)** | **DE.AE-01 / DE.CM-01** | Monitorización continua y captura de anomalías de seguridad y eventos de escaneo. | **SOP-04** | `04-soar-n8n-testing/trigger_alert.py` |
| **RESPONDER (RS)** | **RS.AN-01 / RS.MI-01** | Triage automatizado SOAR con n8n, despacho de alertas críticas a Telegram en $< 15$ min. | **SOP-04** | `04-soar-n8n-testing/mttr_benchmark.py`<br>Flujos n8n de Waldir Chullo |
| **RECUPERAR (RC)** | **RC.RP-01** | Protocolo estandarizado de revocación y desprovisionamiento inmediato de accesos (Offboarding). | **SOP-05** | `03-secrets-management/offboarding-protocol.md` |
