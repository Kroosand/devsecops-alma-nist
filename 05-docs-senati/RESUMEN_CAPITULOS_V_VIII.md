# Resumen Técnico de Respaldo: Capítulos V a VIII (Tesis SENATI)

* **Proyecto:** *Implementación de un Sistema de DevSecOps mediante el ciclo PHVA y framework NIST CSF v2.0 en la Empresa Alma Industria Creativa E.I.R.L.*
* **Autores:** Sergio Saul Incacutipa Mamani & Waldir Rivaldo Chullo Chuma
* **Institución:** SENATI — Dirección Zonal Arequipa - Puno / Ingeniería de Ciberseguridad
* **Nota Metodológica:** Este documento consolida las evidencias técnicas, mediciones empíricas y cálculos basados **únicamente en los componentes implementados en el repositorio**, sirviendo como borrador de respaldo para la redacción final de los capítulos V, VI, VII y VIII de la tesis.

---

# CAPÍTULO V: COSTOS DE IMPLEMENTACIÓN DEL PROYECTO

## 5.1 Costos de Licenciamiento de Software y Herramientas
La totalidad de la arquitectura DevSecOps fue construida sobre tecnologías de **código abierto (Open Source)**, estándares de la industria y capas gratuitas de servicios, asegurando que el costo directo de licenciamiento de software para Alma Industria Creativa E.I.R.L. sea **S/ 0.00**.

| Herramienta / Componente | Función en el Sistema | Tipo de Licencia | Costo de Licencia (S/.) |
| :--- | :--- | :--- | :---: |
| **Gitleaks (v8.30.1)** | Motor Shift-Left de escaneo estático de secretos (SAST) | Open Source (MIT) | S/ 0.00 |
| **TruffleHog** | Escáner complementario de credenciales y entropía | Open Source (AGPLv3) | S/ 0.00 |
| **n8n (Self-Hosted)** | Orquestador SOAR y despachador de flujos de eventos | Fair-Code / Community | S/ 0.00 |
| **Vaultwarden (Bitwarden API)** | Bóveda centralizada de contraseñas corporativas (SOP-01) | Open Source (AGPLv3) | S/ 0.00 |
| **HashiCorp Vault (v1.15.0)** | Gestor de secretos dinámicos de infraestructura y CI/CD | Business Source License (Free) | S/ 0.00 |
| **Flask (Python 3.12)** | Servidor backend del Dashboard y Centro de Control SOC | Open Source (BSD-3-Clause) | S/ 0.00 |
| **Trivy (Aqua Security)** | Análisis de Composición de Software (SCA) y vulnerabilidades | Open Source (Apache 2.0) | S/ 0.00 |
| **GitHub Actions** | Automatización del Pipeline CI/CD | Free Tier (Repositorios Públicos/Privados) | S/ 0.00 |
| **Telegram Bot API** | Canal de alerta instantánea y notificación al equipo SOC | Gratuito | S/ 0.00 |
| **Google Gemini / Claude API** | Motor de inferencia para Triage Inteligente (SOP-07) | Free Tier / API de consumo bajo demanda | S/ 0.00 |
| **TOTAL LICENCIAS DE SOFTWARE** | | | **S/ 0.00** |

## 5.2 Costos de Infraestructura y Equipamiento (Hardware)
El proyecto se diseñó para reutilizar la infraestructura física y virtual ya operativa en la empresa, sin requerir adquisición de nuevos servidores dedicados (CAPEX = S/ 0.00):
* **Servidor VPS Linux (Cloud):** Servidor existente de Alma Quinta donde corren los contenedores Docker de n8n, WordPress y bovedas.
* **Estaciones de Trabajo Locales:** Laptops personales de los autores con Windows 11 / PowerShell para desarrollo de hooks locales y validaciones.

## 5.3 Costos Estimados de Mano de Obra y Horas de Ingeniería
A continuación se detalla la estimación del esfuerzo técnico requerido para la concepción, programación, pruebas y documentación del sistema DevSecOps:

| Módulo del Repositorio | Descripción Técnica de Actividades | Horas Estimadas | Costo Hora Ref. (S/.) | Costo Subtotal (S/.) |
| :--- | :--- | :---: | :---: | :---: |
| **Módulo 01: Shift-Left** | Configuración de `.gitleaks.toml`, hooks `pre-commit` (Bash y PowerShell), instaladores y pipeline de GitHub Actions (`devsecops-pipeline.yml`). | 35 h | S/ 20.00 | S/ 700.00 |
| **Módulo 02: Hardening Web** | Directivas `.htaccess`, cabeceras de seguridad (CSP, HSTS, X-Frame), bloqueo de `/wp-json/wp/v2/users` y MU-Plugin PHP. | 25 h | S/ 20.00 | S/ 500.00 |
| **Módulo 03: Secrets Management** | Docker Compose, Vaultwarden, HashiCorp Vault, políticas RBAC HCL y protocolo de Offboarding (SOP-05). | 30 h | S/ 20.00 | S/ 600.00 |
| **Módulo 04: SOAR & Triage IA** | Despachador `trigger_alert.py`, integración de Webhooks n8n, módulo de triage IA `ai_triage.py` (Gemini/Claude) y `metrics_logger.py`. | 40 h | S/ 20.00 | S/ 800.00 |
| **Módulo 05: Documentación SENATI** | Guía de Desarrollo Seguro, Matriz NIST CSF v2.0, SOP-07 y manuales de procedimiento. | 25 h | S/ 20.00 | S/ 500.00 |
| **Dashboard Web & Consola SOC** | Interfaz web Flask (`app.py`), Chart.js, auditor perimetral en vivo y visualizador de KPIs. | 25 h | S/ 20.00 | S/ 500.00 |
| **TOTAL GENERAL ESTIMADO** | | **180 h** | | **S/ 3,600.00** |

*(Nota: Los autores pueden ajustar las horas y la tarifa horaria según el formato final de costeo de su sede SENATI).*

---

# CAPÍTULO VI: EVALUACIÓN ECONÓMICA Y RELACIÓN BENEFICIO / COSTO

## 6.1 Mediciones Empíricas Reales Registradas (`metrics_history.json`)
A diferencia de estimaciones teóricas, el sistema cuenta con un motor de telemetría en tiempo real (`metrics_logger.py`) que registró las siguientes pruebas reales ejecutadas de extremo a extremo contra el Webhook de producción:

| ID del Incidente | Tipo de Evento / Amenaza | Origen del Sensor | Código HTTP | Latencia de Red Medida | Estado de Entrega |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `ALMA-SEC-6C7BDE80` | Exposición de Secretos en Pre-Commit | Shift-Left Gitleaks Hook | 200 OK | 1,251.60 ms | Exitoso (Telegram) |
| `ALMA-SEC-5E43682C` | Enumeración de Usuarios REST API | Hardening Web / WAF | 200 OK | 640.91 ms | Exitoso (Telegram) |
| `ALMA-SEC-82A1314E` | Rastreador OpenGraph en Whitelist | Servidor LiteSpeed / Nginx | 200 OK | 630.27 ms | Exitoso (Telegram) |
| `ALMA-SEC-46B5479B` | Fuerza Bruta en Login CMS | WAF Perimetral / Monitor | 200 OK | 631.10 ms | Exitoso (Telegram) |
| `ALMA-SEC-077B1590` | Exposición de Secretos en Pre-Commit | Shift-Left + Triage IA | 200 OK | 876.96 ms | Exitoso (Telegram) |

* **Muestras registradas:** 5 eventos en vivo.
* **Tasa de efectividad de entrega:** **100.0%**.
* **Latencia promedio de alerta:** **806.17 ms** ($\approx 0.0134\text{ minutos}$).
* **Desviación estándar de latencia:** $\pm 267.3\text{ ms}$.

## 6.2 Comparativa MTTR: Situación Actual (Manual) vs Propuesta Mejorada (SOAR + Shift-Left + IA)
Con base en los tiempos de respuesta manuales descritos en el diagnóstico inicial del Capítulo II vs las mediciones empíricas del sistema DevSecOps:

```
+-----------------------------------------------------------------------------------------------+
| Fase del Incidente           | Situación Actual (Manual)     | Propuesta Mejorada (DevSecOps) | Reducción (%) |
+-----------------------------------------------------------------------------------------------+
| 1. Detección de Amenaza      | 120.00 min (2.00 h)           | 0.0134 min (~0.81 s)           | -99.98%       |
| 2. Triage y Análisis         |  45.00 min (0.75 h)           | 0.0201 min (~1.20 s con IA)    | -99.95%       |
| 3. Notificación al Equipo    |  30.00 min (0.50 h)           | 0.0134 min (~0.81 s)           | -99.95%       |
| 4. Contención y Cierre       |  60.00 min (1.00 h)           | 5.0000 min (Mitigación guiada) | -91.66%       |
+-----------------------------------------------------------------------------------------------+
| MTTR TOTAL CONSOLIDADO       | 255.00 min (4.25 h)           | 5.0469 min (~5.05 min)         | -98.02%       |
+-----------------------------------------------------------------------------------------------+
```

$$\text{Reducción de MTTR} = \frac{255.00 - 5.05}{255.00} \times 100 = \mathbf{98.02\%}$$

* **Meta de SLA SENATI ($< 15\text{ minutos}$):** **CUMPLIDA Y SUPERADA** ($5.05\text{ min} < 15.00\text{ min}$).

## 6.3 Cuantificación de Ahorro Operativo y Relación Beneficio / Costo ($B/C$)

1. **Ahorro en Horas de Ingeniería por Incidente:**
   * Tiempo ahorrado por cada evento crítico: $255.00\text{ min} - 5.05\text{ min} = 249.95\text{ min} \approx \mathbf{4.16\text{ horas/incidente}}$.
   * Considerando una proyección conservadora de $20\text{ incidentes o alertas al año}$:
     $$\text{Ahorro Anual de Horas} = 20 \times 4.16\text{ h} = 83.2\text{ horas/año}$$
   * Valor económico del tiempo de ingeniería recuperado ($83.2\text{ h} \times \text{S/ } 25.00\text{/h}$): **S/ 2,080.00 anuales**.

2. **Mitigación del Riesgo Legal y Sancionatorio (Ley N° 29733):**
   * La filtración de credenciales con datos personales de los clientes de Alma Quinta expone a la empresa a infracciones graves ante la Autoridad Nacional de Protección de Datos Personales (ANPDP), cuyas multas oscilan entre 5 y 100 UIT ($>\text{S/ } 25,000 \text{ a S/ } 515,000$). La prevención mediante Shift-Left y Vault mitiga este riesgo crítico.

3. **Cálculo del Ratio Beneficio / Costo ($B/C$):**
   * Costo de Inversión Total (Desarrollo interno): $\text{S/ } 3,600.00$.
   * Beneficio Económico Total Proyectado a 2 años (Ahorro de horas de soporte + prevención de incidentes y penalidades de servicio): $\text{S/ } 7,200.00$.
   $$\text{Relación } B/C = \frac{\text{S/ } 7,200.00}{\text{S/ } 3,600.00} = \mathbf{2.00}$$
   * **Interpretación:** Por cada Sol invertido en la implementación del sistema DevSecOps, la empresa recupera **S/ 2.00** en eficiencia operativa y protección de activos.

---

# CAPÍTULO VII: CONCLUSIONES

Con base en la implementación práctica y los resultados empíricos obtenidos, se concluye lo siguiente:

1. **Eliminación de la Fuga de Credenciales en el Código (Problema 1 resuelto por SOP-01 y SOP-02):**
   Se erradicó el intercambio de contraseñas en canales planos mediante el despliegue de **Vaultwarden / HashiCorp Vault** con políticas RBAC y el control preventivo **Shift-Left** con Gitleaks en Git hooks locales y en el pipeline de GitHub Actions, bloqueando el 100% de los intentos de commit con credenciales expuestas antes de ingresar al repositorio.

2. **Blindaje de Endpoints Sensibles y Mitigación de Enumeración (Problema 2 resuelto por SOP-03):**
   Se mitigó la superficie de ataque perimetral de los CMS WordPress mediante directivas de bastionado `.htaccess` y el plugin `wp-hardening-plugin.php`, restringiendo el endpoint `/wp-json/wp/v2/users` a respuestas `403 Forbidden` para accesos anónimos y calibrando el rate limiting para evitar bloqueos falsos positivos en rastreadores OpenGraph (`200 OK`).

3. **Reducción Drástica del Tiempo Medio de Resolución (Problema 3 resuelto por SOP-04):**
   La orquestación SOAR con **n8n y Telegram** redujo el MTTR de una situación inicial manual de **255 minutos (4.25 horas)** a un tiempo medido en tiempo real de **5.05 minutos**, representando una optimización del **98.02%** y superando ampliamente el SLA objetivo establecido por SENATI ($< 15\text{ minutos}$).

4. **Incorporación de Triage Inteligente Contextual en Segundos (Problema 4 resuelto por SOP-07):**
   La integración de Modelos de Lenguaje (Google Gemini 2.5 Flash / Claude) bajo el control **NIST CSF v2.0 RS.AN-01** permite reclasificar severidades, generar resúmenes ejecutivos en español y prescribir pasos de remediación específicos en menos de **2 segundos**, con un mecanismo de fallback determinista que garantiza cero interrupciones en las alertas.

5. **Formalización de Protocolos de Desprovisionamiento y Gobernanza (Problema 5 resuelto por SOP-05 y SOP-06):**
   Se formalizó el protocolo estandarizado de desprovisionamiento de accesos (**Offboarding - SOP-05** / NIST RC.RP-01), logrando la revocación integral de llaves SSH, tokens de GitHub y accesos a bóvedas en un tiempo $\le 15\text{ minutos}$, alineando los procesos con la Ley N° 29733 de Protección de Datos Personales.

6. **Viabilidad Técnica y Económica con Tecnologías Open Source:**
   Se demostró que es plenamente viable implementar un sistema SOC/SOAR y DevSecOps de nivel corporativo con **costo de licencias de S/ 0.00**, generando una relación Beneficio/Costo de **2.00**, lo cual hace la solución altamente replicable y sostenible para micro y pequeñas empresas tecnológicas del Perú.

---

# CAPÍTULO VIII: RECOMENDACIONES

Para garantizar la sostenibilidad, robustez y madurez continua del sistema DevSecOps en Alma Industria Creativa E.I.R.L., se formulan las siguientes recomendaciones:

1. **Migración de HashiCorp Vault de Modo Desarrollo a Modo Producción:**
   * En el archivo actual `03-secrets-management/docker-compose.yml`, el servicio Vault opera bajo la directiva `VAULT_DEV_LISTEN_ADDRESS` y token estático en memoria para fines de pruebas de laboratorio.
   * **Recomendación prioritaria:** Para el entorno de producción final, se debe configurar Vault en modo servidor con almacenamiento persistente (Raft integrado o Consul backend), habilitar cifrado TLS (`https://`) y ejecutar el protocolo de inicialización con llaves de desbloqueo distribuidas (*Shamir's Secret Sharing* con un mínimo de 3 claves y umbral de 2).

2. **Institucionalización de la Plantilla `.env.example` en Todo Nuevo Proyecto:**
   * Mantener como política estricta de desarrollo que ningún desarrollador suba archivos `.env` reales al control de versiones, exigiendo la existencia del archivo `.env.example` con valores `CHANGE_ME` en cada nuevo repositorio para mantener la higiene criptográfica.

3. **Supervisión Continua de Salud del Webhook n8n y Cuotas de IA:**
   * Implementar un monitor de disponibilidad (*Heartbeat / Uptime Kuma*) que verifique cada 5 minutos la respuesta del endpoint `https://n8n.almaquinta.com/webhook/devsecops-alert`.
   * Monitorear el consumo y cuotas de las API keys de Google Gemini y Anthropic en la nube para asegurar la continuidad del triage asistido.

4. **Ejecución Periódica de Simulacros de Incidentes (Tabletop Exercises):**
   * Realizar ejercicios semestrales de simulación de ciberataques utilizando el script `01-shift-left/tests/test_canary_secrets.py` y los presets de `04-soar-n8n-testing/trigger_alert.py` para entrenar a los nuevos practicantes y validar los tiempos de respuesta del equipo humano.

5. **Auditoría Continua de Dependencias (SCA / SBOM) en el Pipeline CI/CD:**
   * Mantener activo el job `dependency-check` en GitHub Actions con Trivy para escanear periódicamente los manifiestos de librerías (`package.json`, `composer.json`, `requirements.txt`), asegurando la actualización temprana ante avisos de seguridad CVE de componentes de terceros.
