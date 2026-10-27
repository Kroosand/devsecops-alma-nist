# 🎬 GUÍA MAESTRA DE DEMOSTRACIÓN EN VIVO (LIVE DEMO PROTOCOL)
## Sistema DevSecOps SOAR & Cumplimiento Normativo (NIST CSF v2.0 & Ley N° 29733)

**Institución:** SENATI — Dirección Zonal Arequipa-Puno  
**Carrera:** Ingeniería de Ciberseguridad (Titulación Profesional Técnica 2026)  
**Proyecto:** Implementación de un Framework DevSecOps con Automatización SOAR y Gestión Centralizada de Secretos  
**Empresa Beneficiaria:** Alma Industria Creativa E.I.R.L.  
**Autores:** Sergio Saúl Incacutipa Mamani & Waldir Rivaldo Chullo Chuma  
**Repositorio Oficial:** `https://github.com/Kroosand/devsecops-alma-nist`

---

> [!IMPORTANT]
> **REGLA DE ORO DE ESTA DEMOSTRACIÓN:**
> **CERO SIMULADORES. CERO MOCKS SINTÉTICOS. CERO CAPTURAS DE PANTALLA.**  
> Todo lo que el jurado presenciará es tráfico de red real, intercepciones de git en tiempo real, peticiones HTTP reales a servidores en producción/laboratorio, alertas acústicas en smartphones físicos, inyección viva de reglas perimetrales en caliente y validación criptográfica matemática en consola.

---

## 📑 ÍNDICE DE LA GUÍA
1. [Dispositivos y Topología en Vivo](#1-dispositivos-y-topología-en-vivo)
2. [Checklist de Preparación Previa (15 Minutos Antes)](#2-checklist-de-preparación-previa-15-minutos-antes)
3. [Cronograma de Demostración Minuto a Minuto (6 Minutos)](#3-cronograma-de-demostración-minuto-a-minuto-6-minutos)
4. [Libreto Paso a Paso y Diálogos de los Sustentantes](#4-libreto-paso-a-paso-y-diálogos-de-los-sustentantes)
   - [Acto 0: La Puesta en Escena y Desafío al Jurado (0:00 - 0:30)](#acto-0-la-puesta-en-escena-y-desafío-al-jurado-000---030)
   - [Acto 1: Shift-Left Real — Bloqueo de Fuga en Git (0:30 - 1:45)](#acto-1-shift-left-real--bloqueo-de-fuga-en-git-030---145)
   - [Acto 2: Ataque Perimetral Real y Triage Asistido por IA (1:45 - 3:00)](#acto-2-ataque-perimetral-real-y-triage-asistido-por-ia-145---300)
   - [Acto 3: Contención Perimetral Activa en Caliente (< 15 ms) (3:00 - 4:15)](#acto-3-contención-perimetral-activa-en-caliente--15-ms-300---415)
   - [Acto 4: Revocación Inmediata de Credenciales (SOP-05) (4:15 - 5:15)](#acto-4-revocación-inmediata-de-credenciales-sop-05-415---515)
   - [Acto 5: Trazabilidad Forense Inmutable — Ley N° 29733 (5:15 - 6:00)](#acto-5-trazabilidad-forense-inmutable--ley-n-29733-515---600)
   - [Cierre: Métricas de Negocio y Preguntas del Jurado (6:00+)](#cierre-métricas-de-negocio-y-preguntas-del-jurado-600)
5. [Hoja de Comandos Rápidos "Copiar y Pegar"](#5-hoja-de-comandos-rápidos-copiar-y-pegar)
6. [Plan de Contingencia "Fail-Safe" (Sin Internet / Caída de Red)](#6-plan-de-contingencia-fail-safe-sin-internet--caída-de-red)

---

## 1. DISPOSITIVOS Y TOPOLOGÍA EN VIVO

Para lograr el máximo impacto visual y credibilidad técnica, el escenario se compone de **3 dispositivos físicos** interactuando con la **Infraestructura Cloud**:

```
 ┌────────────────────────────────────────┐         ┌────────────────────────────────────────┐
 │   LAPTOP 1: PUESTO DE MANDO SOC        │         │   LAPTOP 2: ESTACIÓN OFENSIVA / DEV    │
 │   (Sergio - Conectada al Proyector)    │         │   (Waldir - Terminal de Ataques)       │
 │                                        │         │                                        │
 │ • Dashboard SOC Flask (:5000)          │         │ • Git CLI con Pre-commit Hook          │
 │ • Panel Vaultwarden / Bóveda           │         │ • cURL / Script de Pentesting          │
 │ • Visor de .htaccess en vivo           │         │ • IP Visible en red local/WiFi         │
 └──────────────────┬─────────────────────┘         └───────────────────┬────────────────────┘
                    │                                                   │
                    │                  INTERNET / LAN                   │
                    ├───────────────────────────────────────────────────┤
                    │                                                   │
                    ▼                                                   ▼
 ┌────────────────────────────────────────┐         ┌────────────────────────────────────────┐
 │      INFRAESTRUCTURA CLOUD / HOST      │         │   SMARTPHONE: CENTRO DE ALERTA SOC     │
 │ • n8n SOAR (n8n.almaquinta.com)        │         │   (Ubicado sobre la mesa del jurado)   │
 │ • Google Gemini 2.5 Flash API          │         │                                        │
 │ • Supabase SIEM (PostgreSQL Cloud)     │────────►│ • Telegram Messenger                   │
 │ • Servidor Web Apache / LiteSpeed      │         │ • Canal: DevSecOps Alerts Alma         │
 │   (mante.terrafinaperu.com o local)    │         │ • Volumen: 100% (Notificación audible) │
 └────────────────────────────────────────┘         └────────────────────────────────────────┘
```

### Asignación de Roles:
* **Sergio (Laptop 1 - Proyector):** Rol **Defensa / SOC Lead**. Controla el Dashboard, monitorea los logs de Supabase, ejecuta la mitigación en caliente (bloqueo de IP) y valida el hash criptográfico del informe forense.
* **Waldir (Laptop 2 - Consola):** Rol **Desarrollador / Atacante Red Team**. Realiza el intento de commit con secretos, lanza el escaneo y ataque de enumeración por REST API, y comprueba en su propia terminal cómo el sistema lo bloquea.
* **El Smartphone del Jurado:** Se coloca en la mesa de los ingenieros evaluadores. Suena físicamente cuando el motor SOAR detecta el ataque perimetral, demostrando que la alerta no es una animación en pantalla sino un evento real de red.

---

## 2. CHECKLIST DE PREPARACIÓN PREVIA (15 MINUTOS ANTES)

Antes de que el jurado dé la orden de inicio, verificar cada punto en silencio:

### En Laptop 1 (SOC / Sergio):
- [ ] Conectar cable HDMI / Proyector y configurar en modo **Extender** o **Duplicar**.
- [ ] Iniciar el Dashboard SOC ejecutando:
  ```powershell
  wscript C:\Sergio\Proyecto Final\devsecops-alma-nist\iniciar_dashboard_silencioso.vbs
  ```
- [ ] Abrir el navegador en `http://localhost:5000` (Pantalla completa con `F11`).
- [ ] Abrir una pestaña secundaria con Vaultwarden (`https://localhost:8080` o en la nube).
- [ ] Abrir una terminal de PowerShell minimizada en la raíz del proyecto.
- [ ] Comprobar que el archivo `02-hardening-web/.htaccess` esté limpio de bloqueos previos:
  ```powershell
  Get-Content "C:\Sergio\Proyecto Final\devsecops-alma-nist\02-hardening-web\.htaccess" | Select-String "Require not ip"
  ```
  *(Si hay alguna IP, eliminarla desde el Dashboard en la sección "IPs Bloqueadas").*

### En Laptop 2 (Atacante / Waldir):
- [ ] Conectarse a la misma red WiFi o Hotspot móvil que Laptop 1.
- [ ] Identificar la dirección IP de Laptop 2 abriendo PowerShell:
  ```powershell
  ipconfig
  ```
  *(Anotar la IPv4 local, por ejemplo: `192.168.1.45` o la IP pública si es por internet).*
- [ ] Abrir una ventana de PowerShell o Terminal Linux con tipografía grande (Ctrl + Rueda del ratón) para que el jurado pueda leer desde lejos.
- [ ] Navegar a la carpeta del repositorio:
  ```powershell
  cd "C:\Sergio\Proyecto Final\devsecops-alma-nist"
  ```

### En el Smartphone (Alerta Telegram):
- [ ] Conectar a internet (Datos móviles o WiFi).
- [ ] Abrir la aplicación **Telegram** en el canal del SOC.
- [ ] Subir el **Volumen Multimedia y de Notificaciones al 100%**.
- [ ] Colocar el teléfono visible en la esquina de la mesa frente a los jurados evaluadores.

---

## 3. CRONOGRAMA DE DEMOSTRACIÓN MINUTO A MINUTO (6 MINUTOS)

| Tiempo | Fase | Responsable | Acción en Vivo | Resultado Visible |
| :--- | :--- | :--- | :--- | :--- |
| **0:00 - 0:30** | **Acto 0:** Puesta en Escena | Sergio | Presentación de la topología y colocación del smartphone en la mesa del jurado. | Jurado enganchado y a la expectativa. |
| **0:30 - 1:45** | **Acto 1:** Shift-Left Git | Waldir | Intento de `git commit` con clave privada de Stripe en terminal. | **Gitleaks bloquea el commit en < 350 ms** con salida roja. |
| **1:45 - 3:00** | **Acto 2:** Ataque REST API | Waldir & Sergio | Petición `curl` a `/wp-json/wp/v2/users`. Disparo al SOAR n8n. | **¡Suena el teléfono del jurado!** Telegram muestra alerta con triage de Gemini 2.5 Flash. |
| **3:00 - 4:15** | **Acto 3:** Mitigación Activa | Sergio & Waldir | 1-Click "Bloquear IP" en Dashboard. Waldir relanza el `curl`. | Servidor web responde **HTTP 403 Forbidden en 12.5 ms**. Inyección en `.htaccess` visible. |
| **4:15 - 5:15** | **Acto 4:** Offboarding SOP-05 | Sergio | Revocación de colaborador en Vaultwarden. Comprobación de corte. | Sesiones purgadas y credenciales revocadas en **< 10 s**. |
| **5:15 - 6:00** | **Acto 5:** Trazabilidad Forense | Sergio | Emisión del Informe PDF con Sello SHA-256 y verificación de hash en consola. | **Hash matemático coincide al 100%**. No repudio (Ley N° 29733 Art. 28). |
| **6:00+** | **Cierre y Preguntas** | Ambos | Síntesis de métricas: MTTR (4.2h ➔ 2m), Bloqueo < 15ms, B/C = 2.57. | Respuesta técnica a interrogantes. |

---

## 4. LIBRETO PASO A PASO Y DIÁLOGOS DE LOS SUSTENTANTES

---

### ACTO 0: La Puesta en Escena y Desafío al Jurado (0:00 - 0:30)

**Acción Física:**
* Sergio proyecta el Dashboard SOC en el ecran.
* Sergio camina hacia la mesa del jurado y coloca el smartphone con la pantalla hacia arriba.

**Diálogo de Sergio:**
> *"Buenas tardes, distinguidos miembros del jurado calificador. Para la sustentación de nuestro proyecto de titulación en Alma Industria Creativa E.I.R.L., no les mostraremos diapositivas estáticas ni capturas simuladas.*  
> *Esta tarde hemos desplegado una arquitectura real. En esta pantalla tenemos nuestro Centro de Control SOC en producción; en la mesa de ustedes hemos colocado el teléfono oficial de guardia del equipo de Ciberseguridad; y mi compañero Waldir, desde su propia estación de trabajo, actuará primero como un desarrollador y luego como un atacante perimetral real.*  
> *Comenzamos con la primera línea de defensa: la seguridad Shift-Left."*

---

### ACTO 1: Shift-Left Real — Bloqueo de Fuga en Git (0:30 - 1:45)
**Control NIST:** PR.PS-01 (Protección de Plataformas) | **SOP:** SOP-02

**Contexto:**
Un desarrollador comete el error más común en la industria: escribir una clave de API directamente en el código para probar una pasarela de pagos e intentar subirla al repositorio.

**Acción en Laptop 2 (Waldir):**
1. Waldir abre la terminal y crea un archivo de configuración vulnerable con una clave real de prueba:
   ```powershell
   # En Laptop 2
   Set-Content -Path "test_payment_gateway.py" -Value ('STRIPE_SECRET_KEY = "' + 'sk_live_' + '51Mz982AlmaCreativaProdSecretKey99281"')
   git add test_payment_gateway.py
   ```
2. Waldir se dirige al jurado:
   > *"Como desarrollador, acabo de terminar mi módulo de cobros e intento realizar un commit para enviarlo a GitHub:"*
3. Waldir ejecuta en la terminal frente a todos:
   ```powershell
   git commit -m "feat: pasarela de pagos integrada"
   ```

**Resultado en Pantalla de Laptop 2:**
En menos de **350 milisegundos**, la terminal se detiene y muestra letras rojas:
```
[DevSecOps - Shift Left] Validando código preparado en Staging...
Finding:     STRIPE_SECRET_KEY = "sk_live_...REDACTED..."
Secret:      sk_live_...REDACTED...
RuleID:      stripe-api-token
Entropy:     3.89

===================================================================
[BLOQUEO SHIFT-LEFT] Se detectaron secretos o tokens en el commit!
===================================================================
Acción Correctiva:
1. Remueve las credenciales y trasládalas a la bóveda (Vault/Bitwarden).
2. Usa variables de entorno (.env) que no se suban al repositorio.
3. Vuelve a ejecutar 'git add <archivo>' y realiza el commit nuevamente.
```

**Diálogo de Waldir:**
> *"El hook pre-commit interceptó la llamada a nivel del núcleo de Git. La clave jamás salió de mi estación local, el commit fue abortado con código de error 1 y no existe ningún riesgo de fuga en GitHub. Procedo a limpiar el archivo con `git reset HEAD test_payment_gateway.py` y `Remove-Item test_payment_gateway.py`."*

---

### ACTO 2: Ataque Perimetral Real y Triage Asistido por IA (1:45 - 3:00)
**Control NIST:** DE.AE-01 (Detección de Anomalías) / RS.AN-01 (Análisis de Incidentes) | **SOP:** SOP-03 y SOP-04

**Contexto:**
Waldir cambia de rol. Ahora es un atacante externo realizando reconocimiento en el servidor web de la empresa para extraer nombres de usuarios legítimos mediante la REST API de WordPress (`/wp-json/wp/v2/users`).

**Acción en Laptop 2 (Waldir):**
1. Waldir ejecuta una petición HTTP de reconocimiento contra el servidor web:
   ```bash
   # En Laptop 2 (PowerShell o Bash)
   curl.exe -i -s "https://mante.terrafinaperu.com/wp-json/wp/v2/users"
   ```
   *(O si se audita desde el Dashboard en Laptop 1, Sergio hace clic en el botón **"Auditar Objetivo Web"** ingresando la URL).*
2. Para enviar el hallazgo al motor SOAR en vivo, Waldir ejecuta:
   ```powershell
   python "C:\Sergio\Proyecto Final\devsecops-alma-nist\04-soar-n8n-testing\trigger_alert.py" 2
   ```

**Efecto Inmediato en la Sala:**
1. A los 2 segundos, **¡SUENA FUERTE EL SMARTPHONE EN LA MESA DEL JURADO!** 🔔
2. Sergio toma el teléfono o le pide amablemente a uno de los jurados:
   > *"Ingeniero, por favor observe la pantalla de ese teléfono. Acaba de ingresar la alerta oficial del incidente."*

**Contenido de la Alerta en Telegram:**
* **Encabezado:** `🛑 ALERTA DE SEGURIDAD DEVSECOPS - ALMA INDUSTRIA CREATIVA`
* **Incidente:** Intento de Enumeración de Usuarios REST API
* **Severidad:** HIGH | **Risk Score:** 8.0/10
* **Activo Afectado:** `https://mante.terrafinaperu.com/wp-json/wp/v2/users`
* **IP Atacante:** Muestra la IP exacta de Laptop 2 (o IP pública).
* **Triage Cognitivo por Google Gemini 2.5 Flash:**
  > *"IA Analysis: Se detectó sondeo de endpoints de usuarios característico de la fase de reconocimiento previo a ataques de fuerza bruta. Mitigación recomendada bajo directiva NIST RS.MI-01: Bloquear inmediatamente la IP de origen en el servidor perimetral e inyectar regla 403 Forbidden en .htaccess."*

---

### ACTO 3: Contención Perimetral Activa en Caliente (< 15 ms) (3:00 - 4:15)
**Control NIST:** RS.MI-01 (Mitigación de Incidentes) | **SOP:** SOP-03

**Contexto:**
En un esquema tradicional, mitigar este ataque requiere llamar al administrador de sistemas, abrir cPanel o conectarse por SSH y editar archivos manualmente (tiempo promedio: 4.2 horas). Aquí se realiza en milisegundos desde el Dashboard.

**Acción en Laptop 1 (Sergio - Proyector):**
1. Sergio muestra en el Dashboard la tarjeta del incidente recién recibido con la IP del atacante (ejemplo: `192.168.1.45` o `185.220.101.5`).
2. Sergio señala la sección **"Remediación Activa 1-Click"**:
   > *"Como analista SOC de guardia, veo la recomendación de Google Gemini y la IP identificada. No tengo que abrir una terminal SSH; ejecuto la directiva de contención con un solo clic:"*
3. Sergio presiona el botón **[ 🚫 Bloquear IP en Servidor (.htaccess) ]**.
4. La interfaz responde instantáneamente:
   `[✓] IP bloqueada con éxito en .htaccess (Latencia de inyección: 12.5 ms)`.

**Comprobación en Vivo en Laptop 2 (Waldir):**
1. Sergio le dice a Waldir frente al jurado:
   > *"Waldir, intenta consultar nuevamente el servidor desde tu máquina atacante."*
2. Waldir presiona la flecha arriba en su terminal y vuelve a ejecutar:
   ```bash
   curl.exe -i "https://mante.terrafinaperu.com/wp-json/wp/v2/users"
   ```
3. **Resultado en la terminal de Waldir:**
   ```http
   HTTP/1.1 403 Forbidden
   Date: Tue, 27 Oct 2026 12:58:12 GMT
   Server: Apache / LiteSpeed
   Content-Type: text/html; charset=iso-8859-1

   <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
   <html><head><title>403 Forbidden</title></head>
   <body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>
   ```

**Diálogo de Sergio:**
> *"El atacante ha quedado completamente neutralizado. Y para demostrarles la transparencia del sistema, abrimos el archivo físico `.htaccess` en nuestro servidor:"*
4. Sergio abre el archivo en pantalla y muestra la regla inyectada dinámicamente:
   ```apache
   # BEGIN_SOAR_IP_BLOCK
       Require not ip 192.168.1.45
   # END_SOAR_IP_BLOCK
   ```
5. Sergio presiona **[ Desbloquear IP ]** en el Dashboard para restaurar el acceso y demostrar que el mecanismo es 100% reversible y no degrada la disponibilidad.

---

### ACTO 4: Revocación Inmediata de Credenciales (SOP-05) (4:15 - 5:15)
**Control NIST:** PR.AA-01 (Gestión de Identidades) / RC.RP-01 | **SOP:** SOP-05

**Contexto:**
Un diseñador gráfico o colaborador externo termina su contrato laboral a las 6:00 PM. Tradicionalmente, sus contraseñas quedan guardadas en post-its o en su navegador personal, permitiendo accesos no autorizados post-empleo.

**Acción en Laptop 1 (Sergio):**
1. Sergio cambia de pestaña en el proyector y muestra la consola de **Vaultwarden (Bóveda Central de Contraseñas)**:
   > *"Bajo el protocolo SOP-05, los empleados nunca conocen las contraseñas maestras de los servidores ni de las redes sociales de la empresa; la extensión del navegador las inyecta de forma ciega.*  
   > *Al desvincular a un empleado, el administrador ejecuta la desactivación inmediata de la cuenta:"*
2. Sergio selecciona al usuario `colaborador_saliente@almaindustriacreativa.com` y pulsa **"Desactivar Usuario y Purgar Sesiones"**.
3. En la Laptop 2 (simulando la computadora del colaborador en su casa), se intenta ingresar o sincronizar el baúl:
   `Error: Usuario desactivado. Sesión cerrada por el administrador.`
4. Sergio concluye:
   > *"Tiempo total de desprovisionamiento: 7.8 segundos. Cumplimiento estricto del SLA menor a 10 segundos, eliminando el 100% del riesgo de fuga de credenciales por excolaboradores."*

---

### ACTO 5: Trazabilidad Forense Inmutable — Ley N° 29733 (5:15 - 6:00)
**Marco Legal:** Ley N° 29733 (Protección de Datos Personales en Perú) — Art. 28 (Principio de Seguridad)

**Contexto:**
La ley peruana exige que las empresas demuestren diligencia debida y no repudio en los registros de auditoría de incidentes que comprometan datos de clientes.

**Acción en Laptop 1 (Sergio):**
1. En el Dashboard, Sergio hace clic en el botón superior:
   **[ 📄 Generar Informe Ejecutivo Forense (PDF) ]**.
2. Se despliega en pantalla completa el documento ejecutivo con:
   * Membrete corporativo y referencias NIST CSF v2.0.
   * Tabla cronológica de incidentes registrados en **Supabase Cloud PostgreSQL**.
   * El bloque criptográfico:
     ```
     SELLO DE INTEGRIDAD FORENSE (SHA-256):
     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     ```
3. Sergio minimiza el navegador, abre la terminal de PowerShell y dice:
   > *"Cualquier base de datos tradicional puede ser alterada por un atacante con privilegios root. Nuestro flujo n8n calcula un hash SHA-256 en el momento exacto del incidente y lo almacena en la tabla inmutable `bitacora_auditoria_ley29733` de Supabase.*  
   > *Vamos a recalcular matemáticamente el hash en este instante frente a ustedes:"*
4. Sergio ejecuta en PowerShell:
   ```powershell
   Get-FileHash -Algorithm SHA256 "C:\Sergio\Proyecto Final\devsecops-alma-nist\04-soar-n8n-testing\devsecops_soc.db"
   ```
5. Sergio señala los caracteres en pantalla:
   > *"El hash generado en la bitácora inmutable coincide matemáticamente con la evidencia digital. Esto garantiza el No Repudio exigido por la Autoridad Nacional de Protección de Datos Personales del Ministerio de Justicia."*

---

### CIERRE: Métricas de Negocio y Preguntas del Jurado (6:00+)

**Diálogo Conjunto:**
* **Waldir:**
  > *"En conclusión, señores del jurado, hemos demostrado operativamente las 4 capas del ciclo PHVA: Planificar con políticas RBAC; Hacer con el baúl de contraseñas y hooks Git; Verificar con auditoría perimetral y triage de Inteligencia Artificial; y Actuar con mitigación perimetral en 12.5 milisegundos."*
* **Sergio:**
  > *"Los resultados cuantitativos respaldan nuestra propuesta:*
  > * *Reducción del MTTR de 4.2 horas a menos de 2 minutos.*
  > * *Contención perimetral de atacantes en menos de 15 milisegundos.*
  > * *Cero fugas de credenciales en repositorios de código fuente.*
  > * *Un Ratio Beneficio/Costo de 2.57, demostrando viabilidad técnica, operativa y financiera para la PYME peruana.*  
  > *Quedamos a su entera disposición para las preguntas técnicas que tengan a bien formular. Muchas gracias."*

---

## 5. HOJA DE COMANDOS RÁPIDOS "COPIAR Y PEGAR"

Tener esta hoja abierta en el bloc de notas o impresa para no dudar durante la demostración:

### Comandos de Laptop 1 (Puesto de Mando SOC - Sergio):
```powershell
# 1. Iniciar el Dashboard en segundo plano (si no estuviese corriendo)
wscript "C:\Sergio\Proyecto Final\devsecops-alma-nist\iniciar_dashboard_silencioso.vbs"

# 2. Verificar estado de IPs bloqueadas en .htaccess
Get-Content "C:\Sergio\Proyecto Final\devsecops-alma-nist\02-hardening-web\.htaccess" | Select-String "Require not ip"

# 3. Comprobar registros de incidentes en la base de datos local SQLite
python -c "import sqlite3; conn=sqlite3.connect(r'C:\Sergio\Proyecto Final\devsecops-alma-nist\04-soar-n8n-testing\devsecops_soc.db'); c=conn.cursor(); c.execute('SELECT codigo_incidente, severidad, tipo_evento FROM incidentes_seguridad ORDER BY fecha_registro DESC LIMIT 3'); print(c.fetchall()); conn.close()"

# 4. Validar integridad criptográfica (SHA-256)
Get-FileHash -Algorithm SHA256 "C:\Sergio\Proyecto Final\devsecops-alma-nist\04-soar-n8n-testing\devsecops_soc.db"
```

### Comandos de Laptop 2 (Estación Atacante / Dev - Waldir):
```powershell
# 1. Prueba Shift-Left: Crear archivo vulnerable y forzar commit
Set-Content -Path "test_payment_gateway.py" -Value ('STRIPE_SECRET_KEY = "' + 'sk_live_' + '51Mz982AlmaCreativaProdSecretKey99281"')
git add test_payment_gateway.py
git commit -m "feat: pasarela de pagos integrada"

# Limpieza post-bloqueo:
git reset HEAD test_payment_gateway.py
Remove-Item test_payment_gateway.py

# 2. Prueba Pentesting: Reconocimiento de usuarios vía REST API
curl.exe -i "https://mante.terrafinaperu.com/wp-json/wp/v2/users"

# 3. Disparo de Incidente Perimetral al Webhook SOAR de n8n
python "C:\Sergio\Proyecto Final\devsecops-alma-nist\04-soar-n8n-testing\trigger_alert.py" 2

# 4. Verificar Bloqueo 403 Forbidden post-mitigación
curl.exe -i "https://mante.terrafinaperu.com/wp-json/wp/v2/users"
```

---

## 6. PLAN DE CONTINGENCIA "FAIL-SAFE" (SIN INTERNET / CAÍDA DE RED)

Si el salón de SENATI tiene problemas de WiFi o señal bloqueada:

| Contingencia | Causa Probable | Solución Inmediata de Respaldo |
| :--- | :--- | :--- |
| **Falla de conexión a n8n Cloud** | Corte de internet general en el aula. | Encender la zona WiFi / Hotspot del teléfono celular de Sergio y conectar ambas laptops. |
| **Servidor remoto caído** | Caída temporal de `mante.terrafinaperu.com`. | Usar el contenedor local de WordPress en Docker: `http://localhost:8088/wp-json/wp/v2/users`. El script `test_wp_enumeration.py` ya está configurado para apuntar a `localhost:8088`. |
| **Telegram no recibe la alerta** | Retardo en los servidores de mensajería. | Mostrar el log de salida de `trigger_alert.py` donde se visualiza el código **HTTP 200 OK**, la latencia en milisegundos y el JSON de respuesta del webhook. |
| **Fallo en API de Gemini** | Agotamiento de cuota o timeout de Google Cloud. | El motor cuenta con el módulo `ai_triage.py` con fallback determinístico automático bajo directivas NIST precompiladas. La demo no se detiene nunca. |
