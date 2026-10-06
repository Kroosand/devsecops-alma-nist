-- ==============================================================================
-- ESQUEMA DE BASE DE DATOS RELACIONAL: CENTRO DE CONTROL SOC & DEVSECOPS
-- Empresa: Alma Industria Creativa E.I.R.L.
-- Proyecto: Titulación SENATI - DevSecOps NIST CSF v2.0
-- Motor: SQLite3 / PostgreSQL / MySQL Compatible (ANSI SQL)
-- Control: NIST CSF v2.0 (DE.CM-01 / RS.AN-01 / GV.OC-01) & Ley N° 29733
-- ==============================================================================

-- 1. TABLA: ACTIVOS DE INFORMACIÓN CUSTODIADOS (NIST ID.AM-01)
CREATE TABLE IF NOT EXISTS activos_informacion (
    id_activo INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_activo VARCHAR(50) UNIQUE NOT NULL,      -- Ej: ACT-WP-01, ACT-REPO-01
    nombre_activo VARCHAR(150) NOT NULL,            -- Ej: CMS WordPress Producción
    tipo_activo VARCHAR(50) NOT NULL,               -- Servidor, Repositorio, Base de Datos, API
    criticidad VARCHAR(20) NOT NULL,                -- CRITICA, ALTA, MEDIA, BAJA
    responsable_custodia VARCHAR(100) NOT NULL,     -- Sergio Incacutipa / Waldir Chullo
    segmento_vlan VARCHAR(30) DEFAULT 'VLAN 99',    -- VLAN 10, 20, 30, 99
    estado VARCHAR(20) DEFAULT 'ACTIVO',
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. TABLA: OPERADORES Y ANALISTAS SOC (NIST PR.AA-01 / RBAC)
CREATE TABLE IF NOT EXISTS usuarios_soc (
    id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    nombre_completo VARCHAR(120) NOT NULL,
    rol VARCHAR(50) NOT NULL,                       -- DevSecOps Lead, SOC Analyst, Admin
    correo VARCHAR(100) NOT NULL,
    canal_notificacion VARCHAR(50) DEFAULT 'Telegram Bot',
    estado VARCHAR(20) DEFAULT 'ACTIVO',
    ultimo_acceso DATETIME
);

-- 3. TABLA PRINCIPAL: HISTORIAL DE INCIDENTES DE CIBERSEGURIDAD (NIST RS.AN-01 / SOP-04)
CREATE TABLE IF NOT EXISTS incidentes_seguridad (
    id_incidente INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_incidente VARCHAR(50) UNIQUE NOT NULL,   -- Ej: ALMA-SEC-A4CF71C9
    fecha_registro DATETIME NOT NULL,
    tipo_evento VARCHAR(100) NOT NULL,              -- Fuga de Secretos, Enumeración REST, etc.
    severidad VARCHAR(20) NOT NULL,                 -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score DECIMAL(4,2) NOT NULL,               -- Escala CVSS 0.00 a 10.00
    origen_sensor VARCHAR(100) NOT NULL,            -- Gitleaks, Hardening .htaccess, WAF, etc.
    ip_origen VARCHAR(80),                          -- IP atacante o estación interna
    activo_afectado VARCHAR(150) NOT NULL,
    detalles_tecnicos TEXT,
    control_nist VARCHAR(80) NOT NULL,              -- Ej: PR.PS-01 / DE.CM-01
    procedimiento_sop VARCHAR(80) NOT NULL,         -- Ej: SOP-02 (Shift-Left)
    estado_incidente VARCHAR(30) DEFAULT 'MITIGADO',-- DETECTADO, EN_TRIAGE, MITIGADO, CERRADO
    mitigado_en DATETIME
);

-- 4. TABLA: TRIAGE ASISTIDO POR IA Y ACCIONES DE REMEDIACIÓN (SOP-07 / NIST RS.MI-01)
CREATE TABLE IF NOT EXISTS triage_inteligencia_artificial (
    id_triage INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_incidente VARCHAR(50) NOT NULL,
    modelo_ia VARCHAR(60) NOT NULL,                 -- Google Gemini 2.5 Flash / Claude Sonnet
    triage_origen VARCHAR(80) NOT NULL,             -- Nodo n8n IA / Python SOC Module
    resumen_diagnostico_ia TEXT NOT NULL,
    acciones_sugeridas TEXT NOT NULL,
    latencia_inferencia_ms DECIMAL(8,2),
    fecha_triage DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codigo_incidente) REFERENCES incidentes_seguridad(codigo_incidente) ON DELETE CASCADE
);

-- 5. TABLA: TELEMETRÍA Y MÉTRICAS EMPÍRICAS DE MTTR (NIST RC.RP-01 / CAPÍTULO VI)
CREATE TABLE IF NOT EXISTS telemetria_mttr (
    id_metrica INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_incidente VARCHAR(50) NOT NULL,
    latencia_red_ms DECIMAL(8,2) NOT NULL,          -- Tiempo de despacho hacia Webhook n8n
    codigo_respuesta_http INTEGER NOT NULL,         -- 200 OK, 403, 500
    entrega_exitosa BOOLEAN NOT NULL DEFAULT 1,
    mttr_calculado_min DECIMAL(6,2),                -- MTTR automatizado (~5.05 min)
    ahorro_tiempo_min DECIMAL(6,2),                 -- Ahorro vs 255 min manual
    fecha_medicion DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codigo_incidente) REFERENCES incidentes_seguridad(codigo_incidente) ON DELETE CASCADE
);

-- 6. TABLA: BITÁCORA INMUTABLE DE AUDITORÍA Y TRAZABILIDAD (LEY N° 29733 / SOP-06)
CREATE TABLE IF NOT EXISTS bitacora_auditoria_ley29733 (
    id_log INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_incidente VARCHAR(50) NOT NULL,
    evento_auditado VARCHAR(150) NOT NULL,
    hash_integridad_sha256 VARCHAR(64) NOT NULL,    -- Firma criptográfica del evento
    estado_trazabilidad VARCHAR(50) DEFAULT 'TRAZABILIDAD_GARANTIZADA',
    registrado_por VARCHAR(80) DEFAULT 'n8n_REGISTRO_AUDITORIA_NIST',
    fecha_sellado_tiempo DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codigo_incidente) REFERENCES incidentes_seguridad(codigo_incidente) ON DELETE CASCADE
);

-- ÍNDICES DE ALTO RENDIMIENTO PARA CONSULTAS FORENSES Y REPORTES
CREATE INDEX IF NOT EXISTS idx_incidentes_fecha ON incidentes_seguridad(fecha_registro);
CREATE INDEX IF NOT EXISTS idx_incidentes_severidad ON incidentes_seguridad(severidad);
CREATE INDEX IF NOT EXISTS idx_telemetria_incidente ON telemetria_mttr(codigo_incidente);
