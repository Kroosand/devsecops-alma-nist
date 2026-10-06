-- ==============================================================================
-- ESQUEMA OFICIAL SUPABASE (POSTGRESQL): DEVSECOPS SOC & LEY N° 29733
-- Organización: komi | Proyecto: PROYECTO-FINAL (scuiibzfhingcxdoorsj)
-- Empresa: Alma Industria Creativa E.I.R.L. | SENATI
-- ==============================================================================

-- 1. TABLA: ACTIVOS DE INFORMACIÓN (NIST ID.AM-01)
CREATE TABLE IF NOT EXISTS activos_informacion (
    id_activo BIGSERIAL PRIMARY KEY,
    codigo_activo VARCHAR(50) UNIQUE NOT NULL,
    nombre_activo VARCHAR(150) NOT NULL,
    tipo_activo VARCHAR(50) NOT NULL,
    criticidad VARCHAR(20) NOT NULL,
    responsable_custodia VARCHAR(100) NOT NULL,
    segmento_vlan VARCHAR(30) DEFAULT 'VLAN 99',
    estado VARCHAR(20) DEFAULT 'ACTIVO',
    creado_en TIMESTAMPTZ DEFAULT NOW()
);

-- 2. TABLA: OPERADORES SOC (NIST PR.AA-01 / RBAC)
CREATE TABLE IF NOT EXISTS usuarios_soc (
    id_usuario BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    nombre_completo VARCHAR(120) NOT NULL,
    rol VARCHAR(50) NOT NULL,
    correo VARCHAR(100) NOT NULL,
    canal_notificacion VARCHAR(50) DEFAULT 'Telegram Bot',
    estado VARCHAR(20) DEFAULT 'ACTIVO',
    ultimo_acceso TIMESTAMPTZ DEFAULT NOW()
);

-- 3. TABLA PRINCIPAL: HISTORIAL DE INCIDENTES (NIST RS.AN-01 / SOP-04)
CREATE TABLE IF NOT EXISTS incidentes_seguridad (
    id_incidente BIGSERIAL PRIMARY KEY,
    codigo_incidente VARCHAR(50) UNIQUE NOT NULL,
    fecha_registro TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tipo_evento VARCHAR(100) NOT NULL,
    severidad VARCHAR(20) NOT NULL,
    risk_score NUMERIC(4,2) NOT NULL,
    origen_sensor VARCHAR(100) NOT NULL,
    ip_origen VARCHAR(80),
    activo_afectado VARCHAR(150) NOT NULL,
    detalles_tecnicos TEXT,
    control_nist VARCHAR(80) NOT NULL,
    procedimiento_sop VARCHAR(80) NOT NULL,
    resumen_ia TEXT,
    acciones_recomendadas TEXT,
    estado_incidente VARCHAR(30) DEFAULT 'MITIGADO',
    mitigado_en TIMESTAMPTZ DEFAULT NOW()
);

-- 4. TABLA: TELEMETRÍA Y MÉTRICAS DE MTTR (NIST RC.RP-01 / CAPÍTULO VI)
CREATE TABLE IF NOT EXISTS telemetria_mttr (
    id_metrica BIGSERIAL PRIMARY KEY,
    codigo_incidente VARCHAR(50) REFERENCES incidentes_seguridad(codigo_incidente) ON DELETE CASCADE,
    latencia_red_ms NUMERIC(8,2) NOT NULL,
    codigo_respuesta_http INT NOT NULL,
    entrega_exitosa BOOLEAN NOT NULL DEFAULT TRUE,
    mttr_calculado_min NUMERIC(6,2) DEFAULT 5.05,
    ahorro_tiempo_min NUMERIC(6,2) DEFAULT 249.95,
    fecha_medicion TIMESTAMPTZ DEFAULT NOW()
);

-- 5. TABLA: BITÁCORA INMUTABLE DE AUDITORÍA (LEY N° 29733 / SOP-06)
CREATE TABLE IF NOT EXISTS bitacora_auditoria_ley29733 (
    id_log BIGSERIAL PRIMARY KEY,
    codigo_incidente VARCHAR(50) REFERENCES incidentes_seguridad(codigo_incidente) ON DELETE CASCADE,
    evento_auditado VARCHAR(150) NOT NULL,
    hash_integridad_sha256 VARCHAR(64) NOT NULL,
    estado_trazabilidad VARCHAR(50) DEFAULT 'TRAZABILIDAD_GARANTIZADA',
    registrado_por VARCHAR(80) DEFAULT 'n8n_SOAR_Engine',
    fecha_sellado_tiempo TIMESTAMPTZ DEFAULT NOW()
);

-- ÍNDICES DE RENDIMIENTO
CREATE INDEX IF NOT EXISTS idx_incidentes_fecha ON incidentes_seguridad(fecha_registro);
CREATE INDEX IF NOT EXISTS idx_incidentes_severidad ON incidentes_seguridad(severidad);

-- POBLAR DATOS INICIALES DE LÍNEA BASE (SEMILLAS)
INSERT INTO activos_informacion (codigo_activo, nombre_activo, tipo_activo, criticidad, responsable_custodia, segmento_vlan)
VALUES 
    ('ACT-WP-01', 'CMS WordPress Producción (almaindustriacreativa.com)', 'Servidor Web', 'CRITICA', 'Sergio Incacutipa', 'VLAN 99'),
    ('ACT-GIT-01', 'Repositorio GitHub devsecops-alma-nist', 'Repositorio Código', 'ALTA', 'Waldir Chullo', 'VLAN 20'),
    ('ACT-VAULT-01', 'Bóveda de Secretos HashiCorp Vault (:8200)', 'Infraestructura', 'CRITICA', 'Sergio Incacutipa', 'VLAN 99'),
    ('ACT-VW-01', 'Vaultwarden Bóveda Contraseñas (:8080)', 'Bóveda Humana', 'ALTA', 'Waldir Chullo', 'VLAN 10')
ON CONFLICT (codigo_activo) DO NOTHING;

INSERT INTO usuarios_soc (username, nombre_completo, rol, correo, canal_notificacion)
VALUES 
    ('s_incacutipa', 'Sergio Saul Incacutipa Mamani', 'DevSecOps Lead', 'sergio@almaindustriacreativa.com', 'Telegram Bot'),
    ('w_chullo', 'Waldir Rivaldo Chullo Chuma', 'SOC Infrastructure Lead', 'waldir@almaindustriacreativa.com', 'Telegram Bot')
ON CONFLICT (username) DO NOTHING;
