# ==============================================================================
# POLÍTICA RBAC: QA / ESPECIALISTA EN AUTOMATIZACIÓN (GROWTH)
# Control: SOP-01 (PR.AA-01) - Principio de Menor Privilegio
# ==============================================================================

# Acceso a tokens de testing, APIs de SEO y endpoints de staging
path "secret/data/growth/qa/*" {
  capabilities = ["create", "read", "update", "list"]
}

# Acceso de lectura a tokens de webhooks de prueba
path "secret/data/growth/n8n/testing-webhooks" {
  capabilities = ["read"]
}

# Denegar acceso a infraestructura crítica
path "secret/data/infrastructure/*" {
  capabilities = ["deny"]
}
