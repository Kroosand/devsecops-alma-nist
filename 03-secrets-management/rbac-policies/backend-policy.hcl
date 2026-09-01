# ==============================================================================
# POLÍTICA RBAC: DESARROLLADOR BACKEND
# Control: SOP-01 (PR.AA-01) - Principio de Menor Privilegio
# ==============================================================================

# Lectura y creación de credenciales de desarrollo backend
path "secret/data/growth/backend/*" {
  capabilities = ["create", "read", "update", "list"]
}

# Lectura de credenciales de staging de base de datos
path "secret/data/infrastructure/staging-db" {
  capabilities = ["read"]
}

# Denegar acceso a secretos de producción directa sin aprobación
path "secret/data/infrastructure/production-master-keys" {
  capabilities = ["deny"]
}
