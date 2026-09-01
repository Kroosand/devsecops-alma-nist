# ==============================================================================
# POLÍTICA RBAC: DESARROLLADOR FRONTEND
# Control: SOP-01 (PR.AA-01) - Principio de Menor Privilegio
# ==============================================================================

# Acceso de solo lectura a APIs públicas y variables de entorno frontend
path "secret/data/growth/frontend/*" {
  capabilities = ["read", "list"]
}

# Prohibición explícita de acceso a credenciales de base de datos o claves privadas de servidores
path "secret/data/infrastructure/*" {
  capabilities = ["deny"]
}

path "secret/data/growth/backend/*" {
  capabilities = ["deny"]
}
