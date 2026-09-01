#!/usr/bin/env bash
# ==============================================================================
# Script de Instalación Automatizada de Git Hooks (Linux / macOS / Git Bash)
# ==============================================================================

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
    echo "[!] Error: No estás dentro de un repositorio Git."
    exit 1
fi

HOOKS_DIR="$REPO_ROOT/.git/hooks"
SOURCE_HOOK="$REPO_ROOT/01-shift-left/hooks/pre-commit"
TARGET_HOOK="$HOOKS_DIR/pre-commit"

mkdir -p "$HOOKS_DIR"
cp "$SOURCE_HOOK" "$TARGET_HOOK"
chmod +x "$TARGET_HOOK"

echo "[+] Git Pre-commit Hook instalado exitosamente en:"
echo "    $TARGET_HOOK"
echo "[+] Todo 'git commit' ahora será validado automáticamente con Gitleaks."
