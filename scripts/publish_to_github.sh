#!/usr/bin/env bash
# Script para conectar y publicar automáticamente Constantine en tu GitHub
set -e

echo "⚔️ Publicador de Constantine Antivirus a GitHub"
echo "=============================================="

if ! command -v git &> /dev/null; then
    echo "Error: git no está instalado."
    exit 1
fi

# Comprobar si GitHub CLI está instalado
if command -v gh &> /dev/null; then
    echo "GitHub CLI detectado."
    echo "¿Deseas crear y publicar el repositorio automáticamente con 'gh'? (s/n)"
    read -r resp
    if [[ "$resp" =~ ^[sS]$ ]]; then
        gh repo create constantine-antivirus --public --source=. --remote=origin --push
        echo "✅ ¡Repositorio creado y publicado exitosamente en GitHub!"
        exit 0
    fi
fi

# Flujo estándar con URL de repositorio existente
echo "Por favor introduce tu nombre de usuario de GitHub o la URL del repositorio:"
read -p "Usuario o URL (ej: mi-usuario o https://github.com/mi-usuario/constantine-antivirus.git): " input_target

if [[ "$input_target" =~ ^https:// || "$input_target" =~ ^git@ ]]; then
    REPO_URL="$input_target"
else
    REPO_URL="https://github.com/${input_target}/constantine-antivirus.git"
fi

git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL"
git branch -M main

echo "Subiendo código a $REPO_URL..."
git push -u origin main

echo "✅ ¡Publicación completada exitosamente!"
