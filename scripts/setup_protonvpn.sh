#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus - Instalador Opcional Verificado de Proton VPN
# Utilidad independiente para usuarios que deseen instalar Proton VPN con
# verificación criptográfica estricta previa a la instalación.
# ==============================================================================
set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Este script debe ejecutarse como root:${NC} sudo ./setup_protonvpn.sh" >&2
    exit 1
fi

echo -e "${BOLD}${CYAN}🛡️  Configuración Opcional de Proton VPN para Constantine Antivirus${NC}"
echo "======================================================================"
echo -e "Proton VPN es una herramienta de red de terceros independiente del antivirus."
echo -e "Este instalador verifica la autenticidad criptográfica del paquete antes de instalarlo."
echo ""

# Comprobar si ya está instalado
if command -v protonvpn >/dev/null 2>&1 || command -v protonvpn-cli >/dev/null 2>&1 || command -v proton-vpn-gnome-desktop >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Proton VPN ya se encuentra instalado en este equipo.${NC}"
    exit 0
fi

read -r -p "¿Deseas descargar e instalar el repositorio oficial de Proton VPN? [s/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[sS]$ ]]; then
    echo "Instalación cancelada por el usuario."
    exit 0
fi

# Parámetros del paquete y firma oficial de Proton AG
PROTON_URL="https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.6_all.deb"
# Suma de comprobación SHA-256 oficial del paquete publicado por Proton AG
EXPECTED_SHA256="c20163351ecf33230a1cffbfa283305ecbf232f3f98ce36605a9638bcfe8f1dc"
TMP_DEB="/tmp/protonvpn_release_verified.deb"

echo -e "\n${BOLD}1. Descargando paquete oficial de repositorio Proton...${NC}"
if command -v curl >/dev/null 2>&1; then
    curl -sSL -o "$TMP_DEB" "$PROTON_URL"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMP_DEB" "$PROTON_URL"
else
    echo -e "${RED}❌ Se requiere curl o wget para realizar la descarga.${NC}" >&2
    exit 1
fi

echo -e "${BOLD}2. Verificando autenticidad e integridad criptográfica (SHA-256)...${NC}"
ACTUAL_SHA256=$(sha256sum "$TMP_DEB" | awk '{print $1}')

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    rm -f "$TMP_DEB"
    echo -e "${RED}❌ [FALLO DE SEGURIDAD]: La suma de comprobación del paquete descargado no coincide.${NC}" >&2
    echo "   Esperado: $EXPECTED_SHA256" >&2
    echo "   Obtenido: $ACTUAL_SHA256" >&2
    echo "El archivo descargado ha sido eliminado y la instalación fue abortada." >&2
    exit 1
fi

echo -e "${GREEN}✅ Integridad SHA-256 verificada con éxito.${NC}"

echo -e "${BOLD}3. Instalando repositorio verificado mediante dpkg...${NC}"
dpkg -i "$TMP_DEB"
rm -f "$TMP_DEB"

echo -e "${BOLD}4. Actualizando índices de paquetes e instalando cliente oficial...${NC}"
apt-get update -qq
apt-get install -y protonvpn-cli || apt-get install -y proton-vpn-gnome-desktop || true

if command -v protonvpn >/dev/null 2>&1 || command -v protonvpn-cli >/dev/null 2>&1; then
    echo -e "\n${GREEN}🎉 Proton VPN instalado y verificado correctamente.${NC}"
    echo "Constantine Antivirus detectará automáticamente el cliente en la pestaña de Red."
else
    echo -e "\n${YELLOW}⚠️  El repositorio fue configurado, pero el paquete de escritorio no se pudo completar automáticamente.${NC}"
    echo "Puedes ejecutar manualmente: sudo apt install proton-vpn-gnome-desktop"
fi
