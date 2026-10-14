#!/usr/bin/env bash
# ==============================================================================
# Script de desinstalación para Debian / Ubuntu
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[!] Por favor, ejecuta este script con sudo: sudo bash uninstall.sh"
  exit 1
fi

SERVICE_NAME="modbus-gateway.service"
INSTALL_DIR="/opt/modbus-gateway"

echo "===> Deteniendo y deshabilitando el servicio..."
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

echo "===> Eliminando archivo de servicio systemd..."
rm -f "/etc/systemd/system/${SERVICE_NAME}"
systemctl daemon-reload
systemctl reset-failed

echo "===> ¿Deseas eliminar también los archivos en ${INSTALL_DIR} incluyendo la configuración? (s/N)"
read -r respuesta
if [[ "$respuesta" =~ ^[sS]$ ]]; then
    rm -rf "${INSTALL_DIR}"
    echo "[+] Directorio ${INSTALL_DIR} eliminado."
else
    echo "[+] Se conservaron los archivos en ${INSTALL_DIR}."
fi

echo "================================================================="
echo "  Desinstalación finalizada con éxito."
echo "================================================================="
