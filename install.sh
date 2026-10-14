#!/usr/bin/env bash
# ==============================================================================
# Script de instalación automática para Debian / Ubuntu
# ==============================================================================

set -e

# Asegurar privilegios de root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Por favor, ejecuta este script con sudo: sudo bash install.sh"
  exit 1
fi

INSTALL_DIR="/opt/modbus-gateway"
SERVICE_NAME="modbus-gateway.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "===> [1/5] Verificando dependencias en Debian/Ubuntu..."
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 no encontrado. Instalando via apt..."
    apt-get update -y
    apt-get install -y python3
else
    echo "[+] Python3 ya está instalado: $(python3 --version)"
fi

echo "===> [2/5] Creando directorio de despliegue en ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"

echo "===> [3/5] Copiando archivos de la aplicación..."
cp "${SCRIPT_DIR}/modbus_gateway.py" "${INSTALL_DIR}/"

# Si ya existe un config.json en /opt, no sobreescribirlo para no perder la IP real del usuario
if [ -f "${INSTALL_DIR}/config.json" ]; then
    echo "[!] Se detectó un config.json existente en ${INSTALL_DIR}. Se mantendrá intacto."
else
    if [ -f "${SCRIPT_DIR}/config.json" ]; then
        cp "${SCRIPT_DIR}/config.json" "${INSTALL_DIR}/"
    else
        cp "${SCRIPT_DIR}/config.example.json" "${INSTALL_DIR}/config.json"
    fi
    echo "[+] Archivo de configuración instalado en ${INSTALL_DIR}/config.json"
fi

echo "===> [4/5] Configurando servicio systemd..."
cp "${SCRIPT_DIR}/${SERVICE_NAME}" "/etc/systemd/system/${SERVICE_NAME}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo "===> [5/5] Verificando estado del servicio..."
sleep 1
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "================================================================="
    echo "  ¡INSTALACIÓN COMPLETADA EXITOSAMENTE EN DEBIAN/UBUNTU!"
    echo "================================================================="
    echo "  - Servicio: Activo y en ejecución (puerto 502)"
    echo "  - Configuración: ${INSTALL_DIR}/config.json"
    echo ""
    echo "  Comandos útiles:"
    echo "    Ver logs:      sudo journalctl -u ${SERVICE_NAME} -f"
    echo "    Reiniciar:     sudo systemctl restart ${SERVICE_NAME}"
    echo "    Detener:       sudo systemctl stop ${SERVICE_NAME}"
    echo "    Editar config: sudo nano ${INSTALL_DIR}/config.json"
    echo "================================================================="
else
    echo "[!] El servicio no pudo arrancar. Revisa los logs con: journalctl -u ${SERVICE_NAME} -xe"
    exit 1
fi
