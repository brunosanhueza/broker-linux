# Siemens PLC Smart Gateway & Proxy Multi-Puerto (502, 102, 80)

Servidor proxy intermedio (**Placeholder**) diseñado para **proteger PLCs Siemens (S7-1200 / S7-1500)** contra saturación de conexiones y consultas, actuando como una pasarela transparente y mostrando la identidad del PLC ante auditorías y escaneos de red (**Nmap**).

---

## 🚀 Puertos gestionados por el Gateway

1. **Puerto 502 (Modbus TCP):**
   - **Anti-saturación:** Mantiene **1 sola conexión persistente** hacia el PLC real, serializando las peticiones de múltiples clientes (SCADA, HMI, scripts) en cola con mutex lock.
   - **Identidad Nmap:** Intercepta la función **FC 43 (0x2B, MEI 14 - Read Device Identification)** respondiendo como un PLC Siemens SIMATIC oficial.
   - **Caché opcional:** Si varios clientes consultan los mismos registros simultáneamente, responde desde memoria con TTL en milisegundos.
2. **Puerto 102 (ISO-on-TCP / S7comm):**
   - El puerto por excelencia de Siemens (utilizado por TIA Portal, Step 7, WinCC, Snap7).
   - Reenvío transparente hacia el puerto 102 del PLC real.
   - Permite que escaneos de Nmap con el script oficial `s7-info.nse` obtengan los datos de hardware del PLC Siemens (número de serie, firmware, nombre del sistema, derechos "Original Siemens Equipment").
   - **Control de concurrencia:** Limita las conexiones simultáneas máximas hacia el PLC para no agotar los canales S7.
3. **Puerto 80 (HTTP / Web Server integrado Siemens):**
   - Reenvío hacia el servidor web del PLC. Permite que usuarios o auditores abran la interfaz web de diagnóstico del S7-1200/1500 directamente en el navegador.

---

## ⚙️ Configuración (`config.json`)

Edita el archivo [config.json](file:///c:/Users/zacky\Documents/broker-ubuntu/config.json):

```json
{
  "server": {
    "host": "0.0.0.0",
    "modbus_port": 502,
    "s7_port": 102,
    "http_port": 80
  },
  "plc": {
    "host": "192.168.1.100",           // <-- IP real del PLC Siemens
    "modbus_port": 502,
    "s7_port": 102,
    "http_port": 80,
    "timeout_seconds": 3.0,
    "reconnect_delay_seconds": 2.0
  },
  "features": {
    "enable_modbus_502": true,
    "enable_s7_102": true,
    "enable_http_80": true
  },
  "siemens_identity": {
    "intercept_fc43": true,
    "vendor_name": "SIEMENS AG",
    "product_code": "SIMATIC S7-1200",
    "revision": "V4.5.1",
    "vendor_url": "http://www.siemens.com",
    "product_name": "CPU 1214C DC/DC/DC",
    "model_name": "6ES7 214-1AG40-0XB0",
    "user_application_name": "PLC-SIEMENS-LINEA1"
  },
  "performance": {
    "cache_enabled": false,
    "cache_ttl_ms": 250,
    "max_modbus_connections": 100,
    "max_s7_connections": 8,
    "max_http_connections": 15
  }
}
```

---

## 🐧 Despliegue en Debian / Ubuntu

### Opción 1: Instalación Rápida con Git e `install.sh` (Recomendada)

En tu servidor Debian o Ubuntu recién instalado:

```bash
# 1. Clonar el repositorio
git clone <URL_DE_TU_REPOSITORIO> /tmp/modbus-gateway
cd /tmp/modbus-gateway

# 2. Ejecutar el instalador automático
sudo bash install.sh
```

El script se encargará automáticamente de:
- Verificar e instalar Python 3 si no está presente.
- Desplegar la aplicación en `/opt/modbus-gateway`.
- Configurar y arrancar el servicio en segundo plano con `systemd`.
- Proteger tu `config.json` para no sobreescribir tus IPs en futuras actualizaciones.

Para editar la configuración después de instalar:
```bash
sudo nano /opt/modbus-gateway/config.json
sudo systemctl restart modbus-gateway
```

---

### Opción 2: Ejecutar manualmente con Python

```bash
sudo python3 modbus_gateway.py config.json
```

---

### Opción 3: Con Docker / Docker Compose

```bash
sudo docker compose up -d
```

---

## 🔍 Verificación con Nmap (Los 3 puertos)

Para comprobar cómo se ve el servidor desde otra máquina de la red:

```bash
nmap -p 80,102,502 -sV -sC <IP_DEL_SERVIDOR>
```

### Resultado esperado:
```text
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Siemens SIMATIC S7 Web Server
|_http-title: Siemens SIMATIC S7 Webserver
102/tcp open  iso-tsap Siemens S7 PLC
| s7-info: 
|   Module: 6ES7 214-1AG40-0XB0
|   Basic Hardware: 6ES7 214-1AG40-0XB0
|   Version: 4.5.1
|   System Name: SIMATIC-1200
|   Module Type: CPU 1214C DC/DC/DC
|_  Copyright: Original Siemens Equipment
502/tcp open  modbus   Modbus TCP
| modbus-discover:
|   Vendor: SIEMENS AG
|   Product Code: SIMATIC S7-1200
|   Revision: V4.5.1
|   Vendor URL: http://www.siemens.com
|   Product Name: CPU 1214C DC/DC/DC
|   Model Name: 6ES7 214-1AG40-0XB0
|_  Device Name: PLC-SIEMENS-LINEA1
```
