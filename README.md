# Modbus TCP Smart Gateway & Proxy con Identidad Siemens

Servidor proxy intermedio diseñado para **proteger PLCs Siemens (S7-1200 / S7-1500)** contra saturación de conexiones y consultas, actuando como una pasarela transparente y mostrando la identidad del PLC ante auditorías y escaneos de red (**Nmap**).

---

## 🚀 ¿Qué resuelve este Gateway?

1. **Evita la saturación del PLC:**
   - Los PLCs Siemens (bloque `MB_SERVER`) tienen un límite estricto de conexiones TCP concurrentes (usualmente entre 1 y 4 sockets). Si múltiples sistemas (SCADA, HMI, Grafana, scripts) intentan conectarse al mismo tiempo, el PLC rechaza conexiones (`ECONNREFUSED` / `Connection reset`).
   - El Gateway acepta **decenas o cientos de clientes concurrentes** en el servidor, pero mantiene **una única conexión persistente hacia el PLC real**, serializando las peticiones en cola de forma segura.
2. **Caché opcional de alta velocidad:**
   - Si varios clientes consultan los mismos registros simultáneamente, el Gateway puede responder desde memoria (con TTL de milisegundos configurable), eliminando el 80% de la carga del PLC.
3. **Identidad Siemens en escaneos Nmap (Spoofing / Reconocimiento):**
   - Intercepta el código de función **Modbus FC 43 (0x2B, MEI Type 14 - Read Device Identification)**.
   - Cuando se escanea la IP del servidor con `nmap --script modbus-discover -p 502 <IP_SERVIDOR>`, responde directamente con la información oficial de un **PLC Siemens SIMATIC** con el nombre que elijas.

---

## ⚙️ Configuración (`config.json`)

Edita el archivo [config.json](file:///c:/Users/zacky/Documents/broker-ubuntu/config.json):

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 502
  },
  "plc": {
    "host": "192.168.1.100",           // <-- IP real del PLC Siemens
    "port": 502,                       // <-- Puerto Modbus del PLC
    "timeout_seconds": 3.0,
    "reconnect_delay_seconds": 2.0
  },
  "siemens_identity": {
    "intercept_fc43": true,
    "vendor_name": "SIEMENS AG",
    "product_code": "SIMATIC S7-1200",
    "revision": "V4.5.1",
    "vendor_url": "http://www.siemens.com",
    "product_name": "CPU 1214C DC/DC/DC",
    "model_name": "6ES7 214-1AG40-0XB0",
    "user_application_name": "PLC-SIEMENS-LINEA1" // <-- Nombre identificativo
  },
  "performance": {
    "cache_enabled": false,
    "cache_ttl_ms": 250,
    "max_client_connections": 100
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

## 🔍 Verificación con Nmap

Para comprobar cómo se ve el servidor desde otra máquina de la red:

```bash
nmap -p 502 -sV --script modbus-discover <IP_DEL_SERVIDOR>
```

### Resultado esperado:
```text
PORT    STATE SERVICE VERSION
502/tcp open  modbus  Modbus TCP
| modbus-discover:
|   Vendor: SIEMENS AG
|   Product Code: SIMATIC S7-1200
|   Revision: V4.5.1
|   Vendor URL: http://www.siemens.com
|   Product Name: CPU 1214C DC/DC/DC
|   Model Name: 6ES7 214-1AG40-0XB0
|_  Device Name: PLC-SIEMENS-LINEA1
```
