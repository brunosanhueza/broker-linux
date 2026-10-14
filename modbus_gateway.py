#!/usr/bin/env python3
"""
Modbus TCP Smart Gateway & Proxy con Identidad Siemens
======================================================
- Intercepta consultas en el puerto 502 (o configurado).
- Multiplexa múltiples conexiones de clientes (SCADA, HMI, scripts) en una única
  conexión persistente y serializada hacia el PLC real para evitar saturar sockets y CPU.
- Intercepta peticiones de identificación (FC 43 / 0x2B MEI 14) respondiendo
  como un PLC Siemens (Vendor, Modelo, Versión, etc.) para escaneos como Nmap.
- Soporta caché opcional para lecturas repetidas (evita query storms).
- Genera respuestas de excepción Modbus estándar (0x0B / 0x0A) si el PLC no responde.
"""

import asyncio
import json
import logging
import os
import struct
import sys
import time
from typing import Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ModbusGateway")


class ModbusPLCBridge:
    def __init__(self, host: str, port: int, timeout: float, reconnect_delay: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.reconnect_delay = reconnect_delay
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.lock = asyncio.Lock()
        self._connected = False

    async def connect(self) -> bool:
        """Establece la conexión única persistente con el PLC real."""
        if self._connected and self.writer and not self.writer.is_closing():
            return True

        self.close()
        try:
            logger.info(f"Conectando al PLC real en {self.host}:{self.port}...")
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )
            self._connected = True
            logger.info(f"Conexión exitosa con el PLC real ({self.host}:{self.port})")
            return True
        except Exception as e:
            logger.error(f"Error conectando al PLC real ({self.host}:{self.port}): {e}")
            self._connected = False
            return False

    def close(self):
        """Cierra el socket al PLC."""
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.reader = None
        self.writer = None
        self._connected = False

    async def send_and_receive(self, request_packet: bytes) -> Optional[bytes]:
        """
        Envía un paquete al PLC y espera su respuesta de forma serializada.
        Garantiza que sólo una petición esté en tránsito hacia el PLC a la vez.
        """
        async with self.lock:
            for attempt in range(2):
                if not self._connected:
                    connected = await self.connect()
                    if not connected:
                        if attempt == 0:
                            await asyncio.sleep(self.reconnect_delay)
                            continue
                        return None

                try:
                    # Enviar petición al PLC
                    self.writer.write(request_packet)
                    await self.writer.drain()

                    # Leer cabecera MBAP (7 bytes) de la respuesta
                    mbap_header = await asyncio.wait_for(
                        self.reader.readexactly(7),
                        timeout=self.timeout
                    )
                    _, _, length, _ = struct.unpack(">HHHB", mbap_header)

                    if length < 1:
                        raise ValueError(f"Longitud MBAP inválida desde PLC: {length}")

                    # Leer el PDU (length - 1 bytes porque MBAP length incluye el unit_id)
                    pdu = await asyncio.wait_for(
                        self.reader.readexactly(length - 1),
                        timeout=self.timeout
                    )
                    return mbap_header + pdu

                except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
                    logger.warning(f"Fallo en comunicación con el PLC (intento {attempt+1}/2): {e}")
                    self.close()
                    if attempt == 0:
                        await asyncio.sleep(0.5)
                        continue
                    return None
                except Exception as e:
                    logger.error(f"Error inesperado hablando con el PLC: {e}")
                    self.close()
                    return None
            return None


class ModbusGatewayServer:
    def __init__(self, config_path: str = "config.json"):
        self.config = self.load_config(config_path)
        server_cfg = self.config.get("server", {})
        plc_cfg = self.config.get("plc", {})
        self.host = server_cfg.get("host", "0.0.0.0")
        self.port = server_cfg.get("port", 502)

        self.bridge = ModbusPLCBridge(
            host=plc_cfg.get("host", "192.168.1.100"),
            port=plc_cfg.get("port", 502),
            timeout=plc_cfg.get("timeout_seconds", 3.0),
            reconnect_delay=plc_cfg.get("reconnect_delay_seconds", 2.0)
        )

        self.siemens_cfg = self.config.get("siemens_identity", {})
        self.perf_cfg = self.config.get("performance", {})
        self.cache_enabled = self.perf_cfg.get("cache_enabled", False)
        self.cache_ttl = self.perf_cfg.get("cache_ttl_ms", 250) / 1000.0
        self.read_cache: Dict[Tuple[int, int, bytes], Tuple[float, bytes]] = {}

        self.server: Optional[asyncio.Server] = None
        self.active_clients = 0

    @staticmethod
    def load_config(path: str) -> dict:
        if not os.path.isabs(path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            path = os.path.join(base_dir, path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"No se pudo cargar la configuración desde {path}: {e}")
            sys.exit(1)

    def build_fc43_response(self, tx_id: int, unit_id: int) -> bytes:
        """
        Genera la respuesta oficial Modbus FC 43 (0x2B) MEI 14 (Read Device Identification).
        Esta es la función exacta que consulta Nmap (`modbus-discover.nse`) y herramientas
        de escaneo de seguridad industrial (ICS/SCADA).
        """
        vendor = self.siemens_cfg.get("vendor_name", "SIEMENS AG").encode("ascii", "replace")
        product_code = self.siemens_cfg.get("product_code", "SIMATIC S7-1200").encode("ascii", "replace")
        revision = self.siemens_cfg.get("revision", "V4.5.1").encode("ascii", "replace")
        vendor_url = self.siemens_cfg.get("vendor_url", "http://www.siemens.com").encode("ascii", "replace")
        product_name = self.siemens_cfg.get("product_name", "CPU 1214C DC/DC/DC").encode("ascii", "replace")
        model_name = self.siemens_cfg.get("model_name", "6ES7 214-1AG40-0XB0").encode("ascii", "replace")
        user_app = self.siemens_cfg.get("user_application_name", "PLC-SIEMENS").encode("ascii", "replace")

        # Objetos estándar de identificación Modbus
        objects = [
            (0x00, vendor),
            (0x01, product_code),
            (0x02, revision),
            (0x03, vendor_url),
            (0x04, product_name),
            (0x05, model_name),
            (0x06, user_app),
        ]

        pdu = bytearray()
        pdu.append(0x2B)  # FC 43
        pdu.append(0x0E)  # MEI Type 14 (Device Identification)
        pdu.append(0x01)  # Read Device ID Code (Basic Stream Access)
        pdu.append(0x83)  # Conformity Level (Basic and extended stream/individual)
        pdu.append(0x00)  # More Follows (No)
        pdu.append(0x00)  # Next Object ID (0)
        pdu.append(len(objects))  # Número de objetos

        for obj_id, val in objects:
            pdu.append(obj_id)
            pdu.append(len(val))
            pdu.extend(val)

        # Cabecera MBAP: Transaction ID, Protocol 0, Length (PDU + Unit ID = len + 1), Unit ID
        mbap = struct.pack(">HHHB", tx_id, 0x0000, len(pdu) + 1, unit_id)
        return mbap + bytes(pdu)

    @staticmethod
    def build_exception_response(tx_id: int, unit_id: int, fc: int, exception_code: int = 0x0B) -> bytes:
        """
        Construye una respuesta de excepción Modbus estándar.
        0x0A: Gateway Path Unavailable
        0x0B: Gateway Target Device Failed to Respond
        """
        pdu = bytearray([fc | 0x80, exception_code])
        mbap = struct.pack(">HHHB", tx_id, 0x0000, len(pdu) + 1, unit_id)
        return mbap + bytes(pdu)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Gestiona el ciclo de vida de un cliente conectado al proxy."""
        peer = writer.get_extra_info("peername")
        self.active_clients += 1
        logger.info(f"Nuevo cliente conectado: {peer} (Total activos: {self.active_clients})")

        try:
            while True:
                # 1. Leer cabecera MBAP (7 bytes)
                try:
                    mbap_header = await reader.readexactly(7)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break

                tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", mbap_header)

                if proto_id != 0:
                    logger.warning(f"Protocol ID inválido ({proto_id}) desde {peer}. Desconectando.")
                    break

                if length < 1 or length > 260:
                    logger.warning(f"Longitud Modbus PDU anómala ({length}) desde {peer}.")
                    break

                # 2. Leer PDU (Data de la petición)
                try:
                    pdu = await reader.readexactly(length - 1)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break

                fc = pdu[0]

                # 3. Interceptar escaneos de identificación (Nmap / modbus-discover)
                if fc == 0x2B and len(pdu) >= 2 and pdu[1] == 0x0E:
                    if self.siemens_cfg.get("intercept_fc43", True):
                        logger.info(f"[{peer}] Interceptado FC 43 (Read Device ID) -> Respondiendo identidad SIEMENS")
                        resp = self.build_fc43_response(tx_id, unit_id)
                        writer.write(resp)
                        await writer.drain()
                        continue

                # 4. Verificación de Caché (Opcional para FC 3 y FC 4)
                now = time.time()
                cache_key = None
                if self.cache_enabled and fc in (0x03, 0x04):
                    cache_key = (unit_id, fc, bytes(pdu[1:]))
                    cached_entry = self.read_cache.get(cache_key)
                    if cached_entry and (now - cached_entry[0] < self.cache_ttl):
                        cached_pdu = cached_entry[1]
                        # Reconstruir MBAP con el tx_id actual del cliente
                        resp = struct.pack(">HHHB", tx_id, 0x0000, len(cached_pdu) + 1, unit_id) + cached_pdu
                        writer.write(resp)
                        await writer.drain()
                        continue

                # 5. Redireccionar al PLC real con cola y serialización
                # Reconstruir el paquete completo para enviar al PLC
                plc_request = mbap_header + pdu
                plc_response = await self.bridge.send_and_receive(plc_request)

                if plc_response is not None:
                    # Extraer componentes de la respuesta del PLC
                    plc_tx_id, plc_proto, plc_len, plc_uid = struct.unpack(">HHHB", plc_response[:7])
                    plc_pdu = plc_response[7:]

                    # Guardar en caché si aplica
                    if self.cache_enabled and cache_key and (plc_pdu[0] == fc):
                        self.read_cache[cache_key] = (now, plc_pdu)

                    # Reemplazar el Transaction ID con el que esperaba este cliente
                    client_response = struct.pack(">HHHB", tx_id, plc_proto, plc_len, plc_uid) + plc_pdu
                    writer.write(client_response)
                    await writer.drain()
                else:
                    # Si el PLC no respondió a tiempo o está caído, responder excepción 0x0B
                    logger.warning(f"PLC no respondió a la consulta de {peer}. Enviando excepción Modbus 0x0B.")
                    err_resp = self.build_exception_response(tx_id, unit_id, fc, exception_code=0x0B)
                    writer.write(err_resp)
                    await writer.drain()

        except Exception as e:
            logger.error(f"Error procesando cliente {peer}: {e}")
        finally:
            self.active_clients -= 1
            logger.info(f"Cliente desconectado: {peer} (Restantes: {self.active_clients})")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self):
        """Inicia el servidor proxy."""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            reuse_address=True
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"=== MODBUS GATEWAY SIEMENS INICIADO ===")
        logger.info(f"Escuchando en: {addrs}")
        logger.info(f"Redirigiendo consultas al PLC: {self.bridge.host}:{self.bridge.port}")
        logger.info(f"Falsificación Nmap activa: {self.siemens_cfg.get('product_code')} ({self.siemens_cfg.get('vendor_name')})")

        async with self.server:
            await self.server.serve_forever()


if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    gateway = ModbusGatewayServer(config_file)
    try:
        asyncio.run(gateway.run())
    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario.")
