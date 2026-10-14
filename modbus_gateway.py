#!/usr/bin/env python3
"""
Siemens PLC Smart Gateway & Proxy Multi-Puerto (502, 102, 80)
=============================================================
- Puerto 502 (Modbus TCP):
    * Intercepta escaneos Nmap FC 43 (0x2B MEI 14) respondiendo con identidad oficial Siemens.
    * Conexión única persistente y cola serializada hacia el PLC para evitar saturación de sockets/CPU.
    * Caché de registros opcional.
    * Excepción estándar 0x0B si el PLC real está desconectado.
- Puerto 102 (ISO-on-TCP / S7comm):
    * Proxy bidireccional transparente hacia el puerto S7 del PLC real.
    * Permite que Nmap (`s7-info.nse`), TIA Portal, WinCC y Snap7 detecten y comuniquen con el PLC.
    * Control de concurrencia (semáforo) para proteger el límite de conexiones S7 del PLC.
- Puerto 80 (HTTP Web Server):
    * Proxy bidireccional transparente hacia el servidor web integrado de Siemens.
    * Permite acceder a la interfaz web del PLC y que Nmap detecte el servidor web oficial SIMATIC.
    * Control de saturación HTTP.
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
logger = logging.getLogger("PLC-Gateway")


class ModbusPLCBridge:
    """Gestiona una única conexión persistente y serializada para Modbus hacia el PLC."""
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
        if self._connected and self.writer and not self.writer.is_closing():
            return True

        self.close()
        try:
            logger.info(f"[Modbus:502] Conectando al PLC real en {self.host}:{self.port}...")
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )
            self._connected = True
            logger.info(f"[Modbus:502] Conexión establecida con el PLC real ({self.host}:{self.port})")
            return True
        except Exception as e:
            logger.error(f"[Modbus:502] Error conectando al PLC real ({self.host}:{self.port}): {e}")
            self._connected = False
            return False

    def close(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.reader = None
        self.writer = None
        self._connected = False

    async def send_and_receive(self, request_packet: bytes) -> Optional[bytes]:
        """Envía un paquete al PLC y espera su respuesta con Mutex Lock."""
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
                    self.writer.write(request_packet)
                    await self.writer.drain()

                    mbap_header = await asyncio.wait_for(
                        self.reader.readexactly(7),
                        timeout=self.timeout
                    )
                    _, _, length, _ = struct.unpack(">HHHB", mbap_header)

                    if length < 1:
                        raise ValueError(f"Longitud MBAP inválida: {length}")

                    pdu = await asyncio.wait_for(
                        self.reader.readexactly(length - 1),
                        timeout=self.timeout
                    )
                    return mbap_header + pdu

                except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
                    logger.warning(f"[Modbus:502] Fallo en comunicación con el PLC (intento {attempt+1}/2): {e}")
                    self.close()
                    if attempt == 0:
                        await asyncio.sleep(0.5)
                        continue
                    return None
                except Exception as e:
                    logger.error(f"[Modbus:502] Error inesperado: {e}")
                    self.close()
                    return None
            return None


class StreamProxyService:
    """Proxy bidireccional de flujos TCP con control de concurrencia (para puertos 102 y 80)."""
    def __init__(self, name: str, listen_port: int, target_host: str, target_port: int, max_connections: int, timeout: float = 5.0):
        self.name = name
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.semaphore = asyncio.Semaphore(max_connections)
        self.timeout = timeout
        self.server: Optional[asyncio.Server] = None
        self.current_connections = 0

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        peer = client_writer.get_extra_info("peername")
        self.current_connections += 1
        logger.info(f"[{self.name}] Conexión entrante desde {peer} (Activas: {self.current_connections})")

        try:
            # Limitar concurrencia para no saturar los sockets del PLC
            async with self.semaphore:
                try:
                    plc_reader, plc_writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_host, self.target_port),
                        timeout=self.timeout
                    )
                except Exception as e:
                    logger.warning(f"[{self.name}] No se pudo conectar al PLC ({self.target_host}:{self.target_port}): {e}")
                    return

                try:
                    # Enrutar tráfico bidireccional en paralelo
                    await asyncio.gather(
                        self._pipe(client_reader, plc_writer),
                        self._pipe(plc_reader, client_writer)
                    )
                finally:
                    try:
                        plc_writer.close()
                        await plc_writer.wait_closed()
                    except Exception:
                        pass
        finally:
            self.current_connections -= 1
            logger.info(f"[{self.name}] Conexión finalizada desde {peer} (Restantes: {self.current_connections})")
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def start(self, host: str):
        self.server = await asyncio.start_server(
            self.handle_client,
            host,
            self.listen_port,
            reuse_address=True
        )
        logger.info(f"[{self.name}] Escuchando en {host}:{self.listen_port} -> Reenviando a {self.target_host}:{self.target_port}")


class UnifiedPLCGateway:
    def __init__(self, config_path: str = "config.json"):
        self.config = self.load_config(config_path)
        server_cfg = self.config.get("server", {})
        plc_cfg = self.config.get("plc", {})
        feat_cfg = self.config.get("features", {})
        perf_cfg = self.config.get("performance", {})
        self.siemens_cfg = self.config.get("siemens_identity", {})

        self.host = server_cfg.get("host", "0.0.0.0")
        self.plc_host = plc_cfg.get("host", "192.168.1.100")
        self.timeout = plc_cfg.get("timeout_seconds", 3.0)
        self.reconnect_delay = plc_cfg.get("reconnect_delay_seconds", 2.0)

        # Configuración Modbus 502
        self.enable_502 = feat_cfg.get("enable_modbus_502", True)
        self.modbus_port = server_cfg.get("modbus_port", 502)
        self.plc_modbus_port = plc_cfg.get("modbus_port", 502)
        self.modbus_bridge = ModbusPLCBridge(
            self.plc_host, self.plc_modbus_port, self.timeout, self.reconnect_delay
        )
        self.cache_enabled = perf_cfg.get("cache_enabled", False)
        self.cache_ttl = perf_cfg.get("cache_ttl_ms", 250) / 1000.0
        self.read_cache: Dict[Tuple[int, int, bytes], Tuple[float, bytes]] = {}
        self.active_modbus_clients = 0

        # Configuración S7 102
        self.enable_102 = feat_cfg.get("enable_s7_102", True)
        self.s7_port = server_cfg.get("s7_port", 102)
        self.plc_s7_port = plc_cfg.get("s7_port", 102)
        self.max_s7_conn = perf_cfg.get("max_s7_connections", 8)
        self.s7_proxy = StreamProxyService(
            "S7-Comm:102", self.s7_port, self.plc_host, self.plc_s7_port, self.max_s7_conn, self.timeout
        )

        # Configuración HTTP 80
        self.enable_80 = feat_cfg.get("enable_http_80", True)
        self.http_port = server_cfg.get("http_port", 80)
        self.plc_http_port = plc_cfg.get("http_port", 80)
        self.max_http_conn = perf_cfg.get("max_http_connections", 15)
        self.http_proxy = StreamProxyService(
            "HTTP-Web:80", self.http_port, self.plc_host, self.plc_http_port, self.max_http_conn, self.timeout
        )

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
        """Construye paquete de identidad Siemens FC 43 (0x2B) para Nmap."""
        vendor = self.siemens_cfg.get("vendor_name", "SIEMENS AG").encode("ascii", "replace")
        product_code = self.siemens_cfg.get("product_code", "SIMATIC S7-1200").encode("ascii", "replace")
        revision = self.siemens_cfg.get("revision", "V4.5.1").encode("ascii", "replace")
        vendor_url = self.siemens_cfg.get("vendor_url", "http://www.siemens.com").encode("ascii", "replace")
        product_name = self.siemens_cfg.get("product_name", "CPU 1214C DC/DC/DC").encode("ascii", "replace")
        model_name = self.siemens_cfg.get("model_name", "6ES7 214-1AG40-0XB0").encode("ascii", "replace")
        user_app = self.siemens_cfg.get("user_application_name", "PLC-SIEMENS").encode("ascii", "replace")

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
        pdu.append(0x2B)
        pdu.append(0x0E)
        pdu.append(0x01)
        pdu.append(0x83)
        pdu.append(0x00)
        pdu.append(0x00)
        pdu.append(len(objects))

        for obj_id, val in objects:
            pdu.append(obj_id)
            pdu.append(len(val))
            pdu.extend(val)

        mbap = struct.pack(">HHHB", tx_id, 0x0000, len(pdu) + 1, unit_id)
        return mbap + bytes(pdu)

    @staticmethod
    def build_exception_response(tx_id: int, unit_id: int, fc: int, exception_code: int = 0x0B) -> bytes:
        pdu = bytearray([fc | 0x80, exception_code])
        mbap = struct.pack(">HHHB", tx_id, 0x0000, len(pdu) + 1, unit_id)
        return mbap + bytes(pdu)

    async def handle_modbus_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        self.active_modbus_clients += 1
        logger.info(f"[Modbus:502] Cliente conectado: {peer} (Total activos: {self.active_modbus_clients})")

        try:
            while True:
                try:
                    mbap_header = await reader.readexactly(7)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break

                tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", mbap_header)

                if proto_id != 0 or length < 1 or length > 260:
                    break

                try:
                    pdu = await reader.readexactly(length - 1)
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break

                fc = pdu[0]

                # Interceptar FC 43 (Identidad Siemens para Nmap)
                if fc == 0x2B and len(pdu) >= 2 and pdu[1] == 0x0E:
                    if self.siemens_cfg.get("intercept_fc43", True):
                        logger.info(f"[Modbus:502] Interceptada FC 43 desde {peer} -> Respondiendo identidad Siemens")
                        resp = self.build_fc43_response(tx_id, unit_id)
                        writer.write(resp)
                        await writer.drain()
                        continue

                # Caché de lectura
                now = time.time()
                cache_key = None
                if self.cache_enabled and fc in (0x03, 0x04):
                    cache_key = (unit_id, fc, bytes(pdu[1:]))
                    cached_entry = self.read_cache.get(cache_key)
                    if cached_entry and (now - cached_entry[0] < self.cache_ttl):
                        cached_pdu = cached_entry[1]
                        resp = struct.pack(">HHHB", tx_id, 0x0000, len(cached_pdu) + 1, unit_id) + cached_pdu
                        writer.write(resp)
                        await writer.drain()
                        continue

                # Enviar al PLC real
                plc_request = mbap_header + pdu
                plc_response = await self.modbus_bridge.send_and_receive(plc_request)

                if plc_response is not None:
                    plc_proto = struct.unpack(">H", plc_response[2:4])[0]
                    plc_len = struct.unpack(">H", plc_response[4:6])[0]
                    plc_uid = plc_response[6]
                    plc_pdu = plc_response[7:]

                    if self.cache_enabled and cache_key and (plc_pdu[0] == fc):
                        self.read_cache[cache_key] = (now, plc_pdu)

                    client_response = struct.pack(">HHHB", tx_id, plc_proto, plc_len, plc_uid) + plc_pdu
                    writer.write(client_response)
                    await writer.drain()
                else:
                    err_resp = self.build_exception_response(tx_id, unit_id, fc, exception_code=0x0B)
                    writer.write(err_resp)
                    await writer.drain()

        except Exception as e:
            logger.error(f"[Modbus:502] Error procesando cliente {peer}: {e}")
        finally:
            self.active_modbus_clients -= 1
            logger.info(f"[Modbus:502] Cliente desconectado: {peer} (Restantes: {self.active_modbus_clients})")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self):
        tasks = []

        logger.info("==========================================================")
        logger.info("     INICIANDO GATEWAY MULTI-PUERTO SIEMENS (PLACEHOLDER)")
        logger.info(f"     Destino PLC Real: {self.plc_host}")
        logger.info("==========================================================")

        # 1. Iniciar servidor Modbus (502)
        if self.enable_502:
            modbus_server = await asyncio.start_server(
                self.handle_modbus_client, self.host, self.modbus_port, reuse_address=True
            )
            tasks.append(modbus_server.serve_forever())
            logger.info(f"[+] Puerto 502 (Modbus TCP) ACTIVO en {self.host}:{self.modbus_port}")
            logger.info(f"    -> Intercepción Siemens: {self.siemens_cfg.get('product_code')}")

        # 2. Iniciar servidor S7 (102)
        if self.enable_102:
            await self.s7_proxy.start(self.host)
            tasks.append(self.s7_proxy.server.serve_forever())
            logger.info(f"[+] Puerto 102 (ISO-on-TCP / S7comm) ACTIVO en {self.host}:{self.s7_port}")

        # 3. Iniciar servidor HTTP (80)
        if self.enable_80:
            await self.http_proxy.start(self.host)
            tasks.append(self.http_proxy.server.serve_forever())
            logger.info(f"[+] Puerto 80 (HTTP Siemens Web) ACTIVO en {self.host}:{self.http_port}")

        if not tasks:
            logger.error("No se habilitó ningún puerto en la configuración.")
            return

        await asyncio.gather(*tasks)


if __name__ == "__main__":
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    gateway = UnifiedPLCGateway(config_file)
    try:
        asyncio.run(gateway.run())
    except KeyboardInterrupt:
        logger.info("Servidor detenido.")
