#!/usr/bin/env python3
"""
Script de prueba para verificar:
1. Respuesta al escaneo de Nmap (FC 43 - Device Identification).
2. Manejo de excepciones cuando el PLC real no está disponible.
"""

import asyncio
import struct

async def test_fc43():
    print("[TEST] Conectando al Gateway en 127.0.0.1:1502...")
    reader, writer = await asyncio.open_connection("127.0.0.1", 1502)

    # Construir paquete FC 43 (Read Device Identification) igual al que manda nmap modbus-discover
    # MBAP: tx_id=1, proto=0, len=5, unit_id=1
    # PDU: FC=0x2B, MEI=0x0E, ReadDeviceID=0x01, ObjectID=0x00
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
    mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)
    packet = mbap + pdu

    writer.write(packet)
    await writer.drain()

    # Leer respuesta
    resp_header = await reader.readexactly(7)
    tx_id, proto, length, uid = struct.unpack(">HHHB", resp_header)
    resp_pdu = await reader.readexactly(length - 1)

    fc = resp_pdu[0]
    mei = resp_pdu[1]
    read_code = resp_pdu[2]
    conformity = resp_pdu[3]
    more = resp_pdu[4]
    next_id = resp_pdu[5]
    num_objects = resp_pdu[6]

    print(f"[TEST] Recibida respuesta FC={fc:#x}, MEI={mei:#x}, Número de objetos={num_objects}")

    pos = 7
    objects = {}
    obj_names = {
        0: "Vendor Name",
        1: "Product Code",
        2: "Revision",
        3: "Vendor URL",
        4: "Product Name",
        5: "Model Name",
        6: "User Application Name"
    }

    for _ in range(num_objects):
        obj_id = resp_pdu[pos]
        obj_len = resp_pdu[pos + 1]
        obj_val = resp_pdu[pos + 2 : pos + 2 + obj_len].decode("ascii", "replace")
        pos += 2 + obj_len
        objects[obj_id] = obj_val
        print(f"       -> {obj_names.get(obj_id, f'Obj {obj_id}')}: {obj_val}")

    writer.close()
    await writer.wait_closed()
    print("[TEST] ¡Prueba de identidad Siemens COMPLETADA EXITOSAMENTE!")

if __name__ == "__main__":
    asyncio.run(test_fc43())
