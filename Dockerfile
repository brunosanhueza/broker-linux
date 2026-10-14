FROM python:3.11-slim

WORKDIR /app

# Copiar archivos
COPY modbus_gateway.py config.json /app/

# Exponer el puerto Modbus TCP
EXPOSE 502

# Ejecutar el gateway
CMD ["python", "-u", "modbus_gateway.py", "config.json"]
