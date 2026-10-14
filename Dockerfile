FROM python:3.11-slim

WORKDIR /app

# Copiar archivos
COPY modbus_gateway.py config.json /app/

# Exponer los puertos Modbus TCP (502), S7comm (102) y HTTP (80)
EXPOSE 502 102 80

# Ejecutar el gateway
CMD ["python", "-u", "modbus_gateway.py", "config.json"]
