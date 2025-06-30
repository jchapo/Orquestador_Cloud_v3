#!/bin/bash

echo "🔐 Probando contraseñas comunes para el gateway..."

PASSWORDS=("ubuntu" "lab123" "pucp123" "tel141" "123456" "admin" "password" "laboratorio")
GATEWAY="10.20.12.187"
PORT="5821"

for pass in "${PASSWORDS[@]}"; do
    echo "Probando contraseña: $pass"
    if sshpass -p "$pass" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -p $PORT ubuntu@$GATEWAY "echo 'Conexión exitosa con $pass'" 2>/dev/null; then
        echo "✅ ¡Contraseña encontrada: $pass!"
        echo "export GATEWAY_PASSWORD='$pass'" > ~/.pucp_gateway_pass
        echo "La contraseña se guardó en ~/.pucp_gateway_pass"
        exit 0
    else
        echo "❌ Contraseña incorrecta: $pass"
    fi
done

echo "❌ Ninguna contraseña común funcionó"
echo "💡 Intenta recordar la contraseña que configuraste en Lab 1"
