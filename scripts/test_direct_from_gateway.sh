#!/bin/bash

echo "🔍 Probando conectividad directa desde gateway a headnode..."

ssh ubuntu@10.20.12.187 -p 5821 << 'REMOTE_TEST'
echo "=== Desde el gateway, probando conectividad al headnode ==="

# Test directo al headnode
echo "1. Ping al headnode:"
ping -c 2 10.60.2.21 || echo "❌ No hay ping al headnode"

echo ""
echo "2. Test de puertos en headnode:"
for port in 5000 8774 9292 9696; do
    if nc -z 10.60.2.21 $port 2>/dev/null; then
        echo "✅ Puerto $port en headnode: ABIERTO"
    else
        echo "❌ Puerto $port en headnode: CERRADO"
    fi
done

echo ""
echo "3. Test HTTP directo al headnode:"
curl -s -m 5 http://10.60.2.21:5000/v3 > /dev/null && echo "✅ Keystone responde" || echo "❌ Keystone no responde"
curl -s -m 5 http://10.60.2.21:8774 > /dev/null && echo "✅ Nova responde" || echo "❌ Nova no responde"

echo ""
echo "4. Verificar routing desde gateway:"
ip route | grep 10.60.2
REMOTE_TEST
