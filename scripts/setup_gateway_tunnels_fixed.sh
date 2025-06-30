#!/bin/bash

echo "🚇 Configurando túneles SSH en Gateway para OpenStack (corregido)..."

GATEWAY_IP="10.20.12.187" 
HEADNODE_IP="10.60.2.21"

echo "Estableciendo túneles SSH..."

# Matar procesos SSH existentes
pkill -f "ssh.*$GATEWAY_IP" 2>/dev/null || true
sleep 2

# Crear túneles (sin puerto 80 que requiere privilegios)
ssh -fN -o StrictHostKeyChecking=no \
    -L 5000:$HEADNODE_IP:5000 \
    -L 8774:$HEADNODE_IP:8774 \
    -L 6080:$HEADNODE_IP:6080 \
    -L 9292:$HEADNODE_IP:9292 \
    -L 9696:$HEADNODE_IP:9696 \
    -L 8080:$HEADNODE_IP:80 \
    -p 5821 ubuntu@$GATEWAY_IP

if [ $? -eq 0 ]; then
    echo "✅ Túneles SSH establecidos exitosamente"
    echo "   - Keystone: localhost:5000"
    echo "   - Nova: localhost:8774" 
    echo "   - Glance: localhost:9292"
    echo "   - Neutron: localhost:9696"
    echo "   - NoVNC: localhost:6080"
    echo "   - Horizon: localhost:8080"
    
    # Verificar conectividad
    sleep 3
    if curl -s -m 5 http://localhost:5000 > /dev/null; then
        echo "✅ Keystone accesible en localhost:5000"
        
        # Probar endpoint específico
        if curl -s -m 5 http://localhost:5000/v3 > /dev/null; then
            echo "✅ Keystone v3 endpoint accesible"
        else
            echo "⚠️  Keystone v3 endpoint no responde"
        fi
    else
        echo "⚠️  Keystone no responde"
    fi
else
    echo "❌ Error estableciendo túneles SSH"
    exit 1
fi
