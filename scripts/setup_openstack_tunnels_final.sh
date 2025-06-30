#!/bin/bash

echo "🚇 Configurando túneles SSH OpenStack en puertos no conflictivos..."

GATEWAY_IP="10.20.12.187"
HEADNODE_IP="10.60.2.21"

echo "Estableciendo túneles SSH..."

# Usar puertos diferentes para evitar conflictos
ssh -fN -o StrictHostKeyChecking=no \
    -L 15000:$HEADNODE_IP:5000 \
    -L 18774:$HEADNODE_IP:8774 \
    -L 19292:$HEADNODE_IP:9292 \
    -L 19696:$HEADNODE_IP:9696 \
    -L 16080:$HEADNODE_IP:6080 \
    -L 18080:$HEADNODE_IP:80 \
    -p 5821 ubuntu@$GATEWAY_IP

if [ $? -eq 0 ]; then
    echo "✅ Túneles SSH establecidos en puertos no conflictivos:"
    echo "   - Keystone: localhost:15000"
    echo "   - Nova: localhost:18774"
    echo "   - Glance: localhost:19292"
    echo "   - Neutron: localhost:19696"
    echo "   - NoVNC: localhost:16080"
    echo "   - Horizon: localhost:18080"
    
    # Verificar conectividad
    sleep 3
    echo ""
    echo "Verificando conectividad..."
    
    if curl -s -m 5 http://localhost:15000 > /dev/null; then
        echo "✅ Keystone accesible en localhost:15000"
        
        # Probar endpoint v3
        response=$(curl -s -m 5 http://localhost:15000/v3 2>/dev/null)
        if echo "$response" | grep -q "version\|keystone\|identity" 2>/dev/null; then
            echo "✅ Keystone v3 endpoint responde correctamente"
        else
            echo "📋 Respuesta de Keystone v3: $response"
        fi
    else
        echo "❌ Keystone no accesible en localhost:15000"
    fi
    
    # Probar otros servicios
    for service_port in "Nova:18774" "Glance:19292" "Neutron:19696"; do
        service=$(echo $service_port | cut -d: -f1)
        port=$(echo $service_port | cut -d: -f2)
        
        if curl -s -m 5 http://localhost:$port > /dev/null; then
            echo "✅ $service accesible en localhost:$port"
        else
            echo "⚠️  $service no responde en localhost:$port"
        fi
    done
else
    echo "❌ Error estableciendo túneles SSH"
    exit 1
fi
