#!/bin/bash

echo "🧹 Limpiando túneles SSH existentes..."

# Matar procesos SSH existentes
pkill -f "ssh.*10.20.12.187" 2>/dev/null || true
sleep 3

echo "🚇 Estableciendo túneles SSH limpios para OpenStack..."

GATEWAY_IP="10.20.12.187"
HEADNODE_IP="10.60.2.21"

# Verificar conectividad al gateway primero
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes ubuntu@$GATEWAY_IP -p 5821 "echo 'Gateway accesible'" 2>/dev/null; then
    echo "❌ No se puede conectar al gateway"
    exit 1
fi

echo "✅ Gateway accesible"

# Establecer túneles SSH
echo "Estableciendo túneles SSH..."
ssh -fN -o StrictHostKeyChecking=no \
    -L 15000:$HEADNODE_IP:5000 \
    -L 18774:$HEADNODE_IP:8774 \
    -L 19292:$HEADNODE_IP:9292 \
    -L 19696:$HEADNODE_IP:9696 \
    -L 16080:$HEADNODE_IP:6080 \
    -L 18080:$HEADNODE_IP:80 \
    -p 5821 ubuntu@$GATEWAY_IP

if [ $? -eq 0 ]; then
    echo "✅ Túneles SSH establecidos"
    
    # Esperar un momento para que se establezcan
    sleep 5
    
    echo "🔍 Verificando conectividad..."
    
    # Test Keystone
    if curl -s -m 5 http://localhost:15000/v3 >/dev/null 2>&1; then
        echo "✅ Keystone (localhost:15000): ACCESIBLE"
    else
        echo "❌ Keystone (localhost:15000): NO ACCESIBLE"
    fi
    
    # Test Nova
    if curl -s -m 5 http://localhost:18774 >/dev/null 2>&1; then
        echo "✅ Nova (localhost:18774): ACCESIBLE"
    else
        echo "❌ Nova (localhost:18774): NO ACCESIBLE"
    fi
    
    # Test Glance
    if curl -s -m 5 http://localhost:19292 >/dev/null 2>&1; then
        echo "✅ Glance (localhost:19292): ACCESIBLE"
    else
        echo "❌ Glance (localhost:19292): NO ACCESIBLE"
    fi
    
    # Test Neutron
    if curl -s -m 5 http://localhost:19696 >/dev/null 2>&1; then
        echo "✅ Neutron (localhost:19696): ACCESIBLE"
    else
        echo "❌ Neutron (localhost:19696): NO ACCESIBLE"
    fi
    
else
    echo "❌ Error estableciendo túneles SSH"
    exit 1
fi
