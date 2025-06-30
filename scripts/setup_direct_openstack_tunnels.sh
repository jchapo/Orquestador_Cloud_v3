#!/bin/bash

echo "🚇 Configurando túneles SSH directos a OpenStack VMs..."

GATEWAY_IP="10.20.12.187"

# Matar túneles existentes
pkill -f "ssh.*$GATEWAY_IP" 2>/dev/null || true
sleep 2

# Establecer túnel directo al headnode (puerto 5800)
echo "Estableciendo túnel al headnode (puerto 5800)..."
ssh -fN -o StrictHostKeyChecking=no \
    -L 15000:localhost:5000 \
    -L 18774:localhost:8774 \
    -L 19292:localhost:9292 \
    -L 19696:localhost:9696 \
    -L 16080:localhost:6080 \
    -L 18080:localhost:80 \
    -p 5800 ubuntu@$GATEWAY_IP

if [ $? -eq 0 ]; then
    echo "✅ Túnel directo al headnode establecido"
    
    sleep 3
    echo "🔍 Verificando servicios OpenStack..."
    
    # Test cada servicio
    curl -s -m 5 http://localhost:15000/v3 >/dev/null 2>&1 && echo "✅ Keystone (15000): FUNCIONA" || echo "❌ Keystone: NO FUNCIONA"
    curl -s -m 5 http://localhost:18774 >/dev/null 2>&1 && echo "✅ Nova (18774): FUNCIONA" || echo "❌ Nova: NO FUNCIONA"
    curl -s -m 5 http://localhost:19292 >/dev/null 2>&1 && echo "✅ Glance (19292): FUNCIONA" || echo "❌ Glance: NO FUNCIONA"
    curl -s -m 5 http://localhost:19696 >/dev/null 2>&1 && echo "✅ Neutron (19696): FUNCIONA" || echo "❌ Neutron: NO FUNCIONA"
    
else
    echo "❌ Error estableciendo túnel directo al headnode"
fi
