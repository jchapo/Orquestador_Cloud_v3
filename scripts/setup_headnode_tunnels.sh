#!/bin/bash

echo "🚇 Configurando túneles SSH al headnode real..."

GATEWAY_IP="10.20.12.187"

# Matar túneles existentes
pkill -f "ssh.*$GATEWAY_IP" 2>/dev/null || true
sleep 2

# Método 1: Túnel via gateway con doble salto al headnode interno
echo "Método 1: Túnel doble salto al headnode..."
ssh -fN -o StrictHostKeyChecking=no \
    -o ProxyJump=ubuntu@$GATEWAY_IP:5821 \
    -L 15000:localhost:5000 \
    -L 18774:localhost:8774 \
    -L 19292:localhost:9292 \
    -L 19696:localhost:9696 \
    ubuntu@192.168.202.1

if [ $? -eq 0 ]; then
    echo "✅ Túnel doble salto establecido al headnode"
    
    sleep 3
    echo "🔍 Verificando servicios OpenStack..."
    
    curl -s -m 5 http://localhost:15000/v3 >/dev/null 2>&1 && echo "✅ Keystone (15000): FUNCIONA" || echo "❌ Keystone: NO FUNCIONA"
    curl -s -m 5 http://localhost:18774 >/dev/null 2>&1 && echo "✅ Nova (18774): FUNCIONA" || echo "❌ Nova: NO FUNCIONA"
    curl -s -m 5 http://localhost:19292 >/dev/null 2>&1 && echo "✅ Glance (19292): FUNCIONA" || echo "❌ Glance: NO FUNCIONA"
    curl -s -m 5 http://localhost:19696 >/dev/null 2>&1 && echo "✅ Neutron (19696): FUNCIONA" || echo "❌ Neutron: NO FUNCIONA"
    
    if curl -s -m 5 http://localhost:15000/v3 >/dev/null 2>&1; then
        echo ""
        echo "🎉 ¡CONEXIÓN A OPENSTACK EXITOSA!"
        echo "   Keystone: http://localhost:15000"
        echo "   Nova: http://localhost:18774"
        echo "   Glance: http://localhost:19292"
        echo "   Neutron: http://localhost:19696"
    fi
    
else
    echo "❌ Error estableciendo túnel doble salto"
    
    # Método 2: Túnel directo via gateway con forward
    echo ""
    echo "Método 2: Túnel directo con port forwarding..."
    ssh -fN -o StrictHostKeyChecking=no \
        -L 15000:192.168.202.1:5000 \
        -L 18774:192.168.202.1:8774 \
        -L 19292:192.168.202.1:9292 \
        -L 19696:192.168.202.1:9696 \
        -p 5821 ubuntu@$GATEWAY_IP
        
    if [ $? -eq 0 ]; then
        echo "✅ Túnel directo con port forwarding establecido"
        
        sleep 3
        curl -s -m 5 http://localhost:15000/v3 >/dev/null 2>&1 && echo "✅ Keystone: FUNCIONA" || echo "❌ Keystone: NO FUNCIONA"
    else
        echo "❌ Ambos métodos de túnel fallaron"
    fi
fi
