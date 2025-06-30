#!/bin/bash

echo "🚇 Estableciendo túnel SSH para OpenStack..."

# Gateway IP del grupo 1
GATEWAY_IP="10.20.12.187"

# Verificar si ya existe el túnel
if pgrep -f "ssh.*5000:10.60.2.21:5000" > /dev/null; then
    echo "✅ Túnel SSH ya existe"
    exit 0
fi

echo "Conectando a través del gateway: $GATEWAY_IP"

# Establecer túnel SSH en background para todos los servicios OpenStack
ssh -fN -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -L 5000:10.60.2.21:5000 \
    -L 9292:10.60.2.21:9292 \
    -L 9696:10.60.2.21:9696 \
    -L 8774:10.60.2.21:8774 \
    -L 8776:10.60.2.21:8776 \
    -p 5821 root@$GATEWAY_IP

if [ $? -eq 0 ]; then
    echo "✅ Túnel SSH establecido exitosamente"
    echo "   - Keystone: localhost:5000"
    echo "   - Glance: localhost:9292" 
    echo "   - Neutron: localhost:9696"
    echo "   - Nova: localhost:8774"
    echo "   - Cinder: localhost:8776"
    
    # Verificar conectividad
    sleep 2
    if curl -s -k http://localhost:5000/v3 > /dev/null; then
        echo "✅ Keystone accesible a través del túnel"
    else
        echo "⚠️  Keystone no responde, verificar credenciales SSH"
    fi
else
    echo "❌ Error estableciendo túnel SSH"
    echo "   Verificar:"
    echo "   - Conectividad a $GATEWAY_IP"
    echo "   - Credenciales SSH para root"
    echo "   - Puerto 5821 abierto"
    exit 1
fi
