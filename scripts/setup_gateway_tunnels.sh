#!/bin/bash

echo "🚇 Configurando túneles SSH en Gateway para OpenStack..."

# Según el PDF Lab5, estos son los túneles necesarios
GATEWAY_IP="10.20.12.187"
HEADNODE_IP="10.60.2.21"

# Túneles requeridos según el PDF
TUNNELS=(
    "5000:$HEADNODE_IP:5000"    # Keystone
    "8774:$HEADNODE_IP:8774"    # Nova
    "6080:$HEADNODE_IP:6080"    # NoVNC Console
    "9292:$HEADNODE_IP:9292"    # Glance
    "9696:$HEADNODE_IP:9696"    # Neutron
    "80:$HEADNODE_IP:80"        # Horizon Dashboard
)

echo "Estableciendo túneles SSH..."

# Matar procesos SSH existentes
pkill -f "ssh.*$GATEWAY_IP" 2>/dev/null || true
sleep 2

# Crear túneles
for tunnel in "${TUNNELS[@]}"; do
    echo "  📡 Túnel: localhost:$tunnel"
done

# Comando SSH con todos los túneles
ssh -fN -o StrictHostKeyChecking=no \
    -L 5000:$HEADNODE_IP:5000 \
    -L 8774:$HEADNODE_IP:8774 \
    -L 6080:$HEADNODE_IP:6080 \
    -L 9292:$HEADNODE_IP:9292 \
    -L 9696:$HEADNODE_IP:9696 \
    -L 80:$HEADNODE_IP:80 \
    -p 5821 ubuntu@$GATEWAY_IP

if [ $? -eq 0 ]; then
    echo "✅ Túneles SSH establecidos exitosamente"
    
    # Verificar conectividad
    sleep 3
    if curl -s -m 5 http://localhost:5000/v3 > /dev/null; then
        echo "✅ Keystone accesible en localhost:5000"
    else
        echo "⚠️  Keystone no responde - verificar credenciales"
    fi
else
    echo "❌ Error estableciendo túneles SSH"
    exit 1
fi
