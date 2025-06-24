#!/bin/bash

echo "🚀 Configurando infraestructura R5..."

# 1. Verificar conectividad
echo "📡 Verificando conectividad SSH..."
for server in pucp-server1 pucp-server2 pucp-server3 pucp-server4; do
    if ssh -o ConnectTimeout=5 ubuntu@$server "echo 'OK'" >/dev/null 2>&1; then
        echo "✅ $server: SSH OK"
    else
        echo "❌ $server: SSH FAILED"
        exit 1
    fi
done

# 2. Instalar OVS
echo "🔧 Instalando Open vSwitch..."
for server in pucp-server1 pucp-server2 pucp-server3 pucp-server4; do
    echo "   Configurando $server..."
    ssh ubuntu@$server "
        sudo apt update >/dev/null 2>&1
        sudo apt install -y openvswitch-switch >/dev/null 2>&1
        sudo systemctl enable openvswitch-switch >/dev/null 2>&1
        sudo systemctl start openvswitch-switch >/dev/null 2>&1
        
        # Crear bridge principal
        sudo ovs-vsctl --may-exist add-br ovs1
        
        # Configurar bridge
        sudo ovs-vsctl set bridge ovs1 other-config:forward-bpdu=true
        sudo ip link set ovs1 up
    " && echo "✅ $server: OVS configurado" || echo "❌ $server: OVS falló"
done

# 3. Configurar networking básico
echo "🌐 Configurando networking..."
ssh ubuntu@pucp-server1 "
    # Habilitar IP forwarding
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf >/dev/null 2>&1
    sudo sysctl -p >/dev/null 2>&1
    
    # Configurar iptables básico
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # Instalar iptables-persistent si no existe
    sudo DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent >/dev/null 2>&1
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null 2>&1
" && echo "✅ Networking configurado" || echo "❌ Networking falló"

# 4. Verificar Network Service
echo "🔍 Verificando Network Service..."
if curl -s http://localhost:5004/health >/dev/null 2>&1; then
    echo "✅ Network Service está corriendo"
else
    echo "🔄 Iniciando Network Service..."
    cd /opt/pucp-orchestrator/network_service
    nohup python3 network_service.py > network_service.log 2>&1 &
    sleep 5
    
    if curl -s http://localhost:5004/health >/dev/null 2>&1; then
        echo "✅ Network Service iniciado"
    else
        echo "❌ Network Service falló"
    fi
fi

# 5. Agregar importación requests
echo "📦 Verificando importaciones..."
if ! grep -q "import requests" /opt/pucp-orchestrator/slice_service/drivers/linux_driver.py; then
    sed -i '1i import requests' /opt/pucp-orchestrator/slice_service/drivers/linux_driver.py
    echo "✅ Importación requests agregada"
fi

# 6. Reiniciar Slice Service
echo "🔄 Reiniciando Slice Service..."
pkill -f slice_service.py >/dev/null 2>&1
cd /opt/pucp-orchestrator/slice_service
nohup python3 slice_service.py > slice_service.log 2>&1 &
sleep 5

echo "✅ Configuración R5 completada!"
echo ""
echo "🧪 Ejecuta para validar:"
echo "curl -X GET http://localhost:5002/validate-integration -H \"Authorization: Bearer \$TOKEN\""
