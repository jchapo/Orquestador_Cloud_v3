#!/bin/bash

echo "🔧 Configurando bridges requeridos en servidores..."

servers=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

for server in "${servers[@]}"; do
    echo "=== Configurando $server ==="
    
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ubuntu@$server << 'REMOTE_SCRIPT'
        # Instalar bridge-utils si no está
        sudo apt-get update -qq && sudo apt-get install -y bridge-utils openvswitch-switch
        
        # Crear bridge de management
        if ! sudo brctl show | grep -q br-mgmt; then
            echo "Creando br-mgmt..."
            sudo brctl addbr br-mgmt
            sudo ip link set br-mgmt up
            sudo ip addr add 192.168.201.1/24 dev br-mgmt 2>/dev/null || true
            echo "✅ br-mgmt creado"
        else
            echo "✅ br-mgmt ya existe"
        fi
        
        # Crear/verificar OVS bridge
        if ! sudo ovs-vsctl br-exists ovs1 2>/dev/null; then
            echo "Creando ovs1..."
            sudo ovs-vsctl add-br ovs1
            sudo ip link set ovs1 up
            echo "✅ ovs1 creado"
        else
            echo "✅ ovs1 ya existe"
        fi
        
        # Mostrar estado
        echo "--- Estado de bridges ---"
        sudo brctl show 2>/dev/null | grep -E "bridge|br-mgmt" || echo "brctl: sin bridges"
        sudo ovs-vsctl show 2>/dev/null | grep -E "Bridge|ovs1" || echo "ovs: sin bridges"
        
        # Verificar que existan los dispositivos
        if ip link show br-mgmt >/dev/null 2>&1; then
            echo "✅ br-mgmt device OK"
        else
            echo "❌ br-mgmt device MISSING"
        fi
        
        if ip link show ovs1 >/dev/null 2>&1; then
            echo "✅ ovs1 device OK"  
        else
            echo "❌ ovs1 device MISSING"
        fi
REMOTE_SCRIPT
    
    echo ""
done

echo "✅ Configuración de bridges completada"
