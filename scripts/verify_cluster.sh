#!/bin/bash
# verify_cluster.sh - Verificar configuración del cluster

echo "🔍 Verificando configuración del cluster PUCP"
echo "=============================================="

SERVERS=("server1" "server2" "server3" "server4")
BRIDGE_NAME="ovs1"

for server in "${SERVERS[@]}"; do
    echo
    echo "📡 Verificando $server..."
    
    # Conectividad SSH
    if ssh -o ConnectTimeout=5 ubuntu@pucp-$server "echo '✅ SSH OK'" 2>/dev/null; then
        echo "  ✅ SSH: Conectado"
    else
        echo "  ❌ SSH: Error de conexión"
        continue
    fi
    
    # OpenVSwitch
    if ssh ubuntu@pucp-$server "sudo ovs-vsctl br-exists $BRIDGE_NAME" 2>/dev/null; then
        echo "  ✅ OVS: Bridge $BRIDGE_NAME existe"
        
        # Mostrar configuración
        echo "  📋 Configuración OVS:"
        ssh ubuntu@pucp-$server "sudo ovs-vsctl show | grep -A 3 'Bridge \"$BRIDGE_NAME\"'" | sed 's/^/    /'
    else
        echo "  ❌ OVS: Bridge $BRIDGE_NAME NO existe"
    fi
    
    # Libvirt
    if ssh ubuntu@pucp-$server "sudo virsh net-list --all | grep ovs-network" 2>/dev/null; then
        echo "  ✅ Libvirt: Red OVS configurada"
    else
        echo "  ⚠️  Libvirt: Red OVS no configurada"
    fi
    
    # Recursos
    vcpus=$(ssh ubuntu@pucp-$server "nproc" 2>/dev/null || echo "?")
    ram=$(ssh ubuntu@pucp-$server "free -m | awk '/^Mem:/ {print \$2}'" 2>/dev/null || echo "?")
    echo "  💻 Recursos: ${vcpus} CPUs, ${ram} MB RAM"
done

echo
echo "✅ Verificación completada"
