#!/bin/bash

echo "🔧 Configurando bridges con autenticación..."

servers=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")
SERVER_PASSWORD="ubuntu"

for server in "${servers[@]}"; do
    echo "=== Configurando $server ==="
    
    # Usar sshpass para automatizar password SSH y sudo
    sshpass -p "$SERVER_PASSWORD" ssh -o StrictHostKeyChecking=no ubuntu@$server << 'REMOTE_SCRIPT'
        echo "Conectado a $(hostname)"
        
        # Función para ejecutar comandos con sudo
        run_sudo() {
            echo "ubuntu" | sudo -S "$@" 2>/dev/null
        }
        
        # Actualizar e instalar herramientas necesarias
        echo "Instalando herramientas..."
        run_sudo apt-get update -qq
        run_sudo apt-get install -y bridge-utils openvswitch-switch
        
        # Crear bridge de management
        echo "Configurando br-mgmt..."
        if ! run_sudo brctl show | grep -q br-mgmt; then
            run_sudo brctl addbr br-mgmt
            run_sudo ip link set br-mgmt up
            run_sudo ip addr add 192.168.201.$(hostname -I | cut -d. -f4 | tr -d ' ')/24 dev br-mgmt 2>/dev/null || true
            echo "✅ br-mgmt creado"
        else
            echo "✅ br-mgmt ya existe"
        fi
        
        # Crear/verificar OVS bridge
        echo "Configurando ovs1..."
        if ! run_sudo ovs-vsctl br-exists ovs1 2>/dev/null; then
            run_sudo ovs-vsctl add-br ovs1
            run_sudo ip link set ovs1 up
            echo "✅ ovs1 creado"
        else
            echo "✅ ovs1 ya existe"
        fi
        
        # Verificar estado final
        echo "--- Verificación final ---"
        if ip link show br-mgmt >/dev/null 2>&1; then
            echo "✅ br-mgmt device disponible"
        else
            echo "❌ br-mgmt device faltante"
        fi
        
        if ip link show ovs1 >/dev/null 2>&1; then
            echo "✅ ovs1 device disponible"
        else
            echo "❌ ovs1 device faltante"
        fi
        
        # Mostrar estado de libvirt networks
        echo "--- Estado libvirt ---"
        if run_sudo virsh net-list --all 2>/dev/null; then
            echo "Libvirt networks verificadas"
        else
            echo "Libvirt no disponible o sin networks"
        fi
REMOTE_SCRIPT
    
    echo ""
done

echo "✅ Configuración de bridges completada"
