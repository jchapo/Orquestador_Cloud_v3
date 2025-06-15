#!/bin/bash
# setup_sudo_permissions.sh

echo "🔐 Configurando sudo para comandos libvirt"
echo "=========================================="

SERVERS=("server1" "server2" "server3" "server4")

for server in "${SERVERS[@]}"; do
    echo "📡 Configurando sudo en pucp-$server..."
    
    ssh ubuntu@pucp-$server << 'EOF'
        # Crear archivo sudoers específico para libvirt
        sudo tee /etc/sudoers.d/libvirt-pucp << 'SUDOERS_EOF'
# PUCP Cloud Orchestrator - Libvirt permissions
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/qemu-img
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/chown /var/lib/libvirt/images/*
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/chmod /var/lib/libvirt/images/*
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/ovs-vsctl
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/virsh
SUDOERS_EOF
        
        # Establecer permisos correctos del archivo sudoers
        sudo chmod 440 /etc/sudoers.d/libvirt-pucp
        
        # Verificar sintaxis
        sudo visudo -c
        
        echo "✅ Configuración sudo completada"
EOF
done
