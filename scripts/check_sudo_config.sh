#!/bin/bash
# scripts/check_sudo_config.sh

echo "=== Verificando Configuración Sudo ==="

SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

for server in "${SERVERS[@]}"; do
    echo ""
    echo "🔍 Verificando $server..."
    
    # Verificar grupos del usuario
    echo "  Grupos:"
    ssh "$server" "groups"
    
    # Verificar configuración sudo
    echo "  Configuración sudo:"
    ssh "$server" "sudo -l" 2>/dev/null | head -5 || echo "    Requiere password"
    
    # Test sudo sin password
    echo "  Test sudo sin password:"
    if ssh "$server" "sudo -n whoami" >/dev/null 2>&1; then
        echo "    ✅ Sudo sin password funciona"
    else
        echo "    ❌ Sudo requiere password"
    fi
    
    # Verificar si puede instalar sin sudo (si ya está instalado)
    echo "  Software ya instalado:"
    kvm_installed=$(ssh "$server" "which qemu-kvm >/dev/null 2>&1 && echo 'YES' || echo 'NO'")
    libvirt_installed=$(ssh "$server" "which virsh >/dev/null 2>&1 && echo 'YES' || echo 'NO'")
    ovs_installed=$(ssh "$server" "which ovs-vsctl >/dev/null 2>&1 && echo 'YES' || echo 'NO'")
    
    echo "    KVM: $kvm_installed"
    echo "    libvirt: $libvirt_installed" 
    echo "    OVS: $ovs_installed"
done