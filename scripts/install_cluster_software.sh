#!/bin/bash
"""
Instalar software necesario en los servidores del cluster Linux real
"""

set -e

echo "=== Instalando Software en Cluster Linux Real ==="

# Servidores a configurar
SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

# Función para instalar en un servidor
install_on_server() {
    local server_host=$1
    
    echo "Configurando $server_host..."
    
    ssh "$server_host" << 'EOF'
        set -e
        
        echo "  Actualizando sistema..."
        sudo apt update -q
        
        echo "  Instalando KVM/libvirt..."
        sudo apt install -y -q \
            qemu-kvm \
            libvirt-daemon-system \
            libvirt-clients \
            bridge-utils \
            virt-manager \
            qemu-utils \
            openvswitch-switch \
            python3-libvirt \
            socat \
            netcat-openbsd
        
        echo "  Configurando servicios..."
        sudo systemctl enable libvirtd openvswitch-switch
        sudo systemctl start libvirtd openvswitch-switch
        
        echo "  Configurando usuario en grupos..."
        sudo usermod -a -G libvirt ubuntu
        sudo usermod -a -G kvm ubuntu
        
        echo "  Configurando libvirt..."
        sudo sed -i 's/#unix_sock_group = "libvirt"/unix_sock_group = "libvirt"/' /etc/libvirt/libvirtd.conf
        sudo sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/' /etc/libvirt/libvirtd.conf
        
        echo "  Configurando storage pools..."
        sudo mkdir -p /var/lib/libvirt/images
        
        # Crear pool default si no existe
        if ! virsh pool-info default >/dev/null 2>&1; then
            virsh pool-define-as default dir - - - - "/var/lib/libvirt/images"
            virsh pool-build default
            virsh pool-start default
            virsh pool-autostart default
        fi
        
        echo "  Reiniciando servicios..."
        sudo systemctl restart libvirtd
        
        echo "  ✅ $(hostname) configurado"
EOF
    
    if [ $? -eq 0 ]; then
        echo "  ✅ $server_host configurado exitosamente"
    else
        echo "  ❌ Error configurando $server_host"
        return 1
    fi
}

# Verificar SSH antes de continuar
echo "Verificando acceso SSH a servidores..."
failed_servers=()

for server in "${SERVERS[@]}"; do
    if ssh -o ConnectTimeout=5 "$server" "echo 'SSH OK'" >/dev/null 2>&1; then
        echo "  ✅ $server SSH OK"
    else
        echo "  ❌ $server SSH FAILED"
        failed_servers+=("$server")
    fi
done

if [ ${#failed_servers[@]} -gt 0 ]; then
    echo ""
    echo "❌ Algunos servidores no tienen SSH configurado:"
    for server in "${failed_servers[@]}"; do
        echo "  - $server"
    done
    echo ""
    echo "Configurar SSH primero ejecutando los comandos ssh-copy-id mostrados anteriormente"
    exit 1
fi

echo ""
echo "Instalando software en todos los servidores..."

# Instalar en paralelo
for server in "${SERVERS[@]}"; do
    install_on_server "$server" &
done

# Esperar a que terminen todas las instalaciones
wait

echo ""
echo "=== Verificando Instalación ==="

for server in "${SERVERS[@]}"; do
    echo "Verificando $server..."
    
    # Test libvirt
    if ssh "$server" "virsh list >/dev/null 2>&1"; then
        echo "  ✅ libvirt OK"
    else
        echo "  ❌ libvirt FAILED"
    fi
    
    # Test OVS  
    if ssh "$server" "sudo ovs-vsctl show >/dev/null 2>&1"; then
        echo "  ✅ OVS OK"
    else
        echo "  ❌ OVS FAILED"
    fi
done

echo ""
echo "✅ Instalación de software completada"
echo ""
echo "Próximo paso: python3 test_pucp_real_driver.py"