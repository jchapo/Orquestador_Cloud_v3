#!/bin/bash
# Instalación automatizada usando contraseña "ubuntu"

set -e

echo "=== Instalación Automatizada con Contraseña ==="

# Instalar sshpass si no está disponible
if ! command -v sshpass >/dev/null 2>&1; then
    echo "Instalando sshpass..."
    sudo apt update && sudo apt install -y sshpass
fi

# Contraseña de los servidores
SERVER_PASSWORD="ubuntu"
SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

# Función para ejecutar comando con sudo usando contraseña
run_with_sudo() {
    local server=$1
    local command=$2
    
    ssh "$server" "echo '$SERVER_PASSWORD' | sudo -S $command"
}

# Función para instalar en un servidor
install_on_server() {
    local server_host=$1
    
    echo ""
    echo "🔧 Configurando $server_host..."
    
    # Actualizar sistema
    echo "  Actualizando sistema..."
    run_with_sudo "$server_host" "apt update -q"
    
    # Instalar paquetes (OVS ya está, instalar resto)
    echo "  Instalando KVM y libvirt..."
    run_with_sudo "$server_host" "DEBIAN_FRONTEND=noninteractive apt install -y -q qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager qemu-utils python3-libvirt socat netcat-openbsd"
    
    # Habilitar servicios
    echo "  Habilitando servicios..."
    run_with_sudo "$server_host" "systemctl enable libvirtd"
    run_with_sudo "$server_host" "systemctl start libvirtd"
    
    # Configurar grupos
    echo "  Configurando grupos de usuario..."
    run_with_sudo "$server_host" "usermod -a -G libvirt ubuntu"
    run_with_sudo "$server_host" "usermod -a -G kvm ubuntu"
    
    # Configurar libvirt
    echo "  Configurando libvirt..."
    run_with_sudo "$server_host" "sed -i 's/#unix_sock_group = \"libvirt\"/unix_sock_group = \"libvirt\"/' /etc/libvirt/libvirtd.conf"
    run_with_sudo "$server_host" "sed -i 's/#unix_sock_rw_perms = \"0770\"/unix_sock_rw_perms = \"0770\"/' /etc/libvirt/libvirtd.conf"
    
    # Crear directorio de imágenes
    echo "  Configurando storage..."
    run_with_sudo "$server_host" "mkdir -p /var/lib/libvirt/images"
    run_with_sudo "$server_host" "chown root:libvirt /var/lib/libvirt/images"
    run_with_sudo "$server_host" "chmod 775 /var/lib/libvirt/images"
    
    # Reiniciar libvirtd
    echo "  Reiniciando libvirtd..."
    run_with_sudo "$server_host" "systemctl restart libvirtd"
    
    # Crear storage pool (esto requiere que el usuario esté en el grupo libvirt)
    echo "  Configurando storage pool..."
    ssh "$server_host" << 'EOF'
# Esperar un poco para que los grupos se apliquen
sleep 2

# Verificar acceso a libvirt
if ! virsh list >/dev/null 2>&1; then
    echo "    Esperando que se apliquen grupos..."
    # Usar newgrp para aplicar grupos inmediatamente
    newgrp libvirt << 'NEWGRP_EOF'
    
    # Crear storage pool si no existe
    if ! virsh pool-info default >/dev/null 2>&1; then
        virsh pool-define-as default dir - - - - "/var/lib/libvirt/images"
        virsh pool-build default
        virsh pool-start default
        virsh pool-autostart default
        echo "    Storage pool 'default' creado"
    else
        echo "    Storage pool 'default' ya existe"
    fi
    
    # Verificar que funciona
    virsh list >/dev/null 2>&1 && echo "    ✅ libvirt funcionando"
NEWGRP_EOF
else
    # El usuario ya tiene acceso
    if ! virsh pool-info default >/dev/null 2>&1; then
        virsh pool-define-as default dir - - - - "/var/lib/libvirt/images"
        virsh pool-build default
        virsh pool-start default
        virsh pool-autostart default
        echo "    Storage pool 'default' creado"
    else
        echo "    Storage pool 'default' ya existe"
    fi
fi
EOF
    
    echo "  ✅ $server_host configurado"
    return 0
}

# Verificar conectividad SSH
echo "Verificando conectividad SSH..."
for server in "${SERVERS[@]}"; do
    if ssh -o ConnectTimeout=5 "$server" "echo 'SSH OK'" >/dev/null 2>&1; then
        echo "  ✅ $server SSH OK"
    else
        echo "  ❌ $server SSH FAILED"
        exit 1
    fi
done

echo ""
echo "Instalando software en servidores..."

# Instalar en cada servidor
successful_servers=()
failed_servers=()

for server in "${SERVERS[@]}"; do
    if install_on_server "$server"; then
        successful_servers+=("$server")
    else
        failed_servers+=("$server")
        echo "  ⚠️  Error en $server, continuando..."
    fi
done

echo ""
echo "=== Verificando Instalación ==="

# Verificar cada servidor
for server in "${successful_servers[@]}"; do
    echo ""
    echo "🔍 Verificando $server..."
    
    # Test libvirt
    if ssh "$server" "virsh list >/dev/null 2>&1"; then
        echo "  ✅ libvirt OK"
        
        # Verificar storage pool
        if ssh "$server" "virsh pool-list | grep -q default"; then
            echo "  ✅ storage pool OK"
        else
            echo "  ⚠️  storage pool missing"
        fi
    else
        echo "  ❌ libvirt FAILED"
        echo "    Debug info:"
        ssh "$server" "groups; ls -la /var/run/libvirt/ | head -3" 2>/dev/null || echo "    No debug info"
    fi
    
    # Test OVS (ya estaba instalado)
    if ssh "$server" "echo '$SERVER_PASSWORD' | sudo -S ovs-vsctl show >/dev/null 2>&1"; then
        echo "  ✅ OVS OK"
    else
        echo "  ❌ OVS FAILED"
    fi
    
    # Info del sistema
    hostname=$(ssh "$server" "hostname")
    echo "  📋 Hostname: $hostname"
done

echo ""
echo "═══════════════════════════════════════"
echo "📊 RESUMEN FINAL"
echo "═══════════════════════════════════════"
echo "Servidores exitosos: ${#successful_servers[@]}/4"
echo "Servidores fallidos: ${#failed_servers[@]}/4"

if [ ${#successful_servers[@]} -gt 0 ]; then
    echo ""
    echo "✅ Servidores configurados:"
    for server in "${successful_servers[@]}"; do
        echo "   - $server"
    done
    
    echo ""
    echo "🚀 Próximos pasos:"
    echo "1. Descargar imágenes de VM:"
    echo "   ./download_vm_images.sh"
    echo ""
    echo "2. Probar el driver:"
    echo "   python3 test_pucp_real_driver.py"
else
    echo ""
    echo "❌ No se configuró ningún servidor exitosamente"
fi
