#!/bin/bash
# scripts/verify_cluster_setup.sh
# Verificación completa del cluster con soporte para contraseñas

set -e

echo "=== Verificación Completa del Cluster PUCP ==="

# Configuración
SERVER_PASSWORD="ubuntu"
#SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")
SERVERS=("pucp-server3" "pucp-server4")
# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para ejecutar comando con sudo usando contraseña
run_with_sudo() {
    local server=$1
    local command=$2
    
    ssh "$server" "echo '$SERVER_PASSWORD' | sudo -S $command" 2>/dev/null
}

# Función para logging con colores
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Función para verificar un servidor completo
verify_server() {
    local server=$1
    local server_status="unknown"
    
    echo ""
    echo "════════════════════════════════════════"
    echo "🔍 VERIFICANDO $server"
    echo "════════════════════════════════════════"
    
    # Test 1: Conectividad SSH
    log_test "1. Conectividad SSH"
    if ssh -o ConnectTimeout=5 "$server" "echo 'Connected'" >/dev/null 2>&1; then
        log_info "✅ SSH connection OK"
    else
        log_error "❌ SSH connection FAILED"
        return 1
    fi
    
    # Test 2: Información del sistema
    log_test "2. Información del Sistema"
    ssh "$server" << 'EOF'
echo "  Hostname: $(hostname)"
echo "  OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
echo "  Kernel: $(uname -r)"
echo "  Uptime: $(uptime | cut -d',' -f1)"
echo "  IP Management: $(ip addr show ens3 | grep 'inet ' | awk '{print $2}' || echo 'No IP')"
EOF
    
    # Test 3: Usuarios y grupos
    log_test "3. Usuarios y Grupos"
    groups_output=$(ssh "$server" "groups" 2>/dev/null)
    echo "  Grupos usuario: $groups_output"
    
    if echo "$groups_output" | grep -q "libvirt"; then
        log_info "  ✅ Usuario en grupo libvirt"
        libvirt_group=true
    else
        log_error "  ❌ Usuario NO en grupo libvirt"
        libvirt_group=false
    fi
    
    if echo "$groups_output" | grep -q "kvm"; then
        log_info "  ✅ Usuario en grupo kvm"
        kvm_group=true
    else
        log_warn "  ⚠️  Usuario NO en grupo kvm"
        kvm_group=false
    fi
    
    # Test 4: Servicios del sistema
    log_test "4. Estado de Servicios"
    
    # libvirtd
    libvirtd_status=$(ssh "$server" "systemctl is-active libvirtd 2>/dev/null || echo 'inactive'")
    if [ "$libvirtd_status" = "active" ]; then
        log_info "  ✅ libvirtd: $libvirtd_status"
        libvirtd_ok=true
    else
        log_error "  ❌ libvirtd: $libvirtd_status"
        libvirtd_ok=false
    fi
    
    # openvswitch-switch
    ovs_status=$(ssh "$server" "systemctl is-active openvswitch-switch 2>/dev/null || echo 'inactive'")
    if [ "$ovs_status" = "active" ]; then
        log_info "  ✅ openvswitch-switch: $ovs_status"
        ovs_service_ok=true
    else
        log_error "  ❌ openvswitch-switch: $ovs_status"
        ovs_service_ok=false
    fi
    
    # Test 5: Software instalado
    log_test "5. Software Instalado"
    
    # KVM
#    if ssh "$server" "which qemu-kvm >/dev/null 2>&1"; then
#        kvm_version=$(ssh "$server" "qemu-kvm --version | head -1" 2>/dev/null || echo "Unknown version")
#        log_info "  ✅ KVM: $kvm_version"
#        kvm_installed=true
#    else
#        log_error "  ❌ KVM: No instalado"
#        kvm_installed=false
#    fi

# Versión actualizada para detectar KVM correctamente en Ubuntu 20.04
if ssh "$server" "which qemu-system-x86_64 >/dev/null 2>&1"; then
    kvm_version=$(ssh "$server" "qemu-system-x86_64 --version | head -1" 2>/dev/null || echo "Unknown version")
    log_info "  ✅ KVM: $kvm_version"
    kvm_installed=true
elif ssh "$server" "which kvm >/dev/null 2>&1"; then
    kvm_version=$(ssh "$server" "kvm --version | head -1" 2>/dev/null || echo "Unknown version")
    log_info "  ✅ KVM: $kvm_version"
    kvm_installed=true
elif ssh "$server" "which qemu-kvm >/dev/null 2>&1"; then
    kvm_version=$(ssh "$server" "qemu-kvm --version | head -1" 2>/dev/null || echo "Unknown version")
    log_info "  ✅ KVM: $kvm_version"
    kvm_installed=true
else
    log_error "  ❌ KVM: No instalado"
    kvm_installed=false
fi
    
    # libvirt
    if ssh "$server" "which virsh >/dev/null 2>&1"; then
        libvirt_version=$(ssh "$server" "virsh --version 2>/dev/null || echo 'Unknown'")
        log_info "  ✅ libvirt: $libvirt_version"
        libvirt_installed=true
    else
        log_error "  ❌ libvirt: No instalado"
        libvirt_installed=false
    fi
    
    # OVS
    if ssh "$server" "which ovs-vsctl >/dev/null 2>&1"; then
        ovs_version=$(ssh "$server" "ovs-vsctl --version | head -1 | awk '{print \$4}' 2>/dev/null || echo 'Unknown'")
        log_info "  ✅ OVS: $ovs_version"
        ovs_installed=true
    else
        log_error "  ❌ OVS: No instalado"
        ovs_installed=false
    fi
    
    # Test 6: Funcionalidad libvirt
    log_test "6. Funcionalidad libvirt"
    
    if ssh "$server" "virsh list >/dev/null 2>&1"; then
        log_info "  ✅ virsh list funciona"
        
        # Verificar conexión a hypervisor
        hypervisor_info=$(ssh "$server" "virsh nodeinfo 2>/dev/null | grep 'CPU model\\|Memory size' || echo 'No info available'")
        echo "  Hypervisor info:"
        echo "$hypervisor_info" | sed 's/^/    /'
        
        virsh_ok=true
    else
        log_error "  ❌ virsh list falló"
        echo "    Error details:"
        ssh "$server" "virsh list 2>&1 | head -3 | sed 's/^/      /'"
        virsh_ok=false
    fi
    
    # Test 7: Storage pools
    log_test "7. Storage Pools"
    
    if ssh "$server" "virsh pool-list --all >/dev/null 2>&1"; then
        pools=$(ssh "$server" "virsh pool-list --all 2>/dev/null" || echo "Error getting pools")
        echo "  Storage pools:"
        echo "$pools" | sed 's/^/    /'
        
        if ssh "$server" "virsh pool-list --all 2>/dev/null | grep -q 'default.*active'"; then
            log_info "  ✅ Default storage pool activo"
            storage_ok=true
        else
            log_warn "  ⚠️  Default storage pool no activo"
            storage_ok=false
        fi
    else
        log_error "  ❌ No se pueden listar storage pools"
        storage_ok=false
    fi
    
    # Test 8: OVS funcionalidad
    log_test "8. Funcionalidad OVS"
    
    if run_with_sudo "$server" "ovs-vsctl show >/dev/null 2>&1"; then
        log_info "  ✅ ovs-vsctl show funciona"
        
        # Mostrar configuración OVS
        echo "  Configuración OVS:"
        run_with_sudo "$server" "ovs-vsctl show 2>/dev/null | head -10 | sed 's/^/    /'" || echo "    No se puede mostrar config OVS"
        
        ovs_functional=true
    else
        log_error "  ❌ ovs-vsctl show falló"
        ovs_functional=false
    fi
    
    # Test 9: Permisos y archivos
    log_test "9. Permisos y Archivos"
    
    # Directorio de imágenes
    if ssh "$server" "ls -la /var/lib/libvirt/images/ >/dev/null 2>&1"; then
        images_info=$(ssh "$server" "ls -la /var/lib/libvirt/images/ | head -5" 2>/dev/null || echo "Cannot list")
        echo "  /var/lib/libvirt/images/:"
        echo "$images_info" | sed 's/^/    /'
        images_dir_ok=true
    else
        log_error "  ❌ No se puede acceder a /var/lib/libvirt/images/"
        images_dir_ok=false
    fi
    
    # Socket de libvirt
    if ssh "$server" "ls -la /var/run/libvirt/libvirt-sock* 2>/dev/null | head -3"; then
        log_info "  ✅ Sockets libvirt presentes"
        sockets_ok=true
    else
        log_warn "  ⚠️  Sockets libvirt no encontrados"
        sockets_ok=false
    fi
    
    # Test 10: Capacidades del sistema
    log_test "10. Capacidades del Sistema"
    
    # Verificar KVM support
    if ssh "$server" "lsmod | grep -q kvm"; then
        kvm_modules=$(ssh "$server" "lsmod | grep kvm" 2>/dev/null || echo "No KVM modules")
        log_info "  ✅ Módulos KVM cargados"
        echo "  KVM modules:"
        echo "$kvm_modules" | sed 's/^/    /'
        kvm_support=true
    else
        log_error "  ❌ Módulos KVM no cargados"
        kvm_support=false
    fi
    
    # Verificar /dev/kvm
    if ssh "$server" "ls -la /dev/kvm >/dev/null 2>&1"; then
        kvm_device=$(ssh "$server" "ls -la /dev/kvm 2>/dev/null")
        log_info "  ✅ /dev/kvm presente"
        echo "  Device: $kvm_device"
        kvm_device_ok=true
    else
        log_error "  ❌ /dev/kvm no presente"
        kvm_device_ok=false
    fi
    
    # Test 11: Recursos del sistema
    log_test "11. Recursos del Sistema"
    
    ssh "$server" << 'EOF'
echo "  CPU cores: $(nproc)"
echo "  Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo "  Disk space /: $(df -h / | awk 'NR==2 {print $4}')"
echo "  Disk space /var/lib/libvirt: $(df -h /var/lib/libvirt/images 2>/dev/null | awk 'NR==2 {print $4}' || echo 'N/A')"
EOF
    
    # Evaluación final del servidor
    echo ""
    echo "📊 EVALUACIÓN FINAL DE $server:"
    
    local score=0
    local max_score=11
    
    $libvirtd_ok && ((score++))
    $ovs_service_ok && ((score++))
    $kvm_installed && ((score++))
    $libvirt_installed && ((score++))
    $ovs_installed && ((score++))
    $virsh_ok && ((score++))
    $storage_ok && ((score++))
    $ovs_functional && ((score++))
    $images_dir_ok && ((score++))
    $kvm_support && ((score++))
    $kvm_device_ok && ((score++))
    
    local percentage=$((score * 100 / max_score))
    
    echo "  Puntuación: $score/$max_score ($percentage%)"
    
    if [ $percentage -ge 90 ]; then
        log_info "  ✅ SERVIDOR COMPLETAMENTE FUNCIONAL"
        echo "$server:functional" >> /tmp/server_status.tmp
    elif [ $percentage -ge 70 ]; then
        log_warn "  ⚠️  SERVIDOR MAYORMENTE FUNCIONAL"
        echo "$server:mostly_functional" >> /tmp/server_status.tmp
    elif [ $percentage -ge 50 ]; then
        log_warn "  ⚠️  SERVIDOR PARCIALMENTE FUNCIONAL"
        echo "$server:partial" >> /tmp/server_status.tmp
    else
        log_error "  ❌ SERVIDOR NO FUNCIONAL"
        echo "$server:non_functional" >> /tmp/server_status.tmp
    fi
    
    return 0
}

# Función principal
main() {
    echo "Iniciando verificación completa del cluster..."
    echo "Fecha: $(date)"
    echo ""
    
    # Limpiar archivo temporal
    rm -f /tmp/server_status.tmp
    
    # Verificar cada servidor
    for server in "${SERVERS[@]}"; do
        verify_server "$server"
    done
    
    echo ""
    echo "════════════════════════════════════════"
    echo "📋 RESUMEN FINAL DEL CLUSTER"
    echo "════════════════════════════════════════"
    
    # Leer resultados
    functional_servers=()
    mostly_functional_servers=()
    partial_servers=()
    non_functional_servers=()
    
    if [ -f /tmp/server_status.tmp ]; then
        while IFS=':' read -r server status; do
            case $status in
                "functional")
                    functional_servers+=("$server")
                    ;;
                "mostly_functional")
                    mostly_functional_servers+=("$server")
                    ;;
                "partial")
                    partial_servers+=("$server")
                    ;;
                "non_functional")
                    non_functional_servers+=("$server")
                    ;;
            esac
        done < /tmp/server_status.tmp
    fi
    
    # Mostrar resumen
    echo "✅ Servidores completamente funcionales: ${#functional_servers[@]}"
    for server in "${functional_servers[@]}"; do
        echo "   - $server"
    done
    
    if [ ${#mostly_functional_servers[@]} -gt 0 ]; then
        echo ""
        echo "⚠️  Servidores mayormente funcionales: ${#mostly_functional_servers[@]}"
        for server in "${mostly_functional_servers[@]}"; do
            echo "   - $server"
        done
    fi
    
    if [ ${#partial_servers[@]} -gt 0 ]; then
        echo ""
        echo "⚠️  Servidores parcialmente funcionales: ${#partial_servers[@]}"
        for server in "${partial_servers[@]}"; do
            echo "   - $server"
        done
    fi
    
    if [ ${#non_functional_servers[@]} -gt 0 ]; then
        echo ""
        echo "❌ Servidores no funcionales: ${#non_functional_servers[@]}"
        for server in "${non_functional_servers[@]}"; do
            echo "   - $server"
        done
    fi
    
    # Recomendaciones
    echo ""
    echo "🚀 RECOMENDACIONES:"
    
    local total_usable=$((${#functional_servers[@]} + ${#mostly_functional_servers[@]}))
    
    if [ $total_usable -ge 2 ]; then
        echo "✅ Cluster listo para testing del orchestrator"
        echo "   Ejecutar: python3 scripts/test_pucp_real_driver.py"
    elif [ $total_usable -eq 1 ]; then
        echo "⚠️  Solo 1 servidor funcional - limitado pero usable para testing"
        echo "   Ejecutar: python3 scripts/test_pucp_real_driver.py"
    else
        echo "❌ Cluster no listo - configurar más servidores"
        echo "   Ejecutar: ./scripts/install_with_password.sh"
    fi
    
    if [ ${#partial_servers[@]} -gt 0 ] || [ ${#non_functional_servers[@]} -gt 0 ]; then
        echo ""
        echo "🔧 Para servidores con problemas:"
        echo "   - Revisar logs detallados arriba"
        echo "   - Ejecutar configuración manual: ./scripts/manual_setup_guide.sh"
        echo "   - Reiniciar servicios: sudo systemctl restart libvirtd"
    fi
    
    # Cleanup
    rm -f /tmp/server_status.tmp
    
    echo ""
    echo "✅ Verificación completada!"
}

# Ejecutar verificación
main
