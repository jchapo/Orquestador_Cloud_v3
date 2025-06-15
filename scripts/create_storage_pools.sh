#!/bin/bash
# Crear storage pools en todos los servidores

set -e

echo "=== Creando Storage Pools ==="

SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

# Función para crear storage pool en un servidor
create_storage_pool() {
    local server=$1
    
    echo ""
    echo "💾 Creando storage pool en $server..."
    
    ssh "$server" << 'EOF'
echo "  Verificando directorio de imágenes..."
sudo mkdir -p /var/lib/libvirt/images
sudo chown root:libvirt /var/lib/libvirt/images
sudo chmod 775 /var/lib/libvirt/images

echo "  Creando storage pool 'default'..."
if ! virsh pool-info default >/dev/null 2>&1; then
    virsh pool-define-as default dir - - - - "/var/lib/libvirt/images"
    virsh pool-build default
    virsh pool-start default
    virsh pool-autostart default
    echo "  ✅ Storage pool 'default' creado"
else
    echo "  ✅ Storage pool 'default' ya existe"
    # Asegurar que esté activo
    virsh pool-start default 2>/dev/null || true
    virsh pool-autostart default 2>/dev/null || true
fi

echo "  Verificando storage pool..."
virsh pool-list --all
echo "  📋 $(hostname): Storage pool configurado"
EOF
    
    return $?
}

# Crear storage pools en todos los servidores
successful_pools=()
failed_pools=()

for server in "${SERVERS[@]}"; do
    if create_storage_pool "$server"; then
        successful_pools+=("$server")
    else
        failed_pools+=("$server")
        echo "  ❌ Error creando pool en $server"
    fi
done

echo ""
echo "=== Verificando Storage Pools ==="

for server in "${successful_pools[@]}"; do
    echo ""
    echo "🔍 Verificando $server..."
    
    # Verificar pool
    if ssh "$server" "virsh pool-list | grep -q default.*active"; then
        echo "  ✅ Storage pool activo"
        
        # Mostrar info del pool
        pool_info=$(ssh "$server" "virsh pool-info default | grep -E '(State|Capacity|Available)'")
        echo "$pool_info" | sed 's/^/    /'
    else
        echo "  ❌ Storage pool no activo"
    fi
done

echo ""
echo "═══════════════════════════════════════"
echo "📊 RESUMEN STORAGE POOLS"
echo "═══════════════════════════════════════"
echo "Pools creados exitosamente: ${#successful_pools[@]}/4"
echo "Pools fallidos: ${#failed_pools[@]}/4"

if [ ${#successful_pools[@]} -eq 4 ]; then
    echo ""
    echo "✅ Todos los storage pools configurados correctamente"
    echo ""
    echo "🚀 Próximos pasos:"
    echo "1. Descargar imágenes: ./download_vm_images.sh"
    echo "2. Probar driver: python3 test_pucp_real_driver.py"
else
    echo ""
    echo "⚠️  Algunos storage pools necesitan configuración manual"
fi
