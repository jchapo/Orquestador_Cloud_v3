#!/bin/bash
# setup_libvirt_permissions.sh

echo "🔧 Configurando permisos de libvirt en el cluster PUCP"
echo "===================================================="

SERVERS=("server1" "server2" "server3" "server4")

for server in "${SERVERS[@]}"; do
    echo ""
    echo "📡 Configurando pucp-$server..."
    
    ssh ubuntu@pucp-$server << 'EOF'
        # Verificar y crear directorios necesarios
        echo "📁 Configurando directorios..."
        
        # Crear directorios si no existen
        sudo mkdir -p /var/lib/libvirt/images
        sudo mkdir -p /var/lib/libvirt/iso
        
        # Establecer propietario correcto (libvirt-qemu group)
        sudo chown root:libvirt-qemu /var/lib/libvirt/images
        sudo chown root:libvirt-qemu /var/lib/libvirt/iso
        
        # Establecer permisos correctos
        sudo chmod 775 /var/lib/libvirt/images
        sudo chmod 775 /var/lib/libvirt/iso
        
        # Agregar usuario ubuntu al grupo libvirt-qemu
        sudo usermod -a -G libvirt-qemu ubuntu
        sudo usermod -a -G libvirt ubuntu
        
        # Verificar permisos
        echo "✅ Permisos configurados:"
        ls -la /var/lib/libvirt/images
        
        # Verificar grupos del usuario
        echo "👤 Grupos del usuario ubuntu:"
        groups ubuntu
        
        # Crear imagen base de prueba si no existe
        if [ ! -f "/var/lib/libvirt/images/ubuntu-20.04-server.qcow2" ]; then
            echo "💿 Descargando imagen base Ubuntu 20.04..."
            sudo wget -O /var/lib/libvirt/images/ubuntu-20.04-server.qcow2 \
                "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img" || \
            echo "⚠️ No se pudo descargar la imagen, créala manualmente"
        fi
        
        # Establecer permisos de la imagen base
        sudo chown libvirt-qemu:libvirt-qemu /var/lib/libvirt/images/*.qcow2 2>/dev/null || true
        sudo chmod 664 /var/lib/libvirt/images/*.qcow2 2>/dev/null || true
EOF
    
    if [ $? -eq 0 ]; then
        echo "✅ pucp-$server configurado exitosamente"
    else
        echo "❌ Error configurando pucp-$server"
    fi
done

echo ""
echo "🎯 Configuración de permisos completa"
echo "💡 IMPORTANTE: Los usuarios deben cerrar sesión y volver a conectarse para que los grupos tomen efecto"
