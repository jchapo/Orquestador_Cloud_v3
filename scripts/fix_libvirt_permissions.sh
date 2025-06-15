#!/bin/bash
# fix_libvirt_permissions.sh

echo "🔧 Configurando permisos de libvirt en el cluster PUCP"
echo "=================================================="

SERVERS=("server1" "server2" "server3" "server4")

for server in "${SERVERS[@]}"; do
    echo ""
    echo "📡 Configurando pucp-$server..."
    
    ssh ubuntu@pucp-$server << 'EOF'
        echo "🔍 Verificando estado actual..."
        
        # Verificar directorio de imágenes
        if [ ! -d "/var/lib/libvirt/images" ]; then
            echo "📁 Creando directorio /var/lib/libvirt/images"
            sudo mkdir -p /var/lib/libvirt/images
        fi
        
        # Configurar permisos del directorio
        echo "🔐 Configurando permisos..."
        sudo chown -R libvirt-qemu:libvirt-qemu /var/lib/libvirt/images
        sudo chmod 755 /var/lib/libvirt/images
        
        # Agregar usuario ubuntu al grupo libvirt
        sudo usermod -a -G libvirt ubuntu
        sudo usermod -a -G libvirt-qemu ubuntu
        
        # Configurar permisos para que ubuntu pueda crear archivos
        sudo setfacl -m u:ubuntu:rwx /var/lib/libvirt/images
        sudo setfacl -d -m u:ubuntu:rwx /var/lib/libvirt/images
        
        # Verificar que libvirt esté corriendo
        sudo systemctl enable libvirtd
        sudo systemctl start libvirtd
        
        # Mostrar estado final
        echo "✅ Configuración completada en $(hostname)"
        echo "   Permisos directorio:"
        ls -la /var/lib/libvirt/images/
        echo "   Grupos del usuario ubuntu:"
        groups ubuntu
        echo "   Estado libvirtd:"
        sudo systemctl is-active libvirtd
EOF
    
    if [ $? -eq 0 ]; then
        echo "✅ pucp-$server configurado exitosamente"
    else
        echo "❌ Error configurando pucp-$server"
    fi
done

echo ""
echo "🎯 Configuración de permisos completa"
echo "💡 Es recomendable que los usuarios se reconecten por SSH para que los grupos surtan efecto"
