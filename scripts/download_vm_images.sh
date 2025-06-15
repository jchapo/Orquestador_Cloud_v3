#!/bin/bash
# Descargar imágenes de VM en los servidores

set -e

echo "=== Descargando Imágenes de VM ==="

SERVER_PASSWORD="ubuntu"
SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

# Función para descargar imagen en un servidor
download_images() {
    local server=$1
    
    echo ""
    echo "📥 Descargando imágenes en $server..."
    
    ssh "$server" << 'EOF'
cd /var/lib/libvirt/images

# Función para descargar si no existe
download_if_not_exists() {
    local filename=$1
    local url=$2
    
    if [ ! -f "$filename" ]; then
        echo "  Descargando $filename..."
        wget -q --show-progress -O "$filename" "$url"
        if [ $? -eq 0 ]; then
            echo "  ✅ $filename descargado"
        else
            echo "  ❌ Error descargando $filename"
            rm -f "$filename"
            return 1
        fi
    else
        echo "  ✅ $filename ya existe"
    fi
    return 0
}

# Ubuntu 20.04 (imagen pequeña para testing)
download_if_not_exists "ubuntu-20.04-server.qcow2" \
    "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"

# Configurar permisos
sudo chown libvirt-qemu:libvirt *.qcow2 2>/dev/null || true
sudo chmod 644 *.qcow2 2>/dev/null || true

echo "  ✅ Imágenes configuradas en $(hostname)"
EOF
}

# Verificar que los servidores están configurados
echo "Verificando servidores configurados..."
available_servers=()

for server in "${SERVERS[@]}"; do
    if ssh "$server" "virsh list >/dev/null 2>&1"; then
        echo "  ✅ $server configurado"
        available_servers+=("$server")
    else
        echo "  ❌ $server no configurado"
    fi
done

if [ ${#available_servers[@]} -eq 0 ]; then
    echo "❌ No hay servidores configurados. Ejecutar primero ./install_with_password.sh"
    exit 1
fi

echo ""
echo "Descargando imágenes en ${#available_servers[@]} servidor(es)..."

# Descargar en paralelo
for server in "${available_servers[@]}"; do
    download_images "$server" &
done

# Esperar a que terminen
wait

echo ""
echo "✅ Descarga de imágenes completada"
echo ""
echo "Verificar con:"
echo "  ssh pucp-server1 'ls -la /var/lib/libvirt/images/'"
