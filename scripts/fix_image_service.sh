#!/bin/bash
# scripts/fix_image_service.sh

echo "🖼️ Reparando Image Service..."

# Verificar el servicio
cd /opt/pucp-orchestrator/image_service

echo "🔍 Verificando configuración..."

# Crear directorio de imágenes si no existe
echo "📁 Verificando directorios..."
sudo mkdir -p /var/lib/pucp-orchestrator/images
sudo chown $USER:$USER /var/lib/pucp-orchestrator/images

# Verificar permisos
if [ -w "/var/lib/pucp-orchestrator/images" ]; then
    echo "✅ Directorio de imágenes accesible"
else
    echo "❌ Problemas de permisos en directorio de imágenes"
    sudo chown -R $USER:$USER /var/lib/pucp-orchestrator/
fi

# Test manual del servicio
echo "🚀 Test manual del image service..."
source /opt/pucp-orchestrator/venv/bin/activate

timeout 10 python3 image_service.py &
SERVICE_PID=$!

sleep 3

if ps -p $SERVICE_PID > /dev/null; then
    echo "✅ Image service funciona manualmente"
    kill $SERVICE_PID
    
    # Reiniciar systemd
    sudo systemctl stop pucp-image-service
    sleep 2
    sudo systemctl start pucp-image-service
    sleep 3
    
    if systemctl is-active pucp-image-service >/dev/null; then
        echo "✅ Image service systemd funcionando"
    else
        echo "❌ Problemas con systemd"
        sudo journalctl -u pucp-image-service --since '1 minute ago' --no-pager
    fi
else
    echo "❌ Image service no arranca"
    echo "📋 Verificando logs..."
    sudo journalctl -u pucp-image-service --since '5 minutes ago' --no-pager
fi
