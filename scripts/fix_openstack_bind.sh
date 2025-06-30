#!/bin/bash

echo "🔧 Corrigiendo configuración de bind de OpenStack..."

ssh ubuntu@10.20.12.187 -p 5821 << 'REMOTE_FIX'
ssh ubuntu@10.60.2.21 << 'HEADNODE_FIX'
echo "=== Configurando OpenStack para escuchar en todas las interfaces ==="

# Backup de configuraciones
sudo mkdir -p /root/backup_configs
sudo cp /etc/apache2/sites-available/keystone.conf /root/backup_configs/ 2>/dev/null || true

echo "1. Configurando Apache/Keystone para escuchar en 0.0.0.0:5000..."
sudo sed -i 's/Listen 127.0.0.1:5000/Listen 0.0.0.0:5000/g' /etc/apache2/sites-available/keystone.conf 2>/dev/null || true
sudo sed -i 's/<VirtualHost 127.0.0.1:5000>/<VirtualHost *:5000>/g' /etc/apache2/sites-available/keystone.conf 2>/dev/null || true

echo "2. Configurando Nova API..."
if [ -f /etc/nova/nova.conf ]; then
    sudo sed -i 's/my_ip = 127.0.0.1/my_ip = 0.0.0.0/g' /etc/nova/nova.conf 2>/dev/null || true
    sudo sed -i '/\[DEFAULT\]/a osapi_compute_listen = 0.0.0.0' /etc/nova/nova.conf 2>/dev/null || true
fi

echo "3. Reiniciando servicios..."
sudo systemctl restart apache2
sudo systemctl restart nova-api
sudo systemctl restart neutron-server  
sudo systemctl restart glance-api

echo "4. Esperando servicios..."
sleep 5

echo "5. Verificando puertos después del reinicio:"
netstat -tlnp | grep -E "(5000|8774|9292|9696)"

echo "6. Test final desde IP externa:"
LOCAL_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
curl -s -m 3 http://$LOCAL_IP:5000/v3 | head -3 || echo "❌ Aún no responde desde IP externa"
HEADNODE_FIX
REMOTE_FIX
