#!/bin/bash

echo "🔧 Verificando configuración de OpenStack en headnode..."

ssh ubuntu@10.20.12.187 -p 5821 << 'REMOTE_CHECK'
# Conectar al headnode y revisar configuración
ssh ubuntu@10.60.2.21 << 'HEADNODE_CHECK'
echo "=== Verificando configuración de OpenStack ==="

echo "1. Servicios activos:"
systemctl is-active apache2 keystone nova-api neutron-server glance-api

echo ""
echo "2. Puertos escuchando:"
netstat -tlnp | grep -E "(5000|8774|9292|9696)" | head -10

echo ""
echo "3. Configuración de Apache/Keystone:"
if [ -f /etc/apache2/sites-enabled/keystone.conf ]; then
    echo "✅ Keystone site habilitado"
    grep -E "(Listen|VirtualHost)" /etc/apache2/sites-enabled/keystone.conf
else
    echo "❌ Keystone site no encontrado"
fi

echo ""
echo "4. Test local en headnode:"
curl -s http://localhost:5000/v3 | head -3 || echo "❌ Keystone no responde localmente"

echo ""
echo "5. Test desde IP externa en headnode:"
LOCAL_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
echo "IP local del headnode: $LOCAL_IP"
curl -s -m 3 http://$LOCAL_IP:5000/v3 | head -3 || echo "❌ Keystone no responde desde IP externa"

echo ""
echo "6. Firewall status:"
ufw status 2>/dev/null || echo "UFW no instalado"
iptables -L INPUT | grep -E "(5000|8774|9292|9696)" || echo "No hay reglas iptables para puertos OpenStack"
HEADNODE_CHECK
REMOTE_CHECK
