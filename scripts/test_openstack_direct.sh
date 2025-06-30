#!/bin/bash

echo "🧪 Test directo de OpenStack via gateway..."

ssh ubuntu@10.20.12.187 -p 5821 << 'REMOTE_TEST'
# Conectar al headnode interno y probar OpenStack
ssh ubuntu@192.168.202.1 << 'HEADNODE_TEST'
echo "=== Test directo de OpenStack en headnode ==="

echo "1. Verificar servicios:"
systemctl is-active apache2 nova-api neutron-server glance-api

echo ""
echo "2. Test APIs locales:"
curl -s -m 3 http://localhost:5000/v3 | head -2 && echo "✅ Keystone local OK"
curl -s -m 3 http://localhost:8774 | head -2 && echo "✅ Nova local OK"

echo ""
echo "3. Verificar credenciales OpenStack:"
export OS_AUTH_URL=http://localhost:5000/v3
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=openstack123
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3

echo "Probando comando OpenStack:"
openstack token issue --format value --column id 2>/dev/null | head -20
HEADNODE_TEST
REMOTE_TEST
