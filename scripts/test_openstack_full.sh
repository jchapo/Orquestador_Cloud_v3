#!/bin/bash

echo "🧪 Test completo de conectividad OpenStack..."

# 1. Establecer túnel SSH
echo "=== 1. Estableciendo túnel SSH ==="
/opt/pucp-orchestrator/scripts/setup_openstack_tunnel.sh

if [ $? -ne 0 ]; then
    echo "❌ Error estableciendo túnel SSH"
    exit 1
fi

# 2. Cargar variables de entorno
echo -e "\n=== 2. Cargando variables de entorno ==="
source /opt/pucp-orchestrator/scripts/openstack_env.sh

# 3. Probar conectividad básica
echo -e "\n=== 3. Probando conectividad básica ==="
echo "Probando Keystone..."
if curl -s -k http://localhost:5000/v3 | grep -q "keystone"; then
    echo "✅ Keystone responde"
else
    echo "❌ Keystone no responde"
    exit 1
fi

# 4. Probar autenticación con Python
echo -e "\n=== 4. Probando autenticación Python ==="
cd /opt/pucp-orchestrator
python3 << 'PYTHON_SCRIPT'
import sys
sys.path.append('.')

try:
    from slice_service.openstack.config import OpenStackConfig
    from slice_service.openstack.api_client import OpenStackAPIClient
    
    print("📋 Cargando configuración...")
    config = OpenStackConfig()
    client = OpenStackAPIClient(config.get_auth_config())
    
    print("🔐 Probando autenticación...")
    token = client.session.get_token()
    print(f"✅ Token obtenido: {token[:50]}...")
    
    print("🖥️  Probando Nova...")
    servers = client.nova.servers.list()
    print(f"✅ Nova accesible - {len(servers)} servidores")
    
    print("🌐 Probando Neutron...")
    networks = client.neutron.list_networks()['networks']
    print(f"✅ Neutron accesible - {len(networks)} redes")
    
    print("🖼️  Probando Glance...")
    images = list(client.glance.images.list())
    print(f"✅ Glance accesible - {len(images)} imágenes")
    
    print("\n🎉 ¡Conectividad OpenStack exitosa!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTHON_SCRIPT

echo -e "\n=== 5. Probando deployment de slice ==="
echo "Probando crear slice de prueba..."

curl -X POST http://localhost/api/slices \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInVzZXJfaWQiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzUxMzM4MDk4fQ.xJHztA7QxcoKsPTd_sPEPlyQk3EYo2Wa6pe1fPryUkQ" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-tunnel-slice",
        "infrastructure": "openstack",
        "topology_type": "linear",
        "nodes": [
            {
                "name": "vm1",
                "flavor": "small",
                "image": "cirros-0.5.2"
            }
        ],
        "networks": [
            {
                "name": "test-network",
                "cidr": "192.168.100.0/24"
            }
        ]
    }'

echo -e "\n\n✅ Test completo finalizado"
