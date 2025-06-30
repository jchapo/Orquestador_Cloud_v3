#!/bin/bash

echo "🧪 Test final de conectividad OpenStack"
echo "======================================="

cd /opt/pucp-orchestrator
source venv/bin/activate

python3 << 'PYTHON_TEST'
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
    
    print("🖥️  Probando Nova (Compute)...")
    servers = client.nova.servers.list()
    print(f"✅ Nova: {len(servers)} servidores encontrados")
    
    print("🌐 Probando Neutron (Network)...")
    networks = client.neutron.list_networks()['networks']
    print(f"✅ Neutron: {len(networks)} redes encontradas")
    
    print("🖼️  Probando Glance (Images)...")
    images = list(client.glance.images.list())
    print(f"✅ Glance: {len(images)} imágenes encontradas")
    
    print("⚙️  Probando Flavors...")
    flavors = client.nova.flavors.list()
    print(f"✅ Flavors disponibles: {len(flavors)}")
    for flavor in flavors[:3]:
        print(f"   - {flavor.name}: {flavor.vcpus} vCPUs, {flavor.ram}MB RAM")
    
    print("🔧 Verificando compute nodes...")
    services = client.nova.services.list(binary='nova-compute')
    print(f"✅ Compute nodes activos: {len(services)}")
    for service in services:
        status = "UP" if service.state == "up" else "DOWN"
        print(f"   - {service.host}: {status}")
    
    print("\n🎉 ¡OpenStack completamente funcional!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTHON_TEST

echo ""
echo "🚀 Probando deployment de slice OpenStack..."

SLICE_RESPONSE=$(curl -s -X POST http://localhost/api/slices \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInVzZXJfaWQiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzUxMzM4MDk4fQ.xJHztA7QxcoKsPTd_sPEPlyQk3EYo2Wa6pe1fPryUkQ" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-openstack-final",
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
    }')

echo "Respuesta slice: $SLICE_RESPONSE"

if echo "$SLICE_RESPONSE" | grep -q '"id"'; then
    SLICE_ID=$(echo "$SLICE_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
    echo "✅ Slice creado: $SLICE_ID"
    
    echo "🚀 Probando deployment..."
    DEPLOY_RESPONSE=$(curl -s -X POST "http://localhost/api/slices/$SLICE_ID/deploy" \
        -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInVzZXJfaWQiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzUxMzM4MDk4fQ.xJHztA7QxcoKsPTd_sPEPlyQk3EYo2Wa6pe1fPryUkQ")
    
    echo "Respuesta deployment: $DEPLOY_RESPONSE"
else
    echo "❌ Error creando slice"
fi
