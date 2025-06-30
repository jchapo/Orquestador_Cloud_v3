#!/bin/bash

echo "🚀 Configurando OpenStack Orchestrator para PUCP"
echo "==============================================="

cd /opt/pucp-orchestrator

# 1. Establecer túneles SSH
echo "=== 1. Estableciendo túneles SSH ==="
./scripts/setup_gateway_tunnels.sh

if [ $? -ne 0 ]; then
    echo "❌ Error estableciendo túneles SSH"
    exit 1
fi

# 2. Verificar dependencias OpenStack
echo -e "\n=== 2. Verificando dependencias ==="
source venv/bin/activate

if [ ! -f "requirements_openstack.txt" ]; then
    echo "Creando requirements_openstack.txt..."
    cat > requirements_openstack.txt << 'REQS'
python-openstackclient==6.3.0
python-keystoneclient==5.1.0
python-novaclient==18.4.0
python-neutronclient==8.2.1
python-glanceclient==4.4.0
python-cinderclient==9.3.0
keystoneauth1==5.3.0
osc-lib==2.8.0
REQS
fi

pip install -r requirements_openstack.txt

# 3. Probar conectividad OpenStack
echo -e "\n=== 3. Probando conectividad OpenStack ==="

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
    print(f"✅ Token obtenido exitosamente")
    
    print("🖥️  Probando Nova (Compute)...")
    servers = client.nova.servers.list()
    print(f"✅ Nova: {len(servers)} servidores encontrados")
    
    print("🌐 Probando Neutron (Network)...")
    networks = client.neutron.list_networks()['networks']
    print(f"✅ Neutron: {len(networks)} redes encontradas")
    
    print("🖼️  Probando Glance (Images)...")
    images = list(client.glance.images.list())
    print(f"✅ Glance: {len(images)} imágenes encontradas")
    
    # Listar flavors disponibles
    print("⚙️  Probando flavors...")
    flavors = client.nova.flavors.list()
    print(f"✅ Flavors disponibles: {len(flavors)}")
    for flavor in flavors[:3]:  # Mostrar primeros 3
        print(f"   - {flavor.name}: {flavor.vcpus} vCPUs, {flavor.ram}MB RAM")
    
    # Verificar compute nodes
    print("🔧 Verificando compute nodes...")
    services = client.nova.services.list(binary='nova-compute')
    print(f"✅ Compute nodes activos: {len(services)}")
    for service in services:
        status = "UP" if service.state == "up" else "DOWN"
        print(f"   - {service.host}: {status}")
    
    print("\n🎉 ¡OpenStack completamente accesible!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTHON_TEST

# 4. Probar creación de slice
echo -e "\n=== 4. Probando creación de slice OpenStack ==="

SLICE_RESPONSE=$(curl -s -X POST http://localhost/api/slices \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInVzZXJfaWQiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzUxMzM4MDk4fQ.xJHztA7QxcoKsPTd_sPEPlyQk3EYo2Wa6pe1fPryUkQ" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-openstack-slice",
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
    echo "✅ Slice creado exitosamente"
    SLICE_ID=$(echo "$SLICE_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
    echo "   Slice ID: $SLICE_ID"
    
    # Intentar deployment
    echo "🚀 Probando deployment..."
    DEPLOY_RESPONSE=$(curl -s -X POST "http://localhost/api/slices/$SLICE_ID/deploy" \
        -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInVzZXJfaWQiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzUxMzM4MDk4fQ.xJHztA7QxcoKsPTd_sPEPlyQk3EYo2Wa6pe1fPryUkQ")
    
    echo "Respuesta deployment: $DEPLOY_RESPONSE"
else
    echo "❌ Error creando slice"
fi

echo -e "\n✅ Configuración OpenStack Orchestrator completada"
echo "🌐 Dashboard disponible en: http://localhost/dashboard"
echo "🔗 Horizon OpenStack: http://localhost"
