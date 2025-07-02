#!/bin/bash
# 🔍 Verificar estado completo de OpenStack y crear VMs

echo "🚀 PUCP OpenStack - Verificación y Creación de VMs"
echo "=" * 60

cd /opt/pucp-orchestrator
source venv/bin/activate

echo "📊 1. Verificando estado de OpenStack..."
python3 -c "
import sys
sys.path.append('.')
from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

try:
    config = OpenStackConfig()
    client = OpenStackAPIClient(config.get_auth_config())
    
    print('🔐 Autenticación: ✅')
    token = client.session.get_token()
    print(f'   Token: {token[:30]}...')
    
    print('\n🖥️  Servicios Nova:')
    services = client.nova.services.list()
    for s in services:
        if 'compute' in s.binary:
            status = '✅' if s.state == 'up' else '❌'
            print(f'   {status} {s.binary} en {s.host}: {s.state}')
    
    print('\n💻 Hypervisors:')
    hypervisors = client.nova.hypervisors.list()
    for h in hypervisors:
        status = '✅' if h.state == 'up' else '❌'
        print(f'   {status} {h.hypervisor_hostname}: {h.state} - VMs: {h.running_vms}')
    
    print('\n🌐 Redes:')
    networks = client.neutron.list_networks()['networks']
    for net in networks[:3]:  # Solo las primeras 3
        print(f'   - {net[\"name\"]}: {net[\"status\"]}')
    
    print('\n🖼️  Imágenes:')
    images = list(client.glance.images.list())
    for img in images:
        print(f'   - {img.name}: {img.status}')
    
    print('\n⚙️  Flavors:')
    flavors = client.nova.flavors.list()
    for flavor in flavors:
        print(f'   - {flavor.name}: {flavor.vcpus} vCPUs, {flavor.ram}MB RAM')
        
except Exception as e:
    print(f'❌ Error: {e}')
"

echo -e "\n🎯 2. Estado actual de VMs:"
python3 -c "
import sys
sys.path.append('.')
from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

client = OpenStackAPIClient(OpenStackConfig().get_auth_config())
servers = client.nova.servers.list()
print(f'📋 VMs actuales: {len(servers)}')
for s in servers:
    print(f'   - {s.name}: {s.status} (ID: {s.id})')
"
