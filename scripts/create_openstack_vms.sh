#!/bin/bash
# Script para crear VMs con OpenStack de manera simple

cd /opt/pucp-orchestrator
source venv/bin/activate

echo "🧹 1. Limpiando VM en ERROR..."
python3 -c "
import sys
sys.path.append('.')
from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

try:
    client = OpenStackAPIClient(OpenStackConfig().get_auth_config())
    
    # Eliminar VM en ERROR
    servers = client.nova.servers.list()
    for s in servers:
        if s.status == 'ERROR':
            print(f'🗑️  Eliminando VM en ERROR: {s.name}')
            client.nova.servers.delete(s.id)
            print('✅ VM eliminada')
except Exception as e:
    print(f'Error: {e}')
"

echo -e "\n🚀 2. Creando nueva VM..."
python3 -c "
import sys
import time
sys.path.append('.')
from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

try:
    client = OpenStackAPIClient(OpenStackConfig().get_auth_config())
    
    # Obtener recursos
    networks = client.neutron.list_networks()['networks']
    flavors = client.nova.flavors.list()
    images = list(client.glance.images.list())
    
    # Seleccionar recursos
    network = networks[0]  # Primera red
    flavor = flavors[0]    # small
    image = images[0]      # cirros
    
    print(f'🔧 Usando:')
    print(f'   Red: {network[\"name\"]}')
    print(f'   Flavor: {flavor.name}')
    print(f'   Imagen: {image.name}')
    
    # Crear VM
    vm_name = f'pucp-vm-{int(time.time())}'
    print(f'\\n⚡ Creando VM: {vm_name}')
    
    server = client.nova.servers.create(
        name=vm_name,
        image=image.id,
        flavor=flavor.id,
        nics=[{'net-id': network['id']}],
        availability_zone='nova'
    )
    
    print(f'✅ VM creada: {server.id}')
    print(f'📝 Estado inicial: {server.status}')
    
    # Monitorear durante 2 minutos
    print('\\n⏳ Esperando que VM esté lista (máximo 2 minutos)...')
    for i in range(12):  # 12 x 10 seg = 2 minutos
        time.sleep(10)
        server = client.nova.servers.get(server.id)
        print(f'   [{i+1}/12] Estado: {server.status}')
        
        if server.status == 'ACTIVE':
            print('🎉 ¡VM ACTIVA!')
            if hasattr(server, 'addresses') and server.addresses:
                for net_name, ips in server.addresses.items():
                    for ip in ips:
                        print(f'   📍 IP: {ip[\"addr\"]}')
            break
        elif server.status == 'ERROR':
            print('❌ VM falló')
            if hasattr(server, 'fault'):
                print(f'   Error: {server.fault}')
            break
    
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()
"

echo -e "\n📊 3. Estado final de VMs:"
python3 -c "
import sys
sys.path.append('.')
from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

client = OpenStackAPIClient(OpenStackConfig().get_auth_config())
servers = client.nova.servers.list()
print(f'📋 Total VMs: {len(servers)}')
for s in servers:
    status_icon = '✅' if s.status == 'ACTIVE' else '⚠️' if s.status == 'BUILD' else '❌'
    print(f'   {status_icon} {s.name}: {s.status}')
"
