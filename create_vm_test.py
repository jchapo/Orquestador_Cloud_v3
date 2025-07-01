import sys
sys.path.append('.')

from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

config = OpenStackConfig()
client = OpenStackAPIClient(config.get_auth_config())

print("🚀 Creando VM de prueba...")

# Listar recursos disponibles
networks = client.neutron.list_networks()['networks']
flavors = client.nova.flavors.list()
images = list(client.glance.images.list())

print(f"Redes disponibles: {len(networks)}")
print(f"Flavors disponibles: {len(flavors)}")
print(f"Imágenes disponibles: {len(images)}")

# Tomar la primera red y imagen
network_id = networks[0]['id']
flavor = flavors[0]  # small
image = images[0]

print(f"Usando red: {network_id}")
print(f"Usando flavor: {flavor.name}")
print(f"Usando imagen: {image.name}")

# Crear VM
server = client.nova.servers.create(
    name="vm-test-pucp",
    image=image.id,
    flavor=flavor.id,
    nics=[{'net-id': network_id}]
)

print(f"✅ VM creada con ID: {server.id}")
print(f"📝 Estado: {server.status}")
print("⏳ Esperando que la VM arranque...")
