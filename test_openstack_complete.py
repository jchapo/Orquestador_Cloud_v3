import sys
sys.path.append('.')

try:
    from slice_service.openstack.config import OpenStackConfig
    from slice_service.openstack.api_client import OpenStackAPIClient
    
    config = OpenStackConfig()
    client = OpenStackAPIClient(config.get_auth_config())
    
    print("🔐 Autenticación...")
    token = client.session.get_token()
    print(f"✅ Token: {token[:30]}...")
    
    print("🖥️  Probando Nova...")
    servers = client.nova.servers.list()
    print(f"✅ Nova: {len(servers)} servidores")
    
    print("🌐 Probando Neutron...")
    networks = client.neutron.list_networks()['networks']
    print(f"✅ Neutron: {len(networks)} redes")
    
    print("🖼️  Probando Glance...")
    images = list(client.glance.images.list())
    print(f"✅ Glance: {len(images)} imágenes")
    
    print("⚙️  Probando Flavors...")
    flavors = client.nova.flavors.list()
    print(f"✅ Flavors: {len(flavors)} disponibles")
    for flavor in flavors[:3]:
        print(f"   - {flavor.name}: {flavor.vcpus} vCPUs, {flavor.ram}MB RAM")
    
    print("\n🎉 ¡OpenStack driver funciona COMPLETAMENTE!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
