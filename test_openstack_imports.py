import sys
print(f"Python path: {sys.executable}")
print(f"Python version: {sys.version}")

try:
    import keystoneauth1
    print("✅ keystoneauth1 importado correctamente")
    
    from keystoneauth1 import loading, session
    print("✅ keystoneauth1.loading y session importados")
    
    import sys
    sys.path.append('.')
    
    from slice_service.openstack.config import OpenStackConfig
    print("✅ OpenStackConfig importado")
    
    from slice_service.openstack.api_client import OpenStackAPIClient
    print("✅ OpenStackAPIClient importado")
    
    print("🎉 Todos los imports funcionan!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
