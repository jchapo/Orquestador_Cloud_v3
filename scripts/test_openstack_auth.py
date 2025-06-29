#!/usr/bin/env python3
"""
Test de autenticación con OpenStack
"""
import sys
import os

# Agregar el directorio padre (pucp-orchestrator) al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Agregar específicamente el directorio slice_service
slice_service_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'slice_service')
sys.path.append(slice_service_path)

from slice_service.drivers.openstack_driver import OpenStackDriver

def test_openstack_authentication():
    print("🔐 Testing OpenStack Authentication...")
    
    driver = OpenStackDriver()
    
    # Test de autenticación
    if driver.authenticate():
        print("✅ Authentication successful!")
        print(f"   Token: {driver.token[:20]}...")
        print(f"   Project ID: {driver.project_id}")
        print(f"   Expires: {driver.token_expires}")
        
        # Test de llamada a Nova
        headers = driver._get_headers()
        print("\n🖥️  Testing Nova API...")
        
        import requests
        response = requests.get(f"{driver.nova_url}/flavors", headers=headers)
        if response.status_code == 200:
            flavors = response.json().get('flavors', [])
            print(f"✅ Nova API working - Found {len(flavors)} flavors")
        else:
            print(f"❌ Nova API error: {response.status_code}")
        
        return True
    else:
        print("❌ Authentication failed!")
        return False

if __name__ == '__main__':
    success = test_openstack_authentication()
    sys.exit(0 if success else 1)
