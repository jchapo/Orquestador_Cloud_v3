#!/usr/bin/env python3
"""
Test básico de conectividad con OpenStack
Verifica que podemos conectarnos a todos los servicios
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from openstack.api_client import OpenStackAPIClient
import json

def test_openstack_connectivity():
    """Test completo de conectividad OpenStack"""
    
    print("🔍 PUCP OpenStack Connectivity Test")
    print("=" * 50)
    
    client = OpenStackAPIClient()
    
    # 1. Test de autenticación
    print("\n🔐 Testing Keystone authentication...")
    if client.authenticate():
        print("✅ Keystone authentication: SUCCESS")
        print(f"   Project ID: {client.project_id}")
    else:
        print("❌ Keystone authentication: FAILED")
        return False
    
    # 2. Health check de servicios
    print("\n🏥 Testing service health...")
    health = client.health_check()
    
    for service, status in health['services'].items():
        if status['available']:
            print(f"✅ {service.capitalize()}: {status['status']}")
        else:
            print(f"❌ {service.capitalize()}: {status['status']}")
            if 'error' in status:
                print(f"   Error: {status['error']}")
    
    # 3. Test específicos por servicio
    print("\n🧪 Testing specific service calls...")
    
    # Nova - listar flavors
    try:
        response = client.make_request('GET', 'compute', 'flavors')
        if response.status_code == 200:
            flavors = response.json()['flavors']
            print(f"✅ Nova: Found {len(flavors)} flavors")
        else:
            print(f"❌ Nova: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Nova: {e}")
    
    # Neutron - listar redes
    try:
        response = client.make_request('GET', 'network', 'v2.0/networks')
        if response.status_code == 200:
            networks = response.json()['networks']
            print(f"✅ Neutron: Found {len(networks)} networks")
        else:
            print(f"❌ Neutron: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Neutron: {e}")
    
    # Glance - listar imágenes
    try:
        response = client.make_request('GET', 'image', 'v2/images')
        if response.status_code == 200:
            images = response.json()['images']
            print(f"✅ Glance: Found {len(images)} images")
        else:
            print(f"❌ Glance: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Glance: {e}")
    
    print("\n" + "=" * 50)
    if health['overall']:
        print("🎉 OpenStack connectivity test: SUCCESS")
        return True
    else:
        print("💥 OpenStack connectivity test: FAILED")
        return False

if __name__ == '__main__':
    success = test_openstack_connectivity()
    sys.exit(0 if success else 1)
