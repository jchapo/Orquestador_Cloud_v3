#!/usr/bin/env python3
"""
Script de pruebas básicas para Slice Service
"""
import requests
import json
import sys

BASE_URL = "http://localhost:5002"

def test_health():
    """Caso 2.0.1 - Health check"""
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    print("✓ Health check passed")

def test_create_slice():
    """Caso 2.1.1 - Creación de slice básico"""
    slice_data = {
        "name": "test-slice-automated",
        "infrastructure": "linux", 
        "nodes": [
            {"name": "vm1", "image": "ubuntu-20.04", "flavor": "small"}
        ],
        "networks": [
            {"name": "net1", "cidr": "192.168.100.0/24"}
        ]
    }
    
    headers = {"Authorization": "Bearer YOUR_TOKEN_HERE"}
    response = requests.post(f"{BASE_URL}/slices", 
                           json=slice_data, headers=headers)
    
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["resources"]["total_vcpus"] == 2
    print(f"✓ Slice created: {data['id']}")
    return data["id"]

if __name__ == "__main__":
    try:
        test_health()
        # test_create_slice() # Descomenta cuando tengas token
        print("All tests passed!")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)
