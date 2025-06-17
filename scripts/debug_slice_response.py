#!/usr/bin/env python3
"""
Debug - Inspeccionar respuesta completa de creación de slice
"""

import requests
import json
import sys

# Configuración
API_BASE = "http://localhost/api"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

def authenticate():
    """Autenticar y obtener token"""
    session = requests.Session()
    login_data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD
    }
    
    response = session.post(f"{API_BASE}/auth/login", json=login_data)
    if response.status_code == 200:
        data = response.json()
        token = data.get('token')
        session.headers.update({'Authorization': f'Bearer {token}'})
        return session
    else:
        print(f"❌ Error de autenticación: {response.text}")
        return None

def debug_slice_creation():
    """Crear slice y mostrar respuesta completa"""
    session = authenticate()
    if not session:
        return
    
    print("🔍 DEBUGGING CREACIÓN DE SLICE")
    print("=" * 50)
    
    # Payload exacto del test case 2.1.1
    slice_payload = {
        "name": "debug-test-slice",
        "infrastructure": "linux",
        "nodes": [
            {
                "name": "vm1",
                "image": "ubuntu-20.04",
                "flavor": "small"
            }
        ],
        "networks": [
            {
                "name": "net1",
                "cidr": "192.168.1.0/24"
            }
        ]
    }
    
    print("📤 REQUEST:")
    print(f"URL: {API_BASE}/slices")
    print(f"Method: POST")
    print(f"Headers: {dict(session.headers)}")
    print(f"Payload:")
    print(json.dumps(slice_payload, indent=2))
    
    print("\n" + "-" * 50)
    
    try:
        response = session.post(f"{API_BASE}/slices", json=slice_payload)
        
        print("📥 RESPONSE:")
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Raw Text: {response.text}")
        
        if response.status_code == 201:
            try:
                response_data = response.json()
                print(f"\n📋 PARSED JSON:")
                print(json.dumps(response_data, indent=2))
                
                print(f"\n🔍 ANÁLISIS DE CAMPOS:")
                print(f"- id: {response_data.get('id', 'MISSING')}")
                print(f"- name: {response_data.get('name', 'MISSING')}")
                print(f"- status: {response_data.get('status', 'MISSING')}")
                print(f"- message: {response_data.get('message', 'MISSING')}")
                print(f"- resources: {response_data.get('resources', 'MISSING')}")
                
                # Verificar si hay otros campos con nombres similares
                print(f"\n🔎 TODOS LOS CAMPOS EN LA RESPUESTA:")
                for key, value in response_data.items():
                    print(f"- {key}: {value}")
                
                # Limpiar el slice creado
                slice_id = response_data.get('id')
                if slice_id:
                    print(f"\n🧹 Limpiando slice {slice_id}...")
                    cleanup_response = session.delete(f"{API_BASE}/slices/{slice_id}")
                    if cleanup_response.status_code == 200:
                        print("✅ Slice eliminado correctamente")
                    else:
                        print(f"❌ Error eliminando slice: {cleanup_response.text}")
                
            except json.JSONDecodeError as e:
                print(f"❌ Error parseando JSON: {e}")
        else:
            print(f"❌ Error en request: Status {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error en request: {e}")

def check_slice_flavors():
    """Verificar qué flavors están disponibles"""
    session = authenticate()
    if not session:
        return
    
    print("\n🍃 VERIFICANDO FLAVORS DISPONIBLES")
    print("=" * 50)
    
    try:
        # Intentar obtener flavors o imágenes
        endpoints_to_check = [
            "/flavors",
            "/images", 
            "/templates",
            "/resources",
            "/config"
        ]
        
        for endpoint in endpoints_to_check:
            try:
                response = session.get(f"{API_BASE}{endpoint}")
                print(f"\n🔍 GET {endpoint}:")
                print(f"Status: {response.status_code}")
                if response.status_code == 200:
                    try:
                        data = response.json()
                        print(f"Data: {json.dumps(data, indent=2)}")
                    except:
                        print(f"Raw: {response.text}")
                else:
                    print(f"Error: {response.text}")
            except Exception as e:
                print(f"❌ Error con {endpoint}: {e}")
                
    except Exception as e:
        print(f"❌ Error general: {e}")

if __name__ == '__main__':
    debug_slice_creation()
    check_slice_flavors()
