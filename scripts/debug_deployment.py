#!/usr/bin/env python3
"""
Debug de deployment - Verificar qué está pasando
"""

import requests
import json
import time
import subprocess
import logging

# Configuración
API_BASE = "http://localhost/api"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_services():
    """Verificar estado de servicios"""
    print("🔍 Verificando servicios...")
    
    services = [
        ("API Gateway", "http://localhost:5000/health"),
        ("Slice Service", "http://localhost:5002/health"),
        ("Auth Service", "http://localhost:5001/health"),
        ("Template Service", "http://localhost:5003/health"),
        ("Network Service", "http://localhost:5004/health")
    ]
    
    for name, url in services:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"✅ {name}: OK")
            else:
                print(f"❌ {name}: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ {name}: Error - {e}")

def test_direct_slice_service():
    """Probar slice service directamente (sin nginx)"""
    print("\n🔍 Probando slice service directamente...")
    
    # Login directo al auth service
    login_data = {"username": TEST_USERNAME, "password": TEST_PASSWORD}
    
    try:
        auth_response = requests.post("http://localhost:5001/login", json=login_data)
        if auth_response.status_code != 200:
            print(f"❌ Auth falló: {auth_response.text}")
            return
        
        token = auth_response.json()['token']
        headers = {'Authorization': f'Bearer {token}'}
        
        # Probar recursos directamente
        resources_response = requests.get("http://localhost:5002/resources", headers=headers)
        if resources_response.status_code == 200:
            print("✅ Slice service responde correctamente")
            resources = resources_response.json()
            print(f"   Servidores disponibles: {len(resources.get('servers', []))}")
        else:
            print(f"❌ Slice service error: {resources_response.text}")
            
    except Exception as e:
        print(f"❌ Error en test directo: {e}")

def test_linux_driver():
    """Verificar que el Linux driver funciona"""
    print("\n🔍 Probando Linux driver...")
    
    try:
        # Importar y probar el driver directamente
        import sys
        sys.path.append('/opt/pucp-orchestrator')
        
        from slice_service.drivers.linux_driver import LinuxClusterDriver
        
        driver = LinuxClusterDriver()
        
        # Test de conectividad básica
        for server_name in list(driver.hypervisors.keys())[:2]:  # Solo probar 2 servidores
            try:
                conn = driver.get_connection(server_name)
                if conn and conn.isAlive():
                    print(f"✅ {server_name}: Conectado")
                else:
                    print(f"❌ {server_name}: No conectado")
            except Exception as e:
                print(f"❌ {server_name}: Error - {e}")
        
        driver.close_connections()
        
    except ImportError as e:
        print(f"❌ No se puede importar Linux driver: {e}")
    except Exception as e:
        print(f"❌ Error probando driver: {e}")

def check_libvirt_connectivity():
    """Verificar conectividad libvirt"""
    print("\n🔍 Verificando libvirt...")
    
    servers = ["10.60.1.11", "10.60.1.12"]
    
    for server_ip in servers:
        try:
            # Test SSH
            ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", f"root@{server_ip}", "echo 'SSH OK'"]
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"✅ SSH a {server_ip}: OK")
                
                # Test libvirt
                virsh_cmd = ["virsh", "-c", f"qemu+ssh://root@{server_ip}/system", "list"]
                result = subprocess.run(virsh_cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    print(f"✅ Libvirt en {server_ip}: OK")
                else:
                    print(f"❌ Libvirt en {server_ip}: {result.stderr}")
            else:
                print(f"❌ SSH a {server_ip}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"❌ Timeout conectando a {server_ip}")
        except Exception as e:
            print(f"❌ Error con {server_ip}: {e}")

def create_minimal_slice():
    """Crear slice mínimo para debug"""
    print("\n🔍 Creando slice mínimo...")
    
    session = requests.Session()
    
    # Login
    login_data = {"username": TEST_USERNAME, "password": TEST_PASSWORD}
    auth_response = session.post(f"{API_BASE}/auth/login", json=login_data)
    
    if auth_response.status_code != 200:
        print(f"❌ Auth falló: {auth_response.text}")
        return
    
    token = auth_response.json()['token']
    session.headers.update({'Authorization': f'Bearer {token}'})
    
    # Slice mínimo (solo 1 VM)
    slice_data = {
        "name": f"debug-slice-{int(time.time())}",
        "description": "Slice mínimo para debug",
        "infrastructure": "linux",
        "placement_policy": "balanced",
        "nodes": [
            {
                "name": "debug-vm",
                "image": "ubuntu-20.04",
                "flavor": "small"
            }
        ],
        "networks": [
            {
                "name": "debug-net",
                "cidr": "192.168.200.0/24"
            }
        ]
    }
    
    try:
        print("   Creando slice...")
        create_response = session.post(f"{API_BASE}/slices", json=slice_data, timeout=30)
        
        if create_response.status_code == 201:
            slice_id = create_response.json()['id']
            print(f"✅ Slice creado: {slice_id}")
            
            # Intentar deployment con timeout mayor
            print("   Iniciando deployment...")
            deploy_response = session.post(
                f"{API_BASE}/slices/{slice_id}/deploy", 
                timeout=120  # 2 minutos
            )
            
            if deploy_response.status_code == 200:
                print("✅ Deployment iniciado correctamente")
                result = deploy_response.json()
                print(f"   Status: {result.get('status')}")
            else:
                print(f"❌ Deployment falló: {deploy_response.text}")
                
        else:
            print(f"❌ Slice creation falló: {create_response.text}")
            
    except requests.exceptions.Timeout:
        print("⏰ Timeout en la operación")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("🔍 PUCP Orchestrator - Debug de Deployment")
    print("=" * 50)
    
    test_services()
    test_direct_slice_service()
    check_libvirt_connectivity()
    test_linux_driver()
    create_minimal_slice()
    
    print("\n" + "=" * 50)
    print("Debug completado")

if __name__ == '__main__':
    main()
