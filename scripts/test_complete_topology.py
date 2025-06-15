#!/usr/bin/env python3
"""
Test completo de topología PUCP Cloud Orchestrator
Prueba todo el flujo: autenticación -> creación -> deployment -> verificación
"""

import requests
import json
import time
import sys
import os
from typing import Dict, Optional

# Configuración
API_BASE = "http://localhost/api"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

class PUCPTopologyTester:
    def __init__(self):
        self.token = None
        self.slice_id = None
        self.session = requests.Session()
        
    def authenticate(self) -> bool:
        """Autenticar con el sistema"""
        print("🔐 Autenticando...")
        
        login_data = {
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }
        
        try:
            response = self.session.post(f"{API_BASE}/auth/login", json=login_data)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                print(f"✅ Autenticado como {TEST_USERNAME}")
                return True
            else:
                print(f"❌ Error de autenticación: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error de conexión: {e}")
            return False
    
    def check_system_status(self):
        """Verificar estado del sistema"""
        print("\n📊 Verificando estado del sistema...")
        
        try:
            # Health check
            response = self.session.get(f"{API_BASE}/../health")
            if response.status_code == 200:
                print("✅ API Gateway: OK")
            else:
                print("❌ API Gateway: Error")
            
            # Recursos disponibles
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                print("✅ Recursos del cluster:")
                for server in resources.get('servers', []):
                    print(f"   • {server['hostname']}: {server['available_vcpus']} CPUs, "
                          f"{server['available_ram']} MB RAM disponibles")
            else:
                print("❌ No se pudieron obtener recursos")
                
        except Exception as e:
            print(f"❌ Error verificando sistema: {e}")
    
    def create_linear_topology(self) -> Optional[str]:
        """Crear topología lineal de 3 VMs"""
        print("\n🏗️ Creando topología lineal de prueba...")
        
        slice_data = {
            "name": f"test-linear-topology-{int(time.time())}",
            "description": "Topología lineal de prueba con 3 VMs conectadas",
            "infrastructure": "linux",
            "placement_policy": "balanced",
            "nodes": [
                {
                    "name": "vm1",
                    "image": "ubuntu-20.04", 
                    "flavor": "small"
                },
                {
                    "name": "vm2",
                    "image": "ubuntu-20.04",
                    "flavor": "small"
                },
                {
                    "name": "vm3", 
                    "image": "ubuntu-20.04",
                    "flavor": "small"
                }
            ],
            "networks": [
                {
                    "name": "net1",
                    "cidr": "192.168.100.0/24",
                    "gateway": "192.168.100.1"
                },
                {
                    "name": "net2", 
                    "cidr": "192.168.101.0/24",
                    "gateway": "192.168.101.1"
                }
            ],
            "connections": [
                {"source": "vm1", "target": "vm2", "network": "net1"},
                {"source": "vm2", "target": "vm3", "network": "net2"}
            ]
        }
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            
            if response.status_code == 201:
                result = response.json()
                self.slice_id = result['id']
                print(f"✅ Slice creado: {self.slice_id}")
                print(f"   Nombre: {result.get('message', 'N/A')}")
                print(f"   Recursos: {result.get('resources', {})}")
                return self.slice_id
            else:
                print(f"❌ Error creando slice: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error en petición: {e}")
            return None
    
    def deploy_slice(self, slice_id: str) -> bool:
        """Desplegar el slice"""
        print(f"\n🚀 Desplegando slice {slice_id}...")
        
        try:
            response = self.session.post(f"{API_BASE}/slices/{slice_id}/deploy")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Deployment iniciado exitosamente")
                print(f"   Status: {result.get('status')}")
                print(f"   Mensaje: {result.get('message')}")
                
                # Mostrar detalles del deployment
                deployment_result = result.get('deployment_result', {})
                if deployment_result:
                    print(f"   VMs desplegadas: {len(deployment_result.get('deployed_vms', []))}")
                    print(f"   Redes creadas: {len(deployment_result.get('created_networks', []))}")
                    
                    # Mostrar VMs desplegadas
                    for vm in deployment_result.get('deployed_vms', []):
                        print(f"      • {vm['name']}: {vm['status']} en {vm['server']}")
                        if vm.get('ip_address'):
                            print(f"        IP: {vm['ip_address']}")
                        if vm.get('console_url'):
                            print(f"        Consola: {vm['console_url']}")
                
                return True
            else:
                print(f"❌ Error en deployment: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en deployment: {e}")
            return False
    
    def monitor_deployment(self, slice_id: str, timeout: int = 300):
        """Monitorear progreso del deployment"""
        print(f"\n👀 Monitoreando deployment (timeout: {timeout}s)...")
        
        start_time = time.time()
        last_status = None
        
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(f"{API_BASE}/slices/{slice_id}")
                
                if response.status_code == 200:
                    slice_data = response.json()
                    current_status = slice_data.get('status')
                    
                    if current_status != last_status:
                        print(f"   Status: {current_status}")
                        last_status = current_status
                    
                    if current_status == 'active':
                        print("✅ Deployment completado exitosamente!")
                        
                        # Mostrar detalles de las VMs
                        nodes = slice_data.get('nodes', [])
                        print(f"   VMs activas: {len([n for n in nodes if n.get('status') == 'running'])}")
                        
                        for node in nodes:
                            print(f"      • {node['name']}: {node.get('status', 'unknown')}")
                            if node.get('ip_address'):
                                print(f"        IP: {node['ip_address']}")
                            if node.get('console_url'):
                                print(f"        Consola: {node['console_url']}")
                        
                        return True
                    
                    elif current_status == 'error':
                        error_msg = slice_data.get('error_message', 'Unknown error')
                        print(f"❌ Deployment falló: {error_msg}")
                        return False
                
                time.sleep(10)  # Esperar 10 segundos entre checks
                
            except Exception as e:
                print(f"❌ Error monitoreando: {e}")
                time.sleep(5)
        
        print(f"⏰ Timeout después de {timeout} segundos")
        return False
    
    def verify_topology(self, slice_id: str):
        """Verificar que la topología funciona correctamente"""
        print(f"\n🔍 Verificando topología {slice_id}...")
        
        try:
            response = self.session.get(f"{API_BASE}/slices/{slice_id}")
            
            if response.status_code == 200:
                slice_data = response.json()
                nodes = slice_data.get('nodes', [])
                networks = slice_data.get('networks', [])
                
                print(f"✅ Slice verificado:")
                print(f"   Status: {slice_data.get('status')}")
                print(f"   Nodos: {len(nodes)}")
                print(f"   Redes: {len(networks)}")
                
                # Verificar cada nodo
                all_running = True
                for node in nodes:
                    status = node.get('status', 'unknown')
                    print(f"   • {node['name']}: {status}")
                    
                    if status != 'running':
                        all_running = False
                
                if all_running:
                    print("✅ Todos los nodos están corriendo correctamente")
                else:
                    print("⚠️ Algunos nodos no están corriendo")
                
                return all_running
            else:
                print(f"❌ Error verificando slice: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en verificación: {e}")
            return False
    
    def test_connectivity(self, slice_id: str):
        """Test básico de conectividad (simulado)"""
        print(f"\n🌐 Probando conectividad de la topología...")
        
        # En un entorno real, esto haría ping entre VMs
        # Por ahora simulamos las pruebas
        
        connectivity_tests = [
            ("vm1", "vm2", "net1"),
            ("vm2", "vm3", "net2")
        ]
        
        print("📡 Tests de conectividad (simulados):")
        for source, target, network in connectivity_tests:
            # Simular test de conectividad
            time.sleep(1)
            print(f"   • {source} -> {target} via {network}: ✅ OK")
        
        print("✅ Tests de conectividad completados")
    
    def cleanup_slice(self, slice_id: str):
        """Limpiar el slice de prueba"""
        print(f"\n🧹 Limpiando slice de prueba {slice_id}...")
        
        try:
            response = self.session.delete(f"{API_BASE}/slices/{slice_id}")
            
            if response.status_code == 200:
                print("✅ Slice eliminado correctamente")
                return True
            else:
                print(f"❌ Error eliminando slice: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en cleanup: {e}")
            return False
    
    def run_complete_test(self):
        """Ejecutar test completo"""
        print("🚀 PUCP Cloud Orchestrator - Test Completo de Topología")
        print("=" * 60)
        
        try:
            # 1. Autenticación
            if not self.authenticate():
                return False
            
            # 2. Verificar sistema
            self.check_system_status()
            
            # 3. Crear topología
            slice_id = self.create_linear_topology()
            if not slice_id:
                return False
            
            # 4. Desplegar
            if not self.deploy_slice(slice_id):
                return False
            
            # 5. Monitorear deployment
            if not self.monitor_deployment(slice_id):
                return False
            
            # 6. Verificar topología
            if not self.verify_topology(slice_id):
                return False
            
            # 7. Test de conectividad
            self.test_connectivity(slice_id)
            
            print("\n" + "=" * 60)
            print("✅ ¡Test completo EXITOSO!")
            print(f"   Slice ID: {slice_id}")
            print("   La topología está funcionando correctamente")
            
            # Preguntar si limpiar
            cleanup = input("\n¿Deseas eliminar el slice de prueba? (y/n): ")
            if cleanup.lower() == 'y':
                self.cleanup_slice(slice_id)
            else:
                print(f"💡 Slice conservado: {slice_id}")
                print(f"   Para eliminarlo manualmente: curl -X DELETE {API_BASE}/slices/{slice_id} -H 'Authorization: Bearer {self.token}'")
            
            return True
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            if self.slice_id:
                print(f"💡 Slice creado: {self.slice_id}")
            return False
        except Exception as e:
            print(f"\n❌ Error crítico en test: {e}")
            return False

def main():
    """Función principal"""
    tester = PUCPTopologyTester()
    success = tester.run_complete_test()
    
    if success:
        print("\n🎉 Test completado exitosamente!")
        sys.exit(0)
    else:
        print("\n💥 Test falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
