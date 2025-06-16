#!/usr/bin/env python3
"""
Test completo de topología OpenStack - PUCP Cloud Orchestrator
Prueba el driver OpenStack con creación, deployment y verificación
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

class PUCPOpenStackTester:
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
    
    def check_openstack_status(self):
        """Verificar estado de OpenStack"""
        print("\n📊 Verificando estado de OpenStack...")
        
        try:
            # Health check general
            response = self.session.get(f"{API_BASE}/../health")
            if response.status_code == 200:
                print("✅ API Gateway: OK")
            else:
                print("❌ API Gateway: Error")
            
            # Recursos OpenStack
            response = self.session.get(f"{API_BASE}/resources?infrastructure=openstack")
            if response.status_code == 200:
                resources = response.json()
                print("✅ Recursos de OpenStack:")
                
                openstack_servers = [s for s in resources.get('servers', []) 
                                   if s.get('infrastructure') == 'openstack']
                
                if openstack_servers:
                    for server in openstack_servers:
                        print(f"   • {server['hostname']}: {server['available_vcpus']} CPUs, "
                              f"{server['available_ram']} MB RAM disponibles")
                else:
                    print("   ⚠️ No se encontraron servidores OpenStack configurados")
                    print("   💡 Asegúrate de que los servidores OpenStack estén en la BD")
            else:
                print(f"❌ No se pudieron obtener recursos OpenStack: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error verificando OpenStack: {e}")
    
    def create_simple_openstack_topology(self) -> Optional[str]:
        """Crear topología simple en OpenStack"""
        print("\n🏗️ Creando topología OpenStack de prueba...")
        
        slice_data = {
            "name": f"openstack-test-{int(time.time())}",
            "description": "Topología de prueba en OpenStack con 2 VMs",
            "infrastructure": "openstack",  # ← Clave: usar OpenStack
            "placement_policy": "balanced",
            "availability_zone": "zone1-openstack",
            "nodes": [
                {
                    "name": "web-vm",
                    "image": "cirros",  # Imagen que tienes en Glance
                    "flavor": "small"   # Se mapeará a m1.small
                },
                {
                    "name": "db-vm",
                    "image": "cirros",
                    "flavor": "medium"  # Se mapeará a m1.medium
                }
            ],
            "networks": [
                {
                    "name": "internal-net",
                    "cidr": "10.0.1.0/24",
                    "gateway": "10.0.1.1"
                },
                {
                    "name": "data-net",
                    "cidr": "10.0.2.0/24", 
                    "gateway": "10.0.2.1"
                }
            ],
            "connections": [
                {"source": "web-vm", "target": "db-vm", "network": "internal-net"}
            ]
        }
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            
            if response.status_code == 201:
                result = response.json()
                self.slice_id = result['id']
                print(f"✅ Slice OpenStack creado: {self.slice_id}")
                print(f"   Nombre: {result.get('message', 'N/A')}")
                print(f"   Recursos: {result.get('resources', {})}")
                return self.slice_id
            else:
                print(f"❌ Error creando slice OpenStack: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error en petición: {e}")
            return None
    
    def create_complex_openstack_topology(self) -> Optional[str]:
        """Crear topología compleja en OpenStack"""
        print("\n🏗️ Creando topología OpenStack compleja...")
        
        slice_data = {
            "name": f"openstack-complex-{int(time.time())}",
            "description": "Topología compleja: Web tier + App tier + DB tier en OpenStack",
            "infrastructure": "openstack",
            "placement_policy": "distributed",
            "availability_zone": "zone1-openstack",
            "nodes": [
                {
                    "name": "web-server",
                    "image": "cirros",
                    "flavor": "small"
                },
                {
                    "name": "app-server1",
                    "image": "cirros", 
                    "flavor": "medium"
                },
                {
                    "name": "app-server2",
                    "image": "cirros",
                    "flavor": "medium"
                },
                {
                    "name": "db-server",
                    "image": "cirros",
                    "flavor": "large"
                },
                {
                    "name": "cache-server",
                    "image": "cirros",
                    "flavor": "small"
                }
            ],
            "networks": [
                {
                    "name": "frontend",
                    "cidr": "192.168.10.0/24",
                    "gateway": "192.168.10.1"
                },
                {
                    "name": "backend", 
                    "cidr": "192.168.20.0/24",
                    "gateway": "192.168.20.1"
                },
                {
                    "name": "database",
                    "cidr": "192.168.30.0/24",
                    "gateway": "192.168.30.1"
                }
            ],
            "connections": [
                {"source": "web-server", "target": "app-server1", "network": "frontend"},
                {"source": "web-server", "target": "app-server2", "network": "frontend"},
                {"source": "app-server1", "target": "db-server", "network": "backend"},
                {"source": "app-server2", "target": "db-server", "network": "backend"},
                {"source": "app-server1", "target": "cache-server", "network": "backend"},
                {"source": "app-server2", "target": "cache-server", "network": "backend"}
            ]
        }
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            
            if response.status_code == 201:
                result = response.json()
                self.slice_id = result['id']
                print(f"✅ Slice OpenStack complejo creado: {self.slice_id}")
                print(f"   Nombre: {result.get('message', 'N/A')}")
                print(f"   Recursos totales: {result.get('resources', {})}")
                print(f"   VMs: {len(slice_data['nodes'])}")
                print(f"   Redes: {len(slice_data['networks'])}")
                return self.slice_id
            else:
                print(f"❌ Error creando slice complejo: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error en petición: {e}")
            return None
    
    def deploy_openstack_slice(self, slice_id: str) -> bool:
        """Desplegar slice en OpenStack"""
        print(f"\n🚀 Desplegando slice OpenStack {slice_id}...")
        
        try:
            response = self.session.post(f"{API_BASE}/slices/{slice_id}/deploy")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Deployment OpenStack iniciado exitosamente")
                print(f"   Status: {result.get('status')}")
                print(f"   Mensaje: {result.get('message')}")
                
                # Mostrar detalles del deployment
                deployment_result = result.get('deployment_result', {})
                if deployment_result:
                    print(f"   VMs desplegadas: {len(deployment_result.get('deployed_vms', []))}")
                    print(f"   Redes creadas: {len(deployment_result.get('created_networks', []))}")
                    
                    # Mostrar VMs desplegadas
                    for vm in deployment_result.get('deployed_vms', []):
                        print(f"      • {vm['name']}: {vm.get('status', 'unknown')}")
                        if vm.get('ip_address'):
                            print(f"        IP: {vm['ip_address']}")
                        if vm.get('hypervisor'):
                            print(f"        Hypervisor: {vm['hypervisor']}")
                        if vm.get('console_url'):
                            print(f"        Consola: {vm['console_url']}")
                    
                    # Mostrar redes creadas
                    for net in deployment_result.get('created_networks', []):
                        print(f"      🌐 Red: {net['name']} ({net.get('cidr', 'N/A')})")
                
                # Mostrar errores si los hay
                errors = deployment_result.get('errors', [])
                if errors:
                    print("   ⚠️ Errores durante deployment:")
                    for error in errors:
                        print(f"      • {error}")
                
                return True
            else:
                print(f"❌ Error en deployment OpenStack: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en deployment: {e}")
            return False
    
    def monitor_openstack_deployment(self, slice_id: str, timeout: int = 300):
        """Monitorear progreso del deployment OpenStack"""
        print(f"\n👀 Monitoreando deployment OpenStack (timeout: {timeout}s)...")
        
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
                        print("✅ Deployment OpenStack completado exitosamente!")
                        
                        # Mostrar detalles de las VMs
                        nodes = slice_data.get('nodes', [])
                        active_vms = [n for n in nodes if n.get('status') == 'running']
                        print(f"   VMs activas: {len(active_vms)}/{len(nodes)}")
                        
                        for node in nodes:
                            status = node.get('status', 'unknown')
                            print(f"      • {node['name']}: {status}")
                            if node.get('ip_address'):
                                print(f"        IP: {node['ip_address']}")
                            if node.get('console_url'):
                                print(f"        Consola: {node['console_url']}")
                        
                        return True
                    
                    elif current_status == 'error':
                        error_msg = slice_data.get('error_message', 'Unknown error')
                        print(f"❌ Deployment OpenStack falló: {error_msg}")
                        return False
                
                time.sleep(15)  # Esperar más tiempo para OpenStack
                
            except Exception as e:
                print(f"❌ Error monitoreando: {e}")
                time.sleep(5)
        
        print(f"⏰ Timeout después de {timeout} segundos")
        return False
    
    def verify_openstack_topology(self, slice_id: str):
        """Verificar topología OpenStack"""
        print(f"\n🔍 Verificando topología OpenStack {slice_id}...")
        
        try:
            response = self.session.get(f"{API_BASE}/slices/{slice_id}")
            
            if response.status_code == 200:
                slice_data = response.json()
                nodes = slice_data.get('nodes', [])
                networks = slice_data.get('networks', [])
                
                print(f"✅ Slice OpenStack verificado:")
                print(f"   Status: {slice_data.get('status')}")
                print(f"   Infrastructure: {slice_data.get('infrastructure')}")
                print(f"   Nodos: {len(nodes)}")
                print(f"   Redes: {len(networks)}")
                
                # Verificar cada nodo
                running_vms = 0
                for node in nodes:
                    status = node.get('status', 'unknown')
                    print(f"   • {node['name']}: {status}")
                    
                    if status == 'running':
                        running_vms += 1
                    
                    # Información adicional de OpenStack
                    if node.get('vm_id'):
                        print(f"     OpenStack VM ID: {node['vm_id']}")
                    if node.get('hypervisor'):
                        print(f"     Hypervisor: {node['hypervisor']}")
                
                print(f"\n📊 Resumen:")
                print(f"   VMs corriendo: {running_vms}/{len(nodes)}")
                print(f"   Eficiencia: {(running_vms/len(nodes)*100):.1f}%")
                
                if running_vms == len(nodes):
                    print("✅ Todas las VMs están corriendo correctamente en OpenStack")
                    return True
                else:
                    print("⚠️ Algunas VMs no están corriendo")
                    return False
            else:
                print(f"❌ Error verificando slice: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en verificación: {e}")
            return False
    
    def test_openstack_apis(self):
        """Test directo de APIs OpenStack"""
        print(f"\n🔧 Probando acceso directo a APIs OpenStack...")
        
        openstack_endpoints = {
            "Keystone (Identity)": "http://headnode:5000/v3",
            "Nova (Compute)": "http://headnode:8774/v2.1", 
            "Neutron (Network)": "http://headnode:9696/v2.0",
            "Glance (Images)": "http://headnode:9292/v2"
        }
        
        for service_name, endpoint in openstack_endpoints.items():
            try:
                response = requests.get(endpoint, timeout=10)
                if response.status_code in [200, 300, 401]:  # 401 es normal sin auth
                    print(f"   ✅ {service_name}: Accesible")
                else:
                    print(f"   ❌ {service_name}: Error {response.status_code}")
            except Exception as e:
                print(f"   ❌ {service_name}: Conexión fallida - {e}")
    
    def cleanup_openstack_slice(self, slice_id: str):
        """Limpiar slice OpenStack"""
        print(f"\n🧹 Limpiando slice OpenStack {slice_id}...")
        
        try:
            response = self.session.delete(f"{API_BASE}/slices/{slice_id}")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Slice OpenStack eliminado correctamente")
                
                # Mostrar detalles del cleanup
                if 'deleted_vms' in result:
                    deleted_vms = result['deleted_vms']
                    print(f"   VMs eliminadas: {len(deleted_vms)}")
                    for vm_name in deleted_vms:
                        print(f"      • {vm_name}")
                
                return True
            else:
                print(f"❌ Error eliminando slice OpenStack: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en cleanup: {e}")
            return False
    
    def run_simple_test(self):
        """Ejecutar test simple de OpenStack"""
        print("🚀 PUCP Cloud Orchestrator - Test Simple OpenStack")
        print("=" * 60)
        
        try:
            # 1. Autenticación
            if not self.authenticate():
                return False
            
            # 2. Verificar OpenStack
            self.check_openstack_status()
            self.test_openstack_apis()
            
            # 3. Crear topología simple
            slice_id = self.create_simple_openstack_topology()
            if not slice_id:
                return False
            
            # 4. Desplegar
            if not self.deploy_openstack_slice(slice_id):
                return False
            
            # 5. Monitorear
            if not self.monitor_openstack_deployment(slice_id, timeout=180):
                print("⚠️ Deployment no completó en el tiempo esperado")
                # Continuar para verificar estado actual
            
            # 6. Verificar
            success = self.verify_openstack_topology(slice_id)
            
            print("\n" + "=" * 60)
            if success:
                print("✅ ¡Test OpenStack simple EXITOSO!")
            else:
                print("⚠️ Test OpenStack completado con advertencias")
            
            print(f"   Slice ID: {slice_id}")
            
            # Preguntar si limpiar
            cleanup = input("\n¿Deseas eliminar el slice de prueba? (y/n): ")
            if cleanup.lower() == 'y':
                self.cleanup_openstack_slice(slice_id)
            else:
                print(f"💡 Slice conservado: {slice_id}")
                print(f"   Para ver en Horizon: http://headnode/horizon")
            
            return success
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            if self.slice_id:
                print(f"💡 Slice creado: {self.slice_id}")
            return False
        except Exception as e:
            print(f"\n❌ Error crítico en test: {e}")
            return False
    
    def run_complex_test(self):
        """Ejecutar test complejo de OpenStack"""
        print("🚀 PUCP Cloud Orchestrator - Test Complejo OpenStack")
        print("=" * 60)
        
        try:
            # 1. Autenticación
            if not self.authenticate():
                return False
            
            # 2. Verificar OpenStack
            self.check_openstack_status()
            
            # 3. Crear topología compleja
            slice_id = self.create_complex_openstack_topology()
            if not slice_id:
                return False
            
            # 4. Desplegar
            if not self.deploy_openstack_slice(slice_id):
                return False
            
            # 5. Monitorear (más tiempo para topología compleja)
            if not self.monitor_openstack_deployment(slice_id, timeout=300):
                print("⚠️ Deployment no completó en el tiempo esperado")
            
            # 6. Verificar
            success = self.verify_openstack_topology(slice_id)
            
            print("\n" + "=" * 60)
            if success:
                print("✅ ¡Test OpenStack complejo EXITOSO!")
                print("   🎉 Topología multi-tier desplegada correctamente")
            else:
                print("⚠️ Test OpenStack completado con advertencias")
            
            print(f"   Slice ID: {slice_id}")
            print(f"   Acceso Horizon: http://headnode/horizon")
            
            # Preguntar si limpiar
            cleanup = input("\n¿Deseas eliminar el slice complejo? (y/n): ")
            if cleanup.lower() == 'y':
                self.cleanup_openstack_slice(slice_id)
            else:
                print(f"💡 Slice complejo conservado: {slice_id}")
            
            return success
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            return False
        except Exception as e:
            print(f"\n❌ Error crítico en test: {e}")
            return False

def main():
    """Función principal"""
    print("Selecciona el tipo de test:")
    print("1. Test simple (2 VMs)")
    print("2. Test complejo (5 VMs, 3 redes)")
    print("3. Solo verificar APIs OpenStack")
    
    choice = input("Opción (1/2/3): ").strip()
    
    tester = PUCPOpenStackTester()
    
    if choice == "1":
        success = tester.run_simple_test()
    elif choice == "2":
        success = tester.run_complex_test()
    elif choice == "3":
        tester.authenticate()
        tester.check_openstack_status()
        tester.test_openstack_apis()
        success = True
    else:
        print("❌ Opción inválida")
        sys.exit(1)
    
    if success:
        print("\n🎉 Test OpenStack completado exitosamente!")
        sys.exit(0)
    else:
        print("\n💥 Test OpenStack falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
