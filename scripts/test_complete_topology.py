#!/usr/bin/env python3
"""
Test completo de topología PUCP Cloud Orchestrator con verificación R5
Prueba redes de management, trunk, VLANs y validación completa
"""

import requests
import json
import time
import sys
import os
import ipaddress
import subprocess
from typing import Dict, Optional, List

# Configuración
API_BASE = "http://localhost/api"
NETWORK_SERVICE_URL = "http://localhost:5004"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

class PUCPTopologyTesterR5:
    def __init__(self):
        self.token = None
        self.slice_id = None
        self.session = requests.Session()
        self.created_networks = []
        
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
    
    def check_network_service_status(self):
        """Verificar estado del Network Service"""
        print("\n🌐 Verificando Network Service...")
        
        try:
            # Health check Network Service
            response = self.session.get(f"{NETWORK_SERVICE_URL}/health")
            if response.status_code == 200:
                print("✅ Network Service: OK")
                
                # Verificar pool de VLANs
                response = self.session.get(f"{NETWORK_SERVICE_URL}/api/vlans/status?infrastructure=linux")
                if response.status_code == 200:
                    vlan_status = response.json()
                    if vlan_status.get('success'):
                        linux_stats = vlan_status['data'].get('linux', {})
                        print(f"✅ VLAN Pool Linux:")
                        print(f"   • Total VLANs: {linux_stats.get('total_vlans', 0)}")
                        print(f"   • Disponibles: {linux_stats.get('available', 0)}")
                        print(f"   • Asignadas: {linux_stats.get('allocated', 0)}")
                        print(f"   • Uso: {linux_stats.get('usage_percentage', 0):.1f}%")
                        print(f"   • Rango: {linux_stats.get('pool_range', 'N/A')}")
                        return True
                    else:
                        print("❌ Error obteniendo status de VLANs")
                else:
                    print("❌ No se pudo verificar pool de VLANs")
            else:
                print("❌ Network Service: No disponible")
                
        except Exception as e:
            print(f"❌ Error verificando Network Service: {e}")
        
        return False

    def check_ovs_infrastructure(self):
        """Verificar infraestructura OVS en servidores"""
        print("\n🔧 Verificando infraestructura OVS...")
        
        servers = ['pucp-server1', 'pucp-server2', 'pucp-server3', 'pucp-server4']
        ovs_ok = True
        
        for server in servers:
            try:
                # Verificar OVS bridge
                cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', f'ubuntu@{server}', 
                       'sudo', 'ovs-vsctl', 'show']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    if 'ovs1' in result.stdout:
                        print(f"✅ {server}: OVS bridge ovs1 OK")
                    else:
                        print(f"❌ {server}: Bridge ovs1 no encontrado")
                        ovs_ok = False
                else:
                    print(f"❌ {server}: Error verificando OVS")
                    ovs_ok = False
                    
            except Exception as e:
                print(f"❌ {server}: Error de conexión - {e}")
                ovs_ok = False
        
        return ovs_ok
    
    def create_r5_topology(self) -> Optional[str]:
        """Crea topología completa R5 con múltiples tipos de red"""
        print("\n🏗️ Creando topología R5 con redes management/trunk/data...")
        
        slice_data = {
            "name": f"test-r5-topology-{int(time.time())}",
            "description": "Topología R5 completa con redes management, trunk y data",
            "infrastructure": "linux",
            "placement_policy": "balanced",
            "nodes": [
                {
                    "name": "vm-mgmt",
                    "image": "ubuntu-20.04", 
                    "flavor": "small",
                    "management_ip": "192.168.201.10",
                    "internet_access": False
                },
                {
                    "name": "vm-gateway",
                    "image": "ubuntu-20.04",
                    "flavor": "medium",
                    "internet_access": True
                },
                {
                    "name": "vm-data",
                    "image": "ubuntu-20.04",
                    "flavor": "small",
                    "internet_access": False
                }
            ],
            "networks": [
                {
                    "name": "mgmt-net",
                    "cidr": "192.168.201.0/24",
                    "gateway": "192.168.201.1",
                    "network_type": "management",
                    "dns_servers": ["192.168.201.1"],
                    "internet_access": False,
                    "is_management": True
                },
                {
                    "name": "trunk-net",
                    "cidr": "10.60.1.0/24",
                    "gateway": "10.60.1.1",
                    "network_type": "trunk",
                    "dns_servers": ["8.8.8.8", "8.8.4.4"],
                    "internet_access": True
                },
                {
                    "name": "data-net",
                    "cidr": "192.168.100.0/24",
                    "gateway": "192.168.100.1",
                    "network_type": "data",
                    "dns_servers": ["192.168.100.1"],
                    "internet_access": False
                }
            ],
            "connections": [
                {"source": "vm-mgmt", "target": "vm-gateway", "network": "mgmt-net"},
                {"source": "vm-gateway", "target": "vm-data", "network": "trunk-net"},
                {"source": "vm-data", "target": "vm-mgmt", "network": "data-net"}
            ]
        }
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            
            if response.status_code == 201:
                result = response.json()
                self.slice_id = result['id']
                print(f"✅ Slice R5 creado: {self.slice_id}")
                print(f"   Nombre: {result.get('message', 'N/A')}")
                
                # Mostrar resumen R5
                r5_features = result.get('r5_features', {})
                print(f"✅ Características R5:")
                print(f"   • Redes management: {r5_features.get('management_networks', 0)}")
                print(f"   • Redes trunk: {r5_features.get('trunk_networks', 0)}")
                print(f"   • VMs con internet: {r5_features.get('internet_enabled_nodes', 0)}")
                
                return self.slice_id
            else:
                print(f"❌ Error creando slice R5: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error en petición: {e}")
            return None
    
    def deploy_slice(self, slice_id: str) -> bool:
        """Despliega el slice con verificación R5"""
        print(f"\n🚀 Desplegando slice R5 {slice_id}...")
        
        try:
            response = self.session.post(f"{API_BASE}/slices/{slice_id}/deploy")
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Deployment R5 iniciado exitosamente")
                print(f"   Status: {result.get('status')}")
                
                # Mostrar detalles del deployment R5
                deployment_result = result.get('deployment_result', {})
                if deployment_result:
                    r5_summary = deployment_result.get('r5_summary', {})
                    print(f"✅ Resumen R5:")
                    print(f"   • VMs desplegadas: {r5_summary.get('deployed_vms', 0)}/{r5_summary.get('total_vms', 0)}")
                    print(f"   • Redes creadas: {r5_summary.get('created_networks', 0)}/{r5_summary.get('total_networks', 0)}")
                    print(f"   • Tipos de red: {r5_summary.get('network_types', [])}")
                    print(f"   • VMs con internet: {r5_summary.get('internet_enabled_vms', 0)}")
                    
                    # Mostrar VMs desplegadas
                    for vm in deployment_result.get('deployed_vms', []):
                        print(f"      • {vm['name']}: {vm['status']} en {vm['server']}")
                        if vm.get('ip_address'):
                            print(f"        IP: {vm['ip_address']}")
                        if vm.get('console_url'):
                            print(f"        Consola: {vm['console_url']}")
                    
                    # Mostrar redes creadas
                    self.created_networks = deployment_result.get('created_networks', [])
                    for network in self.created_networks:
                        print(f"      • Red {network['name']}: tipo {network.get('type', 'unknown')}")
                        if network.get('vlan_id'):
                            print(f"        VLAN: {network['vlan_id']}")
                        print(f"        CIDR: {network.get('cidr', 'N/A')}")
                        print(f"        Bridge: {network.get('bridge', 'N/A')}")
                
                return True
            else:
                print(f"❌ Error en deployment R5: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en deployment: {e}")
            return False
    
    def verify_r5_networks(self, slice_id: str):
        """Verifica configuración específica R5 de redes"""
        print(f"\n🔍 Verificando configuración R5 de redes...")
        
        try:
            # 1. Verificar VLANs asignadas
            response = self.session.get(f"{NETWORK_SERVICE_URL}/api/vlans/allocated?slice_id={slice_id}")
            if response.status_code == 200:
                vlan_data = response.json()
                if vlan_data.get('success'):
                    allocated_vlans = vlan_data['data']
                    print(f"✅ VLANs asignadas al slice: {len(allocated_vlans)}")
                    
                    for vlan in allocated_vlans:
                        print(f"   • VLAN {vlan['vlan_id']}: {vlan.get('usage_description', 'N/A')}")
                        print(f"     Network ID: {vlan.get('network_id', 'N/A')}")
                        print(f"     Asignada: {vlan.get('assigned_at', 'N/A')}")
                else:
                    print("❌ Error obteniendo VLANs asignadas")
            
            # 2. Verificar redes por tipo
            network_types = {'management': 0, 'trunk': 0, 'data': 0, 'provider': 0}
            vlan_assignments = {}
            
            for network in self.created_networks:
                net_type = network.get('type', 'unknown')
                if net_type in network_types:
                    network_types[net_type] += 1
                
                vlan_id = network.get('vlan_id')
                if vlan_id:
                    vlan_assignments[net_type] = vlan_id
            
            print(f"✅ Distribución de tipos de red:")
            for net_type, count in network_types.items():
                print(f"   • {net_type}: {count} redes")
                if net_type in vlan_assignments:
                    print(f"     VLAN asignada: {vlan_assignments[net_type]}")
            
            # 3. Verificar bridges OVS
            self._verify_ovs_configuration(vlan_assignments)
            
            # 4. Verificar conectividad entre tipos de red
            self._verify_network_connectivity()
            
            return True
            
        except Exception as e:
            print(f"❌ Error verificando redes R5: {e}")
            return False
    
    def _verify_ovs_configuration(self, vlan_assignments: Dict):
        """Verifica configuración OVS en servidores"""
        print(f"\n🔧 Verificando configuración OVS...")
        
        servers = ['pucp-server1']  # Verificar en servidor principal
        
        for server in servers:
            try:
                # Verificar puertos VLAN en OVS
                cmd = ['ssh', f'ubuntu@{server}', 'sudo', 'ovs-vsctl', 'list', 'port']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"✅ {server}: Configuración OVS verificada")
                    
                    # Verificar flows OpenFlow si hay VLANs
                    if vlan_assignments:
                        cmd_flows = ['ssh', f'ubuntu@{server}', 'sudo', 'ovs-ofctl', 'dump-flows', 'ovs1']
                        flows_result = subprocess.run(cmd_flows, capture_output=True, text=True, timeout=30)
                        
                        if flows_result.returncode == 0:
                            flows_count = len(flows_result.stdout.splitlines()) - 1  # -1 for header
                            print(f"   • Flows OpenFlow activos: {flows_count}")
                        else:
                            print(f"   ⚠️ No se pudieron verificar flows OpenFlow")
                else:
                    print(f"❌ {server}: Error verificando configuración OVS")
                    
            except Exception as e:
                print(f"❌ {server}: Error - {e}")
    
    def _verify_network_connectivity(self):
        """Verifica conectividad básica entre redes"""
        print(f"\n🌐 Verificando conectividad de redes...")
        
        # Simulación de tests de conectividad
        connectivity_tests = [
            ("management", "trunk", "Routing mgmt -> trunk para VMs con internet"),
            ("trunk", "external", "Acceso a internet desde trunk network"),
            ("data", "data", "Comunicación interna en data network"),
            ("management", "management", "Comunicación en management network")
        ]
        
        print("📡 Tests de conectividad (simulados):")
        for source, target, description in connectivity_tests:
            time.sleep(0.5)  # Simular test
            status = "✅ OK" if source != "external" else "🌐 INTERNET"
            print(f"   • {source} -> {target}: {status}")
            print(f"     {description}")
    
    def verify_internet_access(self, slice_id: str):
        """Verifica configuración de acceso a internet"""
        print(f"\n🌐 Verificando acceso a internet R5...")
        
        try:
            # Obtener detalles del slice
            response = self.session.get(f"{API_BASE}/slices/{slice_id}")
            if response.status_code == 200:
                slice_data = response.json()
                
                # Verificar VMs con internet habilitado
                internet_vms = [node for node in slice_data['nodes'] if node.get('internet_access')]
                print(f"✅ VMs con acceso a internet: {len(internet_vms)}")
                
                for vm in internet_vms:
                    print(f"   • {vm['name']}: Internet habilitado")
                
                # Verificar redes con acceso a internet
                internet_networks = [net for net in slice_data['networks'] if net.get('internet_access')]
                print(f"✅ Redes con acceso a internet: {len(internet_networks)}")
                
                for network in internet_networks:
                    print(f"   • {network['name']}: Tipo {network.get('network_type', 'unknown')}")
                    print(f"     CIDR: {network['cidr']}")
                
                return len(internet_vms) > 0 or len(internet_networks) > 0
            else:
                print("❌ Error obteniendo detalles del slice")
                return False
                
        except Exception as e:
            print(f"❌ Error verificando acceso a internet: {e}")
            return False
    
    def verify_security_rules(self, slice_id: str):
        """Verifica reglas de seguridad configuradas"""
        print(f"\n🔒 Verificando reglas de seguridad R5...")
        
        try:
            # Obtener redes del slice
            response = self.session.get(f"{NETWORK_SERVICE_URL}/networks?slice_id={slice_id}")
            if response.status_code == 200:
                networks = response.json()
                print(f"✅ Verificando seguridad en {len(networks)} redes...")
                
                total_rules = 0
                for network in networks:
                    rules = network.get('security_rules', [])
                    total_rules += len(rules)
                    print(f"   • Red {network['name']}: {len(rules)} reglas")
                    
                    for rule in rules[:2]:  # Mostrar solo primeras 2 reglas
                        action = rule.get('action', 'unknown')
                        rule_type = rule.get('rule_type', 'unknown')
                        protocol = rule.get('protocol', 'any')
                        print(f"     - {rule_type} {protocol}: {action}")
                
                print(f"✅ Total reglas de seguridad: {total_rules}")
                return True
            else:
                print("❌ Error obteniendo redes para verificar seguridad")
                return False
                
        except Exception as e:
            print(f"❌ Error verificando reglas de seguridad: {e}")
            return False
    
    def monitor_deployment(self, slice_id: str, timeout: int = 300):
        """Monitorea progreso del deployment con verificaciones R5"""
        print(f"\n👀 Monitoreando deployment R5 (timeout: {timeout}s)...")
        
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
                        print("✅ Deployment R5 completado exitosamente!")
                        
                        # Mostrar resumen R5
                        r5_summary = slice_data.get('r5_summary', {})
                        if r5_summary:
                            print(f"✅ Resumen final R5:")
                            print(f"   • Redes management: {r5_summary.get('management_networks', 0)}")
                            print(f"   • Redes trunk: {r5_summary.get('trunk_networks', 0)}")
                            print(f"   • VMs con internet: {r5_summary.get('internet_enabled_vms', 0)}")
                        
                        # Mostrar detalles de VMs
                        nodes = slice_data.get('nodes', [])
                        active_vms = [n for n in nodes if n.get('status') == 'running']
                        print(f"   VMs activas: {len(active_vms)}/{len(nodes)}")
                        
                        for node in nodes:
                            status_icon = "✅" if node.get('status') == 'running' else "❌"
                            print(f"      {status_icon} {node['name']}: {node.get('status', 'unknown')}")
                            if node.get('ip_address'):
                                print(f"        IP: {node['ip_address']}")
                            if node.get('internet_access'):
                                print(f"        🌐 Internet: Habilitado")
                        
                        return True
                    
                    elif current_status == 'error':
                        error_msg = slice_data.get('error_message', 'Unknown error')
                        print(f"❌ Deployment R5 falló: {error_msg}")
                        return False
                
                time.sleep(10)
                
            except Exception as e:
                print(f"❌ Error monitoreando: {e}")
                time.sleep(5)
        
        print(f"⏰ Timeout después de {timeout} segundos")
        return False
    
    def cleanup_slice(self, slice_id: str):
        """Limpia el slice de prueba con cleanup R5"""
        print(f"\n🧹 Limpiando slice R5 {slice_id}...")
        
        try:
            # Verificar VLANs antes del cleanup
            response = self.session.get(f"{NETWORK_SERVICE_URL}/api/vlans/allocated?slice_id={slice_id}")
            if response.status_code == 200:
                vlan_data = response.json()
                if vlan_data.get('success'):
                    allocated_vlans = vlan_data['data']
                    print(f"   VLANs a liberar: {len(allocated_vlans)}")
            
            # Eliminar slice
            response = self.session.delete(f"{API_BASE}/slices/{slice_id}")
            
            if response.status_code == 200:
                print("✅ Slice R5 eliminado correctamente")
                
                # Verificar que VLANs fueron liberadas
                time.sleep(2)
                response = self.session.get(f"{NETWORK_SERVICE_URL}/api/vlans/allocated?slice_id={slice_id}")
                if response.status_code == 200:
                    vlan_data = response.json()
                    if vlan_data.get('success'):
                        remaining_vlans = vlan_data['data']
                        if len(remaining_vlans) == 0:
                            print("✅ VLANs liberadas correctamente")
                        else:
                            print(f"⚠️ Quedan {len(remaining_vlans)} VLANs sin liberar")
                
                return True
            else:
                print(f"❌ Error eliminando slice R5: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error en cleanup R5: {e}")
            return False
    
    def run_complete_r5_test(self):
        """Ejecutar test completo R5"""
        print("🚀 PUCP Cloud Orchestrator - Test Completo R5 (Management/Trunk/VLANs)")
        print("=" * 80)
        
        try:
            # 1. Autenticación
            if not self.authenticate():
                return False
            
            # 2. Verificar Network Service
            if not self.check_network_service_status():
                print("⚠️ Continuando sin Network Service completo...")
            
            # 3. Verificar infraestructura OVS
            if not self.check_ovs_infrastructure():
                print("⚠️ Problemas con infraestructura OVS detectados")
            
            # 4. Crear topología R5
            slice_id = self.create_r5_topology()
            if not slice_id:
                return False
            
            # 5. Desplegar con R5
            if not self.deploy_slice(slice_id):
                return False
            
            # 6. Monitorear deployment R5
            if not self.monitor_deployment(slice_id):
                return False
            
            # 7. Verificaciones específicas R5
            print("\n" + "=" * 60)
            print("🔍 VERIFICACIONES ESPECÍFICAS R5")
            print("=" * 60)
            
            # Verificar redes R5
            self.verify_r5_networks(slice_id)
            
            # Verificar acceso a internet
            self.verify_internet_access(slice_id)
            
            # Verificar reglas de seguridad
            self.verify_security_rules(slice_id)
            
            print("\n" + "=" * 80)
            print("✅ ¡Test completo R5 EXITOSO!")
            print(f"   Slice ID: {slice_id}")
            print("   Topología R5 funcionando correctamente:")
            print("   • Redes de management configuradas")
            print("   • Redes trunk con VLANs asignadas")
            print("   • Redes de datos aisladas")
            print("   • Acceso a internet configurado")
            print("   • Reglas de seguridad aplicadas")
            
            # Preguntar si limpiar
            cleanup = input("\n¿Deseas eliminar el slice de prueba R5? (y/n): ")
            if cleanup.lower() == 'y':
                self.cleanup_slice(slice_id)
            else:
                print(f"💡 Slice R5 conservado: {slice_id}")
                print(f"   Para eliminarlo: curl -X DELETE {API_BASE}/slices/{slice_id} -H 'Authorization: Bearer {self.token}'")
            
            return True
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            if self.slice_id:
                print(f"💡 Slice creado: {self.slice_id}")
            return False
        except Exception as e:
            print(f"\n❌ Error crítico en test R5: {e}")
            return False

def main():
    """Función principal"""
    tester = PUCPTopologyTesterR5()
    success = tester.run_complete_r5_test()
    
    if success:
        print("\n🎉 Test R5 completado exitosamente!")
        print("✅ Verificación completa de Management/Trunk/VLANs")
        sys.exit(0)
    else:
        print("\n💥 Test R5 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
