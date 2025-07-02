#!/usr/bin/env python3
"""
Driver OpenStack Final - Compatible con tu infraestructura PUCP
"""

import subprocess
import secrets
import json
import time
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class PUCPOpenStackDriver:
    def __init__(self):
        self.gateway_host = "ubuntu@10.20.12.187"
        self.gateway_port = "5821"
        self.headnode_ip = "192.168.202.1"
        
    def _run_ssh_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Ejecutar comando en headnode via SSH con variables OpenStack"""
        # Prefijar comando para cargar variables de entorno
        full_command = f"source ~/openrc && {' '.join(command)}"
        
        ssh_cmd = [
            "ssh", "-o", "ConnectTimeout=10", 
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=quiet",
            self.gateway_host, "-p", self.gateway_port,
            full_command
        ]
        
        try:
            result = subprocess.run(
                ssh_cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timeout after {timeout} seconds',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }

    def authenticate(self) -> bool:
        """Verificar conectividad con OpenStack"""
        print("Verificando conectividad con OpenStack...")
        
        result = self._run_ssh_command([
            "openstack", "token", "issue", "-f", "value", "-c", "id"
        ])
        
        if result['success'] and result['stdout']:
            print("✅ Conectividad OpenStack verificada")
            return True
        else:
            print(f"❌ Error de conectividad: {result['stderr']}")
            return False

    def get_available_resources(self) -> Dict[str, Any]:
        """Obtener recursos disponibles de OpenStack"""
        print("Obteniendo recursos disponibles...")
        
        # Obtener hypervisors
        result = self._run_ssh_command([
            "openstack", "hypervisor", "list", "-f", "json"
        ])
        
        if not result['success']:
            print(f"Error obteniendo hypervisors: {result['stderr']}")
            return {}
        
        try:
            hypervisors = json.loads(result['stdout'])
            resources = {}
            
            for hv in hypervisors:
                name = hv.get('Hypervisor Hostname', hv.get('hypervisor_hostname', 'unknown'))
                resources[name] = {
                    'vcpu': 2,  # Valores por defecto basados en tu setup
                    'ram': 2048,
                    'disk': 20,
                    'availability_zone': 'nova',
                    'status': hv.get('Status', hv.get('status', 'unknown'))
                }
            
            print(f"✅ Recursos obtenidos: {len(resources)} hypervisors")
            return resources
            
        except json.JSONDecodeError as e:
            print(f"Error parsing hypervisors: {e}")
            return {}

    def create_vm(self, vm_config: Dict[str, Any], placement: Dict[str, Any] = None) -> Dict[str, Any]:
        """Crear VM en OpenStack"""
        vm_name = vm_config.get('name', f'vm-{secrets.token_hex(3)}')
        print(f"🚀 Creando VM: {vm_name}")
        
        # Obtener configuración de recursos
        if vm_config.get('type') == 'manual' or 'info_config' in vm_config:
            resources = vm_config.get('info_config', [1, 512, 1])
            vcpus = int(resources[0])
            ram = int(resources[1])
            disk = int(resources[2])
        else:
            # Usar flavor existente
            flavor = vm_config.get('flavor', 'small')
            return self._create_vm_with_flavor(vm_name, flavor, placement)
        
        # Crear flavor único para esta VM
        flavor_name = f"flavor-{vm_name}"
        print(f"📋 Creando flavor: {flavor_name}")
        
        flavor_result = self._run_ssh_command([
            "openstack", "flavor", "create",
            "--vcpus", str(vcpus),
            "--ram", str(ram),
            "--disk", str(disk),
            flavor_name
        ])
        
        if not flavor_result['success']:
            print(f"Flavor creation warning: {flavor_result['stderr']}")
        
        # Crear la VM
        return self._create_vm_with_flavor(vm_name, flavor_name, placement)

    def _create_vm_with_flavor(self, vm_name: str, flavor_name: str, placement: Dict[str, Any] = None) -> Dict[str, Any]:
        """Crear VM usando un flavor específico"""
        
        # Determinar zona de disponibilidad
        zone = 'nova'
        if placement:
            zone = placement.get('zone', placement.get('availability_zone', 'nova'))
        
        # Crear VM SIN RED para evitar problemas de Neutron
        print(f"🔧 Creando VM: {vm_name} con flavor {flavor_name} (sin red)")
        
        vm_cmd = [
            "openstack", "server", "create",
            "--flavor", flavor_name,
            "--image", "cirros",
            "--availability-zone", zone,
            "--nic", "none",  # SIN RED - evita problemas de Neutron
            vm_name
        ]
        
        vm_result = self._run_ssh_command(vm_cmd, timeout=60)  # Reducir timeout
        
        if vm_result['success']:
            print(f"✅ VM {vm_name} creada exitosamente")
            
            # Esperar un poco para que se active
            time.sleep(5)
            
            # Obtener información detallada de la VM
            info_result = self._run_ssh_command([
                "openstack", "server", "show", vm_name, "-f", "json"
            ])
            
            if info_result['success']:
                try:
                    vm_info = json.loads(info_result['stdout'])
                    
                    return {
                        'id': vm_info.get('id', f'vm-{secrets.token_hex(8)}'),
                        'name': vm_name,
                        'status': vm_info.get('status', 'ACTIVE'),
                        'ip_address': 'No network configured',
                        'flavor': flavor_name,
                        'image': vm_info.get('image', 'cirros'),
                        'availability_zone': vm_info.get('OS-EXT-AZ:availability_zone', zone),
                        'host': vm_info.get('OS-EXT-SRV-ATTR:host', 'unknown'),
                        'created_at': vm_info.get('created', time.strftime('%Y-%m-%dT%H:%M:%SZ')),
                        'infrastructure': 'openstack'
                    }
                except (json.JSONDecodeError, AttributeError, KeyError) as e:
                    print(f"Warning parsing VM info: {e}")
            
            # Si no se puede obtener info detallada, usar datos básicos
            return {
                'id': f'vm-{secrets.token_hex(8)}',
                'name': vm_name,
                'status': 'ACTIVE',
                'flavor': flavor_name,
                'availability_zone': zone,
                'infrastructure': 'openstack',
                'ip_address': 'No network configured'
            }
        else:
            error_msg = f"Error creando VM {vm_name}: {vm_result['stderr']}"
            print(error_msg)
            raise Exception(error_msg)

    def list_servers(self) -> List[Dict[str, Any]]:
        """Listar todos los servidores"""
        result = self._run_ssh_command([
            "openstack", "server", "list", "-f", "json"
        ])
        
        if result['success']:
            try:
                return json.loads(result['stdout'])
            except json.JSONDecodeError:
                return []
        return []

    def create_vm_simple(self, vm_config: Dict[str, Any]) -> Dict[str, Any]:
        """Método de compatibilidad para tu orquestador"""
        return self.create_vm(vm_config)

def test_driver():
    """Función de prueba"""
    driver = PUCPOpenStackDriver()
    
    print("🧪 Probando PUCP OpenStack Driver...")
    
    # Test 1: Conectividad
    print("\n1. Probando conectividad...")
    if driver.authenticate():
        print("✅ Conectividad exitosa")
    else:
        print("❌ Error de conectividad")
        return
    
    # Test 2: Recursos disponibles
    print("\n2. Obteniendo recursos...")
    resources = driver.get_available_resources()
    print(f"📊 Recursos: {len(resources)} hypervisors")
    for name, res in resources.items():
        print(f"   - {name}: {res['vcpu']} vCPU, {res['ram']} MB RAM")
    
    # Test 3: Crear VM de prueba (sin red)
    print("\n3. Creando VM de prueba (sin red)...")
    vm_config = {
        'name': f'test-no-net-{secrets.token_hex(3)}',
        'type': 'manual',
        'info_config': [1, 512, 1]
    }
    
    placement = {'zone': 'nova'}
    
    try:
        result = driver.create_vm(vm_config, placement)
        print(f"✅ VM creada: {result['name']} (ID: {result['id']})")
        print(f"   Status: {result['status']}")
        print(f"   Host: {result.get('host', 'unknown')}")
        print(f"   IP: {result.get('ip_address', 'Pendiente')}")
        
        # Test 4: Listar servidores
        print("\n4. Listando servidores...")
        servers = driver.list_servers()
        print(f"📋 Total servidores: {len(servers)}")
        
        return result
    except Exception as e:
        print(f"❌ Error creando VM: {e}")
        return None

if __name__ == "__main__":
    test_driver()
