#!/usr/bin/env python3
"""
Driver OpenStack Simplificado - Via Gateway
"""

import requests
import secrets
import json
from typing import Dict, Any, List

class SimpleOpenStackDriver:
    def __init__(self):
        # Acceder via gateway (puerto forwarding o proxy)
        self.base_url = "http://10.20.12.187"  # Gateway IP
        self.keystone_port = "5821"  # Puerto del headnode en gateway
        self.nova_port = "5821"
        
        self.auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "domain": {"name": "Default"},
                            "name": "admin",
                            "password": "admin123"
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {"name": "Default"},
                        "name": "admin"
                    }
                }
            }
        }
        self.token = None

    def get_token_via_ssh(self):
        """Obtener token ejecutando comando en headnode via SSH"""
        import subprocess
        try:
            # Ejecutar comando OpenStack en el headnode
            cmd = [
                "ssh", "-o", "ConnectTimeout=10", 
                "ubuntu@10.20.12.187", "-p", "5821",
                "openstack", "token", "issue", "-f", "value", "-c", "id"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.token = result.stdout.strip()
                print(f"✅ Token obtenido via SSH: {self.token[:20]}...")
                return True
            else:
                print(f"❌ Error obteniendo token: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error SSH: {e}")
            return False

    def create_vm_via_ssh(self, vm_config: Dict[str, Any]) -> Dict[str, Any]:
        """Crear VM ejecutando comando OpenStack via SSH"""
        import subprocess
        
        vm_name = vm_config.get('name', f'vm-{secrets.token_hex(3)}')
        print(f"🚀 Creando VM via SSH: {vm_name}")
        
        # Obtener recursos
        if vm_config.get('type') == 'manual':
            resources = vm_config.get('info_config', [1, 512, 1])
            vcpus = int(resources[0])
            ram = int(resources[1])
            disk = int(resources[2])
        else:
            vcpus, ram, disk = 1, 512, 1

        try:
            # Crear flavor único
            flavor_name = f"flavor-{vm_name}"
            cmd_flavor = [
                "ssh", "-o", "ConnectTimeout=10",
                "ubuntu@10.20.12.187", "-p", "5821",
                "openstack", "flavor", "create",
                "--vcpus", str(vcpus),
                "--ram", str(ram), 
                "--disk", str(disk),
                flavor_name
            ]
            
            print(f"📋 Creando flavor: {flavor_name}")
            result = subprocess.run(cmd_flavor, capture_output=True, text=True, timeout=15)
            
            if result.returncode != 0:
                print(f"⚠️ Warning crear flavor: {result.stderr}")
            
            # Crear VM
            placement = vm_config.get('placement', {})
            zone = placement.get('zone', 'nova')
            
            cmd_vm = [
                "ssh", "-o", "ConnectTimeout=10",
                "ubuntu@10.20.12.187", "-p", "5821", 
                "openstack", "server", "create",
                "--flavor", flavor_name,
                "--image", "cirros",
                "--availability-zone", zone,
                "--wait",
                vm_name
            ]
            
            print(f"🔧 Creando VM: {vm_name}")
            result = subprocess.run(cmd_vm, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Obtener info de la VM creada
                cmd_info = [
                    "ssh", "-o", "ConnectTimeout=10",
                    "ubuntu@10.20.12.187", "-p", "5821",
                    "openstack", "server", "show", vm_name, "-f", "json"
                ]
                
                info_result = subprocess.run(cmd_info, capture_output=True, text=True, timeout=15)
                
                if info_result.returncode == 0:
                    vm_info = json.loads(info_result.stdout)
                    return {
                        'id': vm_info.get('id', f'vm-{secrets.token_hex(8)}'),
                        'name': vm_name,
                        'status': vm_info.get('status', 'ACTIVE'),
                        'host': vm_info.get('OS-EXT-SRV-ATTR:host', 'unknown'),
                        'zone': vm_info.get('OS-EXT-AZ:availability_zone', zone),
                        'infrastructure': 'openstack'
                    }
                else:
                    print(f"⚠️ VM creada pero no se pudo obtener info: {vm_name}")
                    return {
                        'id': f'vm-{secrets.token_hex(8)}',
                        'name': vm_name,
                        'status': 'ACTIVE',
                        'infrastructure': 'openstack'
                    }
            else:
                print(f"❌ Error creando VM: {result.stderr}")
                raise Exception(f"No se pudo crear VM {vm_name}: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            raise

    def create_vm_simple(self, vm_config: Dict[str, Any]) -> Dict[str, Any]:
        """Método principal para crear VMs"""
        return self.create_vm_via_ssh(vm_config)

def test_driver():
    """Función de prueba"""
    driver = SimpleOpenStackDriver()
    print("🧪 Probando driver via SSH...")
    
    vm_config = {
        'name': f'test-ssh-{secrets.token_hex(3)}',
        'type': 'manual',
        'info_config': [1, 512, 1],
        'placement': {'zone': 'nova'}
    }
    
    try:
        result = driver.create_vm_simple(vm_config)
        print(f"✅ VM creada exitosamente: {result}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_driver()
