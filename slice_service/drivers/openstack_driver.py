#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - OpenStack Driver (R3)
Implementa gestión de VMs usando OpenStack APIs
"""

import requests
import json
import logging
import time
import uuid
from typing import Dict, List, Optional
from datetime import datetime
from .base_driver import BaseDriver

logger = logging.getLogger(__name__)

class OpenStackDriver(BaseDriver):
    """Driver para gestionar VMs en OpenStack usando APIs REST"""
    
    def __init__(self):
        super().__init__()
        self.infrastructure_type = "openstack"
        
        # Configuración basada en tu instalación
        self.keystone_url = "http://headnode:5000/v3"
        self.nova_url = "http://headnode:8774/v2.1" 
        self.neutron_url = "http://headnode:9696/v2.0"
        self.glance_url = "http://headnode:9292/v2"
        
        # Credenciales (usa las mismas de tu service_passwords)
        self.username = "admin"
        self.password = None  # Se carga desde env o config
        self.project_name = "admin"
        self.domain_name = "Default"
        
        self.token = None
        self.project_id = None
        
        # Mapeo de flavors
        self.flavor_mapping = {
            'nano': 'm1.tiny',
            'micro': 'm1.small', 
            'small': 'm1.small',
            'medium': 'm1.medium',
            'large': 'm1.large'
        }
        
        # Mapeo de imágenes
        self.image_mapping = {
            'ubuntu-20.04': 'cirros',  # Usar cirros por ahora
            'centos-8': 'cirros',
        }
    
    def authenticate(self) -> bool:
        """Autenticar con Keystone"""
        # Cargar password desde variables de entorno o config
        if not self.password:
            try:
                import os
                # Intentar cargar desde las mismas credenciales de tu instalación
                admin_pass = os.getenv('ADMIN_PASS')
                if admin_pass:
                    self.password = admin_pass
                else:
                    # Usar password por defecto o cargar desde archivo
                    self.password = self._load_admin_password()
            except:
                logger.error("No se pudo cargar password de admin")
                return False
        
        auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "domain": {"name": self.domain_name},
                            "password": self.password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": self.project_name,
                        "domain": {"name": self.domain_name}
                    }
                }
            }
        }
        
        try:
            response = requests.post(
                f"{self.keystone_url}/auth/tokens",
                json=auth_data,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 201:
                self.token = response.headers.get('X-Subject-Token')
                token_data = response.json()
                self.project_id = token_data['token']['project']['id']
                logger.info("✅ OpenStack authentication successful")
                return True
            else:
                logger.error(f"❌ Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Authentication error: {e}")
            return False
    
    def _load_admin_password(self) -> str:
        """Carga password de admin desde archivo service_passwords"""
        try:
            # Leer desde el archivo que creaste en tu instalación
            with open('/root/service_passwords', 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'ADMIN_PASS=' in line:
                        return line.split('=')[1].strip().replace("'", "")
        except:
            pass
        
        # Password por defecto para desarrollo
        return "openstack123"  # Cambiar por tu password real
    
    def _get_headers(self) -> Dict[str, str]:
        """Obtiene headers para requests con token"""
        return {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token
        }
    
    def create_vm(self, vm_config: Dict, server_name: str = None, 
                  slice_id: str = None, networks: List[Dict] = None) -> Dict:
        """Crea VM usando Nova API"""
        
        if not self.token and not self.authenticate():
            raise Exception("Authentication failed")
        
        try:
            # Mapear configuración
            flavor_name = self.flavor_mapping.get(vm_config.get('flavor', 'small'), 'm1.small')
            image_name = self.image_mapping.get(vm_config.get('image', 'ubuntu-20.04'), 'cirros')
            
            # Obtener IDs de flavor e imagen
            flavor_id = self._get_flavor_id(flavor_name)
            image_id = self._get_image_id(image_name)
            
            if not flavor_id or not image_id:
                raise Exception(f"Flavor {flavor_name} or image {image_name} not found")
            
            # Preparar datos de la VM
            server_data = {
                "server": {
                    "name": vm_config['name'],
                    "imageRef": image_id,
                    "flavorRef": flavor_id,
                    "metadata": {
                        "slice_id": slice_id or "unknown",
                        "created_by": "pucp-orchestrator"
                    }
                }
            }
            
            # Agregar redes si se especifican
            if networks:
                network_configs = []
                for network in networks:
                    net_id = self._get_network_id(network['name'])
                    if net_id:
                        network_configs.append({"uuid": net_id})
                
                if network_configs:
                    server_data["server"]["networks"] = network_configs
            
            # Crear VM via Nova API
            response = requests.post(
                f"{self.nova_url}/servers",
                json=server_data,
                headers=self._get_headers(),
                timeout=60
            )
            
            if response.status_code == 202:
                server_info = response.json()['server']
                vm_id = server_info['id']
                
                # Esperar a que la VM esté activa
                self._wait_for_vm_active(vm_id)
                
                # Obtener información completa
                vm_result = self._get_vm_details(vm_id)
                vm_result.update({
                    'server': server_name or 'openstack-cluster',
                    'slice_id': slice_id
                })
                
                logger.info(f"✅ VM {vm_config['name']} created in OpenStack")
                return vm_result
                
            else:
                raise Exception(f"Nova API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Failed to create VM {vm_config['name']}: {e}")
            raise
    
    def delete_vm(self, vm_name: str, server_name: str = None, 
                  cleanup_disk: bool = True) -> bool:
        """Elimina VM usando Nova API"""
        
        if not self.token and not self.authenticate():
            return False
        
        try:
            # Buscar VM por nombre
            vm_id = self._find_vm_by_name(vm_name)
            if not vm_id:
                logger.warning(f"VM {vm_name} not found")
                return True
            
            # Eliminar VM
            response = requests.delete(
                f"{self.nova_url}/servers/{vm_id}",
                headers=self._get_headers(),
                timeout=30
            )
            
            if response.status_code == 204:
                logger.info(f"✅ VM {vm_name} deleted from OpenStack")
                return True
            else:
                logger.error(f"Failed to delete VM: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting VM {vm_name}: {e}")
            return False
    
    def get_vm_status(self, vm_name: str, server_name: str = None) -> Dict:
        """Obtiene estado de VM"""
        try:
            vm_id = self._find_vm_by_name(vm_name)
            if vm_id:
                return self._get_vm_details(vm_id)
            else:
                return {'name': vm_name, 'status': 'not_found'}
        except Exception as e:
            return {'name': vm_name, 'status': 'error', 'error': str(e)}
    
    def get_vm_console_url(self, vm_name: str, server_name: str = None) -> Optional[str]:
        """Obtiene URL de consola VNC"""
        try:
            vm_id = self._find_vm_by_name(vm_name)
            if not vm_id:
                return None
            
            console_data = {"os-getVNCConsole": {"type": "novnc"}}
            response = requests.post(
                f"{self.nova_url}/servers/{vm_id}/action",
                json=console_data,
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                return response.json()['console']['url']
            
        except Exception as e:
            logger.error(f"Error getting console URL: {e}")
        
        return None
    
    def list_vms(self, server_name: str = None) -> List[Dict]:
        """Lista VMs en OpenStack"""
        if not self.token and not self.authenticate():
            return []
        
        try:
            response = requests.get(
                f"{self.nova_url}/servers/detail",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                servers = response.json()['servers']
                return [self._format_vm_info(srv) for srv in servers]
            else:
                logger.error(f"Failed to list VMs: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error listing VMs: {e}")
            return []
    
    def get_server_resources(self, server_name: str = None) -> List[Dict]:
        """Obtiene recursos de OpenStack compute nodes"""
        if not self.token and not self.authenticate():
            return []
        
        try:
            # Obtener hypervisors
            response = requests.get(
                f"{self.nova_url}/os-hypervisors/detail",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                hypervisors = response.json()['hypervisors']
                resources = []
                
                for hyp in hypervisors:
                    resource_info = {
                        'hostname': hyp['hypervisor_hostname'],
                        'infrastructure': 'openstack',
                        'status': 'active' if hyp['status'] == 'enabled' else 'inactive',
                        'total_vcpus': hyp['vcpus'],
                        'used_vcpus': hyp['vcpus_used'],
                        'available_vcpus': hyp['vcpus'] - hyp['vcpus_used'],
                        'total_ram': hyp['memory_mb'],
                        'used_ram': hyp['memory_mb_used'],
                        'available_ram': hyp['memory_mb'] - hyp['memory_mb_used'],
                        'total_disk': hyp['local_gb'],
                        'used_disk': hyp['local_gb_used'],
                        'available_disk': hyp['local_gb'] - hyp['local_gb_used'],
                        'running_vms': hyp['running_vms']
                    }
                    resources.append(resource_info)
                
                return resources
            else:
                logger.error(f"Failed to get hypervisors: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting server resources: {e}")
            return []
    
    def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:
        """Despliega slice completo en OpenStack"""
        deployed_vms = []
        created_networks = []
        errors = []
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            if not self.authenticate():
                raise Exception("Authentication failed")
            
            logger.info(f"Deploying slice {slice_id} in OpenStack")
            
            # 1. Crear redes usando Neutron
            for network in slice_config.get('networks', []):
                try:
                    network_result = self._create_neutron_network(network, slice_id)
                    created_networks.append(network_result)
                    logger.info(f"✅ Network {network['name']} created")
                except Exception as e:
                    error_msg = f"Failed to create network {network['name']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 2. Crear VMs usando Nova
            for vm_config in slice_config.get('nodes', []):
                vm_name = vm_config['name']
                
                if vm_name not in placement:
                    error_msg = f"No placement found for VM {vm_name}"
                    errors.append(error_msg)
                    continue
                
                try:
                    vm_result = self.create_vm(
                        vm_config, 
                        placement[vm_name]['hostname'],
                        slice_id,
                        created_networks
                    )
                    deployed_vms.append(vm_result)
                    logger.info(f"✅ VM {vm_name} deployed")
                    
                except Exception as e:
                    error_msg = f"Failed to deploy VM {vm_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            return {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deployed_vms': deployed_vms,
                'created_networks': created_networks,
                'errors': errors,
                'summary': {
                    'total_vms': len(slice_config.get('nodes', [])),
                    'deployed_vms': len(deployed_vms),
                    'total_networks': len(slice_config.get('networks', [])),
                    'created_networks': len(created_networks),
                    'deployment_time': datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Critical error deploying slice {slice_id}: {e}")
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deployed_vms': deployed_vms,
                'created_networks': created_networks
            }
    
    def destroy_slice(self, slice_id: str, vm_list: List[Dict]) -> Dict:
        """Destruye slice en OpenStack"""
        deleted_vms = []
        errors = []
        
        try:
            logger.info(f"Destroying slice {slice_id} in OpenStack")
            
            for vm_info in vm_list:
                try:
                    vm_name = vm_info['name']
                    success = self.delete_vm(vm_name)
                    if success:
                        deleted_vms.append(vm_name)
                    else:
                        errors.append(f"Failed to delete VM {vm_name}")
                        
                except Exception as e:
                    error_msg = f"Error deleting VM {vm_info.get('name', 'unknown')}: {e}"
                    errors.append(error_msg)
            
            return {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deleted_vms': deleted_vms,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Critical error destroying slice {slice_id}: {e}")
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deleted_vms': deleted_vms
            }
    
    # Métodos auxiliares privados
    
    def _get_flavor_id(self, flavor_name: str) -> Optional[str]:
        """Obtiene ID de flavor por nombre"""
        try:
            response = requests.get(
                f"{self.nova_url}/flavors",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                flavors = response.json()['flavors']
                for flavor in flavors:
                    if flavor['name'] == flavor_name:
                        return flavor['id']
        except Exception as e:
            logger.error(f"Error getting flavor ID: {e}")
        
        return None
    
    def _get_image_id(self, image_name: str) -> Optional[str]:
        """Obtiene ID de imagen por nombre"""
        try:
            response = requests.get(
                f"{self.glance_url}/images",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                images = response.json()['images']
                for image in images:
                    if image['name'] == image_name:
                        return image['id']
        except Exception as e:
            logger.error(f"Error getting image ID: {e}")
        
        return None
    
    def _get_network_id(self, network_name: str) -> Optional[str]:
        """Obtiene ID de red por nombre"""
        try:
            response = requests.get(
                f"{self.neutron_url}/networks",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                networks = response.json()['networks']
                for network in networks:
                    if network['name'] == network_name:
                        return network['id']
        except Exception as e:
            logger.error(f"Error getting network ID: {e}")
        
        return None
    
    def _find_vm_by_name(self, vm_name: str) -> Optional[str]:
        """Encuentra VM por nombre y retorna su ID"""
        try:
            response = requests.get(
                f"{self.nova_url}/servers",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                servers = response.json()['servers']
                for server in servers:
                    if server['name'] == vm_name:
                        return server['id']
        except Exception as e:
            logger.error(f"Error finding VM: {e}")
        
        return None
    
    def _wait_for_vm_active(self, vm_id: str, timeout: int = 60):
        """Espera a que VM esté activa"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(
                    f"{self.nova_url}/servers/{vm_id}",
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    server = response.json()['server']
                    status = server['status']
                    
                    if status == 'ACTIVE':
                        logger.info(f"VM {vm_id} is active")
                        return True
                    elif status == 'ERROR':
                        raise Exception(f"VM {vm_id} failed to start")
                
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error checking VM status: {e}")
                break
        
        raise Exception(f"VM {vm_id} failed to become active within {timeout} seconds")
    
    def _get_vm_details(self, vm_id: str) -> Dict:
        """Obtiene detalles completos de VM"""
        try:
            response = requests.get(
                f"{self.nova_url}/servers/{vm_id}",
                headers=self._get_headers()
            )
            
            if response.status_code == 200:
                server = response.json()['server']
                return self._format_vm_info(server)
            
        except Exception as e:
            logger.error(f"Error getting VM details: {e}")
        
        return {'vm_id': vm_id, 'status': 'error'}
    
    def _format_vm_info(self, server: Dict) -> Dict:
        """Formatea información de VM"""
        # Obtener IP address
        ip_address = None
        addresses = server.get('addresses', {})
        for network_name, network_addrs in addresses.items():
            for addr in network_addrs:
                if addr['version'] == 4:
                    ip_address = addr['addr']
                    break
            if ip_address:
                break
        
        return {
            'vm_id': server['id'],
            'name': server['name'],
            'status': server['status'].lower(),
            'ip_address': ip_address,
            'flavor': server.get('flavor', {}).get('id'),
            'image': server.get('image', {}).get('id'),
            'created': server.get('created'),
            'updated': server.get('updated'),
            'hypervisor': server.get('OS-EXT-SRV-ATTR:hypervisor_hostname'),
            'slice_id': server.get('metadata', {}).get('slice_id')
        }
    
    def _create_neutron_network(self, network_config: Dict, slice_id: str) -> Dict:
        """Crea red usando Neutron API"""
        network_name = f"{slice_id}-{network_config['name']}"
        
        # Crear red
        network_data = {
            "network": {
                "name": network_name,
                "admin_state_up": True
            }
        }
        
        response = requests.post(
            f"{self.neutron_url}/networks",
            json=network_data,
            headers=self._get_headers()
        )
        
        if response.status_code == 201:
            network = response.json()['network']
            
            # Crear subnet
            subnet_data = {
                "subnet": {
                    "name": f"{network_name}-subnet",
                    "network_id": network['id'],
                    "cidr": network_config['cidr'],
                    "ip_version": 4,
                    "enable_dhcp": True
                }
            }
            
            if network_config.get('gateway'):
                subnet_data['subnet']['gateway_ip'] = network_config['gateway']
            
            subnet_response = requests.post(
                f"{self.neutron_url}/subnets",
                json=subnet_data,
                headers=self._get_headers()
            )
            
            if subnet_response.status_code == 201:
                subnet = subnet_response.json()['subnet']
                return {
                    'name': network_name,
                    'id': network['id'],
                    'subnet_id': subnet['id'],
                    'cidr': network_config['cidr'],
                    'status': 'active'
                }
        
        raise Exception(f"Failed to create network {network_name}")