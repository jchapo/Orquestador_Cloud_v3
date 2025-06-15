#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Linux Driver (R2)
Maneja VMs en cluster Linux usando libvirt/KVM con soporte completo para topologías
"""

import libvirt
import xml.etree.ElementTree as ET
import subprocess
import logging
import uuid
import os
import time
import json
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .base_driver import BaseDriver

logger = logging.getLogger(__name__)

class LinuxClusterDriver(BaseDriver):
    """Driver para gestionar VMs en cluster Linux usando libvirt"""
    
    def __init__(self):
        super().__init__()
        
        # Configuración del cluster según tu documento
        self.hypervisors = {
            'server1': {
                'uri': 'qemu+ssh://ubuntu@pucp-server1/system',
                'ip': 'pucp-server1',  # O usar la IP real si prefieres
                'port': 5811,
                'max_vcpus': 4,        # ← Corregido (viste "CPU cores: 4")
                'max_ram': 4030,       # ← Corregido (viste "Memory: 3.8Gi")
                'max_disk': 100
            },
            'server2': {
                'uri': 'qemu+ssh://ubuntu@pucp-server2/system',  # ← ubuntu, no root
                'ip': 'pucp-server2',
                'port': 5812,
                'max_vcpus': 4,
                'max_ram': 4030,
                'max_disk': 100
            },
            'server3': {
                'uri': 'qemu+ssh://ubuntu@pucp-server3/system',  # ← ubuntu, no root
                'ip': 'pucp-server3',
                'port': 5813,
                'max_vcpus': 4,
                'max_ram': 4030,
                'max_disk': 100
            },
            'server4': {
                'uri': 'qemu+ssh://ubuntu@pucp-server4/system',  # ← ubuntu, no root
                'ip': 'pucp-server4',
                'port': 5814,
                'max_vcpus': 4,
                'max_ram': 4030,
                'max_disk': 100
            }
        }
        
        # Configuración de red (según tu topología)
        self.ovs_bridge = 'ovs1'  # OVS switch del cluster Linux
        self.network_range = '192.168.201.0/24'
        self.gateway_ip = '192.168.201.1'  # Gateway según tu documento
        
        # Storage pools
        self.storage_pools = {
            'default': '/var/lib/libvirt/images',
            'iso': '/var/lib/libvirt/iso'
        }
        
        # Imágenes disponibles
        self.available_images = {
            'ubuntu-20.04': {
                'path': '/home/ubuntu/vm-images/ubuntu-20.04-server.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu20.04'
            },
            'ubuntu-22.04': {
                'path': '/home/ubuntu/vm-images/ubuntu-22.04-server.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu22.04'
            },
            'centos-8': {
                'path': '/home/ubuntu/vm-images/centos-8-stream.qcow2',
                'os_type': 'linux',
                'os_variant': 'centos8'
            }
        }
        
        self.connections = {}  # Cache de conexiones libvirt
    
    def get_connection(self, server_name: str) -> libvirt.virConnect:
        """Obtiene o crea conexión a un hypervisor"""
        if server_name not in self.hypervisors:
            raise ValueError(f"Unknown server: {server_name}")
        
        if server_name not in self.connections:
            try:
                uri = self.hypervisors[server_name]['uri']
                conn = libvirt.open(uri)
                if not conn:
                    raise Exception(f"Failed to connect to {uri}")
                
                self.connections[server_name] = conn
                logger.info(f"Connected to {server_name}: {uri}")
                
            except Exception as e:
                logger.error(f"Connection failed to {server_name}: {e}")
                raise
        
        return self.connections[server_name]
    
    def close_connections(self):
        """Cierra todas las conexiones"""
        for server_name, conn in self.connections.items():
            try:
                if conn and conn.isAlive():
                    conn.close()
                logger.info(f"Closed connection to {server_name}")
            except Exception as e:
                logger.warning(f"Error closing connection to {server_name}: {e}")
        
        self.connections.clear()
    
    def create_vm(self, vm_config: Dict, server_name: str, 
              slice_id: str = None, networks: List[Dict] = None) -> Dict:
        """
        Crea una VM en el servidor especificado
        """
        conn = None
        try:
            logger.info(f"Creating VM {vm_config['name']} on server {server_name}")
            logger.debug(f"VM config: {vm_config}")
            logger.debug(f"Available hypervisors: {list(self.hypervisors.keys())}")
            
            # Verificar que el servidor existe
            if server_name not in self.hypervisors:
                available_servers = list(self.hypervisors.keys())
                raise ValueError(f"Unknown server '{server_name}'. Available servers: {available_servers}")
            
            conn = self.get_connection(server_name)
            
            # Validar configuración
            self._validate_vm_config(vm_config, server_name)
            
            # Preparar disco de la VM
            disk_path = self._prepare_vm_disk(vm_config, server_name)
            
            # Generar XML de la VM
            vm_xml = self._generate_vm_xml(
                vm_config, disk_path, server_name, slice_id, networks
            )
            
            logger.info(f"Creating VM {vm_config['name']} on {server_name}")
            logger.debug(f"VM XML: {vm_xml}")
            
            # Crear la VM
            domain = conn.createXML(vm_xml, 0)
            if not domain:
                raise Exception("Failed to create VM")
            
            # Esperar a que arranque
            self._wait_for_vm_boot(domain, timeout=60)
            
            # Obtener información de la VM
            vm_info = self._get_vm_info(domain, server_name, vm_config)
            
            logger.info(f"✓ VM {vm_config['name']} created successfully on {server_name}")
            return vm_info
            
        except Exception as e:
            logger.error(f"Failed to create VM {vm_config['name']} on {server_name}: {e}")
            logger.error(f"Exception type: {type(e)}")
            logger.error(f"Exception args: {e.args}")
            
            # Cleanup en caso de error
            try:
                self._cleanup_failed_vm(vm_config['name'], server_name)
            except Exception as cleanup_error:
                logger.warning(f"Cleanup failed: {cleanup_error}")
            
            raise
    
    def delete_vm(self, vm_name: str, server_name: str, 
                  cleanup_disk: bool = True) -> bool:
        """Elimina una VM"""
        conn = None
        try:
            conn = self.get_connection(server_name)
            
            # Buscar la VM
            try:
                domain = conn.lookupByName(vm_name)
            except libvirt.libvirtError:
                logger.warning(f"VM {vm_name} not found on {server_name}")
                return True  # Ya no existe
            
            # Parar la VM si está corriendo
            if domain.isActive():
                logger.info(f"Stopping VM {vm_name}")
                domain.destroy()  # Force shutdown
                
                # Esperar a que pare
                timeout = 30
                while timeout > 0 and domain.isActive():
                    time.sleep(1)
                    timeout -= 1
            
            # Obtener info del disco antes de eliminar
            disk_paths = []
            if cleanup_disk:
                disk_paths = self._get_vm_disk_paths(domain)
            
            # Eliminar definición de la VM
            domain.undefine()
            
            # Limpiar discos
            if cleanup_disk:
                for disk_path in disk_paths:
                    self._cleanup_disk(disk_path, server_name)
            
            logger.info(f"✓ VM {vm_name} deleted from {server_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete VM {vm_name}: {e}")
            return False
    
    def get_vm_status(self, vm_name: str, server_name: str) -> Dict:
        """Obtiene estado de una VM"""
        try:
            conn = self.get_connection(server_name)
            domain = conn.lookupByName(vm_name)
            
            return self._get_vm_info(domain, server_name, {'name': vm_name})
            
        except libvirt.libvirtError:
            return {'name': vm_name, 'status': 'not_found'}
        except Exception as e:
            logger.error(f"Error getting VM status: {e}")
            return {'name': vm_name, 'status': 'error', 'error': str(e)}
    
    def get_vm_console_url(self, vm_name: str, server_name: str) -> Optional[str]:
        """Obtiene URL de consola VNC/SPICE"""
        try:
            conn = self.get_connection(server_name)
            domain = conn.lookupByName(vm_name)
            
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            # Buscar configuración de gráficos
            graphics = root.find('.//graphics[@type="vnc"]')
            if graphics is not None:
                port = graphics.get('port')
                if port and port != '-1':
                    # Mapear puerto según tu configuración
                    mapped_port = self.hypervisors[server_name]['port']
                    return f"vnc://{self.gateway_ip}:{mapped_port}"
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get console URL: {e}")
            return None
    
    def list_vms(self, server_name: str = None) -> List[Dict]:
        """Lista todas las VMs"""
        vms = []
        
        servers = [server_name] if server_name else self.hypervisors.keys()
        
        for srv in servers:
            try:
                conn = self.get_connection(srv)
                domains = conn.listAllDomains()
                
                for domain in domains:
                    vm_info = self._get_vm_info(domain, srv, {'name': domain.name()})
                    vms.append(vm_info)
                    
            except Exception as e:
                logger.error(f"Error listing VMs on {srv}: {e}")
        
        return vms
    
    def get_server_resources(self, server_name: str = None) -> List[Dict]:
        """Obtiene información de recursos de servidores"""
        resources = []
        
        servers = [server_name] if server_name else self.hypervisors.keys()
        
        for srv in servers:
            try:
                conn = self.get_connection(srv)
                
                # Información del host
                host_info = conn.getInfo()
                node_info = conn.getNodeInfo()
                
                # Calcular recursos usados
                domains = conn.listAllDomains()
                used_vcpus = 0
                used_ram = 0
                
                for domain in domains:
                    if domain.isActive():
                        domain_info = domain.info()
                        used_vcpus += domain_info[3]  # Number of virtual CPUs
                        used_ram += domain_info[2] // 1024  # Memory in MB
                
                server_config = self.hypervisors[srv]
                
                resource_info = {
                    'hostname': srv,
                    'ip': server_config['ip'],
                    'infrastructure': 'linux',
                    'status': 'active' if conn.isAlive() else 'inactive',
                    'total_vcpus': server_config['max_vcpus'],
                    'used_vcpus': used_vcpus,
                    'available_vcpus': server_config['max_vcpus'] - used_vcpus,
                    'total_ram': server_config['max_ram'],
                    'used_ram': used_ram,
                    'available_ram': server_config['max_ram'] - used_ram,
                    'total_disk': server_config['max_disk'],
                    'used_disk': self._get_used_disk_space(srv),
                    'active_vms': len([d for d in domains if d.isActive()]),
                    'total_vms': len(domains),
                    'cpu_utilization': (used_vcpus / server_config['max_vcpus']) * 100,
                    'ram_utilization': (used_ram / server_config['max_ram']) * 100,
                    'last_updated': datetime.utcnow().isoformat()
                }
                
                resources.append(resource_info)
                
            except Exception as e:
                logger.error(f"Error getting resources for {srv}: {e}")
                # Agregar info básica aunque falle la conexión
                resources.append({
                    'hostname': srv,
                    'infrastructure': 'linux',
                    'status': 'error',
                    'error': str(e)
                })
        
        return resources
    
    def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:
        """
        Despliega un slice completo con sus VMs y redes
        
        Args:
            slice_config: Configuración del slice
            placement: Resultado del VM placement {vm_name: server_assignment}
            
        Returns:
            Dict con resultados del deployment
        """
        deployed_vms = []
        created_networks = []
        errors = []
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            # 1. Crear redes primero
            logger.info(f"Creating networks for slice {slice_id}")
            for network in slice_config.get('networks', []):
                try:
                    network_result = self._create_slice_network(network, slice_id)
                    created_networks.append(network_result)
                    logger.info(f"✓ Network {network['name']} created")
                except Exception as e:
                    error_msg = f"Failed to create network {network['name']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 2. Crear VMs según placement
            logger.info(f"Creating VMs for slice {slice_id}")
            logger.info(f"Placement result: {placement}")  # ← DEBUG: Ver el placement
            for vm_config in slice_config.get('nodes', []):
                vm_name = vm_config['name']
                
                if vm_name not in placement:
                    error_msg = f"No placement found for VM {vm_name}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
                
                server_assignment = placement[vm_name]
                server_name = server_assignment['hostname']
                logger.info(f"Server assignment for {vm_name}: {server_assignment}")
                
                try:
                    # Preparar configuración de VM para el driver
                    driver_vm_config = {
                        'name': vm_name,
                        'cpu': vm_config.get('cpu', 1),
                        'ram': vm_config.get('ram', 1024),
                        'disk': vm_config.get('disk', 10),
                        'image': vm_config.get('image', 'ubuntu-20.04')
                    }
                    
                    vm_result = self.create_vm(
                        driver_vm_config, 
                        server_name, 
                        slice_id, 
                        created_networks
                    )
                    
                    deployed_vms.append(vm_result)
                    logger.info(f"✓ VM {vm_name} deployed on {server_name}")
                    
                except Exception as e:
                    error_msg = f"Failed to deploy VM {vm_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 3. Configurar conectividad entre VMs si se especifica
            if 'connections' in slice_config:
                logger.info(f"Configuring VM connections for slice {slice_id}")
                self._configure_vm_connections(
                    slice_config['connections'], 
                    deployed_vms, 
                    created_networks
                )
            
            deployment_result = {
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
            
            if errors:
                logger.warning(f"Slice {slice_id} deployed with {len(errors)} errors")
            else:
                logger.info(f"✓ Slice {slice_id} deployed successfully")
            
            return deployment_result
            
        except Exception as e:
            logger.error(f"Critical error deploying slice {slice_id}: {e}")
            
            # Cleanup en caso de error crítico
            self._cleanup_slice_deployment(deployed_vms, created_networks)
            
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deployed_vms': deployed_vms,
                'created_networks': created_networks
            }
    
    def destroy_slice(self, slice_id: str, vm_list: List[Dict]) -> Dict:
        """Elimina un slice completo"""
        deleted_vms = []
        errors = []
        
        try:
            logger.info(f"Destroying slice {slice_id}")
            
            for vm_info in vm_list:
                try:
                    vm_name = vm_info['name']
                    server_name = vm_info.get('assigned_host') or vm_info.get('server')
                    
                    if not server_name:
                        logger.warning(f"No server info for VM {vm_name}")
                        continue
                    
                    success = self.delete_vm(vm_name, server_name, cleanup_disk=True)
                    if success:
                        deleted_vms.append(vm_name)
                        logger.info(f"✓ VM {vm_name} deleted")
                    else:
                        errors.append(f"Failed to delete VM {vm_name}")
                        
                except Exception as e:
                    error_msg = f"Error deleting VM {vm_info.get('name', 'unknown')}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # Cleanup de redes del slice
            try:
                self._cleanup_slice_networks(slice_id)
            except Exception as e:
                errors.append(f"Network cleanup error: {e}")
            
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
    
    # Métodos privados auxiliares

    def _get_vm_info(self, domain, server_name: str, vm_config: Dict) -> Dict:
        """Obtiene información completa de una VM"""
        try:
            # Información básica del dominio
            vm_info = domain.info()
            state_names = {
                libvirt.VIR_DOMAIN_NOSTATE: 'no_state',
                libvirt.VIR_DOMAIN_RUNNING: 'running', 
                libvirt.VIR_DOMAIN_BLOCKED: 'blocked',
                libvirt.VIR_DOMAIN_PAUSED: 'paused',
                libvirt.VIR_DOMAIN_SHUTDOWN: 'shutdown',
                libvirt.VIR_DOMAIN_SHUTOFF: 'shutoff',
                libvirt.VIR_DOMAIN_CRASHED: 'crashed'
            }
            
            # Obtener IP de la VM
            ip_address = self._get_vm_ip_address(domain)
            
            # Obtener puerto VNC
            vnc_port = self._get_vnc_port(domain)
            console_url = None
            if vnc_port:
                mapped_port = self.hypervisors[server_name]['port']
                console_url = f"vnc://{self.gateway_ip}:{mapped_port}"
            
            # Obtener metadata del slice
            slice_id = self._get_vm_slice_id(domain)
            
            return {
                'vm_id': domain.UUIDString(),
                'name': domain.name(),
                'status': state_names.get(vm_info[0], 'unknown'),
                'server': server_name,
                'server_ip': self.hypervisors[server_name]['ip'],
                'vcpus': vm_info[3],
                'ram_mb': vm_info[2] // 1024,
                'max_ram_mb': vm_info[1] // 1024,
                'cpu_time': vm_info[4],
                'ip_address': ip_address,
                'console_url': console_url,
                'vnc_port': vnc_port,
                'slice_id': slice_id,
                'created_at': datetime.utcnow().isoformat(),
                'is_active': domain.isActive() == 1,
                'autostart': domain.autostart() == 1
            }
            
        except Exception as e:
            logger.error(f"Error getting VM info: {e}")
            return {
                'vm_id': domain.UUIDString() if domain else None,
                'name': vm_config.get('name', 'unknown'),
                'status': 'error',
                'server': server_name,
                'error': str(e)
            }

    def _get_vm_ip_address(self, domain) -> Optional[str]:
        """Obtiene dirección IP de la VM"""
        try:
            # Método 1: DHCP leases (más confiable)
            ifaces = domain.interfaceAddresses(
                libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
            )
            
            for name, iface in ifaces.items():
                if iface['addrs']:
                    for addr in iface['addrs']:
                        if addr['type'] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                            return addr['addr']
            
            # Método 2: Guest agent (si está disponible)
            try:
                ifaces = domain.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT
                )
                for name, iface in ifaces.items():
                    if iface['addrs']:
                        for addr in iface['addrs']:
                            if addr['type'] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                                return addr['addr']
            except:
                pass
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get VM IP: {e}")
            return None

    def _get_vnc_port(self, domain) -> Optional[int]:
        """Obtiene puerto VNC de la VM"""
        try:
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            graphics = root.find('.//graphics[@type="vnc"]')
            if graphics is not None:
                port = graphics.get('port')
                if port and port != '-1':
                    return int(port)
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get VNC port: {e}")
            return None

    def _get_vm_slice_id(self, domain) -> Optional[str]:
        """Obtiene slice_id del metadata de la VM"""
        try:
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            # Buscar en metadata
            slice_elem = root.find('.//{http://pucp.edu.pe/orchestrator}slice_id')
            if slice_elem is not None:
                return slice_elem.text
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get slice ID: {e}")
            return None

    def _get_vm_disk_paths(self, domain) -> List[str]:
        """Obtiene rutas de discos de la VM"""
        disk_paths = []
        try:
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            disks = root.findall('.//disk[@type="file"]')
            for disk in disks:
                source = disk.find('source')
                if source is not None:
                    file_path = source.get('file')
                    if file_path:
                        disk_paths.append(file_path)
            
        except Exception as e:
            logger.error(f"Error getting disk paths: {e}")
        
        return disk_paths

    def _cleanup_failed_vm(self, vm_name: str, server_name: str):
        """Limpia VM que falló en la creación"""
        try:
            conn = self.get_connection(server_name)
            
            # Intentar eliminar definición si existe
            try:
                domain = conn.lookupByName(vm_name)
                if domain.isActive():
                    domain.destroy()
                domain.undefine()
            except:
                pass
            
            # Limpiar disco si existe
            disk_path = f"/home/ubuntu/vm-disks/{vm_name}.qcow2"
            self._cleanup_disk(disk_path, server_name)
            
        except Exception as e:
            logger.warning(f"Cleanup failed for VM {vm_name}: {e}")

    def _cleanup_slice_deployment(self, deployed_vms: List[Dict], 
                                created_networks: List[Dict]):
        """Limpia deployment fallido de slice"""
        try:
            logger.info("Cleaning up failed slice deployment")
            
            # Eliminar VMs creadas
            for vm_info in deployed_vms:
                try:
                    self.delete_vm(vm_info['name'], vm_info['server'])
                except Exception as e:
                    logger.warning(f"Failed to cleanup VM {vm_info['name']}: {e}")
            
            # Limpiar redes
            for network in created_networks:
                try:
                    # Cleanup de red
                    pass
                except Exception as e:
                    logger.warning(f"Failed to cleanup network {network['name']}: {e}")
                    
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def _get_used_disk_space(self, server_name: str) -> int:
        """Obtiene espacio de disco usado en GB"""
        try:
            server_hostname = self.hypervisors[server_name]['hostname']
            cmd = [
                'ssh', 
                '-o', 'StrictHostKeyChecking=no',
                f'ubuntu@{server_hostname}', 
                'du', '-s', '/home/ubuntu/vm-images'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Resultado en KB, convertir a GB
            kb_used = int(result.stdout.split()[0])
            gb_used = kb_used // (1024 * 1024)
            
            return gb_used
            
        except Exception as e:
            logger.warning(f"Could not get disk usage for {server_name}: {e}")
            return 0

    def _generate_mac_address(self, vm_name: str, server_name: str) -> str:
        """Genera MAC address única para la VM"""
        # Usar hash del nombre + servidor para generar MAC consistente
        import hashlib
        hash_input = f"{vm_name}-{server_name}".encode()
        hash_value = hashlib.md5(hash_input).hexdigest()
        
        # Formato MAC: 52:54:00:XX:XX:XX (prefijo KVM)
        mac = f"52:54:00:{hash_value[0:2]}:{hash_value[2:4]}:{hash_value[4:6]}"
        return mac

    def _create_slice_network(self, network_config: Dict, slice_id: str) -> Dict:
        """Crea red para el slice"""
        try:
            # Para Linux cluster, las redes se manejan a través de OVS
            # Este método coordina con el network_service
            
            network_name = f"{slice_id}-{network_config['name']}"
            
            logger.info(f"Creating network {network_name} for slice {slice_id}")
            
            # En el cluster Linux, todas las redes usan el mismo bridge OVS
            # pero pueden tener diferentes VLANs o configuraciones
            
            return {
                'name': network_name,
                'cidr': network_config['cidr'],
                'vlan_id': None,  # Se asignaría por el network_service
                'status': 'active',
                'bridge': self.ovs_bridge,
                'gateway': network_config.get('gateway'),
                'dns_servers': network_config.get('dns_servers', ['8.8.8.8'])
            }
            
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            raise Exception(f"Network creation failed: {e}")
    
    def _validate_vm_config(self, vm_config: Dict, server_name: str):
        """Valida configuración de VM"""
        required_fields = ['name', 'cpu', 'ram', 'disk', 'image']
        for field in required_fields:
            if field not in vm_config:
                raise ValueError(f"Missing required field: {field}")
        
        # Validar imagen
        if vm_config['image'] not in self.available_images:
            raise ValueError(f"Unknown image: {vm_config['image']}")
        
        # Validar recursos
        server_config = self.hypervisors[server_name]
        if vm_config['cpu'] > server_config['max_vcpus']:
            raise ValueError(f"CPU count exceeds server limit")
        if vm_config['ram'] > server_config['max_ram']:
            raise ValueError(f"RAM exceeds server limit")
    
    def _cleanup_disk(self, disk_path: str, server_name: str):
        """Elimina archivo de disco"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'rm', '-f', disk_path]
            
            subprocess.run(ssh_cmd, check=True, capture_output=True)
            logger.info(f"Disk removed: {disk_path}")
            
        except Exception as e:
            logger.warning(f"Failed to remove disk {disk_path}: {e}")

    
    def _get_compatible_machine_type(self, server_name: str) -> str:
        """Obtiene un tipo de máquina compatible para el servidor"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            
            # Obtener tipos de máquina disponibles
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'qemu-system-x86_64', '-machine', 'help']
            result = subprocess.run(ssh_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                machine_types = result.stdout
                
                # Prioridad para servidores Ubuntu 20.04 con QEMU 4.2.1
                preferred_types = [
                    'ubuntu',            # Alias para pc-i440fx-focal
                    'pc-i440fx-focal',   # Ubuntu 20.04 PC (por defecto)
                    'pc-i440fx-focal-hpb', # Con host-phys-bits=true
                    'pc-i440fx-eoan',    # Ubuntu 19.10 (fallback)
                    'pc-i440fx-xenial',  # Ubuntu 16.04 (fallback)
                    'pc'                 # Genérico (último recurso)
                ]
                
                # Buscar el primer tipo disponible
                for machine_type in preferred_types:
                    if machine_type in machine_types:
                        logger.info(f"Using machine type '{machine_type}' for {server_name}")
                        return machine_type
                
                logger.warning(f"No preferred machine type found for {server_name}, using 'ubuntu'")
                return 'ubuntu'
                
            else:
                logger.error(f"Failed to get machine types for {server_name}: {result.stderr}")
                return 'ubuntu'  # Fallback seguro
                
        except Exception as e:
            logger.error(f"Error detecting machine type for {server_name}: {e}")
            return 'ubuntu'  # Fallback seguro
    
    def _wait_for_vm_boot(self, domain, timeout: int = 60):
        """Espera a que la VM arranque completamente"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                state = domain.state()[0]
                if state == libvirt.VIR_DOMAIN_RUNNING:
                    logger.info(f"VM {domain.name()} is running")
                    return True
                elif state == libvirt.VIR_DOMAIN_SHUTOFF:
                    raise Exception("VM failed to start - shutoff state")
                    
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error checking VM state: {e}")
                break
        
        raise Exception(f"VM {domain.name()} failed to boot within {timeout} seconds")
    
    def _get_compatible_machine_type(self, server_name: str) -> str:
        """Obtiene un tipo de máquina compatible para el servidor"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            
            # Obtener tipos de máquina disponibles
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'qemu-system-x86_64', '-machine', 'help']
            result = subprocess.run(ssh_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                machine_types = result.stdout
                
                # Prioridad para servidores Ubuntu 20.04 con QEMU 4.2.1
                preferred_types = [
                    'ubuntu',            # Alias para pc-i440fx-focal
                    'pc-i440fx-focal',   # Ubuntu 20.04 PC (por defecto)
                    'pc-i440fx-focal-hpb', # Con host-phys-bits=true
                    'pc-i440fx-eoan',    # Ubuntu 19.10 (fallback)
                    'pc-i440fx-xenial',  # Ubuntu 16.04 (fallback)
                    'pc'                 # Genérico (último recurso)
                ]
                
                # Buscar el primer tipo disponible
                for machine_type in preferred_types:
                    if machine_type in machine_types:
                        logger.info(f"Using machine type '{machine_type}' for {server_name}")
                        return machine_type
                
                logger.warning(f"No preferred machine type found for {server_name}, using 'ubuntu'")
                return 'ubuntu'
                
            else:
                logger.error(f"Failed to get machine types for {server_name}: {result.stderr}")
                return 'ubuntu'  # Fallback seguro
                
        except Exception as e:
            logger.error(f"Error detecting machine type for {server_name}: {e}")
            return 'ubuntu'  # Fallback seguro

    def _prepare_vm_disk(self, vm_config: Dict, server_name: str) -> str:
        """Prepara disco de la VM"""
        vm_name = vm_config['name']
        base_image = self.available_images[vm_config['image']]['path']
        
        # Usar directorio del usuario ubuntu con permisos completos
        vm_disk_path = f"/home/ubuntu/vm-disks/{vm_name}.qcow2"
        
        # Crear directorio si no existe
        server_ip = self.hypervisors[server_name]['ip']
        
        # Crear directorio con permisos correctos
        setup_cmds = [
            f'mkdir -p /home/ubuntu/vm-disks',
            f'chmod 755 /home/ubuntu/vm-disks'
        ]
        
        for cmd in setup_cmds:
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
            try:
                subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError:
                pass  # Directory might already exist
        
        # Crear disco usando qemu-img con backing file
        cmd = [
            'qemu-img', 'create', '-f', 'qcow2',
            '-F', 'qcow2', '-b', base_image,
            vm_disk_path, f"{vm_config['disk']}G"
        ]
        
        ssh_cmd = ['ssh', f'ubuntu@{server_ip}'] + cmd
        
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
            logger.info(f"Disk created: {vm_disk_path}")
            return vm_disk_path
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create disk: {e.stderr}")
            raise Exception(f"Disk creation failed: {e.stderr}")
            
    def _generate_vm_xml(self, vm_config: Dict, disk_path: str, 
                        server_name: str, slice_id: str = None, 
                        networks: List[Dict] = None) -> str:
        """Genera XML de configuración de la VM"""
        
        vm_name = vm_config['name']
        vm_uuid = str(uuid.uuid4())
        ram_mb = vm_config['ram']
        vcpus = vm_config['cpu']
        
        # Generar MAC address única
        mac_address = self._generate_mac_address(vm_name, server_name)
        
        # Usar tipo de máquina compatible
        machine_type = self._get_compatible_machine_type(server_name)

        xml_template = f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <uuid>{vm_uuid}</uuid>
  <metadata>
    <pucp:slice_id xmlns:pucp='http://pucp.edu.pe/orchestrator'>{slice_id or 'unknown'}</pucp:slice_id>
    <pucp:server xmlns:pucp='http://pucp.edu.pe/orchestrator'>{server_name}</pucp:server>
  </metadata>
  <memory unit='MiB'>{ram_mb}</memory>
  <currentMemory unit='MiB'>{ram_mb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='{machine_type}'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </disk>
    
    <!-- Controladores PCI para i440FX -->
    <controller type='pci' index='0' model='pci-root'/>
    <controller type='usb' index='0' model='piix3-uhci'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
    </controller>
    
    <!-- Interfaz de red -->
    <interface type='bridge'>
      <mac address='{mac_address}'/>
      <source bridge='{self.ovs_bridge}'/>
      <virtualport type='openvswitch'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    
    <!-- Consola serie -->
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    
    <!-- Dispositivos de entrada -->
    <input type='tablet' bus='usb'>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    
    <!-- Gráficos VNC -->
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    
    <!-- Video y sonido -->
    <video>
      <model type='cirrus' vram='16384' heads='1' primary='yes'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <sound model='ac97'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </sound>
    
    <!-- Memory balloon -->
    <memballoon model='virtio'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </memballoon>
  </devices>
</domain>"""
        
        return xml_template

        